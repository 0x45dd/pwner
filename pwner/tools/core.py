"""Foundation for every pwner tool: the scope guard, the consent gate and the registry.

This module owns the authorization boundary. `tool` registers a tool, `build_dispatch`
wraps each one with `_enforce_scope`, and nothing else in the package needs to remember
to do either. It depends on no other tools module — every sibling imports from here.
"""
from __future__ import annotations

import asyncio
import base64
import inspect
import ipaddress
import os
import re
import shutil
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

NMAP_BIN = os.environ.get("PWNER_NMAP", "nmap")


NUCLEI_BIN = os.environ.get("PWNER_NUCLEI", "nuclei")


HYDRA_BIN = os.environ.get("PWNER_HYDRA", "hydra")


SNMPWALK_BIN = os.environ.get("PWNER_SNMPWALK", "snmpwalk")

#: dirsearch: path/endpoint brute-forcing with real wordlists. Optional — content_discovery
#: and web_crawl work without it, it just goes much wider.
DIRSEARCH_BIN = os.environ.get("PWNER_DIRSEARCH", "dirsearch")


def has_nuclei() -> bool:
    return shutil.which(NUCLEI_BIN) is not None


def has_hydra() -> bool:
    return shutil.which(HYDRA_BIN) is not None


def has_dirsearch() -> bool:
    return bool(shutil.which(DIRSEARCH_BIN))


# Small built-in credential list so brute-force works without an external wordlist.
# Point `wordlist` at SecLists/rockyou for a real engagement.
DEFAULT_USERS = ["admin", "root", "administrator", "guest", "test", "user"]


DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "root", "toor", "admin123", "password123",
    "letmein", "welcome", "1234", "12345", "12345678", "qwerty", "secret",
    "test", "guest", "changeme", "password1", "admin1234", "p@ssw0rd",
]


class OperatorChannel:
    """Operator ⇄ agent channel for live steering + consent.

    Two modes:
    - classic (``managed=False``): drain() reads typed-ahead lines straight from
      stdin; consent() blocks on input(). Used by the one-shot interactive scan.
    - managed (``managed=True``): a live UI (the Textual TUI) owns input and
      *pushes* lines in with push(); consent() parks on a future the UI resolves with
      answer_consent(). This is what lets you keep typing while the agent works."""

    def __init__(self, managed: bool = False):
        self._buf: list[str] = []
        self.managed = managed
        self._consent_fut: asyncio.Future[str] | None = None
        self.consent_text: str | None = None

    def push(self, line: str) -> None:
        """Feed an operator line in (managed mode: called by the live input loop)."""
        self._buf.append(line)

    def has_pending(self) -> bool:
        """True if the operator typed something that hasn't been drained yet (managed mode).

        The agent loop uses this to interrupt a long-running tool so the operator's message
        is acted on right away instead of after the tool finishes."""
        return bool(self._buf)

    def drain(self) -> list[str]:
        """Return complete operator lines (non-blocking; used for live steering)."""
        out = list(self._buf)
        self._buf = []
        if not self.managed:  # classic mode: also sweep typed-ahead stdin
            import select
            while select.select([sys.stdin], [], [], 0)[0]:
                line = sys.stdin.readline()
                if line:
                    out.append(line.strip())
                else:
                    break
        return out

    async def prompt(self, text: str) -> str:
        print(text, end="", flush=True)
        ans = await asyncio.to_thread(input, "")
        return (ans or "").strip()

    # ---- consent -----------------------------------------------------------
    def consent_pending(self) -> bool:
        return self._consent_fut is not None and not self._consent_fut.done()

    def answer_consent(self, line: str) -> bool:
        """Resolve a parked consent request with the operator's line. True if one was waiting."""
        if self._consent_fut is not None and not self._consent_fut.done():
            self._consent_fut.set_result(line)
            return True
        return False

    async def consent(self, text: str) -> str:
        """Ask the operator a consent question and return their raw answer."""
        if not self.managed:
            return await self.prompt(text)
        # managed mode: show the question above the live box, park until answered
        print(text)
        loop = asyncio.get_event_loop()
        self._consent_fut = loop.create_future()
        self.consent_text = text
        try:
            return (await self._consent_fut or "").strip()
        finally:
            self._consent_fut = None
            self.consent_text = None


def _consent_granted(ctx: ScanContext) -> bool:
    """True if the operator approved high-impact actions (--auto-consent, or an
    earlier 'approved' consent decision). Brute-force/active steps require this."""
    if ctx.auto_consent:
        return True
    return any(r.get("decision") == "approved" for r in ctx.consent_requests)


async def _ask_consent(ctx: ScanContext, action: str, target: str, risk: str) -> bool:
    """Prompt the operator interactively for a high-impact action. Falls back to
    auto-approve/auto-deny in non-interactive mode."""
    if ctx.auto_consent:
        return True
    if not ctx.interactive:
        return False
    text = (f"\n  [!] pwner agent requests a HIGH-IMPACT action:\n"
            f"     action: {action}\n"
            f"     target: {target}\n"
            f"     risk:   {risk}\n"
            f"     approve? [y/N] ")
    try:
        ch = ctx.operator_channel
        if ch is not None:
            ans = await ch.consent(text)
        else:
            ans = await asyncio.to_thread(input, text)
    except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
        ans = ""
    return (ans or "").strip().lower() in ("y", "yes", "a", "approve")


async def _consent(ctx: ScanContext, action: str, target: str, risk: str = "high") -> bool:
    """Resolve consent for an action: auto-approve, remembered approval, interactive
    prompt, or auto-deny. Records the decision so the prompt isn't repeated."""
    if ctx.auto_consent:
        return True
    if any(r.get("decision") == "approved" for r in ctx.consent_requests):
        return True
    ok = await _ask_consent(ctx, action, target, risk)
    ctx.consent_requests.append({"action": action, "target": target, "risk": risk,
                                 "decision": "approved" if ok else "denied"})
    return ok


def _covered_by(new: str, scope: str) -> bool:
    """True when every host `new` names already sits inside `scope`.

    Both sides may be a host, a CIDR, a domain, or a comma-separated list of those. The
    IP cases are decided arithmetically; names are compared exactly, because resolving a
    domain to decide authorization would let whoever controls DNS widen the scope.
    """
    if not (new or "").strip() or not (scope or "").strip():
        return False
    scope_nets, scope_names = [], set()
    for part in str(scope).split(","):
        part = part.strip().lower().rstrip(".")
        if not part:
            continue
        try:
            scope_nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            scope_names.add(part)
    for part in str(new).split(","):
        part = part.strip().lower().rstrip(".")
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            if part not in scope_names:
                return False
            continue
        if not any(net.version == s.version and net.subnet_of(s) for s in scope_nets):
            return False
    return True


def _within_authorized_scope(new: str, ctx: ScanContext) -> bool:
    """True when `new` needs no fresh approval: it is inside the current scope, or inside
    something the operator already authorized this session."""
    if _covered_by(new, ctx.target or ""):
        return True
    return any(_covered_by(new, g) for g in ctx.scope_grants)


async def _consent_scope_change(ctx: ScanContext, new: str) -> bool:
    """Approval for moving the authorized scope somewhere it has not been.

    Deliberately NOT `_consent`. That function treats a single earlier approval as
    blanket consent for the rest of the session, which is defensible for "yes, brute
    force this" and indefensible here: approving an SSH brute force must not also
    authorize reaching a different network. `--auto-consent` does not cover this either,
    for the same reason — it approves high-impact *actions* inside the scope, not a new
    scope. Widening is the operator's own decision, so it is made in their own input: by
    answering this prompt, or by naming the wider target on the command line.

    A non-interactive run cannot ask, so the answer there is no.
    """
    if not ctx.interactive:
        return False
    text = (f"\n  [!] pwner agent requests a SCOPE CHANGE:\n"
            f"     current scope: {ctx.target or '(none)'}\n"
            f"     requested:     {new}\n"
            f"     this authorizes traffic to a target the current scope does not cover.\n"
            f"     approve? [y/N] ")
    try:
        ch = ctx.operator_channel
        ans = await ch.consent(text) if ch is not None else await asyncio.to_thread(input, text)
    except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
        ans = ""
    ok = (ans or "").strip().lower() in ("y", "yes", "a", "approve")
    ctx.scope_requests.append({"from": ctx.target or "", "to": new,
                               "decision": "approved" if ok else "denied"})
    return ok


def _grant_scope(ctx: ScanContext, target: str) -> None:
    """Record `target` as authorized, so narrowing and coming back does not re-prompt."""
    if target and target not in ctx.scope_grants:
        ctx.scope_grants.append(target)


def _nuclei_template_dir() -> str | None:
    """Locate the nuclei templates base directory (nuclei v3 doesn't always find it
    on its own). Env override PWNER_NUCLEI_TEMPLATES wins; then common install paths."""
    env = os.environ.get("PWNER_NUCLEI_TEMPLATES")
    if env and os.path.isdir(os.path.expanduser(env)):
        return os.path.expanduser(env)
    for p in ("~/nuclei-templates", "~/.local/nuclei-templates",
              "~/nuclei-templates-main", "~/.config/nuclei/templates"):
        full = os.path.expanduser(p)
        if os.path.isdir(full):
            return full
    return None


# Network-relevant nuclei categories. headless/javascript (browser/JS runtime),
# file/code/cloud (SAST/local/cloud) are excluded — slow or out of scope.
_NUCLEI_CATEGORIES = ("http", "network", "ssl", "dns")


def _nuclei_template_args() -> list[str]:
    """Build the `-t` args: env override (full dir), else the curated categories."""
    env = os.environ.get("PWNER_NUCLEI_TEMPLATES")
    if env and os.path.isdir(os.path.expanduser(env)):
        return ["-t", os.path.expanduser(env)]
    base = _nuclei_template_dir()
    if not base:
        return []
    dirs = [os.path.join(base, c) for c in _NUCLEI_CATEGORIES
            if os.path.isdir(os.path.join(base, c))]
    return ["-t", ",".join(dirs)] if dirs else ["-t", base]


def expand_hosts(target: str, cap: int = 4096) -> list[str]:
    """Expand a CIDR target into individual host strings. Single hosts pass through."""
    t = (target or "").strip()
    if "/" not in t:
        return [t]
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return [t]
    if net.num_addresses > cap:
        raise ToolError(f"range too large ({net.num_addresses} addresses) — cap is {cap}. "
                        f"Narrow the CIDR or raise --range-cap.")
    addrs = list(net.hosts())
    if not addrs:
        addrs = [net.network_address]
    return [str(ip) for ip in addrs]


# Intrusive/destructive NSE categories the agent may NOT request via run_nmap.
BLOCKED_SCRIPT_CATEGORIES = {"brute", "dos", "exploit", "intrusive", "broadcast", "external"}


ALLOWED_SCRIPT_ARGS_HINT = "vuln,safe,default,discovery,version"


# Port presets -> nmap args (each value is a list of argv tokens).
PORT_PRESETS = {
    "top-1000": ["--top-ports", "1000"],
    "top-100": ["--top-ports", "100"],
    "common": ["--top-ports", "1000"],
    "all": ["-p", "1-65535"],
}


class ToolError(RuntimeError):
    """A user-facing tool failure (nmap missing, out of scope, timeout, ...)."""


@dataclass
class ScanContext:
    target: str
    max_rate: int = 1000
    timing: str = "T4"
    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    consent_requests: list[dict] = field(default_factory=list)
    auto_consent: bool = False  # --auto-consent: approve consent gates (use with care)
    interactive: bool = False   # prompt [y/N] on high-impact actions instead of auto-deny
    range_cap: int = 4096
    concurrency: int = 20
    nuclei_severity: str = "low,medium,high,critical"
    operator_channel: Any = None  # OperatorChannel for live steering + interactive consent
    tui: Any = None               # TUI for live log + topology panel (None = plain print)
    exploit: Any = None           # ExploitState: reverse-shell listener + exfil channel (lazy)
    http_cookies: Any = None      # shared cookie jar so web tools stay logged in across calls
    scheme_cache: dict = field(default_factory=dict)  # (host,port) -> "http"/"https", probed once
    ledger: Any = None            # engagement working-memory (surface/creds/hypotheses/tried)
    # Scopes the operator has authorized this session, widest-first in practice. Separate
    # from `target` because `target` moves: narrowing to one host and back again must not
    # count as widening, and `consent_requests` cannot hold these — one approval there is
    # treated as blanket consent, which must never extend to reaching a new network.
    scope_grants: list[str] = field(default_factory=list)
    scope_requests: list[dict] = field(default_factory=list)

    def scope_networks(self) -> list:
        """Return ip_network objects for CIDR targets, else [] (single host)."""
        t = (self.target or "").strip()
        nets = []
        for part in t.split(","):
            part = part.strip()
            if "/" in part and not part.startswith(("http://", "https://")):
                try:
                    nets.append(ipaddress.ip_network(part, strict=False))
                except ValueError:
                    pass
        return nets


def _source_ip_for(target: str) -> str:
    """The local IP the OS uses to reach `target` — the interface facing it (tun0 on a VPN).

    Lives here rather than in session.py because the PCI segmentation test needs the same
    answer for a different reason: the vantage point a test was run from is evidence, and
    an assessor asks for it.
    """
    host = (target or "").split(",")[0].split("/")[0].strip() or "8.8.8.8"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


def _resolve_ips(host: str) -> list[str]:
    """Resolve a hostname/IP to a list of IP strings (best effort, no errors)."""
    host = host.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return list(dict.fromkeys(i[4][0] for i in infos))
    except (socket.gaierror, OSError):
        return []


def in_scope(host: str, ctx: ScanContext) -> bool:
    """True if `host` is the authorized target (single host) or inside its CIDR."""
    if not (ctx.target or "").strip():
        return True
    host = host.strip().lower().rstrip(".")
    nets = ctx.scope_networks()
    if nets:
        for ip in _resolve_ips(host):
            try:
                if any(ipaddress.ip_address(ip) in n for n in nets):
                    return True
            except ValueError:
                continue
        return False
    # Single-host target: allow the exact hostname/IP and its resolved IPs.
    target = ctx.target.strip().lower().rstrip(".")
    if host == target:
        return True
    return bool(set(_resolve_ips(host)) & set(_resolve_ips(target)))


def _require_scope(host: str, ctx: ScanContext) -> None:
    if not in_scope(host, ctx):
        raise ToolError(f"{host!r} is outside the authorized scope ({ctx.target!r})")


# ── Central scope enforcement ────────────────────────────────────────────────
# Tool arguments whose value names a network host or network. Every tool call is
# checked against these in build_dispatch, so being in scope is the default: a new
# tool, or one whose body forgets _require_scope, still cannot reach a host the
# operator never authorized. `domain` is deliberately NOT here — in the AD tools it
# is a Kerberos realm ("CORP.LOCAL"), not a host to send traffic to, and dns_enum
# asks a public resolver about a name rather than touching the target. `cde` is the PCI
# segmentation test's target: the cardholder data environment it tries to reach, which the
# operator has to have authorized like any other.
_SCOPED_ARG_NAMES = ("target", "targets", "host", "hosts", "dc_ip", "server", "ip", "cde")


@dataclass(frozen=True)
class _Tool:
    name: str
    description: str
    properties: dict
    required: tuple[str, ...]
    fn: Callable[..., Any]
    scope_exempt: bool

    def schema(self) -> dict:
        """This tool as an OpenAI-compatible function-calling schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {"type": "object",
                               "properties": self.properties,
                               "required": list(self.required)},
            },
        }


_REGISTRY: dict[str, _Tool] = {}


def tool(description: str, properties: dict | None = None,
         required: list[str] | None = None, *, scope_exempt: bool = False):
    """Register an async tool function. The tool's name is the function's own name.

    scope_exempt=True means the tool takes no network target, so the central scope
    check has nothing to check: scope setup itself, local bookkeeping, offline work,
    third-party lookups, and our own attacker-side infrastructure (listener/exfil bind
    locally; shell_exec runs over an already-established session). Set it deliberately —
    it is the one way to opt a tool out of the authorization boundary.
    """
    def register(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = fn.__name__
        if name in _REGISTRY:
            raise RuntimeError(f"tool {name!r} is already registered")
        if not inspect.iscoroutinefunction(fn):
            raise RuntimeError(f"tool {name!r} must be async")
        props = properties or {}
        req = tuple(required or ())
        unknown = [r for r in req if r not in props]
        if unknown:
            raise RuntimeError(f"tool {name!r} requires undeclared parameter(s): {unknown}")
        _REGISTRY[name] = _Tool(name, description, props, req, fn, scope_exempt)
        return fn
    return register


def tool_schemas() -> list[dict]:
    """Every registered tool as a function-calling schema, in declaration order."""
    return [t.schema() for t in _REGISTRY.values()]


def scope_exempt_tools() -> frozenset[str]:
    """Names of the tools that opted out of the central scope check."""
    return frozenset(name for name, t in _REGISTRY.items() if t.scope_exempt)


def _hosts_in_value(value: Any) -> list[str]:
    """Pull the host/network literals out of one tool argument. Accepts a bare host or
    IP, a CIDR, 'host:port', an absolute URL, a comma-separated list, or a list of any
    of those (nuclei_scan takes up to 500 targets as a list)."""
    if value is None or isinstance(value, bool):
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for v in value:
            out.extend(_hosts_in_value(v))
        return out
    text = str(value).strip()
    if not text:
        return []
    found: list[str] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "://" in part:  # http://host:8443/login -> host
            part = urlsplit(part).hostname or ""
        elif part.startswith("["):  # [2001:db8::1]:443 -> 2001:db8::1
            part = part[1:].split("]", 1)[0]
        elif part.count(":") == 1 and "/" not in part:  # host:445 -> host (IPv6 kept whole)
            part = part.split(":", 1)[0]
        part = part.strip()
        if part:
            found.append(part)
    return found


def _literal_in_scope(literal: str, ctx: ScanContext) -> bool:
    """Scope test for one literal, which may be a host OR a CIDR network. A network
    argument (ping_sweep over a subnet) has to sit entirely inside the authorization,
    so a /24 scope can never be widened to a /16 by a tool argument."""
    if not (ctx.target or "").strip():
        return True  # no scope configured yet — set_target establishes it
    if "/" not in literal:
        return in_scope(literal, ctx)
    try:
        net = ipaddress.ip_network(literal, strict=False)
    except ValueError:
        return in_scope(literal, ctx)  # not a network after all (e.g. a URL path slipped in)
    nets = [n for n in ctx.scope_networks() if n.version == net.version]
    if nets:
        return any(net.subnet_of(n) for n in nets)
    if net.num_addresses == 1:  # /32 or /128 of a single-host scope
        return in_scope(str(net.network_address), ctx)
    return False


def _enforce_scope(tool_name: str, args: dict, ctx: ScanContext) -> None:
    """Scope-check every host-carrying argument of one tool call. Raises ToolError on
    the first literal outside the authorized scope.

    Fails closed: an unregistered name is checked rather than waved through, so a typo
    or a tool wired up outside the registry cannot silently skip the boundary."""
    entry = _REGISTRY.get(tool_name)
    if (entry is not None and entry.scope_exempt) or not isinstance(args, dict):
        return
    for key in _SCOPED_ARG_NAMES:
        if key not in args:
            continue
        for literal in _hosts_in_value(args[key]):
            if not _literal_in_scope(literal, ctx):
                raise ToolError(
                    f"{literal!r} (argument {key!r} of {tool_name}) is outside the authorized "
                    f"scope ({ctx.target!r}). Only the operator can change scope. Say what "
                    f"you need in your reply and wait for them: set_target on a target the "
                    f"current scope does not cover now prompts the operator for approval, "
                    f"and is refused outright when there is nobody to answer.")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _extract_strings(data: bytes, minlen: int = 4) -> list[str]:
    """Printable-ASCII runs out of a binary blob (like `strings`) — makes a pcap/zip/binary
    readable enough to spot cleartext content the parsed-HTML path would mangle or truncate away."""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if b == 9 or 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out


def _scan_creds(data: bytes) -> list[str]:
    """Flag credential-looking content in a downloaded blob — target-agnostic: HTTP Basic auth
    (decoded), cleartext FTP USER/PASS, and generic user/password/token=value pairs. Used to pull
    secrets out of captures, backups, config and source files."""
    hits: list[str] = []
    for b64 in re.findall(rb"[Aa]uthorization:\s*[Bb]asic\s+([A-Za-z0-9+/=]{8,})", data):
        try:
            dec = base64.b64decode(b64).decode("utf-8", "replace")
            if ":" in dec and dec.isprintable():
                hits.append(f"HTTP Basic auth -> {dec}")
        except Exception:  # noqa: BLE001
            pass
    for verb, val in re.findall(rb"(?im)^\s*(USER|PASS)\s+(\S.*?)\r?$", data):
        hits.append(f"FTP {verb.decode()} {val.decode('utf-8', 'replace').strip()[:80]}")
    for m in re.finditer(
            rb"(?i)\b(user(?:name)?|login|email|pass(?:word|wd)?|pwd|secret|token|api[_-]?key)"
            rb"[\"'\]]?\s*[=:]\s*[\"']?([^\x00-\x20&\"'<>\x7f-\xff]{1,80})", data):
        hits.append(m.group(0).decode("ascii", "replace").strip("\"' ")[:120])
    return list(dict.fromkeys(hits))


def _which_any(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _impacket(tool: str) -> str | None:
    """Resolve an impacket example script across install styles (kali/pipx/pip)."""
    return _which_any(f"impacket-{tool}", f"{tool}.py", tool)


def _netexec() -> str | None:
    return _which_any("nxc", "netexec", "crackmapexec", "cme")


def _guarded(name: str, fn: Callable[..., Any], ctx: ScanContext) -> Callable[[dict], Any]:
    """Wrap one tool so the authorized-scope check runs before its body. The wrapper is a
    coroutine on purpose: llm._run_tool builds the task with ensure_future(fn(args)) outside
    its try block, so a ToolError raised synchronously here would abort the whole run instead
    of coming back to the model as a recoverable "out of scope" tool result."""
    async def run(args: dict) -> Any:
        _enforce_scope(name, args or {}, ctx)
        return await fn(ctx, args)
    run.__name__ = f"guarded_{name}"
    return run


def build_dispatch(ctx: ScanContext) -> dict[str, Callable[[dict], Any]]:
    """Tool name -> scope-guarded coroutine, built from the registry. Nothing to keep in
    sync: a @tool-decorated function is dispatchable and guarded by that fact alone."""
    return {name: _guarded(name, entry.fn, ctx) for name, entry in _REGISTRY.items()}

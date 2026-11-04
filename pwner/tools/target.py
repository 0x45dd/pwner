"""Turning an operator's words into an authorized scope.

`resolve_target_spec` accepts an IP, a CIDR, a domain, or an interface name like 'en0'
or 'local' and resolves it to something scannable; `set_target` makes it the scope.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import subprocess

from .core import (
    ScanContext,
    ToolError,
    _consent_scope_change,
    _grant_scope,
    _within_authorized_scope,
    tool,
)

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


@tool("Set/replace the authorized scope FROM THE OPERATOR'S REQUEST. Accepts an IP, "
      "CIDR, domain, OR a local interface name (e.g. 'en0', 'eth0', 'wlan0') or 'local'/'lan' for "
      "this machine's own subnet. Call this whenever the operator tells you what to scan instead of "
      "refusing for lack of a preset target. 'en0 /24' -> the /24 that interface is on.",
      {"target": {"type": "string", "description": "ip | cidr | domain | interface (en0) | 'local'"},
       "prefix": {"type": "integer", "description": "optional CIDR prefix, e.g. 24, for a subnet around an interface IP"}},
      ["target"],
      scope_exempt=True)
async def set_target(ctx: ScanContext, args: dict) -> dict:
    """Set/replace the authorized scope from the operator's request."""
    spec = str(args.get("target") or args.get("spec") or "").strip()
    if not spec:
        raise ToolError("set_target needs a target (ip/cidr/domain or an interface like 'en0').")
    raw_prefix = args.get("prefix")
    prefix = int(raw_prefix) if str(raw_prefix or "").strip().isdigit() else None
    resolved = await asyncio.to_thread(resolve_target_spec, spec, prefix)

    # Scope-exempt means the central guard cannot check this tool: its argument IS the new
    # scope, so there is nothing to check it against. That left the one hole the scope lock
    # could not cover — the agent, told "only the operator can widen scope", could call
    # set_target itself and widen it. Narrowing, or returning to something the operator has
    # already authorized, stays free; going anywhere else needs their answer.
    establishing = not (ctx.target or "").strip() and not ctx.scope_grants
    if not establishing and not _within_authorized_scope(resolved, ctx):
        if not await _consent_scope_change(ctx, resolved):
            raise ToolError(
                f"the operator did not approve a scope change to {resolved!r}; the scope "
                f"is still {ctx.target!r}. Do not call set_target for this target again — "
                f"say what you need in your reply and wait for the operator to say it.")
    _grant_scope(ctx, resolved)
    ctx.target = resolved
    detail = f" (from {spec})" if resolved != spec else ""
    return {"ok": True, "target": resolved, "from": spec,
            "note": f"scope set to {resolved}{detail}"}

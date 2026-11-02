"""nmap-backed tools: port/service/vuln/OS scanning, host discovery, nuclei.

Everything that shells out to nmap goes through `_run_nmap`, which is the only place the
binary, its XML output and the per-call timeout are handled.
"""
from __future__ import annotations

import asyncio
import json
import os
import xml.etree.ElementTree as ET
from typing import Any

from .core import (
    ALLOWED_SCRIPT_ARGS_HINT,
    BLOCKED_SCRIPT_CATEGORIES,
    NMAP_BIN,
    NUCLEI_BIN,
    PORT_PRESETS,
    ScanContext,
    ToolError,
    _is_root,
    _nuclei_template_args,
    _require_scope,
    has_nuclei,
    tool,
)


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


@tool("TCP port scan (SYN if root, else connect). Returns open ports with service names. "
      "YOU control nmap flags via nmap_args — e.g. pass '-Pn' for a known-live host so discovery "
      "doesn't falsely mark it down on a full scan.",
      {"target": {"type": "string"}, "ports": {"type": "string",
       "description": "top-1000|top-100|common|all|explicit '22,80,443' or '1-1024'"},
       "nmap_args": {"type": "string", "description": "extra nmap flags you choose, e.g. '-Pn -T2' (destructive scripts refused)"}},
      [])
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


@tool("nmap version detection (-sV): exact service name/product/version per port.",
      {"target": {"type": "string"}, "ports": {"type": "string", "description": "optional port list; defaults to top-1000"},
       "nmap_args": {"type": "string", "description": "extra nmap flags you choose, e.g. '-Pn --version-all'"}},
      [])
async def service_detect(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    extra = _guard_nmap_args(str(args.get("nmap_args") or ""))
    parsed = await _run_nmap(ctx, "-sV", "--version-light", *extra,
                             *_ports_arg_list(str(args.get("ports", ""))), host)
    return _summarize(parsed)


@tool("nmap detection scripts (vuln+safe) for known CVEs/misconfigs. Run AFTER service_detect.",
      {"target": {"type": "string"}, "ports": {"type": "string", "description": "optional port list"},
       "nmap_args": {"type": "string", "description": "extra nmap flags you choose, e.g. '-Pn' or '--script ssl-enum-ciphers'"}},
      [])
async def vuln_scan(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    extra = _guard_nmap_args(str(args.get("nmap_args") or ""))
    parsed = await _run_nmap(ctx, "-sV", "--script", "vuln", *extra,
                             *_ports_arg_list(str(args.get("ports", ""))), host)
    return _summarize(parsed)


@tool("nmap OS fingerprint (-O).",
      {"target": {"type": "string"}, "nmap_args": {"type": "string", "description": "extra nmap flags, e.g. '-Pn'"}},
      [])
async def os_detect(ctx: ScanContext, args: dict) -> dict:
    host = str(args.get("target") or ctx.target)
    _require_scope(host, ctx)
    if not _is_root():  # -O needs raw sockets; give a clear note instead of a raw nmap error
        return {"hosts": [], "note": "OS detection needs root — re-run pwner with sudo for -O."}
    extra = _guard_nmap_args(str(args.get("nmap_args") or ""))
    parsed = await _run_nmap(ctx, "-O", *extra, host)
    return _summarize(parsed, open_only=False)


@tool("Live-host discovery (-sn). Best first step for a CIDR target.",
      {"target": {"type": "string"}},
      [])
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


@tool("Full-control nmap — YOU write the flags (scan type, -Pn, -p, timing, detection "
      "scripts, ...). Only destructive NSE scripts are refused. Use this when the preset scans don't fit.",
      {"target": {"type": "string"}, "args": {"type": "string", "description": "e.g. '-sU --top-ports 100' or '-sV --script ssl-enum-ciphers -p 443'"}},
      ["args"])
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


@tool("Run nuclei (thousands of known-CVE / misconfig / exposure templates) over target URLs. Use after discovering HTTP/network services.",
      {"targets": {"type": "array", "items": {"type": "string"},
       "description": "Absolute URLs or host:port, e.g. ['http://host:80','host:445']"},
       "severity": {"type": "string", "description": "comma list, default low,medium,high,critical"}},
      [])
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


@tool("Enumerate SMB (445): OS/domain, dialects, signing, shares, users, sessions via "
      "nmap's safe SMB scripts. Read-only, no brute-force. FIRST move whenever 445 is open.",
      {"host": {"type": "string"}, "port": {"type": "integer"}},
      ["host"])
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


@tool("Inspect TLS on a port: certificate (subject/issuer/SAN/validity) + supported "
      "ciphers/protocols (nmap ssl-cert + ssl-enum-ciphers). Read-only.",
      {"host": {"type": "string"}, "port": {"type": "integer"}},
      ["host"])
async def ssl_info(ctx: ScanContext, args: dict) -> dict:
    """Inspect TLS on a port: certificate (subject/issuer/SAN/validity) and supported
    ciphers/protocols via nmap's ssl-cert + ssl-enum-ciphers. Read-only."""
    host = str(args.get("host") or args.get("target") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 443))
    parsed = await _run_nmap(ctx, "-sV", "-p", str(port),
                             "--script", "ssl-cert,ssl-enum-ciphers", host, timeout=180.0)
    return _summarize(parsed, open_only=False)

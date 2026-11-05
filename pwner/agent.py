"""Agentic orchestration + deterministic fallback for pwner."""
from __future__ import annotations

import asyncio
import json
import re

from rich.markup import escape as _esc

from . import tools
from .llm import AIUnavailable, LLMClient, LLMError
from .prompts import SYSTEM
from .tools import ScanContext, ToolError


def _short(args: dict) -> str:
    s = json.dumps(args, default=str)
    return s if len(s) <= 120 else s[:120] + "…"


def _out(ctx: ScanContext, text: str = "") -> None:
    """Route output to the live TUI log (or plain print when not a TTY)."""
    tui = getattr(ctx, "tui", None)
    if tui is not None:
        tui.log(text)
    else:
        print(text)


def _record(ctx: ScanContext, name: str, args: dict, result: dict) -> None:
    """Feed a tool result into the live network-topology panel."""
    tui = getattr(ctx, "tui", None)
    if tui is None:
        return
    host = str(args.get("host") or args.get("target") or args.get("domain") or "").strip()
    if name == "ping_sweep":
        for h in (result.get("live_hosts") or []):
            tui.record_host(h)
    elif name == "dns_enum":
        for ip in (result.get("records") or {}).get("A", []):
            tui.record_host(ip)
    elif name in ("port_scan", "service_detect"):
        if host:
            tui.record_host(host)
        for h in result.get("hosts", []):
            for p in h.get("open_ports", []):
                s = p.get("service", {})
                ver = " ".join(x for x in (s.get("product", ""), s.get("version", "")) if x)
                tui.record_port(host, p["port"], s.get("name", ""), ver)
    elif name == "nuclei_scan":
        for f in (result.get("findings") or []):
            tui.note(f.get("ip") or host, f"[{f.get('severity', '?').upper()}] {f.get('name', '')}")
    elif name == "report_finding":
        tui.note(str(args.get("host") or host), f"[{args.get('severity', '?').upper()}] {args.get('title', '')}")


def _call_label(name: str, args: dict) -> str:
    """A plain-language description of what a tool call is about to do."""
    h = str(args.get("host") or args.get("target") or args.get("domain") or "").strip()
    ports = str(args.get("ports") or "").strip()
    port = args.get("port")
    return {
        "ping_sweep": f"discovering live hosts on {h}",
        "port_scan": f"port-scanning {h}" + (f" ({ports})" if ports else ""),
        "service_detect": f"fingerprinting services on {h}" + (f":{ports}" if ports else ""),
        "os_detect": f"detecting the OS of {h}",
        "banner_grab": f"grabbing the banner from {h}:{port}",
        "http_probe": f"GET {args.get('path') or '/'} on {h}:{port}",
        "web_request": f"{str(args.get('method') or 'GET').upper()} {args.get('path') or '/'} on {h}:{port}",
        "content_discovery": f"mapping paths on {h}:{args.get('port', 80)}",
        "http_download": f"downloading {args.get('path') or '/'} from {h}:{args.get('port', 80)}",
        "vuln_scan": f"running vulnerability scripts on {h}" + (f":{ports}" if ports else ""),
        "nuclei_scan": f"running nuclei CVE/misconfig templates ({len(args.get('targets') or [])} target(s))",
        "exploit_search": f"searching public exploits for {args.get('service','')} {args.get('version','')}".rstrip(),
        "dns_enum": f"enumerating DNS records for {args.get('domain', h)}",
        "ftp_anon": f"testing FTP login on {h}" + (f" as {args.get('user')}" if args.get("user") else " (anonymous)"),
        "ftp_get": f"downloading {args.get('path','')} over FTP from {h}",
        "smb_enum": f"enumerating SMB on {h}:{args.get('port', 445)}",
        "ssl_info": f"inspecting TLS/certificate on {h}:{args.get('port', 443)}",
        "tcp_send": f"sending a raw probe to {h}:{port}",
        "snmp_check": f"checking SNMP on {h}",
        "kerbrute_userenum": f"enumerating domain users on {args.get('domain', h)}",
        "asrep_roast": f"AS-REP roasting {args.get('domain', h)}",
        "kerberoast": f"kerberoasting {args.get('domain', h)} as {args.get('user','')}".rstrip(),
        "ldap_enum": f"LDAP-enumerating {args.get('target') or args.get('dc_ip') or h}",
        "rid_brute": f"RID-cycling {args.get('target') or h}",
        "smb_shares": f"listing SMB shares on {args.get('target') or h}",
        "smb_get": f"downloading {args.get('path','')} from the {args.get('share','C$')} share on {args.get('target') or h}",
        "password_spray": f"spraying {args.get('proto','smb')} on {args.get('target') or h}",
        "secretsdump": f"dumping secrets from {args.get('target') or h}",
        "win_exec": f"executing on {args.get('target') or h} via {args.get('method','wmiexec')}",
        "ssh_exec": f"executing on {args.get('target') or h} over SSH as {args.get('user','')}".rstrip(),
        "bloodhound_collect": f"collecting BloodHound data for {args.get('domain', h)}",
        "adcs_find": f"enumerating ADCS on {args.get('domain', h)}",
        "dc_vuln_check": f"checking DC vulns on {args.get('target') or h}",
        "hash_crack": f"cracking {len(args.get('hashes') or [])} hash(es) offline",
        "cred_check": f"validating {args.get('user','')} across services on {args.get('target') or h}".rstrip(),
        "ledger": ("reviewing the engagement ledger" if str(args.get('action') or 'show') == 'show'
                   else "updating the engagement ledger"),
        "run_nmap": f"running a custom nmap scan on {h}",
        "hydra_brute": f"brute-forcing {args.get('service','')} credentials on {h}:{port}",
        "get_findings": "reviewing the findings so far",
    }.get(name, name)


def _result_summary(name: str, args: dict, result: dict) -> str:
    """One readable line summarizing a tool result (instead of dumping raw JSON)."""
    if not isinstance(result, dict):
        return str(result)[:160]
    if result.get("error"):
        return "error: " + str(result["error"]).splitlines()[0][:140]
    if name == "ping_sweep":
        hs = result.get("live_hosts") or []
        return f"{result.get('count', len(hs))} live host(s)" + (f": {', '.join(hs[:10])}" if hs else "")
    if name == "port_scan":
        parts = []
        for h in result.get("hosts", []):
            ops = [p for p in h.get("open_ports", []) if p.get("state", "open") == "open"]
            nums = ", ".join(str(p["port"]) for p in ops[:14])
            parts.append(f"{h.get('address','')}: {len(ops)} open" + (f" → {nums}" if nums else ""))
        return "; ".join(parts) or "no open ports"
    if name in ("service_detect", "vuln_scan"):
        lines = []
        for h in result.get("hosts", []):
            for p in h.get("open_ports", []):
                s = p.get("service", {})
                extra = " ".join(x for x in (s.get("product", ""), s.get("version", "")) if x)
                tag = f"{h.get('address','')}:{p['port']} {s.get('name','?')} {extra}".rstrip()
                nscr = len(p.get("scripts", []))
                lines.append(tag + (f" ({nscr} script hit)" if name == "vuln_scan" and nscr else ""))
        return "; ".join(lines[:10]) or "no services"
    if name == "os_detect":
        ms = [m for h in result.get("hosts", []) for m in (h.get("os_matches") or [])[:1]]
        return "; ".join(f"{m.get('name')} ({m.get('accuracy')}%)" for m in ms) or "no OS match"
    if name == "banner_grab":
        return (result.get("banner") or result.get("note") or "").splitlines()[0][:140] or "(empty)"
    if name in ("http_probe", "web_request"):
        from urllib.parse import urlsplit
        path = urlsplit(result.get("url", "")).path or args.get("path") or "/"
        ex = " ".join((result.get("body_excerpt") or "").split())
        forms = result.get("forms") or []
        bits = [str(result.get("status", "")), path]
        if result.get("title"):
            bits.append(result["title"])
        if forms:
            bits.append(f"{len(forms)} form(s)")
        head = " · ".join(b for b in bits if b)
        return (head + (f" — {ex[:110]}" if ex else "")).strip(" ·")
    if name == "http_download":
        creds = result.get("credentials") or []
        head = f"{result.get('status','')} · {result.get('size',0)}B · {result.get('content_type','')}".strip(" ·")
        if creds:
            head += f" · CREDS: {creds[0][:80]}" + (f" (+{len(creds)-1})" if len(creds) > 1 else "")
        elif result.get("truncated"):
            head += " · (capped)"
        return head
    if name == "nuclei_scan":
        return f"{len(result.get('findings') or [])} finding(s)"
    if name == "exploit_search":
        return f"{len(result.get('results') or [])} public exploit(s) matched"
    if name == "dns_enum":
        recs = result.get("records") or {}
        return ", ".join(f"{k}×{len(v)}" for k, v in recs.items() if v) or "no records"
    if name == "ftp_anon":
        if result.get("logged_in"):
            n = len(result.get("listing") or [])
            who = "anonymous" if result.get("anonymous") else result.get("user", "")
            return f"login OK as {who}" + (f" · {n} entries" if n else "")
        return "login refused"
    if name in ("ftp_get", "smb_get"):
        if result.get("ok"):
            extra = " (truncated)" if result.get("truncated") else ""
            creds = result.get("creds_found") or []
            if creds:
                extra += f" · {len(creds)} cred hit(s)"
            return f"{result.get('bytes', 0)} bytes" + extra
        return "error: " + str(result.get("error", ""))[:120]
    if name in ("smb_enum", "ssl_info"):
        bits = []
        for h in result.get("hosts", []):
            for s in h.get("host_scripts", []):
                bits.append(s.get("id", ""))
            for p in h.get("open_ports", []):
                for s in p.get("scripts", []):
                    bits.append(s.get("id", ""))
        bits = [b for b in dict.fromkeys(bits) if b]
        return ", ".join(bits[:8]) or "no script output"
    if name == "tcp_send":
        resp = (result.get("response") or "").strip()
        if resp:
            return f"{result.get('sent_bytes', 0)}B sent → {resp.splitlines()[0][:140]}"
        return result.get("note") or f"{result.get('sent_bytes', 0)}B sent, no response"
    if name in ("asrep_roast", "kerberoast"):
        n = result.get("count", len(result.get("hashes") or []))
        return f"{n} crackable hash(es)" + (" — ready to crack" if n else "")
    if name == "kerbrute_userenum":
        v = result.get("valid_users") or []
        return f"{len(v)} valid user(s)" + (f": {', '.join(v[:8])}" if v else "")
    if name == "rid_brute":
        return f"{result.get('count', 0)} principal(s) via RID cycling"
    if name in ("ldap_enum", "adcs_find", "smb_shares"):
        out = (result.get("output") or "").strip()
        if name == "smb_shares" and result.get("pwned"):
            return "Pwn3d! (admin) — " + " ".join(out.split())[:120]
        return " ".join(out.split())[:160] or f"rc={result.get('rc','?')}"
    if name == "password_spray":
        v = result.get("valid") or []
        return (f"VALID: {', '.join(v[:6])}" if v else "no valid creds") if not result.get("denied") else "denied"
    if name == "secretsdump":
        if result.get("denied"):
            return "denied"
        return f"{result.get('count', 0)} secret(s) dumped"
    if name in ("win_exec", "ssh_exec"):
        if result.get("denied"):
            return "denied"
        return " ".join((result.get("output") or "").split())[:160] or "(no output)"
    if name == "bloodhound_collect":
        return f"collected -> {result.get('zip') or result.get('output_dir') or 'see output'}"
    if name == "dc_vuln_check":
        v = result.get("vulnerable") or []
        return (f"VULNERABLE: {', '.join(v)}" if v else "no listed vuln detected")
    if name == "hash_crack":
        return f"{result.get('count', 0)} cracked" if "count" in result else (result.get("output","")[:120] or "done")
    if name == "cred_check":
        vo = result.get("valid_on") or []
        ao = result.get("admin_on") or []
        if not vo:
            return "no service accepted this credential"
        return "valid on: " + ", ".join(vo) + (f"  ·  ADMIN on: {', '.join(ao)}" if ao else "")
    if name == "ledger":
        lg = result.get("ledger") or {}
        return " · ".join(f"{k}:{len(v)}" for k, v in lg.items() if isinstance(v, list)) or "empty"
    if name == "get_findings":
        return f"{len(result.get('findings') or [])} finding(s) so far"
    s = json.dumps(result, default=str)
    return s[:160] + ("…" if len(s) > 160 else "")


async def _emit_thought(ctx: ScanContext, text: str) -> None:
    """The agent's own reasoning (what it says before acting) — the 'thinking' feed."""
    text = text.strip()
    if text:
        _out(ctx, f"[italic grey62]{_esc(text)}[/italic grey62]")


async def _emit_call(ctx: ScanContext, name: str, args: dict) -> None:
    """Announce an action in plain language BEFORE it runs (slow tools show intent)."""
    if name in ("note", "report_finding", "request_consent", "get_findings", "ledger"):
        return
    tui = getattr(ctx, "tui", None)
    if tui is not None:  # feed the live status line / spinner
        try:
            tui.activity = _call_label(name, args)
        except Exception:  # noqa: BLE001
            pass
    _out(ctx, f"[cyan]▸ {_call_label(name, args)}[/cyan] [dim]…[/dim]")


async def _emit_step(ctx: ScanContext, name: str, args: dict, result: dict) -> None:
    _record(ctx, name, args, result)
    if name == "note":
        _out(ctx, f"[italic grey62]{_esc(str(args.get('text', '')))}[/italic grey62]")
        return
    if name == "report_finding":
        sev = str(args.get("severity", "?")).upper()
        color = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "orange3",
                 "LOW": "yellow", "INFO": "blue"}.get(sev, "white")
        _out(ctx, f"[bold {color}][{sev}][/bold {color}] {args.get('title', '')} "
                  f"[cyan]@ {args.get('host', '')}[/cyan]")
        return
    if name == "request_consent":
        dec = (result or {}).get("decision", "?")
        _out(ctx, f"[yellow]consent: {args.get('action', '')} -> {dec}[/yellow]")
        return
    if name == "get_findings":
        _out(ctx, f"[dim]   ↳ {_result_summary(name, args, result)}[/dim]")
        return
    _out(ctx, f"[dim]   ↳ {_result_summary(name, args, result)}[/dim]")


async def run_agentic(ctx: ScanContext, cfg: tuple[str, str, str], max_steps: int | None = None,
                      instructions: str = "") -> tuple[list[dict], str]:
    key, base, model = cfg
    client = LLMClient(key, base, model)
    dispatch = tools.build_dispatch(ctx)
    ch = ctx.operator_channel
    steer = ch.drain if ch is not None else None
    _out(ctx, f"[bold]pwner agent[/bold] [dim]· model={model} · target={ctx.target}[/dim]\n")

    async def on_step(n: str, a: dict, r: dict) -> None:
        await _emit_step(ctx, n, a, r)

    async def on_call(n: str, a: dict) -> None:
        await _emit_call(ctx, n, a)

    async def on_thought(t: str) -> None:
        await _emit_thought(ctx, t)

    # Opt-in extra deliberation for OpenAI/Gemini reasoning models (deepseek-reasoner thinks
    # unconditionally and ignores it). Unset by default so non-reasoning models don't 400.
    import os as _os
    reasoning_effort = ((ctx.reasoning_effort or "").strip()
                        or (_os.environ.get("PWNER_REASONING_EFFORT") or "").strip() or None)
    try:
        summary = await client.run_tools(
            SYSTEM, tools.brief(ctx, instructions), tools.tool_schemas(), dispatch,
            max_steps=max_steps, reasoning_effort=reasoning_effort, on_step=on_step, on_call=on_call,
            on_thought=on_thought, steer=steer,
            open_work=lambda: tools.open_work_report(ctx),
            effort_boost=tools.effort_boost(reasoning_effort or ""))
    except (AIUnavailable, LLMError) as e:
        _out(ctx, f"[red][!] LLM error: {e}[/red]")
        summary = "(LLM error — partial results below)"
    return ctx.findings, summary


def _looks_like_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def _open_ports(ports_res: dict) -> list[int]:
    out = []
    for h in ports_res.get("hosts", []):
        for p in h.get("open_ports", []):
            if p.get("state") == "open":
                out.append(p["port"])
    return sorted(set(out))


def _print_services(ctx: ScanContext, svc: dict) -> None:
    for h in svc.get("hosts", []):
        for p in h.get("open_ports", []):
            s = p.get("service", {})
            name = s.get("name") or "?"
            product = s.get("product") or ""
            version = s.get("version") or ""
            extra = " ".join(x for x in (product, version) if x)
            _out(ctx, f"    [green]{p['port']}/{p.get('protocol', 'tcp')}[/green]  "
                      f"[bold]{name}[/bold]  [dim]{extra}[/dim]".rstrip())


def _print_os(ctx: ScanContext, osd: dict) -> None:
    for h in osd.get("hosts", []):
        for m in h.get("os_matches", [])[:2]:
            _out(ctx, f"    [cyan]OS:[/cyan] {m.get('name')} [dim](accuracy {m.get('accuracy')}%)[/dim]")


def _render_topology(ctx: ScanContext) -> None:
    tui = getattr(ctx, "tui", None)
    if tui is not None:
        tui.render_topology()


_NEGATIVE_MARKERS = (
    "couldn't find", "could not find", "not vulnerable", "no vulnerability",
    "not affected", "not found", "found no", "did not find", "does not appear",
    "not exploitable", "not detected", "no xss", "no sql", "no lfi", "no rfi",
    "no such", "unable to", "is not vulnerable", "isn't vulnerable", "no issue",
)
_INFORMATIONAL_SCRIPTS = {
    "http-server-header", "http-title", "http-favicon", "http-date",
    "http-robots.txt", "http-methods", "http-headers",
}


def _findings_from_vulns(host: str, vulns: dict) -> list[dict]:
    findings = []
    for h in vulns.get("hosts", []):
        for p in h.get("open_ports", []):
            s = p.get("service", {})
            for sc in p.get("scripts", []):
                out = (sc.get("output") or "").strip()
                if not out:
                    continue
                sid = sc.get("id", "")
                if sid in _INFORMATIONAL_SCRIPTS:
                    continue
                low = out.lower()
                if any(m in low for m in _NEGATIVE_MARKERS):
                    continue
                hard = any(k in low for k in ("vulnerable", "exploitable", "cve-"))
                findings.append({
                    "host": host,
                    "port": p["port"],
                    "service": s.get("name", ""),
                    "title": f"{sid} on {s.get('name') or p['port']}",
                    "severity": "high" if hard else "medium",
                    "confidence": "probable",
                    "evidence": out[:500],
                    "remediation": "Review the flagged service and apply the vendor patch / hardening for the reported issue.",
                })
    return findings


async def run_deterministic(ctx: ScanContext, ports: str) -> tuple[list[dict], str]:
    if "/" in (ctx.target or ""):
        return await run_range(ctx, ports)
    _out(ctx, f"[*] pwner deterministic (no AI) · target={ctx.target}\n")
    target = ctx.target
    hosts: list[str] = []
    if "/" in target or _looks_like_ip(target):
        hosts = [target]
    else:
        try:
            dns = await tools.dns_enum(ctx, {"domain": target})
        except ToolError as e:
            _out(ctx, f"  [!] {e}")
            dns = {"records": {}}
        _record(ctx, "dns_enum", {"domain": target}, dns)
        ips = dns.get("records", {}).get("A", [])
        if ips:
            _out(ctx, f"[*] {target} resolves to {', '.join(ips)}")
            hosts = ips
        else:
            _out(ctx, f"[!] {target} did not resolve — scanning hostname directly")
            hosts = [target]

    findings: list[dict] = []
    for host in hosts:
        _out(ctx, f"\n=== {host} ===")
        try:
            ports_res = await tools.port_scan(ctx, {"target": host, "ports": ports})
        except ToolError as e:
            _out(ctx, f"  [!] {e}")
            continue
        _record(ctx, "port_scan", {"target": host}, ports_res)
        open_ports = _open_ports(ports_res)
        if not open_ports:
            _out(ctx, "  no open ports found")
            continue
        _out(ctx, f"  open ports: {', '.join(map(str, open_ports))}")
        try:
            svc = await tools.service_detect(ctx, {"target": host, "ports": ",".join(map(str, open_ports))})
            _record(ctx, "service_detect", {"target": host}, svc)
            _print_services(ctx, svc)
        except ToolError as e:
            _out(ctx, f"  [!] service detect: {e}")
        _out(ctx, "  running vuln detection…")
        try:
            vulns = await tools.vuln_scan(ctx, {"target": host, "ports": ",".join(map(str, open_ports))})
            findings.extend(_findings_from_vulns(host, vulns))
        except ToolError as e:
            _out(ctx, f"  [!] vuln scan: {e}")
        try:
            osd = await tools.os_detect(ctx, {"target": host})
            _print_os(ctx, osd)
        except ToolError as e:
            _out(ctx, f"  [!] os detect: {e}")

    _render_topology(ctx)
    summary = f"Scanned {len(hosts)} host(s); {len(findings)} finding(s) surfaced by detection scripts."
    return findings, summary


def _nuclei_to_finding(nf: dict) -> dict:
    host = nf.get("ip") or ""
    if not host:
        m = re.match(r"https?://([^/:]+)", nf.get("matched_at") or "")
        host = m.group(1) if m else ""
    return {
        "host": host,
        "port": None,
        "service": "nuclei",
        "title": nf.get("name") or nf.get("template_id", ""),
        "severity": nf.get("severity", "info"),
        "confidence": "confirmed",
        "evidence": f"{nf.get('template_id', '')} matched at {nf.get('matched_at', '')}",
        "remediation": (nf.get("description") or "")[:300],
    }


async def run_range(ctx: ScanContext, ports: str) -> tuple[list[dict], str]:
    """Expand a CIDR -> discover live hosts -> deep-scan each in parallel ->
    run nuclei over the discovered services -> aggregate findings."""
    from .tools import (
        ToolError,
        expand_hosts,
        has_nuclei,
        nuclei_scan,
        ping_sweep,
        port_scan,
        service_detect,
        vuln_scan,
    )
    concurrency = max(1, ctx.concurrency)
    _out(ctx, f"[*] pwner range scan · target={ctx.target}\n")
    try:
        hosts = expand_hosts(ctx.target, cap=ctx.range_cap)
    except ToolError as e:
        _out(ctx, f"[!] {e}")
        return [], str(e)
    if len(hosts) > 1:
        _out(ctx, f"[*] {len(hosts)} address(es) in range — discovering live hosts…")
        try:
            sweep = await ping_sweep(ctx, {"target": ctx.target})
            _record(ctx, "ping_sweep", {"target": ctx.target}, sweep)
            live = sweep.get("live_hosts", [])
            if live:
                hosts = live
                _out(ctx, f"[*] {len(live)} live host(s) found")
            else:
                _out(ctx, "[*] sweep found no live hosts; scanning the whole range anyway")
        except ToolError as e:
            _out(ctx, f"  [!] sweep: {e}")
    if not hosts:
        return [], "no hosts in range"

    findings: list[dict] = []
    host_ports: dict[str, list[int]] = {}
    sem = asyncio.Semaphore(max(1, concurrency))

    async def scan_host(host: str) -> None:
        async with sem:
            _out(ctx, f"\n=== {host} ===")
            try:
                pr = await port_scan(ctx, {"target": host, "ports": ports})
            except ToolError as e:
                _out(ctx, f"  [!] port scan: {e}")
                return
            _record(ctx, "port_scan", {"target": host}, pr)
            open_ports = _open_ports(pr)
            host_ports[host] = open_ports
            if not open_ports:
                _out(ctx, "  no open ports")
                return
            _out(ctx, f"  open ports: {', '.join(map(str, open_ports))}")
            try:
                svc = await service_detect(ctx, {"target": host, "ports": ",".join(map(str, open_ports))})
                _record(ctx, "service_detect", {"target": host}, svc)
                _print_services(ctx, svc)
            except ToolError as e:
                _out(ctx, f"  [!] service detect: {e}")
            try:
                v = await vuln_scan(ctx, {"target": host, "ports": ",".join(map(str, open_ports))})
                findings.extend(_findings_from_vulns(host, v))
            except ToolError as e:
                _out(ctx, f"  [!] vuln scan: {e}")

    await asyncio.gather(*(scan_host(h) for h in hosts))

    if has_nuclei():
        targets: list[str] = []
        for host, ports in host_ports.items():
            for p in ports:
                targets.append(f"http://{host}:{p}")
                if p == 443:
                    targets.append(f"https://{host}:{p}")
        if targets:
            _out(ctx, f"\n[*] nuclei over {len(targets)} target(s)…")
            try:
                n = await nuclei_scan(ctx, {"targets": targets, "severity": ctx.nuclei_severity})
                _record(ctx, "nuclei_scan", {"target": ctx.target}, n)
                nf = [_nuclei_to_finding(f) for f in n.get("findings", [])]
                findings.extend(nf)
                _out(ctx, f"  nuclei: {len(nf)} finding(s)")
            except ToolError as e:
                _out(ctx, f"  [!] nuclei: {e}")
    else:
        _out(ctx, "\n[*] nuclei not installed — skipping known-CVE template scan "
                "(install with `brew install nuclei` for full coverage)")

    _render_topology(ctx)
    summary = f"Scanned {len(hosts)} host(s) across {ctx.target}; {len(findings)} finding(s)."
    return findings, summary

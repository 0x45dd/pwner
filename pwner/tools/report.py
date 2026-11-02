"""Findings, the engagement ledger, dependency status and the agent's brief."""
from __future__ import annotations

import asyncio
import json
import os
import shutil

from .core import (
    NMAP_BIN,
    SNMPWALK_BIN,
    ScanContext,
    ToolError,
    _consent,
    _impacket,
    _netexec,
    _nuclei_template_dir,
    _which_any,
    has_hydra,
    has_nuclei,
    tool,
)


@tool("STOP and ask the operator before a high-impact action (active exploitation, brute-force, mass traffic). Returns approved/denied.",
      {"action": {"type": "string"}, "target": {"type": "string"},
       "risk": {"type": "string", "enum": ["medium", "high", "critical"]}},
      ["action", "target"],
      scope_exempt=True)
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


@tool("Search public exploits for a service/version (searchsploit + nuclei template names). Read-only — use after fingerprinting a version.",
      {"service": {"type": "string"}, "version": {"type": "string"}},
      ["service"],
      scope_exempt=True)
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


@tool("Record a fact/hypothesis about the target (scratchpad).",
      {"text": {"type": "string"}},
      ["text"],
      scope_exempt=True)
async def note(ctx: ScanContext, args: dict) -> dict:
    text = str(args.get("text") or "").strip()
    ctx.notes.append(text)
    return {"noted": True, "notes_count": len(ctx.notes)}


@tool("File ONE confirmed finding (severity + evidence + remediation).",
      {"host": {"type": "string"}, "port": {"type": "integer"}, "service": {"type": "string"},
       "title": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
       "confidence": {"type": "string", "enum": ["confirmed", "probable", "possible"]},
       "evidence": {"type": "string"}, "remediation": {"type": "string"}},
      ["host", "title", "severity"],
      scope_exempt=True)
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


@tool("List findings reported so far.",
      {},
      [],
      scope_exempt=True)
async def get_findings(ctx: ScanContext, args: dict) -> dict:
    return {"findings": ctx.findings}


@tool("Your engagement working-memory: surface (open services), creds (+ where tested), "
      "facts, ranked hypotheses (with status), and what you've tried. action='show' returns it; "
      "action='update' merges `data` (list fields append+dedup). Review it before deciding the next "
      "move so you don't circle or leave an obvious lead (a found cred, an untested service) untouched.",
      {"action": {"type": "string", "enum": ["show", "update", "clear"]},
       "data": {"type": "object", "description": "fields to merge, e.g. {\"creds\":[...],\"hypotheses\":[...],\"tried\":[...]}"}},
      [],
      scope_exempt=True)
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

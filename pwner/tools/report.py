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
    has_dirsearch,
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


# Install hints per package manager. The point of keying these by platform is that a hint
# is only useful if the reader can paste it: "brew install nmap" on a Debian box is noise.
# `None` means the tool has no package in that ecosystem and needs the fallback route.
# Each entry was checked against that ecosystem's own index, not assumed.
_PACKAGES: dict[str, dict[str, str | None]] = {
    "nmap":         {"brew": "nmap", "apt": "nmap", "kali": "nmap",
                     "pacman": "nmap", "dnf": "nmap"},
    # nuclei: Homebrew, Fedora and Kali carry it; Debian does not, and Arch has it only
    # in the AUR.
    "nuclei":       {"brew": "nuclei", "apt": None, "kali": "nuclei",
                     "pacman": None, "dnf": "nuclei"},
    "hydra":        {"brew": "hydra", "apt": "hydra", "kali": "hydra",
                     "pacman": "hydra", "dnf": "hydra"},
    # the binary is snmpwalk, but no distro names the package that.
    "snmpwalk":     {"brew": "net-snmp", "apt": "snmp", "kali": "snmp",
                     "pacman": "net-snmp", "dnf": "net-snmp-utils"},
    # exploitdb: Homebrew, Arch and Kali package it; plain Debian/Ubuntu and Fedora do not.
    "searchsploit": {"brew": "exploitdb", "apt": None, "kali": "exploitdb",
                     "pacman": "exploitdb", "dnf": None},
    "hashcat":      {"brew": "hashcat", "apt": "hashcat", "kali": "hashcat",
                     "pacman": "hashcat", "dnf": "hashcat"},
    # dirsearch: a Debian Security Tools package, so apt and Kali both have it. Homebrew
    # has no formula and Arch carries it only in the AUR, so those two get pipx.
    "dirsearch":    {"brew": None, "apt": "dirsearch", "kali": "dirsearch",
                     "pacman": None, "dnf": None},
    # Kali packages the whole AD toolchain that every other distro leaves to pipx, and
    # ships most of it preinstalled. Sending a Kali user to pipx would build a second,
    # worse copy of something already on their PATH.
    "impacket":          {"kali": "impacket-scripts"},
    "certipy":           {"kali": "certipy-ad"},
    "bloodhound-python": {"kali": "bloodhound.py"},
    "netexec":           {"kali": "netexec"},
}
_INSTALL_CMD = {"brew": "brew install", "apt": "sudo apt install", "kali": "sudo apt install",
                "pacman": "sudo pacman -S", "dnf": "sudo dnf install"}

# Tools from a language ecosystem rather than the OS package manager. netexec is NOT on
# PyPI, so `pipx install netexec` fails — it has to come from the repository.
_PIPX_PACKAGES = {
    "impacket": "impacket",
    "certipy": "certipy-ad",
    "bloodhound-python": "bloodhound",
    "netexec": "git+https://github.com/Pennyw0rth/NetExec",
    "dirsearch": "dirsearch",
}


_OS_RELEASE = "/etc/os-release"  # module-level so tests can point it at a fixture


def _is_kali() -> bool:
    """Kali names itself in os-release. It is treated as its own ecosystem rather than as
    Debian because its repository carries a lot that Debian's does not — nuclei, exploitdb,
    impacket, netexec, certipy — so the Debian hints would send a Kali user the long way
    round for things that are already on their PATH."""
    try:
        with open(_OS_RELEASE, encoding="utf-8") as fh:
            for line in fh:
                key, sep, value = line.strip().partition("=")
                if sep and key == "ID" and value.strip('"\'').lower() == "kali":
                    return True
    except OSError:
        pass
    return False


def _package_manager() -> str | None:
    """Which OS package manager this machine actually has, so hints are paste-ready."""
    for mgr in ("brew", "apt", "pacman", "dnf"):
        if shutil.which(mgr):
            return "kali" if mgr == "apt" and _is_kali() else mgr
    return None


def _hint(name: str, pm: str | None) -> str:
    """How to install `name` here. When this machine has no package manager we recognise,
    name the package per ecosystem rather than printing a command that cannot run.

    The OS package wins over the language-ecosystem one: if the distro ships it, that is
    the copy the rest of the system expects."""
    pkg = _PACKAGES.get(name, {}).get(pm) if pm else None
    if pkg:
        return f"{_INSTALL_CMD[pm]} {pkg}"
    if name in _PIPX_PACKAGES:
        return f"pipx install {_PIPX_PACKAGES[name]}"
    if name == "kerbrute":
        # Upstream ships linux_386 and linux_amd64 only — arm64 needs the Go route.
        # Kali does not package it either, so this is the route everywhere.
        return "prebuilt binary from github.com/ropnop/kerbrute (arm64: go install)"
    if name == "nuclei":
        return "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    if name == "searchsploit":
        return "clone gitlab.com/exploit-database/exploitdb and symlink searchsploit"
    known = [f"{m}: {p}" for m, p in _PACKAGES.get(name, {}).items() if p]
    return f"install the package for your system — {' · '.join(known)}" if known else \
        f"see the {name} project page"


def dependency_status() -> list[dict]:
    """Live install status of every EXTERNAL binary pwner can shell out to, with the
    pwner tools each one powers and how to install it on THIS machine. nmap is core; the
    rest are optional and only matter when the relevant tools are used."""
    pm = _package_manager()
    checks = [
        ("nmap", bool(shutil.which(NMAP_BIN)), _hint("nmap", pm), True,
         "port_scan/service_detect/vuln_scan/os_detect/ping_sweep/smb_enum/ssl_info/run_nmap"),
        ("nuclei", has_nuclei(), _hint("nuclei", pm), False, "nuclei_scan"),
        ("dirsearch", has_dirsearch(), _hint("dirsearch", pm), False, "dirsearch_scan"),
        ("hydra", has_hydra(), _hint("hydra", pm), False, "hydra_brute"),
        ("snmpwalk", bool(shutil.which(SNMPWALK_BIN)), _hint("snmpwalk", pm), False, "snmp_check"),
        ("searchsploit", bool(shutil.which("searchsploit")), _hint("searchsploit", pm), False,
         "exploit_search (ExploitDB)"),
        ("impacket", bool(_impacket("GetNPUsers")), _hint("impacket", pm), False,
         "asrep_roast/kerberoast/secretsdump/win_exec"),
        ("netexec", bool(_netexec()), _hint("netexec", pm), False,
         "ldap_enum/rid_brute/smb_shares/smb_get/password_spray/win_exec(winrm)/ssh_exec/dc_vuln_check"),
        ("kerbrute", bool(shutil.which("kerbrute")), _hint("kerbrute", pm), False,
         "kerbrute_userenum"),
        ("certipy", bool(_which_any("certipy", "certipy-ad")), _hint("certipy", pm), False, "adcs_find"),
        ("bloodhound-python", bool(shutil.which("bloodhound-python")), _hint("bloodhound-python", pm),
         False, "bloodhound_collect"),
        ("hashcat", bool(_which_any("hashcat", "john")), _hint("hashcat", pm), False, "hash_crack"),
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

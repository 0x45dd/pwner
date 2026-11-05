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


def open_work_report(ctx: ScanContext) -> str | None:
    """What the engagement still has outstanding, or None when nothing is.

    Handed to the agent loop at the moment the model stops calling tools. It is a reading of
    the ledger and nothing else: no judgement about whether the work is worth doing, no
    suggestion of what to do about it, no mention of tools. The agent put every one of these
    entries there itself, and deciding that an open hypothesis is not worth chasing is a
    legitimate answer — which is why this says "still open" and stops talking.
    """
    hyp = open_hypotheses(ctx)
    surface = untested_surface(ctx)
    if not hyp and not surface:
        return None
    lines = ["[ENGAGEMENT STATE] Before this turn ends, what your own ledger still has open:"]
    if hyp:
        lines.append(f"\n{len(hyp)} unresolved hypothes{'is' if len(hyp) == 1 else 'es'}:")
        for h in hyp[:10]:
            bits = [f"  - [{h.get('id')}] ({h.get('status')}) {h.get('statement')}"]
            if h.get("test"):
                bits.append(f"      how you said you would test it: {h['test']}")
            lines.append("\n".join(bits))
        if len(hyp) > 10:
            lines.append(f"  … and {len(hyp) - 10} more")
    if surface:
        shown = ", ".join(surface[:12])
        more = f" … and {len(surface) - 12} more" if len(surface) > 12 else ""
        lines.append(f"\nRecorded as surface but not mentioned in anything you tried: "
                     f"{shown}{more}")
    lines.append("\nResolve what you have settled, chase what you have not, or say plainly "
                 "why it is not worth chasing. Any of the three ends the turn.")
    return "\n".join(lines)


HYPOTHESIS_STATES = ("open", "testing", "confirmed", "refuted")


def _empty_ledger() -> dict:
    return {"surface": [], "creds": [], "hypotheses": [], "tried": [], "facts": []}


def _as_hypothesis(item: object, n: int) -> dict:
    """Accept a bare sentence or a full record and always store a record.

    The old ledger took hypotheses as free strings, so a session could note "maybe SMB
    signing is off" and have no way to ever come back to it: no id to resolve, no status to
    read. Strings are still accepted, because refusing them would just make the agent stop
    recording the half-formed suspicions that are worth the most; they are promoted here
    instead.
    """
    if isinstance(item, dict):
        h = dict(item)
    else:
        h = {"statement": str(item)}
    h["statement"] = str(h.get("statement") or "").strip()
    h["id"] = str(h.get("id") or f"h{n}")
    status = str(h.get("status") or "open").lower()
    h["status"] = status if status in HYPOTHESIS_STATES else "open"
    for k in ("evidence", "test", "note"):
        h[k] = str(h.get(k) or "").strip()
    return h


def open_hypotheses(ctx: ScanContext) -> list[dict]:
    led = ctx.ledger or {}
    return [h for h in (led.get("hypotheses") or [])
            if isinstance(h, dict) and h.get("status") in ("open", "testing")]


def untested_surface(ctx: ScanContext) -> list[str]:
    """Surface entries that no `tried` entry mentions.

    Deliberately a substring match rather than anything structured: `surface` and `tried`
    are both free text the agent writes, so the only honest question is whether what it
    recorded as a service appears anywhere in what it recorded as attempted. Wrong in both
    directions at the margins, which is why this feeds a prompt-free "here is what looks
    untouched" report and never a decision.
    """
    led = ctx.ledger or {}
    tried = " ".join(str(t).lower() for t in (led.get("tried") or []))
    out = []
    for s in (led.get("surface") or []):
        text = str(s).strip()
        if text and text.lower() not in tried:
            out.append(text)
    return out


@tool("Your engagement working-memory: `surface` (open services), `creds` (+ where tested), "
      "`facts`, `tried`, and `hypotheses` as records you can resolve later. action='show' returns "
      "it (optional `filter`: {\"status\":\"open\"} or {\"match\":\"text\"}); action='update' merges "
      "`data` (list fields append+dedup); action='resolve' needs `id` + `status` "
      "(open|testing|confirmed|refuted) and closes out a hypothesis. A hypothesis survives context "
      "compaction, so record a suspicion the moment you have it instead of hoping it is still in "
      "the transcript later.",
      {"action": {"type": "string", "enum": ["show", "update", "resolve", "clear"]},
       "data": {"type": "object", "description": "fields to merge, e.g. {\"creds\":[...],\"tried\":[...],\"hypotheses\":[{\"statement\":\"...\",\"evidence\":\"...\",\"test\":\"how I would check\"}]}"},
       "id": {"type": "string", "description": "hypothesis id, for action='resolve'"},
       "status": {"type": "string", "enum": list(HYPOTHESIS_STATES)},
       "note": {"type": "string", "description": "what settled it, for action='resolve'"},
       "filter": {"type": "object", "description": "narrow action='show': {\"status\":\"open\"} or {\"match\":\"smb\"}"}},
      [],
      scope_exempt=True)
async def ledger(ctx: ScanContext, args: dict) -> dict:
    """Your engagement working-memory, and the only state that outlives context compaction.

    Holds what you KNOW (`surface`, `creds` + where each was tested, `facts`), what you have
    `tried`, and your `hypotheses` as records with an id, the evidence behind them, how you
    would test them, and a status. Resolve them as you settle them: an open hypothesis is a
    question still owed an answer, and it is reported back to you if you try to finish with
    one outstanding.
    """
    if ctx.ledger is None:
        ctx.ledger = _empty_ledger()
    action = str(args.get("action") or "show").lower()

    if action == "clear":
        ctx.ledger = _empty_ledger()
        return {"ledger": ctx.ledger}

    if action == "update":
        data = args.get("data")
        if not isinstance(data, dict):
            return {"error": "update needs `data` as an object"}
        for k, v in data.items():
            if k == "hypotheses":
                cur = ctx.ledger.setdefault("hypotheses", [])
                have = {str(h.get("statement", "")).lower() for h in cur if isinstance(h, dict)}
                for item in (v if isinstance(v, list) else [v]):
                    h = _as_hypothesis(item, len(cur) + 1)
                    if not h["statement"] or h["statement"].lower() in have:
                        continue
                    # An id the agent reused would silently overwrite the earlier one.
                    if any(isinstance(e, dict) and e.get("id") == h["id"] for e in cur):
                        h["id"] = f"h{len(cur) + 1}"
                    cur.append(h)
                    have.add(h["statement"].lower())
            elif isinstance(v, list):
                cur = ctx.ledger.setdefault(k, [])
                for item in v:
                    if item not in cur:
                        cur.append(item)
            else:
                ctx.ledger[k] = v

    elif action == "resolve":
        hid = str(args.get("id") or "").strip()
        status = str(args.get("status") or "").lower()
        if not hid:
            return {"error": "resolve needs `id`"}
        if status not in HYPOTHESIS_STATES:
            return {"error": f"status must be one of {', '.join(HYPOTHESIS_STATES)}"}
        for h in (ctx.ledger.get("hypotheses") or []):
            if isinstance(h, dict) and h.get("id") == hid:
                h["status"] = status
                note = str(args.get("note") or "").strip()
                if note:
                    h["note"] = note
                return {"resolved": h, "open_hypotheses": len(open_hypotheses(ctx))}
        return {"error": f"no hypothesis with id {hid!r}",
                "ids": [h.get("id") for h in (ctx.ledger.get("hypotheses") or [])
                        if isinstance(h, dict)]}

    # show, and the tail of update/resolve
    view = dict(ctx.ledger)
    f = args.get("filter")
    if isinstance(f, dict) and f:
        hyp = [h for h in (view.get("hypotheses") or []) if isinstance(h, dict)]
        want = str(f.get("status") or "").lower()
        if want:
            hyp = [h for h in hyp if h.get("status") == want]
        match = str(f.get("match") or "").lower()
        if match:
            hyp = [h for h in hyp if match in json.dumps(h, default=str).lower()]
            for key in ("surface", "creds", "tried", "facts"):
                view[key] = [x for x in (view.get(key) or [])
                             if match in json.dumps(x, default=str).lower()]
        view["hypotheses"] = hyp
    return {"ledger": view, "open_hypotheses": len(open_hypotheses(ctx))}


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

"""Active Directory and credentialed-execution tools.

These wrap third-party binaries (impacket, netexec, kerbrute, certipy, hashcat, ...)
through `_run_cli`. The destructive ones are consent-gated on top of the scope check.
"""
from __future__ import annotations

import asyncio
import os
import re

from .core import (
    DEFAULT_PASSWORDS,
    HYDRA_BIN,
    ScanContext,
    ToolError,
    _consent,
    _impacket,
    _netexec,
    _require_scope,
    _scan_creds,
    _which_any,
    has_hydra,
    tool,
)


@tool("Brute-force credentials on one service with hydra. CONSENT-GATED — only runs if approved. Use only when the target warrants it and after cheaper checks fail.",
      {"target": {"type": "string"},
       "service": {"type": "string", "description": "hydra protocol: ftp|ssh|rdp|smb|mysql|postgres|smtp|http-get|..."},
       "port": {"type": "integer"}, "username": {"type": "string"},
       "wordlist": {"type": "string", "description": "path to a password list; omit for a small built-in list"}},
      ["target", "service", "port"])
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


@tool("Validate/enumerate domain usernames via Kerberos pre-auth — no password, "
      "no lockout. Give a domain, the DC, and a list of candidate usernames. Read-only.",
      {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "target": {"type": "string"},
       "users": {"type": "array", "items": {"type": "string"}, "description": "candidate usernames"}},
      ["domain"])
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


@tool("AS-REP roast: recover crackable Kerberos hashes for accounts with pre-auth "
      "disabled. Needs NO credentials — just a domain + user(s). Returns $krb5asrep hashes. Read-only.",
      {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
       "users": {"type": "array", "items": {"type": "string"}}},
      ["domain"])
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


@tool("Kerberoast: request service tickets for SPN accounts -> crackable $krb5tgs "
      "hashes. Needs valid domain creds. Read-only.",
      {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
       "password": {"type": "string"}, "nthash": {"type": "string"}},
      ["domain", "user"])
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


@tool("Enumerate the domain over LDAP (netexec): users, groups, computers, password "
      "policy, account descriptions, AS-REP-able/Kerberoastable accounts, trusts. Null/anonymous bind "
      "or supplied creds/hash. Read-only.",
      {"target": {"type": "string"}, "dc_ip": {"type": "string"}, "domain": {"type": "string"},
       "user": {"type": "string"}, "password": {"type": "string"}, "nthash": {"type": "string"}},
      [])
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


@tool("RID-cycle a host over SMB to pull domain users/groups — works over a null session. "
      "Read-only.",
      {"target": {"type": "string"}, "domain": {"type": "string"}, "user": {"type": "string"},
       "password": {"type": "string"}, "nthash": {"type": "string"}},
      [])
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


@tool("List SMB shares and read/write access on a host (null session or creds). Read-only.",
      {"target": {"type": "string"}, "host": {"type": "string"}, "domain": {"type": "string"},
       "user": {"type": "string"}, "password": {"type": "string"}, "nthash": {"type": "string"}},
      [])
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


@tool("Download ONE file from an SMB share and read its contents (capped 256 KiB) — the "
      "SMB counterpart to ftp_get. Null session or creds/nthash (pass-the-hash). Read-only. After "
      "smb_shares finds a readable share, pull a config/backup/flag out of it.",
      {"target": {"type": "string"}, "host": {"type": "string"}, "domain": {"type": "string"},
       "user": {"type": "string"}, "password": {"type": "string"}, "nthash": {"type": "string"},
       "share": {"type": "string", "description": "share name, default C$"},
       "path": {"type": "string", "description": "share-relative path, e.g. 'Users\\\\Public\\\\flag.txt'"}},
      ["path"])
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


@tool("Spray ONE password across MANY users over a protocol "
      "(smb/ldap/winrm/mssql/rdp/ssh). CONSENT-GATED — account-lockout risk; check the password "
      "policy first. Returns which user/password pairs are valid.",
      {"target": {"type": "string"}, "proto": {"type": "string"}, "domain": {"type": "string"},
       "users": {"type": "array", "items": {"type": "string"}},
       "spray_password": {"type": "string"}},
      ["users", "spray_password"])
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


@tool("Dump credential material: local SAM/LSA secrets, or domain NTDS.dit hashes "
      "(dump_type='ntds' against a DC). Supports pass-the-hash. CONSENT-GATED.",
      {"target": {"type": "string"}, "domain": {"type": "string"}, "user": {"type": "string"},
       "password": {"type": "string"}, "nthash": {"type": "string"},
       "dump_type": {"type": "string", "enum": ["local", "ntds"]}},
      ["user"])
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


@tool("Execute a command on a Windows host and read output — SMB (wmiexec/psexec/smbexec) "
      "or WinRM. Pass-the-hash via nthash. CONSENT-GATED (code execution).",
      {"target": {"type": "string"}, "domain": {"type": "string"}, "user": {"type": "string"},
       "password": {"type": "string"}, "nthash": {"type": "string"}, "command": {"type": "string"},
       "method": {"type": "string", "enum": ["wmiexec", "psexec", "smbexec", "atexec", "winrm"]}},
      ["user", "command"])
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


@tool("Execute a command on a Linux/Unix host over SSH and read the output — the Linux "
      "counterpart to win_exec. Auth with a password OR a private key file. CONSENT-GATED (code "
      "execution). Run this on ANY SSH credential you recover (e.g. from cred_check) to enumerate, "
      "read flags and escalate — a validated SSH login is a dead end without it.",
      {"target": {"type": "string"}, "host": {"type": "string"}, "user": {"type": "string"},
       "password": {"type": "string"}, "key_file": {"type": "string", "description": "path to a private key (alternative to password)"},
       "port": {"type": "integer", "description": "default 22"}, "command": {"type": "string"}},
      ["user", "command"])
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


@tool("Collect AD attack-path data (users/groups/ACLs/sessions/GPOs/trusts) "
      "into a BloodHound zip via bloodhound-python. Read-only, heavy. Needs domain creds.",
      {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
       "password": {"type": "string"}, "nthash": {"type": "string"}},
      ["domain", "user"])
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


@tool("Enumerate AD Certificate Services and flag vulnerable templates (ESC1-ESC16) via "
      "certipy. Read-only. Needs domain creds.",
      {"domain": {"type": "string"}, "dc_ip": {"type": "string"}, "user": {"type": "string"},
       "password": {"type": "string"}, "nthash": {"type": "string"}},
      ["domain", "user"])
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


@tool("SAFE detection-only checks for known DC/Windows flaws (Zerologon, noPac, "
      "PetitPotam, MS17-010) via netexec modules — detection, NOT exploitation. Read-only.",
      {"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"},
       "checks": {"type": "array", "items": {"type": "string"}}},
      [])
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


@tool("Crack recovered hashes OFFLINE (hashcat/john) against a wordlist. Safe — no "
      "target contact. hash_type is a hashcat mode (18200 AS-REP, 13100 Kerberoast, 1000 NTLM).",
      {"hashes": {"type": "array", "items": {"type": "string"}}, "hash_type": {"type": "string"},
       "wordlist": {"type": "string", "description": "path to a wordlist, e.g. rockyou.txt"}},
      ["hashes", "wordlist"],
      scope_exempt=True)
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


@tool("Validate ONE credential across the target's auth services (smb/winrm/rdp/ldap/"
      "mssql/ssh/ftp) via netexec — 'where does this credential actually work?'. Read-only. Run this "
      "on ANY credential you recover: one that fails one service often works another (e.g. RDP but "
      "not WinRM), so never conclude from a single service.",
      {"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"},
       "nthash": {"type": "string"}, "domain": {"type": "string"},
       "services": {"type": "array", "items": {"type": "string"},
       "description": "subset to test; default smb,winrm,rdp,ldap,mssql,ssh,ftp"}},
      ["user"])
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

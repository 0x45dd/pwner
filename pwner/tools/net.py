"""Per-service network tools that need no nmap: DNS, banners, raw TCP, SNMP, FTP."""
from __future__ import annotations

import asyncio
import ftplib
import re
import shutil

from .core import (
    SNMPWALK_BIN,
    ScanContext,
    ToolError,
    _require_scope,
    tool,
)


@tool("DNS records (A/AAAA/CNAME/MX/NS/TXT) for a domain.",
      {"domain": {"type": "string"}},
      [])
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


@tool("Raw banner from one host:port (for a port nmap didn't identify).",
      {"host": {"type": "string"}, "port": {"type": "integer"}},
      ["host", "port"])
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


@tool("FTP login + directory listing (read-only recon). Anonymous by default; pass "
      "user/password to test credentials you found elsewhere.",
      {"host": {"type": "string"}, "port": {"type": "integer"},
       "user": {"type": "string"}, "password": {"type": "string"}},
      ["host"])
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


@tool("Download ONE file over FTP and read its contents (capped 256 KiB) — a config, "
      "backup, source file, or flag. Anonymous by default; pass user/password for an account.",
      {"host": {"type": "string"}, "port": {"type": "integer"}, "path": {"type": "string"},
       "user": {"type": "string"}, "password": {"type": "string"}},
      ["host", "path"])
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


@tool("Send raw bytes to a TCP port and read the reply — speak any protocol banner_grab "
      "can't (Redis 'INFO', memcached 'stats', a DB handshake, a custom service). data is text with "
      "\\r\\n/\\t escapes honored; set hex=true to send a hex string. Read/recon only.",
      {"host": {"type": "string"}, "port": {"type": "integer"},
       "data": {"type": "string", "description": "payload to send; empty just reads the greeting"},
       "hex": {"type": "boolean", "description": "true: interpret data as a hex string"},
       "crlf": {"type": "boolean", "description": "append CRLF if missing (default true)"},
       "read_bytes": {"type": "integer"}, "timeout": {"type": "number"}},
      ["host", "port"])
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


@tool("Read SNMP system info with a community string (default 'public'). Read-only recon.",
      {"host": {"type": "string"}, "community": {"type": "string"}},
      ["host"])
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

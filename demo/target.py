#!/usr/bin/env python3
"""A deliberately weak HTTP service, for demos and local testing. Loopback only.

This exists so pwner has something real to find without pointing it at anyone else's
machine. It binds 127.0.0.1 and refuses to bind anything else — the whole point is that
running it cannot expose a weak service to a network.

    python demo/target.py          # serves on 127.0.0.1:8080

The weaknesses are the obvious ones a kiosk-style appliance tends to ship with: the
login hint tells you the password IS the serial number, and an unauthenticated status
endpoint hands out the serial number. Nothing here is a real product, and the device
name, serials and credentials are invented.
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERIAL = "NX-DH-2024-B7042"          # invented
DEVICE = "DocReader DeviceHub DH-100"

LOGIN_PAGE = f"""<!doctype html>
<html><head><title>DeviceHub - Login</title></head>
<body>
  <h1>{DEVICE}</h1>
  <h2>Sign In &mdash; STAFF ACCESS</h2>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Sign In</button>
  </form>
  <p><small>Default password is the device serial number.</small></p>
  <p><a href="/api/status">status</a> &middot; <a href="/backup/">backups</a></p>
</body></html>
"""

DASHBOARD = f"""<!doctype html>
<html><head><title>DeviceHub - Dashboard</title></head>
<body>
  <h1>{DEVICE} &mdash; Dashboard</h1>
  <table>
    <tr><td>Scanner account</td><td>svc_scanner / Sc@nner-2024</td></tr>
    <tr><td>Firmware</td><td>2.1.4</td></tr>
  </table>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "DeviceHub/2.1.4"

    def log_message(self, fmt, *args):      # keep the demo terminal clean
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html", **headers):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in headers.items():
            self.send_header(k.replace("_", "-"), v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/login"):
            self._send(200, LOGIN_PAGE)
        elif path == "/api/status":
            # leaks the serial, which the login page says is the default password
            self._send(200, json.dumps({
                "device": DEVICE, "serial": SERIAL,
                "firmware": "2.1.4", "uptime_s": 48213,
            }, indent=2), "application/json")
        elif path == "/backup/":
            self._send(200, "<html><body><h1>Index of /backup/</h1>"
                            "<a href='config.bak'>config.bak</a></body></html>")
        elif path == "/backup/config.bak":
            self._send(200, f"admin_password={SERIAL}\nsnmp_community=public\n", "text/plain")
        elif path == "/dashboard":
            if "authed=1" in (self.headers.get("Cookie") or ""):
                self._send(200, DASHBOARD)
            else:
                self._send(302, "", Location="/login")
        else:
            self._send(404, "<html><body>404</body></html>")

    def do_POST(self):
        if self.path != "/login":
            return self._send(404, "<html><body>404</body></html>")
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        supplied = ""
        for pair in body.split("&"):
            k, _, v = pair.partition("=")
            if k == "password":
                supplied = v.replace("%21", "!").replace("+", " ")
        if supplied == SERIAL:
            self._send(302, "", Location="/dashboard", Set_Cookie="authed=1; Path=/")
        else:
            self._send(401, "<html><body><p>Invalid password.</p></body></html>")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    # Host is NOT configurable on purpose: a deliberately weak service should never be
    # one flag away from listening on a real interface.
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"demo target on http://127.0.0.1:{args.port} (loopback only) — Ctrl-C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""HTTP tools: scheme probing, endpoint discovery, and raw request/response work.

The cookie jar lives on the ScanContext, so a login in one call keeps the session
authenticated for the next.
"""
from __future__ import annotations

import asyncio
import re
import socket
from html import unescape

from .core import (
    ScanContext,
    _extract_strings,
    _require_scope,
    _scan_creds,
    tool,
)


def _tls_handshake_ok(host: str, port: int, timeout: float = 4.0) -> bool:
    """True if host:port completes a TLS handshake — so we pick https vs http correctly on ANY
    port (8443, 9443, ...), not just 443."""
    import ssl
    sctx = ssl.create_default_context()
    sctx.check_hostname = False
    sctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with sctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:  # noqa: BLE001 — not TLS (plain HTTP), filtered, refused, etc.
        return False


async def _scheme_for(ctx: ScanContext, host: str, port: int, explicit: str | None = None) -> str:
    """Pick http/https for host:port. Honors an explicit scheme, short-circuits 80/443, else probes
    the TLS handshake ONCE per (host,port) and caches it — fixes the old port==443-only assumption."""
    if explicit in ("http", "https"):
        return explicit
    if port == 80:
        return "http"
    if port == 443:
        return "https"
    cache = ctx.scheme_cache
    key = (host, port)
    if key not in cache:
        cache[key] = "https" if await asyncio.to_thread(_tls_handshake_ok, host, port) else "http"
    return cache[key]


def _sync_cookies(ctx: ScanContext, client) -> None:
    """Persist the cookies a client collected (incl. across redirects) back onto the ctx jar so the
    NEXT web tool call is still logged in."""
    try:
        ctx.http_cookies = client.cookies
    except Exception:  # noqa: BLE001
        pass


def _collected_set_cookie(r) -> str:
    """All Set-Cookie headers across the redirect chain — so a login 302's cookie isn't hidden by
    the final 200 (httpx only exposes the final response's headers)."""
    out = []
    for resp in list(getattr(r, "history", []) or []) + [r]:
        sc = resp.headers.get("set-cookie", "")
        if sc:
            out.append(sc)
    return " || ".join(out)[:600]


@tool("Fetch a web page and SEE it: status, server, title, body excerpt, links, "
      "forms (action/method/input names) and HTML comments. Use this to actually READ a web app.",
      {"host": {"type": "string"}, "port": {"type": "integer"}, "path": {"type": "string"}},
      ["host", "port"])
async def http_probe(ctx: ScanContext, args: dict) -> dict:
    import httpx
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    path = str(args.get("path") or "/")
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    url = f"{scheme}://{host}:{port}{path}"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True,
                                     cookies=ctx.http_cookies) as c:
            r = await c.get(url)
            _sync_cookies(ctx, c)
        parsed = _parse_html(r.text)
        return {"url": url, "status": r.status_code,
                "server": r.headers.get("server", ""),
                "content_type": r.headers.get("content-type", ""),
                "title": parsed["title"],
                "links": parsed["links"][:40],
                "forms": parsed["forms"],
                "comments": parsed["comments"][:10],
                "body_excerpt": parsed["text"][:1500],
                "headers": dict(list(r.headers.items())[:20])}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": f"{type(e).__name__}: {str(e)[:200]}"}


def _parse_html(text: str) -> dict:
    """Pull the useful structure out of an HTML page so the agent can actually read the app:
    title, links, forms (action/method/input names), HTML comments, and a tag-stripped text excerpt."""
    body = text or ""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:200]
    # Entities are decoded, not passed through. It matters most for links: a query string
    # written href="/x?a=1&amp;y=2" has to come back as /x?a=1&y=2, or the agent requests
    # a URL with a literal "&amp;" in it. Text and comments just read better decoded.
    links = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', body, re.I)
    links = list(dict.fromkeys(
        unescape(a.strip()) for a in links
        if a.strip() and not a.lower().startswith(("data:", "javascript:", "#"))))
    comments = [unescape(c.strip())[:200] for c in re.findall(r"<!--(.*?)-->", body, re.S) if c.strip()]
    forms = []
    for fm in re.findall(r"<form\b(.*?)</form>", body, re.I | re.S):
        a = re.search(r'action\s*=\s*["\']([^"\']*)["\']', fm, re.I)
        md = re.search(r'method\s*=\s*["\']([^"\']*)["\']', fm, re.I)
        inputs = re.findall(r'<(?:input|textarea|select)\b[^>]*name\s*=\s*["\']([^"\']+)["\']', fm, re.I)
        forms.append({"action": a.group(1) if a else "", "method": (md.group(1) if md else "get").upper(),
                      "inputs": inputs[:20]})
    txt = re.sub(r"<script\b.*?</script>", " ", body, flags=re.I | re.S)
    txt = re.sub(r"<style\b.*?</style>", " ", txt, flags=re.I | re.S)
    txt = re.sub(r"<[^>]+>", " ", txt)
    # Unescape after stripping tags, so an escaped "&lt;script&gt;" in the page body
    # cannot turn into a tag that the stripper above has already run past.
    txt = re.sub(r"\s+", " ", unescape(txt)).strip()
    return {"title": title, "links": links, "forms": forms, "comments": comments, "text": txt}


# Common paths probed by content_discovery (mapped early to reveal a web app's attack surface).
_COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/admin", "/administrator",
    "/login", "/logout", "/register", "/signup", "/dashboard", "/home", "/index.php",
    "/api", "/api/v1", "/api/v2", "/docs", "/swagger", "/swagger.json", "/openapi.json",
    "/graphql", "/console", "/debug", "/status", "/health", "/metrics", "/server-status",
    "/phpinfo.php", "/info.php", "/test", "/dev", "/staging", "/backup", "/backups",
    "/config", "/config.php", "/settings", "/uploads", "/upload", "/files", "/static",
    "/assets", "/js", "/css", "/users", "/user", "/account", "/profile", "/portal",
    "/internal", "/private", "/secret", "/data", "/db", "/logs", "/wp-login.php",
    "/wp-admin/", "/.htaccess", "/web.config", "/flag", "/flag.txt",
]


#: a signature seen on at least this many paths, and this share of them, is the server
#: answering everything the same way rather than that many real endpoints existing.
_CATCH_ALL_MIN_PATHS = 8
_CATCH_ALL_SHARE = 0.5
#: how many example paths to carry for a signature that is only summarised
_SAMPLES = 4


def summarise_probes(found: list[dict], tested: int) -> dict:
    """Collapse probe hits by response signature, and name a catch-all when we see one.

    Two problems, one cause. A server that answers every path with the same page defeats
    the 404 filter above, so every probed path becomes a "hit": the model is handed
    hundreds of near-identical JSON objects that are both wrong and, repeated per host
    and port, large enough to exhaust the context window. Grouping on
    (status, length, redirect) turns that into one line and labels it for what it is.

    Pure function on purpose, so the behaviour is testable without a server."""
    groups: dict[tuple, list[str]] = {}
    for hit in found:
        key = (hit["status"], hit["len"], hit.get("redirect", ""))
        groups.setdefault(key, []).append(hit["path"])

    catch_all = None
    for (status, length, redirect), hit_paths in groups.items():
        if (len(hit_paths) >= _CATCH_ALL_MIN_PATHS
                and tested and len(hit_paths) / tested >= _CATCH_ALL_SHARE
                and 200 <= status < 400):
            catch_all = {
                "status": status, "len": length, "redirect": redirect,
                "paths": len(hit_paths),
                "note": (f"{len(hit_paths)} of {tested} probed paths returned the identical "
                         f"response (status {status}, {length} bytes). The server almost "
                         f"certainly serves the same page for everything, so none of these "
                         f"is evidence that the path exists. Confirm one with web_request "
                         f"and compare it against a path you invent."),
            }
            break

    summary, listed = [], 0
    for (status, length, redirect), hit_paths in sorted(
            groups.items(), key=lambda kv: (-len(kv[1]), kv[0][0])):
        row: dict = {"status": status, "len": length, "paths": len(hit_paths)}
        if redirect:
            row["redirect"] = redirect
        # List paths while a signature is still rare enough to mean something, and
        # always keep a few samples so the model can follow up on the rest.
        if len(hit_paths) <= _SAMPLES:
            row["examples"] = hit_paths
            listed += len(hit_paths)
        else:
            row["examples"] = hit_paths[:_SAMPLES]
            row["more"] = len(hit_paths) - _SAMPLES
        summary.append(row)

    out: dict = {"tested": tested, "distinct_responses": len(groups), "responses": summary}
    if catch_all:
        out["catch_all"] = catch_all
    else:
        # Without a catch-all the hit list is small, so hand it over in full.
        out["found"] = found
    return out


@tool("Map a web app's hidden paths/endpoints: probes a built-in list of common "
      "paths (+ any you add) and returns which exist (non-404), grouped by response "
      "signature. A server that answers everything the same way is reported as a "
      "catch-all instead of as hundreds of findings. Run this early on any web service.",
      {"host": {"type": "string"}, "port": {"type": "integer"},
       "paths": {"type": "array", "items": {"type": "string"},
       "description": "extra paths to also try, e.g. ['/api/users','/v2/login']"}},
      ["host"])
async def content_discovery(ctx: ScanContext, args: dict) -> dict:
    """Map a web app's hidden paths: probe a built-in list (+ any supplied) and report what exists."""
    import httpx
    host = str(args.get("host") or args.get("target") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    base = f"{scheme}://{host}:{port}"
    extra = args.get("paths") or []
    if isinstance(extra, str):
        extra = [p.strip() for p in extra.split(",") if p.strip()]
    paths = list(dict.fromkeys(_COMMON_PATHS + [str(p) for p in extra]))
    sem = asyncio.Semaphore(min(20, (ctx.concurrency or 20)))

    async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=False,
                                 cookies=ctx.http_cookies) as c:
        async def probe(p: str):
            url = base + (p if p.startswith("/") else "/" + p)
            async with sem:
                try:
                    r = await c.get(url)
                except Exception:  # noqa: BLE001
                    return None
            if r.status_code == 404:
                return None
            loc = r.headers.get("location", "") if 300 <= r.status_code < 400 else ""
            return {"path": p, "status": r.status_code, "len": len(r.content), "redirect": loc}
        results = await asyncio.gather(*[probe(p) for p in paths])
    found = sorted((x for x in results if x), key=lambda x: (x["status"], x["path"]))
    return {"base": base, **summarise_probes(found, len(paths))}


@tool("Send a CUSTOM HTTP request (any method/path/headers/body/params) and get the full "
      "parsed response — for testing endpoints, logins, parameters, auth bypass, IDOR. This is how you "
      "interact with and exploit a web app's own logic (what nuclei can't do on a custom app).",
      {"host": {"type": "string"}, "port": {"type": "integer"},
       "method": {"type": "string", "description": "GET|POST|PUT|DELETE|..."},
       "path": {"type": "string"}, "headers": {"type": "object"}, "params": {"type": "object"},
       "data": {"type": "object", "description": "form fields for a POST"},
       "json": {"type": "object", "description": "JSON request body"}},
      ["host", "path"])
async def web_request(ctx: ScanContext, args: dict) -> dict:
    """Send a custom HTTP request and return the parsed response — for testing endpoints, logins,
    parameters, auth bypass and IDOR (i.e. actually exercising the web app's own logic). Cookies
    persist across calls, so once you log in you stay authenticated. For a RAW body (binary upload,
    exact bytes) pass `body` (text) or `body_b64` (base64-decoded to bytes)."""
    import base64 as _b64

    import httpx
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    method = str(args.get("method") or "GET").upper()
    path = str(args.get("path") or "/")
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
    headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
    params = args.get("params") if isinstance(args.get("params"), dict) else None
    data = args.get("data")
    json_body = args.get("json")
    content = None  # raw request body (bytes) — for binary uploads / exact bytes
    if args.get("body_b64"):
        try:
            content = _b64.b64decode(str(args["body_b64"]))
        except Exception:  # noqa: BLE001
            return {"url": url, "error": "body_b64 is not valid base64"}
    elif args.get("body") is not None:
        content = str(args["body"]).encode("utf-8", "replace")
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True,
                                     cookies=ctx.http_cookies) as c:
            r = await c.request(method, url, headers=headers, params=params,
                                data=data if content is None else None,
                                json=json_body if content is None else None, content=content)
            _sync_cookies(ctx, c)
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": f"{type(e).__name__}: {str(e)[:200]}"}
    ctype = r.headers.get("content-type", "").lower()
    parsed = _parse_html(r.text) if "html" in ctype else {
        "title": "", "links": [], "forms": [], "comments": [], "text": r.text[:2500]}
    return {"url": url, "method": method, "status": r.status_code, "content_type": ctype,
            "set_cookie": _collected_set_cookie(r),
            "title": parsed["title"], "links": parsed["links"][:40], "forms": parsed["forms"],
            "comments": parsed["comments"][:10], "body_excerpt": (parsed["text"] or r.text)[:2500],
            "headers": dict(list(r.headers.items())[:20])}


@tool("Download an HTTP response in FULL, binary-safe, and extract what matters: "
      "the text (or a strings extraction for binary — pcaps, zips, backups, images) PLUS any "
      "credentials found inside (HTTP Basic, FTP USER/PASS, user/password/token pairs). Use when a "
      "path is a file/binary or when http_probe's body was truncated. Don't judge a file by its first KB.",
      {"host": {"type": "string"}, "port": {"type": "integer"}, "path": {"type": "string"},
       "method": {"type": "string"}, "headers": {"type": "object"}},
      ["host", "path"])
async def http_download(ctx: ScanContext, args: dict) -> dict:
    """Download a response in FULL (binary-safe) and extract what matters — for files http_probe
    can't read: pcaps, zips, backups, images, source. Returns the text (or a `strings` extraction
    for binary) PLUS any credentials found inside. Use whenever a path is a file/binary or when a
    normal probe's body was truncated — don't judge a file by its first few KB."""
    import httpx
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    method = str(args.get("method") or "GET").upper()
    path = str(args.get("path") or "/")
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
    headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
    cap = 12 * 1024 * 1024  # 12 MiB
    chunks: list[bytes] = []
    total = 0
    try:
        async with httpx.AsyncClient(timeout=45.0, verify=False, follow_redirects=True,
                                     cookies=ctx.http_cookies) as c:
            async with c.stream(method, url, headers=headers) as r:
                status = r.status_code
                ctype = r.headers.get("content-type", "")
                clen = r.headers.get("content-length", "")
                async for chunk in r.aiter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > cap:
                        break
            _sync_cookies(ctx, c)
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": f"{type(e).__name__}: {str(e)[:200]}"}
    data = b"".join(chunks)[:cap]
    sample = data[:8192]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
    is_text = bool(sample) and printable / len(sample) > 0.85
    if is_text:
        extract = data.decode("utf-8", "replace")[:9000]
    else:  # binary (pcap/zip/image): give the readable strings instead of mojibake
        extract = "\n".join(_extract_strings(data))[:9000]
    creds = _scan_creds(data)
    return {"url": url, "status": status, "content_type": ctype,
            "size": len(data), "declared_length": clen, "truncated": total > cap,
            "is_text": is_text, "credentials": creds[:50], "extract": extract}

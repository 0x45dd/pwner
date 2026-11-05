"""HTTP tools: scheme probing, endpoint discovery, and raw request/response work.

The cookie jar lives on the ScanContext, so a login in one call keeps the session
authenticated for the next.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import time
from html import unescape
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .core import (
    DIRSEARCH_BIN,
    ScanContext,
    ToolError,
    _extract_strings,
    _require_scope,
    _scan_creds,
    has_dirsearch,
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


# ── dirsearch: the path-finding tool ─────────────────────────────────────────
#: dirsearch writes its report only when it finishes, so a run killed on timeout
#: normally leaves nothing. We still try to read the file: some versions flush as they
#: go, and a partial list beats none.
_DIRSEARCH_DEFAULT_TIMEOUT = 300.0
_DIRSEARCH_MAX_TIMEOUT = 1800.0


def _dirsearch_rows(report: dict, base: str) -> list[dict]:
    """Map dirsearch's JSON results onto the shape summarise_probes already speaks.

    dirsearch reports absolute URLs and `content-length`; the grouping logic wants a path
    and `len`, so the translation happens here rather than in two places.
    """
    rows: list[dict] = []
    for r in report.get("results") or []:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or "")
        path = url[len(base):] if url.startswith(base) else (urlsplit(url).path or "/")
        try:
            length = int(r.get("content-length") or 0)
        except (TypeError, ValueError):
            length = 0
        rows.append({"path": path or "/", "status": int(r.get("status") or 0),
                     "len": length, "redirect": str(r.get("redirect") or "")})
    return rows


@tool("Brute-force paths and endpoints with dirsearch and a real wordlist — far wider than "
      "content_discovery's small built-in list. This is the path-finding tool: reach for it when "
      "you want coverage of a web app's hidden surface rather than a quick look. Results come back "
      "grouped by response signature, and a server that answers everything the same way is named "
      "as a catch-all instead of reported as hundreds of hits.",
      {"host": {"type": "string"}, "port": {"type": "integer"},
       "path": {"type": "string", "description": "base path to search under, default /"},
       "extensions": {"type": "string",
                      "description": "comma list appended to every word, e.g. 'php,bak,old,zip'"},
       "wordlist": {"type": "string", "description": "absolute path to a wordlist; "
                                                     "omit to use dirsearch's own"},
       "exclude_status": {"type": "string", "description": "status codes to drop, e.g. '404,403'"},
       "include_status": {"type": "string", "description": "only these codes, e.g. '200,301'"},
       "timeout": {"type": "integer", "description": "overall seconds, default 300"}},
      ["host"])
async def dirsearch_scan(ctx: ScanContext, args: dict) -> dict:
    """Brute-force paths with dirsearch and a real wordlist, grouped by response signature."""
    host = str(args.get("host") or ctx.target or "")
    _require_scope(host, ctx)
    if not has_dirsearch():
        raise ToolError("dirsearch not found. Install it: `sudo apt install dirsearch` on "
                        "Debian/Ubuntu/Kali, or `pipx install dirsearch` anywhere else.")
    port = int(args.get("port", 80))
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    base = f"{scheme}://{host}:{port}"
    path = str(args.get("path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    url = base + path
    try:
        overall = float(args.get("timeout") or _DIRSEARCH_DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        raise ToolError("timeout must be a number") from None
    overall = min(max(overall, 10.0), _DIRSEARCH_MAX_TIMEOUT)

    import tempfile
    fd, report_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    cmd = [DIRSEARCH_BIN, "-u", url, "-q", "--no-color",
           "--format=json", "-o", report_path,
           "-t", str(max(1, min(50, (ctx.concurrency or 20)))),
           "--timeout", "5"]
    if args.get("wordlist"):
        cmd += ["-w", str(args["wordlist"])]
    if args.get("extensions"):
        cmd += ["-e", str(args["extensions"])]
    if args.get("include_status"):
        cmd += ["-i", str(args["include_status"])]
    elif args.get("exclude_status"):
        cmd += ["-x", str(args["exclude_status"])]
    timed_out = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            _, err = await asyncio.wait_for(proc.communicate(), timeout=overall)
        except asyncio.TimeoutError:
            timed_out = True
            err = b""
            proc.kill()
            await proc.wait()
        try:
            with open(report_path, encoding="utf-8") as f:
                report = json.load(f)
        except (OSError, ValueError):
            report = {}
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass

    if not report and timed_out:
        raise ToolError(
            f"dirsearch timed out after {overall:g}s with no report written. Narrow it: "
            f"pass a smaller wordlist, fewer extensions, or a deeper starting path.")
    if not report:
        msg = err.decode("utf-8", "replace")[:300] if err else ""
        raise ToolError(f"dirsearch produced no report. {msg}".strip())

    rows = _dirsearch_rows(report, base)
    tested = 0
    info = report.get("info")
    if isinstance(info, dict):
        try:
            tested = int(info.get("total_requests") or 0)
        except (TypeError, ValueError):
            tested = 0
    # summarise_probes needs a denominator to judge a catch-all. dirsearch reports only
    # its hits, so without the request count the share is meaningless; fall back to the
    # hit count, which makes the catch-all test conservative rather than wrong.
    out = {"base": base, "searched": path, "tool": "dirsearch",
           **summarise_probes(sorted(rows, key=lambda r: (r["status"], r["path"])),
                              tested or len(rows))}
    if timed_out:
        out["partial"] = (f"dirsearch was stopped at {overall:g}s; this is what it had found "
                          f"by then, not a complete search.")
    return out


# ── web_crawl: the app's real surface ────────────────────────────────────────
_CRAWL_MAX_PAGES = 300
_CRAWL_MAX_DEPTH = 6
#: extensions that are never worth fetching during a crawl: they add pages and bytes
#: without adding surface. The agent can still http_download any of them by name.
_CRAWL_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff",
                   ".woff2", ".ttf", ".eot", ".css", ".pdf", ".zip", ".gz", ".mp4", ".mp3")


def _same_origin_path(link: str, base_path: str, host: str, port: int, scheme: str) -> str | None:
    """Resolve one link against the page it was found on, and return its path+query if it
    stays on this origin. None means "not ours", which is also how out-of-scope hosts are
    dropped: a crawl must never follow a link off the authorized target.
    """
    link = (link or "").strip()
    if not link or link.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    sp = urlsplit(link)
    if sp.scheme and sp.scheme not in ("http", "https"):
        return None
    if sp.netloc:
        netloc_host = sp.hostname or ""
        netloc_port = sp.port or (443 if sp.scheme == "https" else 80)
        if netloc_host.lower() != host.lower() or netloc_port != port:
            return None
        path = sp.path or "/"
    elif link.startswith("/"):
        path = sp.path
    else:  # relative to the directory of the page it came from
        root = base_path.rsplit("/", 1)[0]
        path = f"{root}/{sp.path}" if sp.path else base_path
    # collapse . and .. without resolving against the filesystem
    parts: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    norm = "/" + "/".join(parts)
    if path.endswith("/") and norm != "/":
        norm += "/"
    return urlunsplit(("", "", norm, sp.query, ""))


def _surface_key(path_q: str) -> tuple[str, tuple[str, ...]]:
    """The identity of a crawl target: its path plus the NAMES of its query parameters.

    Values are deliberately excluded. /item?id=1 and /item?id=2 are the same endpoint and
    the same surface, and treating them as two would let any paginated or id-driven page
    expand the crawl without end.
    """
    sp = urlsplit(path_q)
    names = tuple(sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)}))
    return (sp.path or "/", names)


@tool("Crawl a web app from a starting page and return its REAL surface: every reachable "
      "path, the query parameters each one takes, and every form with its method and input names. "
      "content_discovery and dirsearch guess paths from a wordlist; this one follows the app's own "
      "links and forms, so it finds what the app actually exposes. Run it before testing parameters.",
      {"host": {"type": "string"}, "port": {"type": "integer"},
       "path": {"type": "string", "description": "where to start, default /"},
       "max_pages": {"type": "integer", "description": "pages to fetch, default 60, cap 300"},
       "max_depth": {"type": "integer", "description": "link depth, default 3, cap 6"}},
      ["host"])
async def web_crawl(ctx: ScanContext, args: dict) -> dict:
    """Crawl a web app and return its real surface: paths, query parameters and forms."""
    import httpx
    host = str(args.get("host") or ctx.target or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    base = f"{scheme}://{host}:{port}"
    start = str(args.get("path") or "/")
    if not start.startswith("/"):
        start = "/" + start
    # `or` would be wrong here: max_depth=0 is a real request ("just this page") and
    # `0 or 3` is 3, so a caller asking for the seed alone would silently get a 3-deep
    # crawl. None means "not given"; 0 means 0.
    md, mp = args.get("max_depth"), args.get("max_pages")
    try:
        max_pages = min(max(60 if mp is None else int(mp), 1), _CRAWL_MAX_PAGES)
        max_depth = min(max(3 if md is None else int(md), 0), _CRAWL_MAX_DEPTH)
    except (TypeError, ValueError):
        raise ToolError("max_pages and max_depth must be integers") from None

    queue: list[tuple[str, int]] = [(start, 0)]
    seen: set[tuple[str, tuple[str, ...]]] = {_surface_key(start)}
    pages: list[dict] = []
    surface: dict[tuple[str, tuple[str, ...]], dict] = {}
    forms: list[dict] = []
    form_keys: set[tuple] = set()
    skipped_offsite = 0
    sem = asyncio.Semaphore(min(20, (ctx.concurrency or 20)))

    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False,
                                 cookies=ctx.http_cookies) as c:
        async def fetch(pq: str) -> dict | None:
            async with sem:
                try:
                    return await c.get(base + pq)
                except Exception:        # noqa: BLE001 - an unreachable page is just not surface
                    return None

        while queue and len(pages) < max_pages:
            batch = queue[: max(1, min(len(queue), max_pages - len(pages)))]
            queue = queue[len(batch):]
            responses = await asyncio.gather(*[fetch(pq) for pq, _ in batch])
            for (pq, depth), r in zip(batch, responses, strict=True):
                if r is None:
                    continue
                sp = urlsplit(pq)
                key = _surface_key(pq)
                params = sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)})
                entry = surface.setdefault(key, {"path": sp.path or "/", "params": params,
                                                 "methods": ["GET"]})
                loc = r.headers.get("location", "") if 300 <= r.status_code < 400 else ""
                pages.append({"path": pq, "status": r.status_code,
                              "len": len(r.content), "redirect": loc})
                entry["status"] = r.status_code
                ctype = (r.headers.get("content-type") or "").lower()
                if loc:
                    nxt = _same_origin_path(loc, sp.path or "/", host, port, scheme)
                    if nxt and _surface_key(nxt) not in seen and depth < max_depth:
                        seen.add(_surface_key(nxt))
                        queue.append((nxt, depth + 1))
                if "html" not in ctype:
                    continue   # only HTML carries links and forms, which is the surface
                parsed = _parse_html(r.text)
                if parsed["title"]:
                    entry["title"] = parsed["title"][:120]
                for fm in parsed["forms"]:
                    action = _same_origin_path(fm.get("action") or pq, sp.path or "/",
                                               host, port, scheme) or pq
                    fkey = (urlsplit(action).path, fm.get("method", "GET"),
                            tuple(fm.get("inputs") or []))
                    if fkey in form_keys:
                        continue
                    form_keys.add(fkey)
                    forms.append({"action": urlsplit(action).path, "method": fm.get("method", "GET"),
                                  "inputs": (fm.get("inputs") or [])[:20]})
                    fk = _surface_key(action)
                    fe = surface.setdefault(fk, {"path": urlsplit(action).path,
                                                 "params": [], "methods": ["GET"]})
                    if fm.get("method", "GET") not in fe["methods"]:
                        fe["methods"].append(fm.get("method", "GET"))
                    for name in (fm.get("inputs") or []):
                        if name not in fe["params"]:
                            fe["params"].append(name)
                if depth >= max_depth:
                    continue
                for link in parsed["links"]:
                    nxt = _same_origin_path(link, sp.path or "/", host, port, scheme)
                    if nxt is None:
                        skipped_offsite += 1
                        continue
                    if urlsplit(nxt).path.lower().endswith(_CRAWL_SKIP_EXT):
                        continue
                    k = _surface_key(nxt)
                    if k in seen:
                        continue
                    seen.add(k)
                    queue.append((nxt, depth + 1))
        _sync_cookies(ctx, c)

    rows = sorted(surface.values(), key=lambda e: e["path"])
    with_params = [e for e in rows if e["params"]]
    out = {
        "base": base, "started_at": start,
        "pages_fetched": len(pages), "endpoints": len(rows),
        "max_pages": max_pages, "max_depth": max_depth,
        "surface": rows[:200],
        "forms": forms[:60],
        "parameterised_endpoints": [f"{e['path']}?{'&'.join(e['params'])}" for e in with_params][:60],
        "responses": summarise_probes(pages, len(pages)).get("responses", []),
    }
    if len(rows) > 200:
        out["surface_truncated"] = len(rows) - 200
    if queue:
        out["unvisited_queued"] = len(queue)
        out["note"] = (f"stopped at the {max_pages}-page limit with {len(queue)} links still "
                       f"queued; raise max_pages or start deeper to go further")
    if skipped_offsite:
        out["skipped_offsite_links"] = skipped_offsite
    return out


# ── param_probe: one call instead of twenty ──────────────────────────────────
#: Payload classes, owned here rather than by the model. The point of the tool is that
#: the agent stops hand-iterating payloads one request at a time: it gets the whole
#: differential in a single call and reasons about the result instead of the next guess.
#:
#: Every payload is read-only and side-effect-free. There is no DROP, no sleep and no
#: write: a detection probe that damages the target is not a detection probe, and a
#: time-based payload is a small denial of service against the app under test.
_PAYLOADS: dict[str, tuple[str, ...]] = {
    "sqli":      ("'", '"', "')", "' OR '1'='1' -- ", "1 AND 1=2"),
    "xss":       ("pwnrprobe<x>\"'", "<pwnrprobe>"),
    "traversal": ("../../../../etc/passwd", "....//....//....//etc/passwd"),
    "cmdi":      (";id", "|id", "$(id)", "`id`"),
    "ssti":      ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"),
    "nosql":     ('{"$ne":null}', "[$ne]=1"),
    "lfi":       ("php://filter/convert.base64-encode/resource=index",),
}

#: Database error text. Matched case-insensitively, and only counted when it is ABSENT
#: from the baseline response: an app that prints SQL errors on every page is a finding
#: about the app, not about this parameter.
_SQL_ERRORS = (
    "sql syntax", "mysql_fetch", "you have an error in your sql", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated", "pg_query",
    "psqlexception", "sqlite3.operationalerror", "sqlite_error", "ora-0",
    "syntax error at or near", "odbc driver", "sqlstate",
)

#: (marker, what it means). Baseline-relative like the errors above.
_EVIDENCE = (
    ("uid=", "command execution: `id` output in the response"),
    ("root:x:", "file read: /etc/passwd content in the response"),
    ("root:*:", "file read: /etc/passwd content in the response"),
    ("49", "template or expression evaluation: 7*7 was computed"),
)

#: a length change smaller than this is noise on most apps (timestamps, csrf tokens)
_LEN_NOISE = 32

#: Reflection only counts as a signal when a character that can OPEN A TAG survives.
#: Measured against a real app that echoes its input: without this gate every one of the
#: twenty payloads came back "reflected", because echoing `../../etc/passwd` reflects it
#: too. That is true and useless, and it buried the one payload that mattered.
_TAG_CHARS = ("<", ">")


def _signals(body: str, baseline: str) -> list[str]:
    """What this response shows that the baseline did not.

    Everything is differential on purpose. Absolute matching is what makes parameter
    probes unusable: a page that happens to contain "49", or an app that renders a SQL
    warning in its footer, produces a hit on every parameter you ever test.
    """
    low, base_low = body.lower(), baseline.lower()
    out: list[str] = []
    for err in _SQL_ERRORS:
        if err in low and err not in base_low:
            out.append(f"sql_error: {err}")
            break
    for marker, meaning in _EVIDENCE:
        if marker in body and marker not in baseline:
            out.append(meaning)
    return out


@tool("Test ONE parameter against a whole set of payload classes in a single call, and get the "
      "differential against a clean baseline: status, length, timing, database errors, reflection "
      "and evidence of execution. Use this instead of sending web_request yourself over and over "
      "with a different payload each time — one call covers SQLi, XSS, traversal, command "
      "injection, template injection, NoSQL and LFI, and tells you which ones moved.",
      {"host": {"type": "string"}, "port": {"type": "integer"},
       "path": {"type": "string"},
       "param": {"type": "string", "description": "the parameter name to test"},
       "method": {"type": "string", "description": "GET (default) or POST"},
       "baseline": {"type": "string", "description": "a normal, valid value for the parameter "
                                                     "(default '1')"},
       "others": {"type": "object", "description": "other parameters to hold constant, "
                                                   "e.g. {\"page\":\"1\"}"},
       "classes": {"type": "array", "items": {"type": "string"},
                   "description": "payload classes to run; omit for all. One of: "
                                  "sqli, xss, traversal, cmdi, ssti, nosql, lfi"}},
      ["host", "path", "param"])
async def param_probe(ctx: ScanContext, args: dict) -> dict:
    """Probe one parameter across payload classes and return the differential vs a baseline.

    Not consent-gated, deliberately and consistently: these are the same requests
    web_request already sends ungated, batched into one call, and every payload is
    read-only. Gating it while leaving web_request open would only push the agent back to
    sending them one at a time, which is the behaviour this tool exists to replace.
    """
    import httpx
    host = str(args.get("host") or "")
    _require_scope(host, ctx)
    port = int(args.get("port", 80))
    path = str(args.get("path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    param = str(args.get("param") or "").strip()
    if not param:
        raise ToolError("param_probe needs the name of the parameter to test (param=...)")
    method = str(args.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        raise ToolError("method must be GET or POST")
    baseline_value = str(args.get("baseline") or "1")
    others = args.get("others") if isinstance(args.get("others"), dict) else {}
    others = {str(k): str(v) for k, v in others.items()}

    wanted = args.get("classes")
    if isinstance(wanted, str):
        wanted = [c.strip() for c in wanted.split(",") if c.strip()]
    if wanted:
        unknown = [c for c in wanted if c not in _PAYLOADS]
        if unknown:
            raise ToolError(f"unknown payload class(es) {unknown}. "
                            f"Available: {', '.join(_PAYLOADS)}")
        classes = {c: _PAYLOADS[c] for c in wanted}
    else:
        classes = dict(_PAYLOADS)

    scheme = await _scheme_for(ctx, host, port, args.get("scheme"))
    url = f"{scheme}://{host}:{port}{path}"
    sem = asyncio.Semaphore(min(10, max(1, (ctx.concurrency or 20) // 2)))

    async def send(client, value: str) -> dict:
        fields = {**others, param: value}
        started = time.perf_counter()
        try:
            async with sem:
                if method == "POST":
                    r = await client.post(url, data=fields)
                else:
                    r = await client.get(url, params=fields)
        except Exception as e:                        # noqa: BLE001
            return {"error": f"{type(e).__name__}: {str(e)[:120]}",
                    "ms": round((time.perf_counter() - started) * 1000)}
        return {"status": r.status_code, "len": len(r.content),
                "ms": round((time.perf_counter() - started) * 1000),
                "body": r.text[:20000]}

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True,
                                 cookies=ctx.http_cookies) as c:
        base = await send(c, baseline_value)
        if "error" in base:
            return {"url": url, "param": param,
                    "error": f"baseline request failed, nothing to compare against: {base['error']}"}
        flat = [(cls, p) for cls, payloads in classes.items() for p in payloads]
        results = await asyncio.gather(*[send(c, p) for _, p in flat])
        _sync_cookies(ctx, c)

    base_body = base.get("body", "")
    rows: list[dict] = []
    interesting: list[dict] = []
    for (cls, payload), res in zip(flat, results, strict=True):
        row: dict = {"class": cls, "payload": payload[:60]}
        if "error" in res:
            row["error"] = res["error"]
            rows.append(row)
            continue
        body = res.get("body", "")
        row.update({"status": res["status"], "len": res["len"], "ms": res["ms"]})
        flags: list[str] = []
        if res["status"] != base["status"]:
            flags.append(f"status {base['status']} -> {res['status']}")
        delta = res["len"] - base["len"]
        # An app that echoes its input returns a longer page for a longer payload. That
        # is arithmetic, not a finding, so only the part of the delta the echo does NOT
        # account for counts.
        unexplained = abs(delta - (len(payload) - len(baseline_value)))
        if abs(delta) > _LEN_NOISE and unexplained > _LEN_NOISE:
            flags.append(f"len {base['len']} -> {res['len']} ({delta:+d})")
        if base["ms"] and res["ms"] > base["ms"] * 3 + 500:
            flags.append(f"slower: {base['ms']}ms -> {res['ms']}ms")
        if (any(ch in payload for ch in _TAG_CHARS)
                and payload in body and payload not in base_body):
            flags.append("reflected unencoded (tag characters survived)")
        flags += _signals(body, base_body)
        if flags:
            row["signals"] = flags
            interesting.append({"class": cls, "payload": payload[:60], "signals": flags})
        rows.append(row)

    by_class: dict[str, int] = {}
    for item in interesting:
        by_class[item["class"]] = by_class.get(item["class"], 0) + 1
    return {
        "url": url, "param": param, "method": method,
        "baseline": {"value": baseline_value, "status": base["status"],
                     "len": base["len"], "ms": base["ms"]},
        "payloads_sent": len(flat),
        "classes_tested": sorted(classes),
        "moved": by_class,
        "interesting": interesting[:40],
        # The parameter moved the response in a way the baseline does not explain, which is
        # the one outcome here worth thinking harder about. Read by the agent loop, which
        # raises the reasoning budget for the next few steps; it is a measurement, not a
        # finding, and says nothing about whether the thing is exploitable.
        "significance": "high" if interesting else "low",
        "results": rows,
        "note": ("Every signal is measured against the baseline, so a page that always "
                 "contains a marker does not produce a hit. An empty `interesting` means "
                 "nothing this parameter was given changed the response in a way worth "
                 "chasing. Confirm anything listed with web_request before reporting it."),
    }

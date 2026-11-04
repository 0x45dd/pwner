"""Mapping a web app's surface, and probing one parameter instead of twenty.

Three tools, one problem between them. The prompt already told the agent to "test the
app's logic", but the only tool for it sent a single request, so the agent obeyed by
hammering one endpoint with a slightly different payload each time — the loop
tests/test_loop_detection.py exists to catch. These tools replace that with: crawl the
app's real surface, brute-force the paths it does not link to, and test a parameter
across whole payload classes in one call.

The signal-to-noise tests near the bottom are the ones that matter. They came out of
running param_probe against a real app that echoes its input: before they passed, all
twenty payloads came back "reflected" and the one finding that mattered was buried.
"""
from __future__ import annotations

import asyncio

import pytest

from pwner.tools import ScanContext, ToolError
from pwner.tools.web import (
    _LEN_NOISE,
    _dirsearch_rows,
    _same_origin_path,
    _signals,
    _surface_key,
    param_probe,
    web_crawl,
)


def ctx(target="10.0.0.5", **kw):
    return ScanContext(target=target, **kw)


# ── resolving a link, which is also where scope is kept ──────────────────────

def origin(link, base_path="/dir/page.html", host="10.0.0.5", port=80, scheme="http"):
    return _same_origin_path(link, base_path, host, port, scheme)


@pytest.mark.parametrize("link,expected", [
    ("/admin", "/admin"),
    ("about.html", "/dir/about.html"),
    ("./about.html", "/dir/about.html"),
    ("../up.html", "/up.html"),
    ("/a/b/../c", "/a/c"),
    ("/trailing/", "/trailing/"),
    ("/q?id=1", "/q?id=1"),
    ("http://10.0.0.5:80/abs", "/abs"),
])
def test_links_resolve_to_a_path_on_this_origin(link, expected):
    assert origin(link) == expected


@pytest.mark.parametrize("link", [
    "https://evil.example.com/x",      # another host
    "http://10.0.0.5:8080/other",      # same host, another service
    "//cdn.example.com/lib.js",        # protocol-relative, elsewhere
    "mailto:a@b.c", "tel:+1", "javascript:alert(1)", "data:text/html,x", "#frag", "",
])
def test_anything_not_on_this_origin_is_dropped(link):
    """This is the crawler's half of the scope boundary: following an off-target link
    would send traffic to a host the operator never authorized."""
    assert origin(link) is None


def test_a_non_http_scheme_is_dropped_even_on_our_host():
    assert origin("ftp://10.0.0.5/pub") is None


# ── what counts as one endpoint ──────────────────────────────────────────────

def test_parameter_values_are_not_part_of_the_endpoint_identity():
    """/item?id=1 and /item?id=2 are one endpoint. Treating them as two is how a
    paginated or id-driven site expands a crawl without end."""
    assert _surface_key("/item?id=1") == _surface_key("/item?id=2")


def test_parameter_names_are_part_of_it():
    assert _surface_key("/item?id=1") != _surface_key("/item?slug=x")


def test_parameter_order_does_not_matter():
    assert _surface_key("/s?a=1&b=2") == _surface_key("/s?b=9&a=8")


def test_a_different_path_is_a_different_endpoint():
    assert _surface_key("/a") != _surface_key("/b")


# ── dirsearch output mapping ─────────────────────────────────────────────────

def test_dirsearch_rows_become_the_shape_the_grouping_speaks():
    report = {"results": [
        {"url": "http://h:80/admin", "status": 301, "content-length": 0, "redirect": "/admin/"},
        {"url": "http://h:80/api", "status": 200, "content-length": 42, "redirect": ""},
    ]}
    rows = _dirsearch_rows(report, "http://h:80")
    assert rows == [
        {"path": "/admin", "status": 301, "len": 0, "redirect": "/admin/"},
        {"path": "/api", "status": 200, "len": 42, "redirect": ""},
    ]


def test_dirsearch_rows_survive_a_missing_or_junk_field():
    report = {"results": [{"url": "http://h:80/x", "status": 200}, "not a dict", None]}
    assert _dirsearch_rows(report, "http://h:80") == [
        {"path": "/x", "status": 200, "len": 0, "redirect": ""}]


def test_an_empty_report_is_not_an_error():
    assert _dirsearch_rows({}, "http://h:80") == []


# ── signals are differential ─────────────────────────────────────────────────

def test_a_sql_error_the_baseline_already_had_is_not_a_signal():
    """An app that renders a SQL warning on every page is a finding about the app, not
    about this parameter. Absolute matching makes every parameter look vulnerable."""
    page = "<html>Warning: mysql something</html>"
    assert _signals(page, page) == []


def test_a_new_sql_error_is_a_signal():
    out = _signals("You have an error in your SQL syntax near x", "all fine")
    assert any("sql_error" in s for s in out)


def test_command_output_appearing_is_a_signal():
    assert any("command execution" in s for s in _signals("uid=0(root)", "hello"))


def test_etc_passwd_content_appearing_is_a_signal():
    assert any("file read" in s for s in _signals("root:x:0:0:", "hello"))


def test_arithmetic_evaluation_is_a_signal_only_when_it_is_new():
    assert any("evaluation" in s for s in _signals("result 49", "result"))
    assert _signals("page 49 of 100", "page 49 of 100") == []


# ── the crawl, against a fake app ────────────────────────────────────────────

class _Resp:
    def __init__(self, body="", status=200, ctype="text/html", headers=None):
        self.status_code = status
        self.text = body
        self.content = body.encode()
        self.headers = {"content-type": ctype, **(headers or {})}


APP = {
    "/": '<html><title>Shop</title><a href="/items?id=1">i</a><a href="/about">a</a>'
         '<a href="https://evil.example.com/x">off</a><a href="/logo.png">p</a>'
         '<form action="/search" method="post"><input name="q"><input name="page"></form></html>',
    "/about": '<html><title>About</title><a href="/items?id=2">more</a><a href="/about">self</a></html>',
    "/items": '<html><title>Item</title>one item</html>',
    "/search": '<html><title>Search</title>results</html>',
    "/logo.png": "PNGDATA",
}


def fake_app(seen=None, app=None):
    pages = APP if app is None else app

    class _C:
        cookies = {}

        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

        async def get(self, url, params=None):
            from urllib.parse import urlsplit
            path = urlsplit(url).path
            if seen is not None:
                seen.append(path)
            if path not in pages:
                return _Resp("not found", 404)
            ctype = "image/png" if path.endswith(".png") else "text/html"
            return _Resp(pages[path], 200, ctype)

        async def post(self, url, data=None):
            return await self.get(url)

    return lambda **kw: _C()


def test_the_crawl_finds_the_apps_own_surface(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", fake_app())
    r = asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80}))
    paths = {e["path"] for e in r["surface"]}
    assert {"/", "/about", "/items", "/search"} <= paths
    byp = {e["path"]: e["params"] for e in r["surface"]}
    assert byp["/items"] == ["id"]
    assert sorted(byp["/search"]) == ["page", "q"]


def test_forms_are_reported_with_their_method_and_inputs(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", fake_app())
    r = asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80}))
    assert {"action": "/search", "method": "POST", "inputs": ["q", "page"]} in r["forms"]


def test_a_form_target_carries_its_method_onto_the_surface(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", fake_app())
    r = asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80}))
    search = [e for e in r["surface"] if e["path"] == "/search"][0]
    assert "POST" in search["methods"]


def test_an_offsite_link_is_counted_and_not_fetched(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr("httpx.AsyncClient", fake_app(seen))
    r = asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80}))
    assert r["skipped_offsite_links"] >= 1
    assert not [p for p in seen if "evil" in p]


def test_assets_are_not_crawled(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr("httpx.AsyncClient", fake_app(seen))
    asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80}))
    assert "/logo.png" not in seen, "images add pages and bytes, never surface"


def test_the_same_endpoint_with_two_values_is_fetched_once(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr("httpx.AsyncClient", fake_app(seen))
    asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80}))
    assert seen.count("/items") == 1, "?id=1 and ?id=2 are one endpoint"


def test_a_self_link_does_not_loop(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr("httpx.AsyncClient", fake_app(seen))
    asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80}))
    assert seen.count("/about") == 1


def test_the_page_budget_is_honoured_and_reported(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", fake_app())
    r = asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80, "max_pages": 2}))
    assert r["pages_fetched"] <= 2
    assert r["max_pages"] == 2


def test_depth_zero_fetches_only_the_seed(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr("httpx.AsyncClient", fake_app(seen))
    r = asyncio.run(web_crawl(ctx(), {"host": "10.0.0.5", "port": 80, "max_depth": 0}))
    assert r["pages_fetched"] == 1 and seen == ["/"]


def test_a_host_outside_scope_is_refused(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", fake_app())
    with pytest.raises(ToolError, match="outside the authorized scope"):
        asyncio.run(web_crawl(ctx(target="10.0.0.5"), {"host": "8.8.8.8", "port": 80}))


# ── param_probe, and the noise a real app taught us about ────────────────────

def echo_app(behaviour="echo"):
    """A fake endpoint. `behaviour` picks what the parameter does."""
    class _C:
        cookies = {}

        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

        async def get(self, url, params=None, data=None):
            v = str((params or {}).get("q", ""))
            if behaviour == "echo":
                return _Resp(f"<html>results for {v}</html>")
            if behaviour == "sqli" and ("'" in v or '"' in v):
                return _Resp(f"<html>You have an error in your SQL syntax near '{v}'</html>", 500)
            if behaviour == "always_error":
                return _Resp("<html>Warning: mysql is unhappy, as ever</html>")
            if behaviour == "inert":
                return _Resp("<html>same page every time</html>")
            return _Resp("<html>ok</html>")

        async def post(self, url, params=None, data=None):
            return await self.get(url, params=data)

    return lambda **kw: _C()


def probe(monkeypatch, behaviour, **extra):
    monkeypatch.setattr("httpx.AsyncClient", echo_app(behaviour))
    args = {"host": "10.0.0.5", "port": 80, "path": "/search", "param": "q", **extra}
    return asyncio.run(param_probe(ctx(), args))


def test_one_call_covers_every_payload_class(monkeypatch):
    r = probe(monkeypatch, "inert")
    assert r["payloads_sent"] > 15, "the point is one call instead of twenty"
    assert set(r["classes_tested"]) >= {"sqli", "xss", "traversal", "cmdi", "ssti", "nosql", "lfi"}


def test_an_inert_parameter_produces_nothing_to_chase(monkeypatch):
    r = probe(monkeypatch, "inert")
    assert r["interesting"] == []
    assert r["moved"] == {}


def test_a_sql_error_is_found_and_attributed(monkeypatch):
    r = probe(monkeypatch, "sqli")
    assert r["moved"].get("sqli")
    sig = " ".join(s for i in r["interesting"] for s in i["signals"])
    assert "sql_error" in sig and "status 200 -> 500" in sig


def test_merely_echoing_a_payload_is_not_a_signal(monkeypatch):
    """The regression a real app produced: an endpoint that echoes its input reflected
    all twenty payloads, so `interesting` was twenty rows and the finding was buried.
    Reflection counts only when a tag-opening character survives."""
    r = probe(monkeypatch, "echo")
    classes = {i["class"] for i in r["interesting"]}
    assert "traversal" not in classes, "echoing a file path is not a traversal finding"
    assert "cmdi" not in classes, "echoing ;id is not command execution"
    assert "nosql" not in classes


def test_a_surviving_tag_character_still_is_a_signal(monkeypatch):
    r = probe(monkeypatch, "echo")
    assert "xss" in {i["class"] for i in r["interesting"]}
    assert any("tag characters survived" in s
               for i in r["interesting"] for s in i["signals"])


def test_a_length_change_the_echo_explains_is_suppressed(monkeypatch):
    """A longer payload echoed back makes a longer page. That is arithmetic."""
    r = probe(monkeypatch, "echo")
    lens = [s for i in r["interesting"] for s in i["signals"] if s.startswith("len ")]
    assert lens == [], f"echo-explained length deltas leaked through: {lens}"


def test_an_app_that_always_errors_does_not_make_every_payload_a_finding(monkeypatch):
    r = probe(monkeypatch, "always_error")
    assert r["interesting"] == []


def test_the_baseline_is_reported_so_the_comparison_is_auditable(monkeypatch):
    r = probe(monkeypatch, "inert", baseline="42")
    assert r["baseline"]["value"] == "42"
    assert "status" in r["baseline"] and "len" in r["baseline"]


def test_a_single_class_can_be_selected(monkeypatch):
    r = probe(monkeypatch, "sqli", classes=["sqli"])
    assert r["classes_tested"] == ["sqli"]
    assert r["payloads_sent"] == 5


def test_an_unknown_class_is_refused_with_the_list(monkeypatch):
    with pytest.raises(ToolError, match="unknown payload class"):
        probe(monkeypatch, "inert", classes=["sqli", "telepathy"])


def test_a_missing_parameter_name_is_refused(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", echo_app("inert"))
    with pytest.raises(ToolError, match="needs the name of the parameter"):
        asyncio.run(param_probe(ctx(), {"host": "10.0.0.5", "path": "/x", "param": "  "}))


def test_an_unsupported_method_is_refused(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", echo_app("inert"))
    with pytest.raises(ToolError, match="GET or POST"):
        asyncio.run(param_probe(ctx(), {"host": "10.0.0.5", "path": "/x",
                                        "param": "q", "method": "DELETE"}))


def test_post_is_supported(monkeypatch):
    r = probe(monkeypatch, "sqli", method="POST")
    assert r["method"] == "POST"
    assert r["moved"].get("sqli")


def test_a_host_outside_scope_is_refused_here_too(monkeypatch):
    monkeypatch.setattr("httpx.AsyncClient", echo_app("inert"))
    with pytest.raises(ToolError, match="outside the authorized scope"):
        asyncio.run(param_probe(ctx(target="10.0.0.5"),
                                {"host": "8.8.8.8", "path": "/x", "param": "q"}))


def test_the_noise_floor_is_a_named_constant():
    assert _LEN_NOISE > 0

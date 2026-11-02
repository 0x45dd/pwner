"""Tests for the HTML reader the web tools hand to the agent.

_parse_html is how the agent actually *reads* a web app — title, links, forms, comments
and a tag-stripped excerpt. Whatever it gets wrong, the agent reasons from.
"""
from __future__ import annotations

import pytest

from pwner.tools import _parse_html

PAGE = """<!doctype html>
<html><head><title>  Kiosk &mdash;
 Login </title></head>
<body>
  <!-- TODO: default pass is the serial &amp; nothing else -->
  <h1>Sign In &mdash; STAFF ACCESS</h1>
  <form method="POST" action="/login">
    <input type="password" name="password">
    <input type="hidden" name="csrf">
    <button>Go</button>
  </form>
  <a href="/api/items?a=1&amp;b=2">items</a>
  <a href="javascript:void(0)">js</a>
  <a href="#top">anchor</a>
  <a href="data:text/plain,x">data</a>
  <a href="/api/items?a=1&amp;b=2">dupe</a>
  <script>var secret = "not in text";</script>
  <style>body{color:red}</style>
</body></html>
"""


def test_title_is_decoded_and_whitespace_collapsed():
    assert _parse_html(PAGE)["title"] == "Kiosk — Login"


def test_links_are_deduped_and_filtered():
    """javascript:, data: and bare anchors are not fetchable, so they are dropped. Order
    is document order over href/src/action, which puts the form's action first here."""
    assert _parse_html(PAGE)["links"] == ["/login", "/api/items?a=1&b=2"]


def test_link_entities_are_decoded():
    """The one that actually breaks requests: a query string written with &amp; has to
    come back as &, or the agent fetches a URL containing a literal "&amp;"."""
    links = _parse_html(PAGE)["links"]
    assert "/api/items?a=1&b=2" in links
    assert not any("&amp;" in a for a in links)


def test_forms_capture_method_action_and_input_names():
    assert _parse_html(PAGE)["forms"] == [
        {"action": "/login", "method": "POST", "inputs": ["password", "csrf"]}]


def test_comments_are_kept_and_decoded():
    """HTML comments are where appliances leave hints; they are worth reading."""
    assert _parse_html(PAGE)["comments"] == ["TODO: default pass is the serial & nothing else"]


def test_script_and_style_bodies_are_excluded_from_text():
    text = _parse_html(PAGE)["text"]
    assert "not in text" not in text
    assert "color:red" not in text


def test_text_is_decoded_and_readable():
    assert "Sign In — STAFF ACCESS" in _parse_html(PAGE)["text"]


def test_escaped_markup_survives_as_literal_text():
    """&lt;script&gt; is decoded AFTER tags are stripped, so escaped markup shows up as
    text rather than being treated as a tag and thrown away — the agent should be able to
    see that a page echoes input escaped."""
    out = _parse_html("<html><body><p>&lt;script&gt;alert(1)&lt;/script&gt;</p></body></html>")
    assert "<script>alert(1)</script>" in out["text"]


@pytest.mark.parametrize("body", ["", "not html at all", "<html>", "<title>x"])
def test_malformed_input_does_not_raise(body):
    out = _parse_html(body)
    assert set(out) == {"title", "links", "forms", "comments", "text"}


def test_none_is_handled():
    assert _parse_html(None)["title"] == ""

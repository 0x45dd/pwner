"""Provider configuration: presets, local endpoints, and model discovery.

The regression these pin: `--provider ollama` used to fail with "no API key
configured" because LLMClient required a key unconditionally and the CLI only built a
client when one was present. Servers on your own hardware have no key, so the
advertised local-model support could not actually be used without inventing one.
"""
from __future__ import annotations

import asyncio

import pytest

from pwner.llm import (
    LOCAL_PROVIDERS,
    PRESETS,
    AIUnavailable,
    LLMClient,
    discover_models,
    is_local_endpoint,
    resolve_config,
)

# ── which endpoints count as "on my own hardware" ────────────────────────────

@pytest.mark.parametrize("url", [
    "http://localhost:11434/v1",
    "http://127.0.0.1:13305/api/v1",
    "http://[::1]:8080/v1",
    "http://192.168.1.50:13305/api/v1",   # the realistic Lemonade case: another box
    "http://10.0.0.7:8000/api/v1",
    "http://172.16.4.2:8000/v1",
    "http://workstation.local:13305/api/v1",
    "http://box.lan:11434/v1",
    "http://169.254.3.4:8000/v1",         # link-local
])
def test_local_endpoints_are_recognised(url):
    assert is_local_endpoint(url) is True


@pytest.mark.parametrize("url", [
    "https://api.openai.com/v1",
    "https://api.deepseek.com",
    "https://api.anthropic.com/v1",
    "https://generativelanguage.googleapis.com/v1beta/openai",
    "http://8.8.8.8/v1",                  # public IP is not local
    "http://evil.example.com/v1",
    "",
    "not a url at all",
])
def test_remote_endpoints_are_not_local(url):
    assert is_local_endpoint(url) is False


# ── the regression: a local server needs no API key ──────────────────────────

@pytest.mark.parametrize("provider", sorted(LOCAL_PROVIDERS))
def test_local_provider_works_with_no_api_key(provider):
    """This raised AIUnavailable before, which made `--provider ollama` unusable."""
    base = PRESETS[provider]["base_url"]
    client = LLMClient("", base, "some-model")
    assert client.base_url == base.rstrip("/")


def test_remote_provider_still_requires_a_key():
    with pytest.raises(AIUnavailable):
        LLMClient("", "https://api.openai.com/v1", "gpt-4o-mini")


def test_no_authorization_header_when_there_is_no_key():
    c = LLMClient("", "http://localhost:11434/v1", "llama3.1")
    assert "Authorization" not in c._headers
    assert c._headers["Content-Type"] == "application/json"


def test_key_is_sent_when_present_even_on_a_local_endpoint():
    """Lemonade does support keys (it separates inference from admin), so a key given
    for a local endpoint must still be sent rather than dropped."""
    c = LLMClient("sk-local", "http://192.168.1.50:13305/api/v1", "m")
    assert c._headers["Authorization"] == "Bearer sk-local"


# ── the lemonade preset ──────────────────────────────────────────────────────

def test_lemonade_preset_shape():
    p = PRESETS["lemonade"]
    assert p["base_url"] == "http://localhost:13305/api/v1"
    # deliberately blank: model names are per-install, so it is discovered, not guessed
    assert p["model"] == ""
    assert is_local_endpoint(p["base_url"])


def test_every_preset_has_a_base_url():
    for name, p in PRESETS.items():
        assert p["base_url"], name
        assert "model" in p, name


# ── saved config is actually honoured ────────────────────────────────────────

def test_saved_base_url_and_model_are_used(monkeypatch):
    """Both were ignored before: only the preset or an explicit flag could set them,
    so `pwner setup` could not configure a local server once and be done."""
    monkeypatch.setattr("pwner.config.load", lambda: {
        "provider": "lemonade", "api_key": "", "base_url": "http://10.1.1.9:9000/api/v1",
        "model": "Qwen3-Coder-30B"})
    key, base, model = resolve_config("", "", "", "")
    assert base == "http://10.1.1.9:9000/api/v1"
    assert model == "Qwen3-Coder-30B"
    assert key == ""


def test_explicit_arguments_still_beat_saved_config(monkeypatch):
    monkeypatch.setattr("pwner.config.load", lambda: {
        "provider": "lemonade", "base_url": "http://10.1.1.9:9000/api/v1", "model": "saved"})
    _, base, model = resolve_config("", "", "http://127.0.0.1:1/api/v1", "explicit")
    assert base == "http://127.0.0.1:1/api/v1"
    assert model == "explicit"


# ── model discovery ──────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, payload, raise_exc=None):
        self._p, self._e = payload, raise_exc

    def raise_for_status(self):
        if self._e:
            raise self._e

    def json(self):
        return self._p


def _fake_client(resp, seen=None):
    class _C:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            if seen is not None:
                seen.append((url, headers))
            if isinstance(resp, Exception):
                raise resp
            return resp
    return lambda **kw: _C()


def test_discover_models_parses_the_openai_shape(monkeypatch):
    payload = {"data": [{"id": "Qwen3-Coder-30B"}, {"id": "Cyber-8B"}]}
    monkeypatch.setattr("httpx.AsyncClient", _fake_client(_Resp(payload)))
    assert asyncio.run(discover_models("http://localhost:13305/api/v1")) == [
        "Qwen3-Coder-30B", "Cyber-8B"]


def test_discover_models_hits_the_models_path_and_omits_empty_auth(monkeypatch):
    seen: list = []
    monkeypatch.setattr("httpx.AsyncClient", _fake_client(_Resp({"data": []}), seen))
    asyncio.run(discover_models("http://localhost:13305/api/v1/"))
    url, headers = seen[0]
    assert url == "http://localhost:13305/api/v1/models"
    assert "Authorization" not in headers


def test_discover_models_sends_a_key_when_given(monkeypatch):
    seen: list = []
    monkeypatch.setattr("httpx.AsyncClient", _fake_client(_Resp({"data": []}), seen))
    asyncio.run(discover_models("http://localhost:13305/api/v1", "lemon-key"))
    assert seen[0][1]["Authorization"] == "Bearer lemon-key"


@pytest.mark.parametrize("bad", [
    RuntimeError("connection refused"),
    _Resp({"data": "not a list"}),
    _Resp({"unexpected": "shape"}),
    _Resp(["plain", "list", "of", "strings"]),
])
def test_discover_models_returns_empty_rather_than_raising(monkeypatch, bad):
    """An unreachable or odd server must not crash setup; the caller asks the operator."""
    monkeypatch.setattr("httpx.AsyncClient", _fake_client(bad))
    assert asyncio.run(discover_models("http://localhost:1/api/v1")) == []

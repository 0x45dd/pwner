"""Choosing a provider and a model without restarting.

Two problems this covers.

The first was a bug with a daily cost. `pwner` with no arguments decided whether it was
already configured by looking for a saved `api_key`, but a server on your own hardware
has no key, so the wizard saved `api_key: ""` for Ollama and Lemonade and then treated
that as "never configured". Every single launch went back through the setup prompts with
working settings already on disk.

The second is that changing the model meant leaving the session and running `pwner setup`
again, which also discarded the target, the findings and the conversation. `/model` and
`/provider` change it in place, and `pwner --pick` offers the menu at launch for people
who want it without making every other launch pay for it.
"""
from __future__ import annotations

import asyncio

import pytest

from pwner.cli import _effective_provider, _is_configured
from pwner.llm import PRESETS, LLMClient
from pwner.repl import ReplSession, _persist, _provider_of
from pwner.tools import ScanContext

# ── the launch bug ───────────────────────────────────────────────────────────

def test_a_saved_api_key_is_configured():
    assert _is_configured({"provider": "openai", "api_key": "sk-x"}) is True


@pytest.mark.parametrize("provider", ["ollama", "lemonade"])
def test_a_local_provider_with_no_key_is_configured(provider):
    """The actual regression: these save an empty key, and an empty key is falsy."""
    assert _is_configured({"provider": provider, "api_key": ""}) is True


def test_a_local_base_url_alone_is_configured():
    """A custom llama.cpp or vLLM server is set with --base-url and matches no preset."""
    assert _is_configured({"base_url": "http://192.168.1.50:13305/api/v1"}) is True


def test_an_empty_config_is_not_configured():
    assert _is_configured({}) is False


def test_a_hosted_provider_without_a_key_is_not_configured():
    """Nothing to reuse, so the wizard is the right answer here."""
    assert _is_configured({"provider": "openai", "api_key": ""}) is False


def test_a_remote_base_url_without_a_key_is_not_configured():
    assert _is_configured({"base_url": "https://api.openai.com/v1"}) is False


# ── naming the provider in force ─────────────────────────────────────────────

def test_the_flag_wins_over_the_saved_provider(monkeypatch):
    monkeypatch.setattr("pwner.config.load", lambda: {"provider": "openai"})
    args = type("A", (), {"provider": "lemonade"})()
    assert _effective_provider(args) == "lemonade"


def test_the_saved_provider_is_used_when_no_flag_is_given(monkeypatch):
    monkeypatch.setattr("pwner.config.load", lambda: {"provider": "lemonade"})
    args = type("A", (), {"provider": None})()
    assert _effective_provider(args) == "lemonade"


def test_a_preset_base_url_is_labelled_with_its_provider_name():
    client = LLMClient("k", PRESETS["openai"]["base_url"], "gpt-x")
    assert _provider_of(client) == "openai"


def test_a_custom_endpoint_gets_no_label_rather_than_a_wrong_one():
    client = LLMClient("", "http://192.168.1.50:9999/v1", "m")
    assert _provider_of(client) == ""


def test_no_client_has_no_provider():
    assert _provider_of(None) == ""


# ── persisting a change ──────────────────────────────────────────────────────

def test_persist_keeps_the_api_key_it_did_not_touch(tmp_path, monkeypatch):
    """save() rewrites the whole file, so a naive save(model=...) would drop the key."""
    cfg = tmp_path / "config.json"
    monkeypatch.setattr("pwner.config.CONFIG_PATH", str(cfg))
    import pwner.config as pwner_config
    pwner_config.save({"provider": "openai", "api_key": "sk-secret", "model": "old"})
    assert _persist(model="new") is True
    after = pwner_config.load()
    assert after["api_key"] == "sk-secret"
    assert after["model"] == "new"
    assert after["provider"] == "openai"


def test_persist_ignores_empty_values(monkeypatch):
    """An empty model must not blank out a good one."""
    store = {"provider": "lemonade", "model": "keep-me"}
    saved: dict = {}
    monkeypatch.setattr("pwner.config.load", lambda: dict(store))
    monkeypatch.setattr("pwner.config.save", lambda cfg: saved.update(cfg))
    assert _persist(model="") is True
    assert saved["model"] == "keep-me"


# ── /model and /provider ─────────────────────────────────────────────────────

class _Tui:
    def __init__(self):
        self.lines: list[str] = []

    def log(self, s):
        self.lines.append(str(s))

    @property
    def text(self):
        return "\n".join(self.lines)


def session(client=None, provider="lemonade", busy=False):
    s = object.__new__(ReplSession)
    s.ctx = ScanContext(target="10.0.0.5")
    s.client = client
    s.provider = provider
    s.model = getattr(client, "model", "deterministic")
    s.tui = _Tui()
    s._busy = busy
    s.on_refresh = lambda: None
    return s


def stub_models(monkeypatch, names, persisted=None):
    async def _d(base, key=None, *a, **kw):
        return list(names)
    monkeypatch.setattr("pwner.repl.discover_models", _d)
    monkeypatch.setattr("pwner.repl._persist",
                        lambda **kw: (persisted.update(kw) if persisted is not None else None) or True)


MODELS = ["Qwen3.6-35B", "gpt-oss-120b", "Qwen3-Coder-30B"]


def test_model_with_no_argument_lists_what_the_server_serves(monkeypatch):
    stub_models(monkeypatch, MODELS)
    s = session(LLMClient("", "http://localhost:13305/api/v1", "gpt-oss-120b"))
    asyncio.run(s._cmd_model(""))
    assert "Qwen3.6-35B" in s.tui.text
    assert "(current)" in s.tui.text
    assert s.client.model == "gpt-oss-120b", "listing must not change anything"


def test_model_switches_by_number(monkeypatch):
    persisted = {}
    stub_models(monkeypatch, MODELS, persisted)
    s = session(LLMClient("", "http://localhost:13305/api/v1", "gpt-oss-120b"))
    asyncio.run(s._cmd_model("3"))
    assert s.client.model == "Qwen3-Coder-30B"
    assert s.model == "Qwen3-Coder-30B", "the status line has to follow the client"
    assert persisted == {"model": "Qwen3-Coder-30B"}, "the next launch should use it too"


def test_model_switches_by_name(monkeypatch):
    stub_models(monkeypatch, MODELS, {})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "gpt-oss-120b"))
    asyncio.run(s._cmd_model("Qwen3.6-35B"))
    assert s.client.model == "Qwen3.6-35B"


def test_a_model_the_server_does_not_have_is_refused(monkeypatch):
    """Silently accepting it would leave the session broken until the next request."""
    stub_models(monkeypatch, MODELS, {})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "gpt-oss-120b"))
    asyncio.run(s._cmd_model("gpt-9"))
    assert s.client.model == "gpt-oss-120b"
    assert "not on that server" in s.tui.text


def test_an_unreachable_server_still_allows_setting_a_name_by_hand(monkeypatch):
    stub_models(monkeypatch, [], {})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "old"))
    asyncio.run(s._cmd_model("some-model"))
    assert s.client.model == "some-model"


def test_switching_is_refused_while_a_turn_is_running(monkeypatch):
    """The in-flight turn is holding this client; swapping the model under it would
    change the model mid-conversation."""
    stub_models(monkeypatch, MODELS, {})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "gpt-oss-120b"), busy=True)
    asyncio.run(s._cmd_model("1"))
    assert s.client.model == "gpt-oss-120b"
    assert "a turn is running" in s.tui.text


def test_listing_is_allowed_while_a_turn_is_running(monkeypatch):
    stub_models(monkeypatch, MODELS, {})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "gpt-oss-120b"), busy=True)
    asyncio.run(s._cmd_model(""))
    assert "Qwen3.6-35B" in s.tui.text


def test_model_without_a_client_says_why_rather_than_crashing(monkeypatch):
    stub_models(monkeypatch, MODELS, {})
    s = session(None)
    asyncio.run(s._cmd_model("1"))
    assert "--no-ai" in s.tui.text


def test_provider_with_no_argument_lists_the_presets(monkeypatch):
    stub_models(monkeypatch, MODELS, {})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "m"), provider="lemonade")
    asyncio.run(s._cmd_provider(""))
    for name in PRESETS:
        assert name in s.tui.text
    assert "(current)" in s.tui.text


def test_an_unknown_provider_is_refused(monkeypatch):
    stub_models(monkeypatch, MODELS, {})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "m"))
    asyncio.run(s._cmd_provider("hal9000"))
    assert "unknown provider" in s.tui.text
    assert s.provider == "lemonade"


def test_switching_to_a_local_provider_rebuilds_the_client(monkeypatch):
    persisted = {}
    stub_models(monkeypatch, MODELS, persisted)
    monkeypatch.setattr("pwner.config.load", lambda: {"provider": "lemonade", "api_key": ""})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "m"), provider="lemonade")
    asyncio.run(s._cmd_provider("ollama"))
    assert s.provider == "ollama"
    assert s.client.base_url == PRESETS["ollama"]["base_url"].rstrip("/")
    assert s.client.model == MODELS[0], "the model comes from the new server"
    assert persisted["provider"] == "ollama"


def test_carrying_a_key_to_a_different_hosted_provider_is_called_out(monkeypatch):
    """The saved key belongs to whoever it was saved for. Reusing it silently turns into
    a confusing 401 on the first request."""
    stub_models(monkeypatch, [], {})
    monkeypatch.setattr("pwner.config.load",
                        lambda: {"provider": "openai", "api_key": "sk-openai"})
    s = session(LLMClient("sk-openai", PRESETS["openai"]["base_url"], "gpt-x"),
                provider="openai")
    asyncio.run(s._cmd_provider("anthropic"))
    assert s.provider == "anthropic"
    assert "saved for openai" in s.tui.text
    assert "401" in s.tui.text


def test_a_hosted_provider_with_no_key_leaves_the_session_alone(monkeypatch):
    stub_models(monkeypatch, [], {})
    monkeypatch.setattr("pwner.config.load", lambda: {"provider": "lemonade", "api_key": ""})
    s = session(LLMClient("", "http://localhost:13305/api/v1", "m"), provider="lemonade")
    asyncio.run(s._cmd_provider("openai"))
    assert s.provider == "lemonade", "a failed switch must not half-apply"
    assert s.client.base_url == "http://localhost:13305/api/v1"
    assert "not changed" in s.tui.text


# ── the commands are discoverable ────────────────────────────────────────────

@pytest.mark.parametrize("cmd", ["/model", "/provider"])
def test_the_new_commands_are_in_the_help_and_the_completion_table(cmd):
    from pwner.repl import _COMMANDS, HELP
    assert cmd in _COMMANDS, "autocompletion reads this table"
    assert cmd in HELP


# ── the picker prompt does not mislabel a borrowed key ───────────────────────

def _prompt_with(monkeypatch, saved, answers):
    """Drive _prompt_provider with scripted answers, capturing the prompts it printed."""
    from pwner import cli
    seen: list[str] = []
    it = iter(answers)

    def fake_input(prompt=""):
        seen.append(prompt)
        return next(it, "")

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(cli, "discover_models", lambda *a, **kw: _noop_models())
    out = cli._prompt_provider(saved)
    return out, seen


async def _noop_models():
    return []


def test_switching_provider_says_whose_key_it_is_about_to_reuse(monkeypatch):
    """Found by actually running the picker: the prompt said "(saved)" while switching
    from deepseek to openai, so pressing Enter silently sent the deepseek key to
    OpenAI."""
    saved = {"provider": "deepseek", "api_key": "sk-deepseek"}
    out, prompts = _prompt_with(monkeypatch, saved, ["openai", ""])
    key_prompt = [p for p in prompts if p.startswith("API key")][0]
    assert "saved for deepseek" in key_prompt
    assert out["provider"] == "openai"
    assert out["api_key"] == "sk-deepseek", "it is still reused, just no longer silently"


def test_staying_on_the_same_provider_just_says_saved(monkeypatch):
    saved = {"provider": "deepseek", "api_key": "sk-deepseek"}
    _, prompts = _prompt_with(monkeypatch, saved, ["deepseek", ""])
    key_prompt = [p for p in prompts if p.startswith("API key")][0]
    assert "(saved)" in key_prompt
    assert "saved for" not in key_prompt


def test_with_no_saved_key_the_prompt_explains_the_consequence(monkeypatch):
    _, prompts = _prompt_with(monkeypatch, {}, ["openai", ""])
    key_prompt = [p for p in prompts if p.startswith("API key")][0]
    assert "deterministic" in key_prompt

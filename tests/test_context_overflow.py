"""Recovering from a full context window instead of dying at it.

From a field report against a self-hosted llama.cpp backend: the run crossed the
configured window, the backend returned HTTP 400 with context_length_exceeded, and the
session had no way forward. llama.cpp disables --context-shift by default, which is the
right call for an agent (silent truncation corrupts tool state) but means the harness
owns recovery. These tests pin that recovery: recognise the error, shrink the prompt,
and never resend something that cannot fit.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from pwner.llm import (
    ContextOverflow,
    LLMClient,
    LLMError,
    _as_overflow,
    compact_messages,
    transcript_size,
)

# the body the backend actually returned, verbatim from the report
LLAMA_BODY = json.dumps({"error": {"code": "context_length_exceeded", "details": {
    "backend": "llama-server", "response": {"error": {
        "code": 400,
        "message": ("request (67147 tokens) exceeds the available context size "
                    "(65536 tokens), try increasing it"),
        "n_ctx": 65536, "n_prompt_tokens": 67147,
        "type": "exceed_context_size_error"}}}}})

OPENAI_BODY = json.dumps({"error": {
    "message": ("This model's maximum context length is 128000 tokens. However, your "
                "messages resulted in 130500 tokens. Please reduce the length of the messages."),
    "code": "context_length_exceeded"}})


# ── recognising it ───────────────────────────────────────────────────────────

def test_llama_cpp_overflow_is_recognised_with_both_numbers():
    e = _as_overflow(400, LLAMA_BODY)
    assert isinstance(e, ContextOverflow)
    assert e.n_ctx == 65536
    assert e.n_prompt == 67147


def test_openai_wording_is_recognised_too():
    e = _as_overflow(400, OPENAI_BODY)
    assert isinstance(e, ContextOverflow)


@pytest.mark.parametrize("status,body", [
    (400, '{"error":"unknown model"}'),
    (400, '{"error":"tools is not supported"}'),
    (500, LLAMA_BODY),          # a 500 is not this
    (429, LLAMA_BODY),
])
def test_other_failures_are_not_mistaken_for_overflow(status, body):
    assert _as_overflow(status, body) is None


def test_overflow_is_an_llm_error_so_existing_handlers_still_catch_it():
    assert issubclass(ContextOverflow, LLMError)


# ── compaction ───────────────────────────────────────────────────────────────

def _transcript(n_tools: int, tool_chars: int = 4000) -> list[dict]:
    msgs = [{"role": "system", "content": "SYSTEM PROMPT"},
            {"role": "user", "content": "scan 10.0.0.0/24"}]
    for i in range(n_tools):
        msgs.append({"role": "assistant", "content": f"step {i}"})
        msgs.append({"role": "tool", "tool_call_id": f"c{i}", "content": "x" * tool_chars})
    return msgs


def test_compaction_actually_shrinks_the_transcript():
    msgs = _transcript(12)
    before = transcript_size(msgs)
    after = transcript_size(compact_messages(msgs))
    assert after < before
    assert after * 2 < before, "compaction should be worth doing, not cosmetic"


def test_the_task_and_the_system_prompt_are_never_touched():
    msgs = _transcript(12)
    out = compact_messages(msgs)
    assert out[0] == msgs[0]
    assert out[1] == msgs[1]


def test_recent_turns_survive_intact():
    msgs = _transcript(12)
    out = compact_messages(msgs, keep_recent=6)
    assert out[-6:] == msgs[-6:]


def test_dropped_detail_is_marked_rather_than_silently_lost():
    """A hole the model cannot see is worse than a smaller prompt."""
    out = compact_messages(_transcript(12), keep_recent=4, max_tool_chars=100)
    trimmed = [m for m in out if m.get("role") == "tool" and "dropped" in str(m.get("content"))]
    assert trimmed, "no tool result was trimmed"
    assert "run the tool again" in trimmed[0]["content"]


def test_a_short_transcript_is_returned_unchanged():
    msgs = _transcript(1)
    assert compact_messages(msgs) == msgs


def test_only_tool_output_is_trimmed():
    msgs = [{"role": "system", "content": "S"}, {"role": "user", "content": "task"}]
    msgs += [{"role": "assistant", "content": "y" * 5000} for _ in range(10)]
    out = compact_messages(msgs, keep_recent=2, max_tool_chars=50)
    assert all(len(m["content"]) == 5000 for m in out[2:] if m["role"] == "assistant")


# ── the loop recovers ────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = payload if isinstance(payload, str) else json.dumps(payload)

    def json(self):
        return self._payload if isinstance(self._payload, dict) else json.loads(self._payload)


def _client_that_overflows_until(threshold: int, seen: list):
    """A backend that 400s while the prompt is bigger than `threshold` characters."""
    class _C:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, headers=None, json=None):          # noqa: A002
            size = transcript_size(json["messages"])
            seen.append(size)
            if size > threshold:
                return _FakeResponse(400, LLAMA_BODY)
            return _FakeResponse(200, {"choices": [{"message": {
                "role": "assistant", "content": "done", "tool_calls": []}}]})
    return lambda **kw: _C()


def test_the_loop_compacts_and_succeeds(monkeypatch):
    seen: list = []
    monkeypatch.setattr("httpx.AsyncClient", _client_that_overflows_until(20000, seen))
    client = LLMClient("k", "https://api.example.com/v1", "m")
    messages = _transcript(12)
    out = asyncio.run(client.run_turn(messages, tools=[], dispatch={}, max_steps=1))
    assert out is not None
    assert len(seen) >= 2, "it should have retried"
    assert seen[-1] < seen[0], "the retry must be smaller than the attempt that failed"


def test_an_unshrinkable_prompt_raises_rather_than_looping(monkeypatch):
    seen: list = []
    # nothing will ever be small enough
    monkeypatch.setattr("httpx.AsyncClient", _client_that_overflows_until(1, seen))
    client = LLMClient("k", "https://api.example.com/v1", "m")
    with pytest.raises(ContextOverflow) as err:
        asyncio.run(client.run_turn(_transcript(12), tools=[], dispatch={}, max_steps=1))
    assert "will not fit" in str(err.value)
    assert len(seen) < 10, "it must give up, not retry forever"


def test_every_retry_is_strictly_smaller(monkeypatch):
    seen: list = []
    monkeypatch.setattr("httpx.AsyncClient", _client_that_overflows_until(1, seen))
    client = LLMClient("k", "https://api.example.com/v1", "m")
    with pytest.raises(ContextOverflow):
        asyncio.run(client.run_turn(_transcript(12), tools=[], dispatch={}, max_steps=1))
    assert seen == sorted(seen, reverse=True), f"prompt sizes did not shrink monotonically: {seen}"
    assert len(set(seen)) == len(seen), "a prompt was resent at the same size"

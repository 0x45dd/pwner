"""Tool calls in one assistant message run at once, without breaking the history.

A model that asks for four port scans in one message means them to happen together. They
used to run strictly in sequence, so the batch cost the sum of its parts and a deep scan
spent its wall clock waiting rather than thinking.

The invariant that makes this delicate is not speed, it is the conversation: **every
tool_call in an assistant message must get exactly one matching tool response, in order**,
or the provider rejects the next request with a 400. Concurrency puts three things at risk
and each is tested here:

  * ordering — responses must follow the tool_calls, not completion order
  * cancellation — a turn killed mid-batch must still answer every id
  * the operator's terminal — two tools asking for consent at the same moment would print
    over each other and race for one line of stdin, so prompts serialize on a lock

The last one is a correctness fix that was needed the moment anything ran concurrently, and
it is why `_ask_consent` re-checks for a remembered approval after taking the lock.
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from pwner.llm import LLMClient
from pwner.tools import ScanContext, _ask_consent, _consent


class FakeClient(LLMClient):
    def __init__(self, script):
        super().__init__("k", "http://localhost:0/v1", "m")
        self.script = list(script)

    async def _post(self, payload):
        turn = self.script.pop(0) if self.script else {"content": "done"}
        msg = {"role": "assistant", "content": turn.get("content")}
        if turn.get("tool_calls"):
            msg["tool_calls"] = [
                {"id": f"c{i}", "type": "function",
                 "function": {"name": n, "arguments": json.dumps(a)}}
                for i, (n, a) in enumerate(turn["tool_calls"])
            ]
        return {"choices": [{"message": msg}]}


def run(client, dispatch, script_calls, **kw):
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    client.script = [{"tool_calls": script_calls}, {"content": "done"}]
    text = asyncio.run(client.run_turn(msgs, [], dispatch, **kw))
    return text, msgs


def tool_responses(msgs):
    return [m for m in msgs if m.get("role") == "tool"]


# ── it is actually concurrent ────────────────────────────────────────────────

def test_a_batch_runs_concurrently_rather_than_end_to_end():
    """Four 100ms sleeps finish in about 100ms, not 400."""
    async def slow(_args):
        await asyncio.sleep(0.1)
        return {"ok": True}

    client = FakeClient([])
    started = time.monotonic()
    run(client, {"slow": slow}, [("slow", {"i": i}) for i in range(4)])
    elapsed = time.monotonic() - started
    assert elapsed < 0.3, f"took {elapsed:.2f}s — the batch is still serialized"


def test_a_single_call_still_takes_the_simple_path():
    async def one(_args):
        return {"ok": 1}

    _, msgs = run(FakeClient([]), {"one": one}, [("one", {})])
    assert len(tool_responses(msgs)) == 1


# ── the history stays valid, which is the part a 400 punishes ────────────────

def test_every_tool_call_gets_exactly_one_response():
    async def ok(_args):
        return {"ok": True}

    _, msgs = run(FakeClient([]), {"ok": ok}, [("ok", {"i": i}) for i in range(5)])
    ids = [m["tool_call_id"] for m in tool_responses(msgs)]
    assert ids == ["c0", "c1", "c2", "c3", "c4"]
    assert len(ids) == len(set(ids))


def test_responses_follow_the_tool_calls_not_the_finishing_order():
    """The slowest call is first in the batch. Its response must still be first."""
    async def slow(_args):
        await asyncio.sleep(0.05)
        return {"which": "slow"}

    async def fast(_args):
        return {"which": "fast"}

    _, msgs = run(FakeClient([]), {"slow": slow, "fast": fast},
                  [("slow", {}), ("fast", {}), ("fast", {})])
    order = [json.loads(m["content"])["which"] for m in tool_responses(msgs)]
    assert order == ["slow", "fast", "fast"]


def test_one_tool_raising_does_not_lose_the_others_responses():
    async def boom(_args):
        raise RuntimeError("nope")

    async def ok(_args):
        return {"ok": True}

    _, msgs = run(FakeClient([]), {"boom": boom, "ok": ok},
                  [("ok", {}), ("boom", {}), ("ok", {})])
    bodies = [json.loads(m["content"]) for m in tool_responses(msgs)]
    assert len(bodies) == 3
    assert "error" in bodies[1] and "nope" in bodies[1]["error"]


def test_an_unknown_tool_name_in_a_batch_fails_closed_without_taking_the_batch_down():
    async def ok(_args):
        return {"ok": True}

    _, msgs = run(FakeClient([]), {"ok": ok}, [("ok", {}), ("ghost", {})])
    bodies = [json.loads(m["content"]) for m in tool_responses(msgs)]
    assert bodies[0] == {"ok": True}
    assert "unknown tool ghost" in bodies[1]["error"]


def test_bad_json_arguments_are_answered_rather_than_executed():
    calls: list[dict] = []

    async def ok(args):
        calls.append(args)
        return {"ok": True}

    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    client = FakeClient([])

    async def post(_payload):
        if client.script:
            return {"choices": [{"message": {"role": "assistant", "content": "done"}}]}
        client.script = [1]
        return {"choices": [{"message": {
            "role": "assistant", "content": None,
            "tool_calls": [
                {"id": "c0", "type": "function",
                 "function": {"name": "ok", "arguments": "{not json"}},
                {"id": "c1", "type": "function",
                 "function": {"name": "ok", "arguments": "{\"real\": 1}"}},
            ]}}]}

    client._post = post  # type: ignore[method-assign]
    asyncio.run(client.run_turn(msgs, [], {"ok": ok}))
    bodies = [json.loads(m["content"]) for m in tool_responses(msgs)]
    assert "not valid JSON" in bodies[0]["error"]
    assert bodies[1] == {"ok": True}
    assert calls == [{"real": 1}], "the malformed call must not reach the tool"


def test_a_cancelled_batch_still_answers_every_id():
    """Otherwise the next request 400s on an unanswered tool_call and the session is dead."""
    async def hangs(_args):
        await asyncio.sleep(10)
        return {"ok": True}

    async def cancels(_args):
        raise asyncio.CancelledError

    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    client = FakeClient([{"tool_calls": [("cancels", {}), ("hangs", {})]}])
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(client.run_turn(msgs, [], {"cancels": cancels, "hangs": hangs}))
    ids = {m["tool_call_id"] for m in tool_responses(msgs)}
    assert ids == {"c0", "c1"}, "a tool_call was left without a response"


# ── the operator's terminal is a single resource ─────────────────────────────

def test_concurrent_consent_prompts_do_not_interleave():
    """Two tools asking at once would print over each other and race for one line of input.
    With the lock the second waiter finds the first approval already remembered, so the
    operator is asked once — which is the documented session-wide behaviour, reached safely."""
    asked: list[float] = []
    inside = 0
    overlapped = False

    async def prompt(_text):
        nonlocal inside, overlapped
        inside += 1
        if inside > 1:
            overlapped = True
        asked.append(time.monotonic())
        await asyncio.sleep(0.02)
        inside -= 1
        return "y"

    class Ch:
        consent = staticmethod(prompt)

        @staticmethod
        def has_pending():
            return False

    ctx = ScanContext(target="10.0.0.5", interactive=True)
    ctx.operator_channel = Ch()

    async def go():
        return await asyncio.gather(*[
            _consent(ctx, f"action{i}", "10.0.0.5", "high") for i in range(4)])

    out = asyncio.run(go())
    assert all(out), "the approval did not propagate"
    assert not overlapped, "two prompts were open at the same time"
    assert len(asked) == 1, f"the operator was asked {len(asked)} times for one batch"


def test_the_lock_does_not_change_the_non_interactive_answer():
    ctx = ScanContext(target="10.0.0.5", interactive=False)
    assert asyncio.run(_ask_consent(ctx, "a", "t", "high")) is False


def test_the_lock_does_not_change_the_auto_consent_answer():
    ctx = ScanContext(target="10.0.0.5", auto_consent=True)
    assert asyncio.run(_ask_consent(ctx, "a", "t", "high")) is True


def test_a_refusal_inside_the_lock_is_still_a_refusal_for_that_call():
    ctx = ScanContext(target="10.0.0.5", interactive=True)

    class Ch:
        @staticmethod
        async def consent(_text):
            return "n"

    ctx.operator_channel = Ch()
    assert asyncio.run(_consent(ctx, "a", "t", "high")) is False
    assert [r["decision"] for r in ctx.consent_requests] == ["denied"]


def test_the_prompt_lock_survives_separate_event_loops():
    """An asyncio.Lock binds to the loop that first awaits it, and every asyncio.run makes a
    new one. Keying the lock per loop is what stops the second run raising."""
    ctx = ScanContext(target="10.0.0.5", auto_consent=True)
    for _ in range(3):
        assert asyncio.run(_ask_consent(ctx, "a", "t", "high")) is True

    ctx2 = ScanContext(target="10.0.0.5", interactive=True)

    class Ch:
        @staticmethod
        async def consent(_text):
            return "y"

    ctx2.operator_channel = Ch()
    assert asyncio.run(_consent(ctx2, "a", "t", "high")) is True
    assert asyncio.run(_consent(ctx2, "b", "t", "high")) is True

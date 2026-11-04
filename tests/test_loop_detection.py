"""Breaking the agent out of a loop that varies its payload.

From a real run: the agent confirmed command injection on one endpoint, then spent
48 steps and five minutes POSTing to that same endpoint with a slightly different
command each time, learning nothing. None of the three existing guards fired, because
all of them key on the arguments:

  * stall_sig matches only a byte-identical tool-call batch
  * its else-branch resets the counter on any single different step
  * the identical-result nudge keys on (tool, args), so a changing payload gives every
    call a fresh signature that is only ever seen once

The failure mode they all miss is the same tool, against the same place, with a new
payload every time. These tests pin the call-site window that catches it.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from pwner.llm import _SITE_NUDGE, _SITE_STOP, _SITE_WINDOW, LLMClient, _call_site


def _tc(name="web_request", tid="1", **args):
    return {"id": tid, "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


# ── the site signature ───────────────────────────────────────────────────────

def test_payload_does_not_change_the_site():
    """This is the whole point: different command, same place."""
    a = _call_site(_tc(host="php.testsparker.com", port=80, path="/nslookup.php",
                       data={"cmd": "dir"}))
    b = _call_site(_tc(host="php.testsparker.com", port=80, path="/nslookup.php",
                       data={"cmd": "type C:\\\\boot.ini"}))
    assert a == b


def test_a_different_endpoint_is_a_different_site():
    a = _call_site(_tc(host="h", port=80, path="/nslookup.php"))
    b = _call_site(_tc(host="h", port=80, path="/artist.php"))
    assert a != b


def test_a_different_host_is_a_different_site():
    assert _call_site(_tc(host="a", path="/x")) != _call_site(_tc(host="b", path="/x"))


def test_a_different_tool_is_a_different_site():
    assert _call_site(_tc(name="web_request", host="h")) != _call_site(_tc(name="http_probe", host="h"))


@pytest.mark.parametrize("bad", ["", "not json", "[1,2,3]", "null"])
def test_malformed_arguments_do_not_crash_the_signature(bad):
    tc = {"id": "1", "function": {"name": "web_request", "arguments": bad}}
    assert _call_site(tc).startswith("web_request|")


# ── the loop is caught end to end ────────────────────────────────────────────

class _Resp:
    def __init__(self, payload):
        self.status_code = 200
        self._p = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._p


def _looping_backend(seen: list, name="web_request"):
    """A model that hits one endpoint forever, with a new payload each time."""
    class _C:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, headers=None, json=None):          # noqa: A002
            msgs = json["messages"]
            seen.append(msgs[-1])
            n = len(seen)
            return _Resp({"choices": [{"message": {
                "role": "assistant", "content": "trying another command",
                "tool_calls": [{"id": f"c{n}", "type": "function", "function": {
                    "name": name,
                    # same host and path every time; only the payload moves
                    "arguments": __import__("json").dumps(
                        {"host": "php.testsparker.com", "port": 80,
                         "path": "/nslookup.php", "data": {"cmd": f"cmd-{n}"}})}}]}}]})
    return lambda **kw: _C()


def _run(monkeypatch, name="web_request", max_steps=60):
    seen: list = []
    monkeypatch.setattr("httpx.AsyncClient", _looping_backend(seen, name))
    client = LLMClient("k", "https://api.example.com/v1", "m")

    async def tool(args):
        # a result that differs slightly every time, so the identical-result nudge
        # never fires either — exactly what the real endpoint did
        tool.n += 1
        return {"status": 200, "len": 8340, "body": f"Volume in drive C has {tool.n}"}
    tool.n = 0

    messages = [{"role": "system", "content": "S"}, {"role": "user", "content": "test it"}]
    out = asyncio.run(client.run_turn(messages, tools=[], dispatch={name: tool},
                                      max_steps=max_steps))
    return out, messages


def test_the_varying_payload_loop_is_eventually_stopped(monkeypatch):
    out, _ = _run(monkeypatch)
    assert "stopped" in out.lower()
    assert "without progress" in out.lower()


def test_the_model_is_warned_before_it_is_stopped(monkeypatch):
    """A nudge first: the run should get a chance to recover rather than just dying."""
    _, messages = _run(monkeypatch)
    notes = [m for m in messages
             if m.get("role") == "user" and "[SYSTEM NOTE]" in str(m.get("content"))]
    assert notes, "the agent was stopped without ever being told it was looping"
    assert "materially different" in notes[0]["content"]


def test_it_stops_within_a_bounded_number_of_steps(monkeypatch):
    """48 steps of this was the actual complaint."""
    _, messages = _run(monkeypatch)
    calls = [m for m in messages if m.get("role") == "tool"]
    assert len(calls) <= _SITE_STOP + _SITE_WINDOW, f"took {len(calls)} tool calls to notice"


def test_thresholds_are_ordered_sensibly():
    assert _SITE_NUDGE < _SITE_STOP <= _SITE_WINDOW


# ── tools whose job is to be polled are left alone ───────────────────────────

@pytest.mark.parametrize("name", ["listener", "exfil", "get_findings"])
def test_pollable_tools_are_not_treated_as_a_loop(monkeypatch, name):
    """Waiting on a reverse shell means calling the same thing repeatedly on purpose."""
    out, messages = _run(monkeypatch, name=name, max_steps=_SITE_STOP + _SITE_WINDOW + 5)
    assert "without progress" not in out.lower()
    assert not [m for m in messages
                if m.get("role") == "user" and "looping" in str(m.get("content"))]

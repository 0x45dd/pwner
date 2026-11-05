"""The loop's only mechanism that argues for more work instead of less.

Every other guard in `run_turn` exists to stop a stuck agent: the identical-batch counter,
the identical-result counter, the call-site window. Nothing balanced them, so the cheapest
way for a model to end a run was to stop calling tools — and the loop agreed, however much
it had left open. A scan that stopped early and a scan that finished looked identical from
the outside.

So the termination boundary now asks. When the model emits no tool calls, `open_work` gets
to report what the ledger still has outstanding and that text comes back as one more user
turn. Three properties matter and each has tests below:

  * it reports STATE, never an instruction — the agent decides what an open hypothesis is
    worth, and "not worth chasing" is a legitimate answer
  * it is capped, so an agent that answers by stopping again is allowed to stop
  * it never breaks a run: a raising or empty `open_work` is the same as no `open_work`

The other half is reasoning budget. A tool that found something says so in its result
(`significance: "high"`), because the tool is holding the evidence and the loop is not; the
loop converts that into one notch more effort for the next few steps and knows nothing about
which tools set it or why.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from pwner.llm import LLMClient
from pwner.tools import (
    EFFORT_LEVELS,
    ScanContext,
    effort_boost,
    ledger,
    open_hypotheses,
    open_work_report,
    untested_surface,
)

# ── a fake provider: scripted assistant turns, so the loop is the only thing under test ──

class FakeClient(LLMClient):
    """An LLMClient whose _post replays a script instead of calling a provider."""

    def __init__(self, script):
        super().__init__("k", "http://localhost:0/v1", "m")
        self.script = list(script)
        self.payloads: list[dict] = []

    async def _post(self, payload):
        self.payloads.append(json.loads(json.dumps(payload, default=str)))
        turn = self.script.pop(0) if self.script else {"content": "done"}
        if callable(turn):
            turn = turn(payload)
        msg = {"role": "assistant", "content": turn.get("content")}
        if turn.get("tool_calls"):
            msg["tool_calls"] = [
                {"id": f"c{i}", "type": "function",
                 "function": {"name": n, "arguments": json.dumps(a)}}
                for i, (n, a) in enumerate(turn["tool_calls"])
            ]
        return {"choices": [{"message": msg}]}


def run(client, dispatch, **kw):
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    text = asyncio.run(client.run_turn(msgs, [], dispatch, **kw))
    return text, msgs


def ctx_with(hypotheses=(), surface=(), tried=()) -> ScanContext:
    c = ScanContext(target="10.0.0.5")
    asyncio.run(ledger(c, {"action": "update", "data": {
        "hypotheses": list(hypotheses), "surface": list(surface), "tried": list(tried)}}))
    return c


# ── the termination boundary ─────────────────────────────────────────────────

def test_a_run_with_open_work_does_not_end_on_the_first_silence():
    """The whole point: the model stopped, the ledger had not.

    `open_work` goes quiet on the second call, which is the real shape of this — the agent
    resolves the hypothesis and there is nothing left to report."""
    pending = ["[ENGAGEMENT STATE] one hypothesis open"]
    client = FakeClient([{"content": "all done"}, {"content": "actually, checked it"}])
    text, msgs = run(client, {}, open_work=lambda: pending.pop(0) if pending else None)
    assert text == "actually, checked it"
    assert any(m.get("role") == "user" and "ENGAGEMENT STATE" in str(m.get("content"))
               for m in msgs), "the open-work report never reached the model"


def test_nothing_open_means_the_run_ends_immediately():
    client = FakeClient([{"content": "all done"}])
    text, msgs = run(client, {}, open_work=lambda: None)
    assert text == "all done"
    assert sum(1 for m in msgs if m.get("role") == "user") == 1


def test_no_open_work_callback_is_the_old_behaviour():
    client = FakeClient([{"content": "all done"}])
    assert run(client, {})[0] == "all done"


def test_the_agent_is_allowed_to_stop_anyway():
    """It is a question, not a gate. An agent that answers by stopping again stops, and the
    cap is what guarantees that — otherwise a hypothesis it has judged not worth chasing
    would hold the run open forever."""
    client = FakeClient([{"content": "done"}] * 6)
    text, msgs = run(client, {}, open_work=lambda: "still open", open_work_limit=2)
    assert text == "done"
    assert sum(1 for m in msgs if m.get("content") == "still open") == 2


def test_the_cap_is_configurable_and_zero_disables_it():
    client = FakeClient([{"content": "done"}] * 4)
    _, msgs = run(client, {}, open_work=lambda: "still open", open_work_limit=0)
    assert not any(m.get("content") == "still open" for m in msgs)


def test_a_raising_open_work_never_breaks_the_run():
    """Bookkeeping must not be able to end an engagement."""
    def boom():
        raise RuntimeError("ledger is a mess")

    client = FakeClient([{"content": "done"}])
    assert run(client, {}, open_work=boom)[0] == "done"


def test_the_report_is_a_user_turn_not_a_tool_result():
    """A synthetic tool response would need a tool_call_id to answer, and there is no call
    to answer: the model emitted none. Providers reject a tool message without one."""
    client = FakeClient([{"content": "done"}, {"content": "ok"}])
    _, msgs = run(client, {}, open_work=lambda: "open stuff")
    injected = [m for m in msgs if m.get("content") == "open stuff"]
    assert injected and injected[0]["role"] == "user"
    assert "tool_call_id" not in injected[0]


# ── what the report actually says ────────────────────────────────────────────

def test_the_report_names_the_hypothesis_and_its_id():
    c = ctx_with(hypotheses=[{"statement": "SMB signing is off", "test": "run smb_enum"}])
    text = open_work_report(c)
    assert "SMB signing is off" in text
    assert "[h1]" in text
    assert "run smb_enum" in text, "the agent's own plan for testing it is the useful part"


def test_the_report_offers_declining_as_an_outcome():
    """Without this it reads as an order, and an agent that cannot say "not worth it" will
    invent work to satisfy it."""
    c = ctx_with(hypotheses=["something"])
    assert "not worth chasing" in open_work_report(c)


def test_the_report_names_no_tool_and_prescribes_no_action():
    """State, not a playbook. The moment this sentence says which tool to reach for it has
    become a hardcoded methodology living in the wrong place."""
    c = ctx_with(hypotheses=["idle rpc port"], surface=["445/tcp smb"])
    text = open_work_report(c).lower()
    for banned in ("you should", "next, run", "nmap", "nuclei", "netexec", "hydra"):
        assert banned not in text, f"the report is prescribing: {banned!r}"


def test_a_resolved_hypothesis_drops_out_of_the_report():
    c = ctx_with(hypotheses=[{"statement": "SMB signing is off"}])
    assert open_work_report(c) is not None
    asyncio.run(ledger(c, {"action": "resolve", "id": "h1", "status": "refuted",
                           "note": "signing required"}))
    assert open_work_report(c) is None


def test_an_empty_ledger_reports_nothing():
    assert open_work_report(ScanContext(target="10.0.0.5")) is None


def test_surface_nobody_tried_is_reported():
    c = ctx_with(surface=["445/tcp smb", "3389/tcp rdp"], tried=["smb_enum on 445/tcp smb"])
    text = open_work_report(c)
    assert "3389/tcp rdp" in text
    assert "445/tcp smb" not in text.split("not mentioned")[-1]


def test_a_long_report_is_truncated_rather_than_flooding_the_context():
    c = ctx_with(hypotheses=[f"hypothesis {i}" for i in range(40)])
    text = open_work_report(c)
    assert "and 30 more" in text
    assert text.count("hypothesis") <= 14


# ── hypotheses as records ────────────────────────────────────────────────────

def test_a_bare_sentence_is_promoted_to_a_record():
    """Strings stay accepted on purpose: refusing them would make the agent stop recording
    the half-formed suspicions that are worth the most."""
    c = ctx_with(hypotheses=["maybe the DC allows unsigned LDAP"])
    h = (c.ledger or {})["hypotheses"][0]
    assert h["statement"] == "maybe the DC allows unsigned LDAP"
    assert h["status"] == "open"
    assert h["id"] == "h1"


def test_a_full_record_is_kept_as_given():
    c = ctx_with(hypotheses=[{"statement": "s", "evidence": "e", "test": "t",
                             "status": "testing"}])
    h = (c.ledger or {})["hypotheses"][0]
    assert (h["evidence"], h["test"], h["status"]) == ("e", "t", "testing")


def test_hypotheses_get_distinct_ids():
    c = ctx_with(hypotheses=["one", "two", "three"])
    ids = [h["id"] for h in (c.ledger or {})["hypotheses"]]
    assert len(set(ids)) == 3


def test_a_reused_id_does_not_overwrite_the_earlier_hypothesis():
    c = ctx_with(hypotheses=[{"id": "h1", "statement": "first"}])
    asyncio.run(ledger(c, {"action": "update",
                           "data": {"hypotheses": [{"id": "h1", "statement": "second"}]}}))
    hyp = (c.ledger or {})["hypotheses"]
    assert len(hyp) == 2
    assert len({h["id"] for h in hyp}) == 2
    assert [h["statement"] for h in hyp] == ["first", "second"]


def test_the_same_statement_twice_is_one_hypothesis():
    c = ctx_with(hypotheses=["dup"])
    asyncio.run(ledger(c, {"action": "update", "data": {"hypotheses": ["dup", "DUP"]}}))
    assert len((c.ledger or {})["hypotheses"]) == 1


def test_an_unknown_status_falls_back_to_open_rather_than_vanishing():
    c = ctx_with(hypotheses=[{"statement": "s", "status": "mostly sure"}])
    assert (c.ledger or {})["hypotheses"][0]["status"] == "open"


def test_a_blank_statement_is_dropped():
    c = ctx_with(hypotheses=[{"statement": "   "}, "real one"])
    assert [h["statement"] for h in (c.ledger or {})["hypotheses"]] == ["real one"]


@pytest.mark.parametrize("status", ["open", "testing", "confirmed", "refuted"])
def test_resolve_accepts_every_declared_status(status):
    c = ctx_with(hypotheses=["s"])
    out = asyncio.run(ledger(c, {"action": "resolve", "id": "h1", "status": status}))
    assert out["resolved"]["status"] == status


def test_resolve_rejects_a_status_outside_the_enum():
    c = ctx_with(hypotheses=["s"])
    assert "error" in asyncio.run(
        ledger(c, {"action": "resolve", "id": "h1", "status": "done-ish"}))


def test_resolve_on_an_unknown_id_lists_the_real_ids():
    """A model that guessed an id gets the answer rather than a dead end."""
    c = ctx_with(hypotheses=["s"])
    out = asyncio.run(ledger(c, {"action": "resolve", "id": "h99", "status": "confirmed"}))
    assert "error" in out and out["ids"] == ["h1"]


def test_resolve_needs_an_id():
    c = ctx_with(hypotheses=["s"])
    assert "error" in asyncio.run(ledger(c, {"action": "resolve", "status": "confirmed"}))


def test_open_hypotheses_counts_testing_as_still_open():
    c = ctx_with(hypotheses=[{"statement": "a", "status": "testing"},
                             {"statement": "b", "status": "confirmed"},
                             {"statement": "c", "status": "open"}])
    assert {h["statement"] for h in open_hypotheses(c)} == {"a", "c"}


def test_show_reports_the_open_count_so_it_is_visible_without_counting():
    c = ctx_with(hypotheses=["a", "b"])
    assert asyncio.run(ledger(c, {"action": "show"}))["open_hypotheses"] == 2


# ── the ledger stays queryable as it grows ───────────────────────────────────

def test_show_can_filter_by_status():
    c = ctx_with(hypotheses=[{"statement": "a", "status": "confirmed"}, "b"])
    out = asyncio.run(ledger(c, {"action": "show", "filter": {"status": "open"}}))
    assert [h["statement"] for h in out["ledger"]["hypotheses"]] == ["b"]


def test_show_can_filter_by_text_across_the_whole_ledger():
    """Depth usually comes from joining two observations made twenty steps apart, and the
    only join mechanism used to be the context window — which compaction truncates."""
    c = ctx_with(hypotheses=["smb signing", "rdp nla"], surface=["445/tcp smb", "3389/tcp rdp"])
    out = asyncio.run(ledger(c, {"action": "show", "filter": {"match": "smb"}}))
    assert [h["statement"] for h in out["ledger"]["hypotheses"]] == ["smb signing"]
    assert out["ledger"]["surface"] == ["445/tcp smb"]


def test_an_unfiltered_show_returns_everything():
    c = ctx_with(hypotheses=["a"], surface=["s"], tried=["t"])
    out = asyncio.run(ledger(c, {"action": "show"}))["ledger"]
    assert len(out["hypotheses"]) == 1 and out["surface"] == ["s"] and out["tried"] == ["t"]


def test_filtering_does_not_mutate_the_stored_ledger():
    c = ctx_with(hypotheses=["smb", "rdp"])
    asyncio.run(ledger(c, {"action": "show", "filter": {"status": "confirmed"}}))
    assert len((c.ledger or {})["hypotheses"]) == 2, "the filter ate the ledger"


def test_update_still_appends_and_dedupes_the_free_lists():
    c = ctx_with(surface=["a"])
    asyncio.run(ledger(c, {"action": "update", "data": {"surface": ["a", "b"]}}))
    assert (c.ledger or {})["surface"] == ["a", "b"]


def test_clear_empties_every_field():
    c = ctx_with(hypotheses=["a"], surface=["s"])
    out = asyncio.run(ledger(c, {"action": "clear"}))["ledger"]
    assert out == {"surface": [], "creds": [], "hypotheses": [], "tried": [], "facts": []}


def test_update_rejects_a_non_object_payload():
    c = ScanContext(target="10.0.0.5")
    assert "error" in asyncio.run(ledger(c, {"action": "update", "data": ["not", "a", "dict"]}))


def test_untested_surface_is_empty_when_everything_was_tried():
    c = ctx_with(surface=["445/tcp"], tried=["hit 445/tcp with smb_enum"])
    assert untested_surface(c) == []


# ── reasoning budget ─────────────────────────────────────────────────────────

def test_the_effort_ladder_goes_up_one_notch_and_stops_at_the_top():
    assert effort_boost("low") == "medium"
    assert effort_boost("medium") == "high"
    assert effort_boost("high") == "high"


def test_an_unset_effort_boosts_to_medium_rather_than_to_nothing():
    """Unset has to stay the default — a model that does not know the parameter answers 400
    to it — but once a tool has reported a real signal the deliberation is worth it."""
    assert effort_boost("") == "medium"
    assert effort_boost("nonsense") == "medium"
    assert all(lvl in EFFORT_LEVELS for lvl in ("low", "medium", "high"))


def test_a_significant_tool_result_raises_the_effort_for_the_next_steps():
    async def loud(_args):
        return {"significance": "high", "interesting": ["something"]}

    client = FakeClient([
        {"tool_calls": [("probe", {})]},
        {"tool_calls": [("probe2", {})]},
        {"content": "done"},
    ])
    run(client, {"probe": loud, "probe2": loud},
        reasoning_effort="low", effort_boost="high", effort_boost_steps=3)
    efforts = [p.get("reasoning_effort") for p in client.payloads]
    assert efforts[0] == "low", "the first request is before any tool has run"
    assert efforts[1] == "high", "the significant result did not raise the budget"


def test_an_unremarkable_result_leaves_the_effort_alone():
    async def quiet(_args):
        return {"significance": "low"}

    client = FakeClient([{"tool_calls": [("probe", {})]}, {"content": "done"}])
    run(client, {"probe": quiet}, reasoning_effort="low", effort_boost="high")
    assert [p.get("reasoning_effort") for p in client.payloads] == ["low", "low"]


def test_the_boost_expires_instead_of_lasting_the_whole_run():
    async def loud(_args):
        return {"significance": "high"}

    async def quiet(_args):
        return {"significance": "low"}

    client = FakeClient([
        {"tool_calls": [("loud", {})]},
        {"tool_calls": [("quiet", {})]},
        {"tool_calls": [("quiet", {})]},
        {"content": "done"},
    ])
    run(client, {"loud": loud, "quiet": quiet},
        reasoning_effort="low", effort_boost="high", effort_boost_steps=1)
    efforts = [p.get("reasoning_effort") for p in client.payloads]
    assert efforts[1] == "high"
    assert efforts[-1] == "low", "the boost never came back down"


def test_no_effort_is_sent_at_all_when_none_is_configured():
    """The default. A non-reasoning model 400s on an unknown parameter, so silence is the
    only safe thing to send."""
    async def loud(_args):
        return {"significance": "high"}

    client = FakeClient([{"tool_calls": [("probe", {})]}, {"content": "done"}])
    run(client, {"probe": loud})
    assert all("reasoning_effort" not in p for p in client.payloads)


def test_open_work_also_raises_the_budget_for_the_answer():
    """The agent is being asked to reconsider; thinking harder is the point of asking."""
    client = FakeClient([{"content": "done"}, {"content": "ok"}])
    run(client, {}, open_work=lambda: "open stuff",
        reasoning_effort="low", effort_boost="high", effort_boost_steps=2)
    assert client.payloads[1].get("reasoning_effort") == "high"


def test_a_significance_value_other_than_high_is_ignored():
    """Only an explicit "high" counts, so a tool returning a stray string cannot quietly
    triple the bill for the rest of the run."""
    async def odd(_args):
        return {"significance": "quite interesting really"}

    client = FakeClient([{"tool_calls": [("probe", {})]}, {"content": "done"}])
    run(client, {"probe": odd}, reasoning_effort="low", effort_boost="high")
    assert [p.get("reasoning_effort") for p in client.payloads] == ["low", "low"]


def test_a_non_dict_tool_result_does_not_crash_the_significance_check():
    async def weird(_args):
        return "just a string"

    client = FakeClient([{"tool_calls": [("probe", {})]}, {"content": "done"}])
    assert run(client, {"probe": weird}, effort_boost="high")[0] == "done"

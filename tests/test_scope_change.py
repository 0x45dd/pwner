"""The one hole the scope lock could not cover: the agent widening its own scope.

Every tool call is checked against the operator's target by the dispatch wrapper, which
is why `set_target` has to be scope-exempt: its argument IS the new scope, so there is
nothing to check it against. That left a path the guard could not see, and the refusal
message pointed straight at it — "Only the operator can widen scope, ask them, then
set_target". A model read that as an instruction, and was observed live doing exactly
this: refused on a host outside scope, then calling set_target on that host and scanning
it. The published claim that the agent cannot widen its own authorization was false.

The fix is an approval that is specifically about scope:

  * moving inside the current scope, or back to something the operator already
    authorized, needs nothing — narrowing reduces authority
  * going anywhere else needs the operator's answer, every time
  * a remembered consent for some other action does not buy it, because `_consent`
    treats one approval as blanket consent and that must never reach the scope
  * `--auto-consent` does not buy it either: it approves high-impact actions inside the
    scope, not a new scope
  * a non-interactive run cannot ask, so the answer there is no
"""
from __future__ import annotations

import asyncio

import pytest

from pwner.tools import ScanContext, ToolError, build_dispatch, set_target
from pwner.tools.core import _covered_by, _within_authorized_scope


def ctx(target="10.0.0.99", **kw) -> ScanContext:
    return ScanContext(target=target, **kw)


def change(c: ScanContext, target: str):
    return asyncio.run(set_target(c, {"target": target}))


# ── the coverage arithmetic the decision rests on ────────────────────────────

@pytest.mark.parametrize("new,scope", [
    ("10.0.0.5", "10.0.0.0/24"),
    ("10.0.0.0/25", "10.0.0.0/24"),
    ("10.0.0.0/24", "10.0.0.0/24"),
    ("10.0.0.5", "10.0.0.5"),
    ("10.0.0.5,10.0.0.6", "10.0.0.0/24"),
    ("example.com", "example.com"),
    ("10.0.0.5", "10.0.0.0/24,192.168.0.0/16"),
])
def test_these_are_already_covered(new, scope):
    assert _covered_by(new, scope) is True


@pytest.mark.parametrize("new,scope", [
    ("10.0.0.0/16", "10.0.0.0/24"),          # the classic widening
    ("10.0.1.5", "10.0.0.0/24"),             # neighbour network
    ("8.8.8.8", "10.0.0.0/24"),
    ("10.0.0.5,8.8.8.8", "10.0.0.0/24"),     # one covered host does not carry the other
    ("evil.example.com", "example.com"),     # a name is not a parent of a subdomain
    ("10.0.0.5", ""),                        # nothing authorized covers nothing
    ("", "10.0.0.0/24"),
])
def test_these_are_not(new, scope):
    assert _covered_by(new, scope) is False


def test_a_domain_is_never_resolved_to_decide_authorization():
    """Resolving a name here would hand scope control to whoever controls DNS: point a
    hostname at an address inside the scope and the check would wave it through."""
    assert _covered_by("localhost", "127.0.0.0/8") is False


# ── the attack, end to end ───────────────────────────────────────────────────

def test_the_agent_cannot_widen_its_own_scope():
    """The live observation, reproduced: refused on a host, then set_target on it."""
    c = ctx(target="10.0.0.99")
    d = build_dispatch(c)
    with pytest.raises(ToolError, match="outside the authorized"):
        asyncio.run(d["port_scan"]({"target": "10.0.0.5"}))
    with pytest.raises(ToolError, match="did not approve a scope change"):
        change(c, "10.0.0.5")
    assert c.target == "10.0.0.99", "the scope moved anyway"


def test_the_refusal_no_longer_tells_the_model_to_call_set_target():
    """The old message was an instruction for the bypass."""
    c = ctx(target="10.0.0.99")
    d = build_dispatch(c)
    with pytest.raises(ToolError) as e:
        asyncio.run(d["port_scan"]({"target": "10.0.0.5"}))
    msg = str(e.value)
    assert "ask them, then set_target" not in msg
    assert "Only the operator" in msg


def test_a_denial_tells_the_agent_what_to_do_instead_of_retrying():
    """Without this the model just calls set_target again, which is the loop."""
    c = ctx()
    with pytest.raises(ToolError) as e:
        change(c, "8.8.8.8")
    assert "again" in str(e.value) and "wait for the operator" in str(e.value)


def test_a_remembered_approval_for_something_else_does_not_widen_scope():
    """_consent treats one approval as blanket consent for the session. Gating the scope
    on it would mean approving an SSH brute force also authorized a new network."""
    c = ctx()
    c.consent_requests.append({"action": "hydra_brute", "target": "10.0.0.99",
                               "risk": "high", "decision": "approved"})
    with pytest.raises(ToolError, match="did not approve a scope change"):
        change(c, "203.0.113.7")
    assert c.target == "10.0.0.99"


def test_auto_consent_does_not_widen_scope():
    """--auto-consent approves high-impact actions inside the scope. A different network
    is not a harder action, it is a different victim."""
    c = ctx(auto_consent=True)
    with pytest.raises(ToolError, match="did not approve a scope change"):
        change(c, "203.0.113.7")
    assert c.target == "10.0.0.99"


def test_a_non_interactive_run_refuses_rather_than_assuming():
    """Nothing is recorded because nothing was asked: with no operator to answer, the
    gate refuses before it prompts rather than waiting on a prompt nobody will see."""
    c = ctx(interactive=False)
    with pytest.raises(ToolError):
        change(c, "203.0.113.7")
    assert c.scope_requests == []
    assert c.target == "10.0.0.99"


# ── what still has to work ───────────────────────────────────────────────────

def test_establishing_the_first_scope_needs_no_approval():
    """The ordinary path: the operator says "scan 10.0.0.0/24" to a session with no
    target, and the agent sets it. There is no scope yet to protect."""
    c = ctx(target="")
    assert change(c, "10.0.0.0/24")["target"] == "10.0.0.0/24"
    assert c.target == "10.0.0.0/24"


def test_narrowing_is_free():
    c = ctx(target="10.0.0.0/24")
    assert change(c, "10.0.0.5")["target"] == "10.0.0.5"


def test_returning_to_something_already_authorized_is_free():
    """Narrow to one host, then go back. The operator authorized the /24; coming back to
    it is not a widening, and re-prompting for it would train them to say yes."""
    c = ctx(target="")
    change(c, "10.0.0.0/24")
    change(c, "10.0.0.5")
    assert change(c, "10.0.0.0/24")["target"] == "10.0.0.0/24"


def test_widening_past_every_grant_is_still_refused():
    c = ctx(target="")
    change(c, "10.0.0.0/24")
    change(c, "10.0.0.5")
    with pytest.raises(ToolError):
        change(c, "10.0.0.0/16")
    assert c.target == "10.0.0.5"


def test_within_authorized_scope_reads_both_the_target_and_the_grants():
    c = ctx(target="10.0.0.5")
    c.scope_grants.append("192.168.1.0/24")
    assert _within_authorized_scope("10.0.0.5", c) is True
    assert _within_authorized_scope("192.168.1.9", c) is True
    assert _within_authorized_scope("172.16.0.1", c) is False


# ── the interactive answer ───────────────────────────────────────────────────

def test_an_approved_change_moves_the_scope_and_is_recorded(monkeypatch):
    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert change(c, "203.0.113.7")["target"] == "203.0.113.7"
    assert c.target == "203.0.113.7"
    assert [r["decision"] for r in c.scope_requests] == ["approved"]
    assert c.scope_requests[0]["from"] == "10.0.0.99"


def test_a_refused_change_leaves_everything_alone(monkeypatch):
    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    with pytest.raises(ToolError):
        change(c, "203.0.113.7")
    assert c.target == "10.0.0.99"
    assert [r["decision"] for r in c.scope_requests] == ["denied"]


def test_an_approval_is_asked_again_for_a_different_target(monkeypatch):
    """One yes authorizes one scope, not the habit of saying yes."""
    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    change(c, "203.0.113.7")
    asked: list[str] = []

    def record(prompt=""):
        asked.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", record)
    with pytest.raises(ToolError):
        change(c, "198.51.100.1")
    assert asked, "the second target was not put to the operator"
    assert c.target == "203.0.113.7"


def test_the_prompt_says_what_is_being_authorized(monkeypatch):
    asked: list[str] = []

    def record(prompt=""):
        asked.append(prompt)
        return "n"

    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", record)
    with pytest.raises(ToolError):
        change(c, "203.0.113.7")
    text = asked[0]
    assert "SCOPE CHANGE" in text
    assert "10.0.0.99" in text and "203.0.113.7" in text


def test_scope_approvals_do_not_leak_into_the_action_consent_gate(monkeypatch):
    """They are recorded in their own list on purpose. Putting them in consent_requests
    would turn a scope approval into blanket consent for brute force and exploitation,
    which would be a worse hole than the one being closed."""
    from pwner.tools import _consent_granted
    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    change(c, "203.0.113.7")
    assert c.consent_requests == []
    assert _consent_granted(c) is False


def test_set_target_stays_scope_exempt():
    """It has to be: its argument is the new scope, so the central guard has nothing to
    check it against. That is exactly why it carries its own gate."""
    from pwner.tools import scope_exempt_tools
    assert "set_target" in scope_exempt_tools()

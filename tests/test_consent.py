"""Tests for the consent gate — the second half of the safety model.

Scope decides WHERE pwner may act; consent decides WHETHER it may do the destructive
things there. These tests pin down the part that is easy to get wrong: an approval is
remembered, so the rules for granting and retracting it have to be exact.
"""
from __future__ import annotations

import asyncio

import pytest

from pwner.tools import ScanContext, _consent, _consent_granted


def ctx(**kw) -> ScanContext:
    return ScanContext(target="10.0.0.5", **kw)


def ask(c: ScanContext, action: str = "brute-force ftp") -> bool:
    return asyncio.run(_consent(c, action, c.target, "high"))


# ── granting ─────────────────────────────────────────────────────────────────

def test_non_interactive_denies_by_default():
    """Piped/scripted runs must never auto-approve a destructive action."""
    c = ctx()
    assert ask(c) is False
    assert _consent_granted(c) is False


def test_auto_consent_approves_without_prompting():
    c = ctx(auto_consent=True)
    assert ask(c) is True
    assert _consent_granted(c) is True


def test_denial_is_recorded_and_does_not_grant():
    c = ctx()
    ask(c)
    assert [r["decision"] for r in c.consent_requests] == ["denied"]
    assert _consent_granted(c) is False


def test_interactive_approval_is_recorded(monkeypatch):
    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert ask(c) is True
    assert [r["decision"] for r in c.consent_requests] == ["approved"]


@pytest.mark.parametrize("answer", ["n", "", "no", "nope", "x"])
def test_interactive_refusal_denies(monkeypatch, answer):
    """Anything that is not an affirmative must deny — including a bare Enter."""
    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", lambda *a: answer)
    assert ask(c) is False


# ── remembering: approval is session-wide, by design ─────────────────────────

def test_one_approval_covers_later_actions(monkeypatch):
    """Documented behaviour: the first `y` approves the rest of the session, so the
    operator is not re-prompted mid-engagement. Blunt, and the README says so — this
    test is here so narrowing it later is a deliberate, visible change."""
    c = ctx(interactive=True)
    calls = []
    monkeypatch.setattr("builtins.input", lambda *a: (calls.append(1), "y")[1])
    assert ask(c, "brute-force ftp") is True
    assert ask(c, "secretsdump on the DC") is True   # never prompted
    assert ask(c, "exfil to our listener") is True
    assert len(calls) == 1, "operator was prompted more than once"


def test_a_denial_does_not_suppress_the_next_prompt(monkeypatch):
    """Only approvals are remembered; a denial must not stop pwner from asking again."""
    c = ctx(interactive=True)
    answers = iter(["n", "y"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    assert ask(c, "brute-force ftp") is False
    assert ask(c, "brute-force ssh") is True


# ── retracting ───────────────────────────────────────────────────────────────

def test_consent_off_retracts_a_remembered_approval(monkeypatch):
    """`/consent off` logs "high-impact actions will prompt [y/N]" — that message is
    only true if it also clears the remembered approval, which _consent() otherwise
    treats as blanket consent."""
    from pwner.repl import ReplSession

    c = ctx(interactive=True)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert ask(c) is True
    assert _consent_granted(c) is True

    logged: list[str] = []
    session = object.__new__(ReplSession)          # no TUI/LLM needed for one command
    session.ctx = c
    session.tui = type("T", (), {"log": lambda _s, m: logged.append(m)})()
    asyncio.run(ReplSession._command(session, "/consent off"))

    assert _consent_granted(c) is False, "approval survived /consent off"
    assert c.auto_consent is False
    assert "retracted" in " ".join(logged)


def test_consent_on_grants_without_touching_history():
    from pwner.repl import ReplSession

    c = ctx()
    session = object.__new__(ReplSession)
    session.ctx = c
    session.tui = type("T", (), {"log": lambda _s, m: None})()
    asyncio.run(ReplSession._command(session, "/consent on"))
    assert c.auto_consent is True
    assert _consent_granted(c) is True

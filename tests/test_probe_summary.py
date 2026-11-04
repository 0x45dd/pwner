"""Grouping of content_discovery hits by response signature.

Why this exists: a server that answers every path with the same page returns no 404s,
which defeats the only size control the probe had. Every probed path became a "hit", so
the model was handed hundreds of near-identical objects that were both false and, once
repeated per host and port, large enough to exhaust a 64k context window. These tests
pin both halves of the fix — the catch-all gets named, and the payload gets small.
"""
from __future__ import annotations

import json

import pytest

from pwner.tools.web import _CATCH_ALL_MIN_PATHS, summarise_probes


def hits(n, status=200, length=8340, redirect="", start=0):
    return [{"path": f"/p{i}", "status": status, "len": length, "redirect": redirect}
            for i in range(start, start + n)]


# ── catch-all detection ──────────────────────────────────────────────────────

def test_identical_responses_everywhere_are_reported_as_a_catch_all():
    out = summarise_probes(hits(62), tested=62)
    assert "catch_all" in out
    assert out["catch_all"]["paths"] == 62
    assert out["distinct_responses"] == 1
    assert "same page for everything" in out["catch_all"]["note"]


def test_a_catch_all_suppresses_the_per_path_list():
    """This is the part that was blowing the context window."""
    out = summarise_probes(hits(62), tested=62)
    assert "found" not in out, "the full hit list must not be carried when it is all noise"


def test_a_normal_server_keeps_its_full_hit_list():
    found = [{"path": "/", "status": 200, "len": 1200, "redirect": ""},
             {"path": "/admin", "status": 401, "len": 20, "redirect": ""},
             {"path": "/old", "status": 302, "len": 0, "redirect": "/new"}]
    out = summarise_probes(found, tested=62)
    assert "catch_all" not in out
    assert out["found"] == found
    assert out["distinct_responses"] == 3


@pytest.mark.parametrize("n,tested,expect", [
    (_CATCH_ALL_MIN_PATHS - 1, 62, False),   # too few paths to be conclusive
    (_CATCH_ALL_MIN_PATHS, 62, False),       # enough paths, but only 13% of what was probed
    (31, 62, True),                          # half of everything probed: catch-all
    (62, 62, True),
])
def test_catch_all_needs_both_a_count_and_a_share(n, tested, expect):
    out = summarise_probes(hits(n), tested=tested)
    assert ("catch_all" in out) is expect


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_uniform_error_responses_are_not_called_a_catch_all(status):
    """An endpoint that 401s everywhere is a real finding about auth, not a catch-all."""
    out = summarise_probes(hits(62, status=status), tested=62)
    assert "catch_all" not in out


def test_redirect_target_is_part_of_the_signature():
    """Same status and length but different Location is a different response."""
    found = hits(30, status=302, length=0, redirect="/a") + \
            hits(30, status=302, length=0, redirect="/b", start=30)
    out = summarise_probes(found, tested=62)
    assert out["distinct_responses"] == 2
    assert "catch_all" not in out


# ── size, which is the whole point ───────────────────────────────────────────

def test_the_catch_all_payload_is_an_order_of_magnitude_smaller():
    found = hits(62)
    before = len(json.dumps({"tested": 62, "found": found}))
    after = len(json.dumps(summarise_probes(found, tested=62)))
    assert after * 5 < before, f"{after} vs {before} bytes is not a worthwhile reduction"


def test_summary_carries_examples_so_the_model_can_follow_up():
    out = summarise_probes(hits(62), tested=62)
    row = out["responses"][0]
    assert row["paths"] == 62
    assert 0 < len(row["examples"]) <= 5
    assert row["more"] == 62 - len(row["examples"])


def test_a_rare_signature_is_listed_in_full():
    """Two paths sharing a signature is interesting; it should not be summarised away."""
    found = hits(60) + [{"path": "/secret", "status": 200, "len": 55, "redirect": ""}]
    out = summarise_probes(found, tested=62)
    rare = [r for r in out["responses"] if r["len"] == 55][0]
    assert rare["examples"] == ["/secret"]
    assert "more" not in rare


# ── degenerate input ─────────────────────────────────────────────────────────

def test_nothing_found_is_not_an_error():
    out = summarise_probes([], tested=62)
    assert out["tested"] == 62
    assert out["distinct_responses"] == 0
    assert out["responses"] == []
    assert out["found"] == []
    assert "catch_all" not in out


def test_zero_probed_does_not_divide_by_zero():
    assert "catch_all" not in summarise_probes([], tested=0)

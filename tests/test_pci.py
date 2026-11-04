"""PCI DSS segmentation testing and exposure retest.

The thing worth testing here is not that a TCP connect works — it is the judgement the
module makes about what a connect *outcome means for isolation*, which is a different
question from the one a port scan answers. Three outcomes, three meanings:

  * the handshake completes      -> a path exists, isolation has failed
  * nothing comes back           -> the packet was dropped, isolation is evidenced
  * a RST comes back             -> something on the path answered, so isolation is NOT
                                    evidenced; but a TCP connect cannot say whether that
                                    was the host or a firewall rejecting for it

That third case is where tools get it wrong in both directions. Counting it as a pass
manufactures evidence of a boundary that was never demonstrated; counting it as a failure
invents a finding. These tests pin it as inconclusive, and pin that an inconclusive probe
never becomes a filed finding.
"""
from __future__ import annotations

import asyncio
import errno
import json

import pytest

from pwner.tools import ScanContext, ToolError
from pwner.tools.pci import (
    _LIST_CAP,
    _PORT_CAP,
    DEFAULT_CDE_PORTS,
    classify_error,
    parse_ports,
    pci_retest,
    segmentation_test,
    segmentation_verdict,
    summarise_segmentation,
)


def ctx(target="10.0.0.0/24", **kw):
    return ScanContext(target=target, **kw)


def probes(n, state="filtered", port=443, start=0):
    return [{"host": f"10.0.0.{i}", "port": port, "state": state}
            for i in range(start, start + n)]


# ── what one connect outcome means ───────────────────────────────────────────

def test_a_completed_handshake_is_open():
    assert classify_error(None) == "open"


@pytest.mark.parametrize("exc", [asyncio.TimeoutError(), TimeoutError()])
def test_either_kind_of_timeout_is_filtered(exc):
    """Both classes, because they are not the same one on every supported version. On
    3.11+ asyncio.TimeoutError *is* the builtin TimeoutError; on 3.10 it is
    concurrent.futures.TimeoutError while the builtin one — what a socket-level timeout
    raises — is an OSError with no errno. Matching only the asyncio alias classified a
    dropped packet as "error" on 3.10, turning the most common outcome on a working
    boundary into 'inconclusive'. CI caught it on 3.10 after it passed on 3.12."""
    assert classify_error(exc) == "filtered"


def test_a_refused_connection_is_its_own_state_not_a_generic_error():
    """ConnectionRefusedError is an OSError; it must be matched before that branch,
    because 'refused' and 'error' mean opposite things for the verdict."""
    assert classify_error(ConnectionRefusedError()) == "refused"


@pytest.mark.parametrize("err", [errno.EHOSTUNREACH, errno.ENETUNREACH,
                                 errno.EHOSTDOWN, errno.ENETDOWN])
def test_no_route_is_unreachable(err):
    assert classify_error(OSError(err, "no route")) == "unreachable"


def test_an_unrecognised_oserror_is_an_error_not_a_pass():
    """A local failure (out of file descriptors, for instance) must never read as
    'the packet was blocked' — that would turn our own breakage into PCI evidence."""
    assert classify_error(OSError(errno.EMFILE, "too many open files")) == "error"


# ── the verdict, which is the PCI-meaningful part ────────────────────────────

def test_one_reachable_path_fails_the_whole_boundary():
    states = ["filtered"] * 5000 + ["open"]
    assert segmentation_verdict(states) == "not_isolated"


@pytest.mark.parametrize("states", [
    ["filtered"] * 10,
    ["unreachable"] * 10,
    ["filtered", "unreachable", "filtered"],
])
def test_everything_demonstrably_blocked_is_isolated(states):
    assert segmentation_verdict(states) == "isolated"


def test_a_refused_port_is_inconclusive_not_isolated():
    """The case this module exists to get right: a closed port that answers with a RST
    proves a packet reached something, so the boundary was not demonstrated."""
    assert segmentation_verdict(["filtered", "refused"]) == "inconclusive"


def test_a_refused_port_is_also_not_reported_as_a_failure():
    assert segmentation_verdict(["refused"]) != "not_isolated"


def test_open_beats_inconclusive():
    assert segmentation_verdict(["refused", "error", "open"]) == "not_isolated"


def test_nothing_probed_is_inconclusive_rather_than_isolated():
    """An empty run must not read as a clean boundary."""
    assert segmentation_verdict([]) == "inconclusive"


def test_an_unknown_state_defaults_to_inconclusive():
    assert segmentation_verdict(["something_new"]) == "inconclusive"


# ── port parsing ─────────────────────────────────────────────────────────────

def test_no_ports_given_uses_the_default_cde_set():
    assert parse_ports(None) == sorted(DEFAULT_CDE_PORTS)
    assert parse_ports("  ") == sorted(DEFAULT_CDE_PORTS)


def test_a_list_and_a_range_both_parse():
    assert parse_ports("443,22,80") == [22, 80, 443]
    assert parse_ports("20-23") == [20, 21, 22, 23]
    assert parse_ports("22,8000-8002") == [22, 8000, 8001, 8002]


def test_a_backwards_range_is_read_the_way_it_was_meant():
    assert parse_ports("23-20") == [20, 21, 22, 23]


def test_duplicates_collapse():
    assert parse_ports("443,443,443") == [443]


@pytest.mark.parametrize("spec", ["http", "22,abc", "0", "65536", "1-70000", "-"])
def test_nonsense_ports_are_refused(spec):
    with pytest.raises(ToolError):
        parse_ports(spec)


def test_a_full_port_sweep_is_refused_with_a_reason():
    """A segmentation test asks whether a path exists, not what is listening everywhere;
    65535 ports per host is how you turn this into a week-long scan by accident."""
    with pytest.raises(ToolError) as e:
        parse_ports("1-65535")
    assert str(_PORT_CAP) in str(e.value)


# ── the summary, and its size ────────────────────────────────────────────────

def test_the_blocked_bulk_is_counted_not_listed():
    """5000 identical 'blocked' rows is exactly the payload that exhausted a context
    window in the web probe; the boundary working must not cost anything to report."""
    out = summarise_segmentation(probes(5000))
    assert out["counts"]["blocked"] == 5000
    assert out["reachable"] == []
    assert len(json.dumps(out)) < 1000


def test_failures_are_listed_because_each_one_matters():
    out = summarise_segmentation(probes(3, "filtered") + probes(2, "open", start=100))
    assert out["counts"] == {"reachable": 2, "blocked": 3, "inconclusive": 0}
    assert [p["host"] for p in out["reachable"]] == ["10.0.0.100", "10.0.0.101"]


def test_a_flood_of_failures_is_capped_and_says_how_many_were_dropped():
    out = summarise_segmentation(probes(_LIST_CAP + 7, "open"))
    assert len(out["reachable"]) == _LIST_CAP
    assert out["more_reachable"] == 7


def test_inconclusive_probes_are_carried_separately_from_failures():
    out = summarise_segmentation(probes(4, "refused"))
    assert out["counts"] == {"reachable": 0, "blocked": 0, "inconclusive": 4}
    assert len(out["inconclusive"]) == 4
    assert out["verdict"] == "inconclusive"


def test_the_raw_states_are_kept_so_the_reason_survives():
    out = summarise_segmentation(probes(2, "refused") + probes(1, "unreachable", start=50))
    assert out["states"] == {"refused": 2, "unreachable": 1}


# ── the tool end to end ──────────────────────────────────────────────────────

def fake_probe(mapping, default="filtered"):
    """Stand in for the network: (host, port) -> state."""
    async def _p(host, port, timeout):
        return {"host": host, "port": port,
                "state": mapping.get((host, port), default)}
    return _p


def run_seg(monkeypatch, args, mapping=None, c=None, default="filtered"):
    monkeypatch.setattr("pwner.tools.pci._probe", fake_probe(mapping or {}, default))
    monkeypatch.setattr("pwner.tools.pci._source_ip_for", lambda t: "192.168.9.9")
    c = c or ctx()
    return asyncio.run(segmentation_test(c, args)), c


def test_a_holding_boundary_reports_isolated_with_evidence(monkeypatch):
    res, _ = run_seg(monkeypatch, {"cde": "10.0.0.5", "ports": "443"})
    assert res["verdict"] == "isolated"
    assert res["vantage_point"] == "192.168.9.9"
    assert res["tested_at"].endswith("Z")
    assert res["requirement"].startswith("PCI DSS 11.4.5")
    assert res["hosts_tested"] == 1 and res["ports_tested"] == 1


def test_a_reachable_cde_port_fails_and_is_filed_as_a_finding(monkeypatch):
    res, c = run_seg(monkeypatch, {"cde": "10.0.0.5", "ports": "443,3306"},
                     mapping={("10.0.0.5", 3306): "open"})
    assert res["verdict"] == "not_isolated"
    assert res["findings_filed"] == 1
    f = c.findings[0]
    assert (f["host"], f["port"]) == ("10.0.0.5", 3306)
    assert f["severity"] == "high"
    assert "192.168.9.9" in f["evidence"], "the vantage point is the evidence"
    assert "11.4.4" in f["remediation"], "the fix points at the retest requirement"


def test_running_it_twice_does_not_duplicate_the_finding(monkeypatch):
    c = ctx()
    run_seg(monkeypatch, {"cde": "10.0.0.5", "ports": "3306"},
            mapping={("10.0.0.5", 3306): "open"}, c=c)
    res2, _ = run_seg(monkeypatch, {"cde": "10.0.0.5", "ports": "3306"},
                      mapping={("10.0.0.5", 3306): "open"}, c=c)
    assert len(c.findings) == 1
    assert "findings_filed" not in res2


def test_an_inconclusive_probe_never_becomes_a_finding(monkeypatch):
    """Filing a finding off a RST would invent a failure we cannot stand behind."""
    res, c = run_seg(monkeypatch, {"cde": "10.0.0.5", "ports": "443"},
                     default="refused")
    assert res["verdict"] == "inconclusive"
    assert c.findings == []
    assert "firewall reject" in res["inconclusive_note"]


def test_a_clean_run_carries_no_inconclusive_note(monkeypatch):
    res, _ = run_seg(monkeypatch, {"cde": "10.0.0.5", "ports": "443"})
    assert "inconclusive_note" not in res


def test_a_cidr_cde_is_expanded(monkeypatch):
    res, _ = run_seg(monkeypatch, {"cde": "10.0.0.0/29", "ports": "443"})
    assert res["hosts_tested"] == 6
    assert res["probes"] == 6


def test_the_cde_falls_back_to_the_authorized_target(monkeypatch):
    res, _ = run_seg(monkeypatch, {"ports": "443"}, c=ctx(target="10.0.0.7"))
    assert res["cde"] == "10.0.0.7"


# ── the scope boundary still applies ─────────────────────────────────────────

def test_a_cde_outside_the_authorized_scope_is_refused(monkeypatch):
    monkeypatch.setattr("pwner.tools.pci._probe", fake_probe({}))
    with pytest.raises(ToolError, match="outside the authorized scope"):
        asyncio.run(segmentation_test(ctx(target="10.0.0.0/24"), {"cde": "8.8.8.8"}))


def test_a_cde_network_must_sit_entirely_inside_the_authorization(monkeypatch):
    """The CDE is normally a CIDR, and _require_scope cannot judge a network — it resolves
    its argument as a hostname. Without the network-aware check a /24 authorization would
    be widened to a /16 just by naming it as the CDE."""
    monkeypatch.setattr("pwner.tools.pci._probe", fake_probe({}))
    with pytest.raises(ToolError, match="outside the authorized scope"):
        asyncio.run(segmentation_test(ctx(target="10.0.0.0/24"),
                                      {"cde": "10.0.0.0/16", "ports": "443"}))


def test_a_cde_subnet_of_the_authorization_is_allowed(monkeypatch):
    res, _ = run_seg(monkeypatch, {"cde": "10.0.0.0/30", "ports": "443"},
                     c=ctx(target="10.0.0.0/24"))
    assert res["verdict"] == "isolated"


def test_cde_is_one_of_the_centrally_scoped_argument_names():
    """Belt and braces: the body checks it, and so does the dispatch wrapper, so a future
    refactor that drops the body check does not silently open the boundary."""
    from pwner.tools import _SCOPED_ARG_NAMES
    assert "cde" in _SCOPED_ARG_NAMES


def test_retest_cannot_be_used_to_reach_a_host_outside_scope(monkeypatch):
    """`findings` is not a centrally scoped argument name, so without the body's own
    check this tool would be a way around the scope guard."""
    monkeypatch.setattr("pwner.tools.pci._probe", fake_probe({}))
    with pytest.raises(ToolError, match="outside the authorized scope"):
        asyncio.run(pci_retest(ctx(target="10.0.0.0/24"),
                               {"findings": [{"host": "8.8.8.8", "port": 443}]}))


# ── 11.4.4 retest ────────────────────────────────────────────────────────────

def run_retest(monkeypatch, args, mapping=None, c=None, default="filtered"):
    monkeypatch.setattr("pwner.tools.pci._probe", fake_probe(mapping or {}, default))
    monkeypatch.setattr("pwner.tools.pci._source_ip_for", lambda t: "192.168.9.9")
    return asyncio.run(pci_retest(c or ctx(), args))


def test_a_closed_port_reads_as_the_exposure_being_gone(monkeypatch):
    res = run_retest(monkeypatch, {"findings": [{"host": "10.0.0.5", "port": 3306,
                                                 "title": "MySQL exposed"}]})
    assert res["counts"] == {"exposure_gone": 1}
    assert res["findings"][0]["status"] == "exposure_gone"
    assert res["requirement"] == "PCI DSS 11.4.4"


def test_a_still_open_port_reads_as_still_exposed(monkeypatch):
    res = run_retest(monkeypatch, {"findings": [{"host": "10.0.0.5", "port": 3306}]},
                     mapping={("10.0.0.5", 3306): "open"})
    assert res["findings"][0]["status"] == "still_exposed"


def test_the_retest_says_out_loud_that_it_only_checks_exposure(monkeypatch):
    """A version or configuration finding is not closed by a port being shut, and a
    retest that implied otherwise would close real findings on false evidence."""
    res = run_retest(monkeypatch, {"findings": [{"host": "10.0.0.5", "port": 3306}]})
    assert res["verification"] == "exposure_only"
    assert "version" in res["note"]


def test_a_finding_with_no_port_is_sent_back_for_a_real_recheck(monkeypatch):
    res = run_retest(monkeypatch, {"findings": [{"host": "10.0.0.5",
                                                 "title": "weak TLS config"}]})
    row = res["findings"][0]
    assert row["status"] == "needs_manual_recheck"
    assert "no port" in row["reason"]


def test_a_finding_with_no_host_is_not_silently_dropped(monkeypatch):
    res = run_retest(monkeypatch, {"findings": [{"title": "policy gap"}]})
    assert res["findings"][0]["status"] == "needs_manual_recheck"
    assert res["retested"] == 1


def test_a_refused_port_is_inconclusive_on_retest_too(monkeypatch):
    res = run_retest(monkeypatch, {"findings": [{"host": "10.0.0.5", "port": 3306}]},
                     default="refused")
    assert res["findings"][0]["status"] == "inconclusive"


def test_with_no_argument_it_retests_what_is_on_the_record(monkeypatch):
    c = ctx()
    c.findings.append({"host": "10.0.0.5", "port": 3306, "title": "MySQL exposed"})
    res = run_retest(monkeypatch, {}, c=c)
    assert res["retested"] == 1
    assert res["findings"][0]["title"] == "MySQL exposed"


def test_an_empty_record_is_not_an_error(monkeypatch):
    res = run_retest(monkeypatch, {})
    assert res["retested"] == 0
    assert "no findings" in res["note"]


def test_a_huge_retest_is_capped_and_says_so(monkeypatch):
    many = [{"host": f"10.0.0.{i}", "port": 3306} for i in range(_LIST_CAP + 4)]
    res = run_retest(monkeypatch, {"findings": many})
    assert len(res["findings"]) == _LIST_CAP
    assert res["more"] == 4
    assert res["retested"] == _LIST_CAP + 4

"""Tests for the authorization boundary.

This is the file to be strict in: the scope guard is the only thing standing between
"pentest the host I was authorized to test" and "scan a stranger". Every test here is
offline — hostname cases monkeypatch _resolve_ips so no DNS query is made.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

from pwner import tools
from pwner.tools import (
    ScanContext,
    ToolError,
    _enforce_scope,
    _hosts_in_value,
    _literal_in_scope,
    build_dispatch,
    in_scope,
)


def ctx(target: str) -> ScanContext:
    return ScanContext(target=target)


# ── scope_networks / in_scope ────────────────────────────────────────────────

@pytest.mark.parametrize("target,expected", [
    ("10.0.0.5", []),
    ("10.0.0.0/24", ["10.0.0.0/24"]),
    ("10.0.0.0/24,192.168.1.0/24", ["10.0.0.0/24", "192.168.1.0/24"]),
    ("10.0.0.7/24", ["10.0.0.0/24"]),          # non-strict: host bits are masked off
    ("example.com", []),                        # a domain carries no network
    ("https://example.com/x", []),              # URL target is not read as a CIDR
    ("", []),
])
def test_scope_networks(target, expected):
    assert [str(n) for n in ctx(target).scope_networks()] == expected


@pytest.mark.parametrize("host,allowed", [
    ("10.0.0.5", True),
    ("10.0.0.0", True),
    ("10.0.0.255", True),
    ("10.0.1.5", False),
    ("192.168.1.5", False),
    ("8.8.8.8", False),
])
def test_in_scope_cidr(host, allowed):
    assert in_scope(host, ctx("10.0.0.0/24")) is allowed


@pytest.mark.parametrize("host,allowed", [
    ("10.0.0.5", True),
    ("10.0.0.5.", True),       # trailing dot
    (" 10.0.0.5 ", True),      # surrounding space
    ("10.0.0.6", False),
])
def test_in_scope_single_host(host, allowed):
    assert in_scope(host, ctx("10.0.0.5")) is allowed


def test_in_scope_without_target_is_permissive():
    """No target set yet == no scope to violate; set_target establishes it. Documented
    behaviour — this test exists so a change to it has to be deliberate."""
    assert in_scope("8.8.8.8", ctx("")) is True


def test_in_scope_matches_hostname_by_resolved_ip(monkeypatch):
    monkeypatch.setattr(tools, "_resolve_ips",
                        lambda h: ["10.0.0.5"] if h in ("web.lab", "10.0.0.5") else [])
    assert in_scope("web.lab", ctx("10.0.0.0/24")) is True
    assert in_scope("web.lab", ctx("10.0.0.5")) is True


def test_unresolvable_hostname_is_refused(monkeypatch):
    """A name we cannot resolve must not be assumed in scope."""
    monkeypatch.setattr(tools, "_resolve_ips", lambda h: [])
    assert in_scope("nope.invalid", ctx("10.0.0.0/24")) is False


# ── host extraction from tool arguments ──────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    ("10.0.0.5", ["10.0.0.5"]),
    ("  10.0.0.5  ", ["10.0.0.5"]),
    ("10.0.0.5,10.0.0.6", ["10.0.0.5", "10.0.0.6"]),
    ("10.0.0.0/24", ["10.0.0.0/24"]),
    ("10.0.0.5:445", ["10.0.0.5"]),
    ("http://10.0.0.5:8443/login", ["10.0.0.5"]),
    ("https://web.lab/x?a=b", ["web.lab"]),
    ("[2001:db8::1]:443", ["2001:db8::1"]),
    ("2001:db8::1", ["2001:db8::1"]),                       # bare IPv6 kept whole
    (["10.0.0.5", "http://10.0.0.6:80"], ["10.0.0.5", "10.0.0.6"]),
    (["a.lab,b.lab", "c.lab"], ["a.lab", "b.lab", "c.lab"]),
    ("", []),
    (None, []),
    (True, []),
    ([], []),
])
def test_hosts_in_value(value, expected):
    assert _hosts_in_value(value) == expected


# ── network-valued arguments cannot widen the authorization ──────────────────

@pytest.mark.parametrize("literal,allowed", [
    ("10.0.0.0/24", True),     # exactly the scope
    ("10.0.0.0/25", True),     # narrower
    ("10.0.0.64/26", True),    # narrower, offset
    ("10.0.0.0/16", False),    # WIDER than the authorization
    ("10.0.0.0/8", False),
    ("0.0.0.0/0", False),      # the whole internet
    ("192.168.1.0/24", False),
])
def test_cidr_argument_must_sit_inside_scope(literal, allowed):
    assert _literal_in_scope(literal, ctx("10.0.0.0/24")) is allowed


@pytest.mark.parametrize("literal,allowed", [
    ("10.0.0.5/32", True),
    ("10.0.0.5/24", False),    # a /24 around an authorized single host is 256 hosts
    ("10.0.0.6/32", False),
])
def test_cidr_argument_against_single_host_scope(literal, allowed):
    assert _literal_in_scope(literal, ctx("10.0.0.5")) is allowed


def test_ipv6_cidr_does_not_crash_against_ipv4_scope():
    assert _literal_in_scope("2001:db8::/32", ctx("10.0.0.0/24")) is False


# ── _enforce_scope across the tool surface ───────────────────────────────────

def test_enforce_scope_allows_in_scope_args():
    _enforce_scope("port_scan", {"target": "10.0.0.5", "ports": "top-100"}, ctx("10.0.0.0/24"))
    _enforce_scope("banner_grab", {"host": "10.0.0.9", "port": 22}, ctx("10.0.0.0/24"))


def test_enforce_scope_ignores_non_host_args():
    """Ports and flags must never be mistaken for hosts."""
    _enforce_scope("port_scan", {"ports": "22,80,443", "nmap_args": "-Pn -T2"}, ctx("10.0.0.5"))


def test_enforce_scope_skips_absent_and_empty_args():
    """An omitted or empty target means the tool falls back to ctx.target, which is in
    scope by definition."""
    _enforce_scope("port_scan", {}, ctx("10.0.0.5"))
    _enforce_scope("port_scan", {"target": ""}, ctx("10.0.0.5"))
    _enforce_scope("port_scan", {"target": None}, ctx("10.0.0.5"))


@pytest.mark.parametrize("tool,args", [
    ("port_scan", {"target": "8.8.8.8"}),
    ("banner_grab", {"host": "8.8.8.8", "port": 22}),
    ("web_request", {"host": "evil.example", "port": 80}),
    ("smb_enum", {"target": "10.9.9.9"}),
    ("secretsdump", {"dc_ip": "10.9.9.9"}),
    ("ssh_exec", {"host": "10.9.9.9"}),
])
def test_enforce_scope_refuses_out_of_scope(tool, args, monkeypatch):
    monkeypatch.setattr(tools, "_resolve_ips",
                        lambda h: [h] if h[0].isdigit() else [])
    with pytest.raises(ToolError, match="outside the authorized scope"):
        _enforce_scope(tool, args, ctx("10.0.0.0/24"))


@pytest.mark.parametrize("tool", sorted(tools._SCOPE_EXEMPT_TOOLS))
def test_exempt_tools_are_not_scope_checked(tool):
    """The exempt list is deliberate (local bookkeeping, offline work, our own
    attacker-side infra). Assert it, so adding a network tool to it is a visible choice."""
    _enforce_scope(tool, {"target": "8.8.8.8", "host": "8.8.8.8"}, ctx("10.0.0.0/24"))


def test_exempt_list_contains_no_unknown_tool():
    assert tools._SCOPE_EXEMPT_TOOLS <= set(build_dispatch(ctx("10.0.0.5")))


# ── regressions: tools that reached the network with no scope check ──────────
# ping_sweep, nuclei_scan and hydra_brute each took a caller-supplied target and
# passed it straight to nmap / nuclei / hydra without calling _require_scope.

def test_ping_sweep_cannot_sweep_a_wider_network():
    with pytest.raises(ToolError, match="outside the authorized scope"):
        _enforce_scope("ping_sweep", {"target": "10.0.0.0/16"}, ctx("10.0.0.0/24"))


def test_nuclei_scan_refuses_an_out_of_scope_url_in_a_list():
    """nuclei_scan accepts up to 500 targets; one bad entry has to fail the call."""
    targets = [f"http://10.0.0.{i}:80" for i in range(1, 20)] + ["http://example.com"]
    with pytest.raises(ToolError, match="outside the authorized scope"):
        _enforce_scope("nuclei_scan", {"targets": targets}, ctx("10.0.0.0/24"))


def test_nuclei_scan_allows_in_scope_urls_and_hostports():
    _enforce_scope("nuclei_scan",
                   {"targets": ["http://10.0.0.5:8443", "10.0.0.6:445"]},
                   ctx("10.0.0.0/24"))


def test_hydra_brute_is_scope_checked_before_the_consent_gate():
    with pytest.raises(ToolError, match="outside the authorized scope"):
        _enforce_scope("hydra_brute", {"target": "8.8.8.8", "port": 21}, ctx("10.0.0.0/24"))


# ── wiring: the guard is actually installed on every dispatch entry ──────────

def test_every_dispatched_tool_is_wrapped():
    d = build_dispatch(ctx("10.0.0.5"))
    assert d, "dispatch is empty"
    assert all(inspect.iscoroutinefunction(fn) for fn in d.values())
    assert all(fn.__name__ == f"guarded_{name}" for name, fn in d.items())


def test_dispatch_and_schemas_do_not_drift():
    """TOOL_SCHEMAS and build_dispatch are maintained by hand; a tool present in one and
    missing from the other is how ping_sweep/nuclei_scan drifted out of scope coverage."""
    advertised = {s["function"]["name"] for s in tools.TOOL_SCHEMAS}
    assert advertised == set(build_dispatch(ctx("10.0.0.5")))


def test_guard_rejects_through_the_dispatch_entry():
    """End-to-end: the refusal happens before the tool body, so no nmap/nuclei process
    is ever started for an out-of-scope host."""
    d = build_dispatch(ctx("10.0.0.0/24"))
    with pytest.raises(ToolError, match="outside the authorized scope"):
        asyncio.run(d["ping_sweep"]({"target": "0.0.0.0/0"}))


def test_guard_failure_is_recoverable_for_the_model():
    """llm._run_tool turns an exception raised inside the task into an {"error": ...}
    tool result. That only works if the wrapper is a coroutine: were it a plain function,
    the raise would happen at ensure_future(fn(args)) — outside its try block — and kill
    the whole run instead of coming back to the model."""
    d = build_dispatch(ctx("10.0.0.0/24"))
    coro = d["port_scan"]({"target": "8.8.8.8"})          # nothing raised yet
    with pytest.raises(ToolError):
        asyncio.run(coro)                                  # raised on await, inside the task

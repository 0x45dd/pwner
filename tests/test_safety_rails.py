"""Tests for the non-scope safety rails and the operator-facing target parser."""
from __future__ import annotations

import ipaddress

import pytest

from pwner import tools
from pwner.tools import (
    BLOCKED_SCRIPT_CATEGORIES,
    ToolError,
    _guard_nmap_args,
    resolve_target_spec,
)

# ── run_nmap escape hatch: intrusive NSE categories are refused ──────────────

@pytest.mark.parametrize("category", sorted(BLOCKED_SCRIPT_CATEGORIES))
def test_blocked_script_categories_are_refused(category):
    with pytest.raises(ToolError, match="refused"):
        _guard_nmap_args(f"-sV --script {category}")


def test_blocked_category_refused_in_a_script_list():
    with pytest.raises(ToolError, match="refused"):
        _guard_nmap_args("--script=default,safe,exploit")


def test_blocked_category_refused_regardless_of_case():
    with pytest.raises(ToolError, match="refused"):
        _guard_nmap_args("--script BRUTE")


def test_error_names_every_blocked_category_present():
    with pytest.raises(ToolError) as e:
        _guard_nmap_args("--script brute,dos")
    assert "brute" in str(e.value) and "dos" in str(e.value)


@pytest.mark.parametrize("raw,expected", [
    ("-Pn -sV", ["-Pn", "-sV"]),
    ("--script vuln", ["--script", "vuln"]),
    ("--script safe,default,discovery", ["--script", "safe,default,discovery"]),
    ("-p- -T2", ["-p-", "-T2"]),
    ("   -Pn   ", ["-Pn"]),
    ("", []),
    (None, []),
])
def test_detection_args_pass_through(raw, expected):
    assert _guard_nmap_args(raw) == expected


def test_category_name_without_script_flag_is_not_refused():
    """The rail is about running intrusive scripts, not the word appearing anywhere —
    e.g. --script-timeout or a path containing 'exploit' must not be false-positived."""
    assert _guard_nmap_args("--script-timeout 30s") == ["--script-timeout", "30s"]
    assert _guard_nmap_args("-sV --version-all") == ["-sV", "--version-all"]


# ── resolve_target_spec: operator phrase -> scannable target ─────────────────

@pytest.mark.parametrize("spec,expected", [
    ("10.0.0.5", "10.0.0.5"),
    ("10.0.0.0/24", "10.0.0.0/24"),
    ("  10.0.0.5  ", "10.0.0.5"),
    ("example.com", "example.com"),          # hostname passes through
    ("sub.example.com", "sub.example.com"),
])
def test_resolve_target_spec_passes_through(spec, expected, monkeypatch):
    # A non-IP spec is offered to _iface_ipv4_prefix first, which shells out to
    # ip/ifconfig to ask whether it names a local interface. None == "not one".
    monkeypatch.setattr("pwner.tools.target._iface_ipv4_prefix", lambda iface: None)
    assert resolve_target_spec(spec) == expected


def test_explicit_prefix_widens_a_bare_ip_to_its_network():
    assert resolve_target_spec("10.0.0.7", prefix=24) == "10.0.0.0/24"
    assert resolve_target_spec("10.0.0.7", prefix=16) == "10.0.0.0/16"


def test_prefix_does_not_override_an_explicit_cidr():
    assert resolve_target_spec("10.0.0.0/25", prefix=16) == "10.0.0.0/25"


def test_interface_with_prefix_resolves_to_that_subnet(monkeypatch):
    monkeypatch.setattr("pwner.tools.target._iface_ipv4_prefix", lambda iface: ("192.168.5.37", 24))
    for spec in ("en0/24", "en0 /24", "EN0 / 24"):
        assert resolve_target_spec(spec) == "192.168.5.0/24"


def test_interface_without_prefix_uses_the_interface_netmask(monkeypatch):
    monkeypatch.setattr("pwner.tools.target._iface_ipv4_prefix", lambda iface: ("192.168.5.37", 25))
    assert resolve_target_spec("en0") == "192.168.5.0/25"


@pytest.mark.parametrize("word", ["local", "lan", "my network", "LOCAL", "here"])
def test_local_words_resolve_to_this_machines_subnet(word, monkeypatch):
    monkeypatch.setattr("pwner.tools.target._primary_ipv4", lambda: "192.168.1.42")
    assert resolve_target_spec(word) == "192.168.1.0/24"


def test_local_word_honours_an_explicit_prefix(monkeypatch):
    monkeypatch.setattr("pwner.tools.target._primary_ipv4", lambda: "192.168.1.42")
    assert resolve_target_spec("local", prefix=16) == "192.168.0.0/16"


def test_local_word_errors_when_the_subnet_is_undiscoverable(monkeypatch):
    monkeypatch.setattr("pwner.tools.target._primary_ipv4", lambda: None)
    with pytest.raises(ToolError, match="local subnet"):
        resolve_target_spec("local")


def test_resolved_spec_is_always_a_valid_scope_for_an_interface(monkeypatch):
    """Whatever resolve_target_spec returns for an interface becomes ctx.target, so it
    has to parse as a network — otherwise scope_networks() silently yields nothing and
    the CIDR branch of the guard never engages."""
    monkeypatch.setattr("pwner.tools.target._iface_ipv4_prefix", lambda iface: ("10.1.2.3", 24))
    resolved = resolve_target_spec("eth0")
    assert ipaddress.ip_network(resolved, strict=False)
    assert tools.ScanContext(target=resolved).scope_networks()

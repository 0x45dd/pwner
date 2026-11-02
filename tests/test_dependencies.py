"""Tests for the external-tool status report behind `pwner doctor` and `/doctor`.

These hints are factual claims about other people's package repositories, so they rot.
The ones pinned here were each checked against the upstream source of truth (the Debian
archive, the Arch package API, Fedora's mdapi, PyPI) — if one changes, this is where it
should fail rather than in a user's terminal.
"""
from __future__ import annotations

import pytest

from pwner import cli
from pwner.tools import dependency_status
from pwner.tools.report import _hint, _package_manager

MANAGERS = ["brew", "apt", "pacman", "dnf"]
TOOLS = ["nmap", "nuclei", "hydra", "snmpwalk", "hashcat", "searchsploit",
         "impacket", "netexec", "certipy", "bloodhound-python", "kerbrute"]


# ── package-manager detection ────────────────────────────────────────────────

def test_detects_the_package_manager_present(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda c: "/usr/bin/" + c if c == "pacman" else None)
    assert _package_manager() == "pacman"


def test_no_package_manager_is_not_an_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda c: None)
    assert _package_manager() is None


# ── every tool produces a usable hint on every platform ──────────────────────

@pytest.mark.parametrize("pm", MANAGERS + [None])
@pytest.mark.parametrize("name", TOOLS)
def test_hint_is_non_empty_and_names_no_other_manager(name, pm):
    """A hint has to be paste-ready on the platform it is shown for: 'brew install nmap'
    on a Debian box is noise, which is the bug this replaced."""
    hint = _hint(name, pm)
    assert hint.strip()
    for other in MANAGERS:
        if other != pm:
            assert not hint.startswith(f"{other} install"), hint
            assert not hint.startswith(f"sudo {other} "), hint


@pytest.mark.parametrize("pm,expected", [
    ("brew", "brew install nmap"),
    ("apt", "sudo apt install nmap"),
    ("pacman", "sudo pacman -S nmap"),
    ("dnf", "sudo dnf install nmap"),
])
def test_nmap_hint_per_manager(pm, expected):
    assert _hint("nmap", pm) == expected


def test_snmpwalk_package_name_differs_per_distro():
    """The binary is snmpwalk but no distro calls the package that."""
    assert _hint("snmpwalk", "apt") == "sudo apt install snmp"
    assert _hint("snmpwalk", "brew") == "brew install net-snmp"
    assert _hint("snmpwalk", "dnf") == "sudo dnf install net-snmp-utils"
    assert _hint("snmpwalk", "pacman") == "sudo pacman -S net-snmp"


# ── the claims that were wrong before, pinned ────────────────────────────────

@pytest.mark.parametrize("pm", MANAGERS + [None])
def test_netexec_is_never_suggested_from_pypi(pm):
    """netexec is NOT on PyPI — `pipx install netexec` fails. It must come from the repo."""
    hint = _hint("netexec", pm)
    assert "github.com/Pennyw0rth/NetExec" in hint
    assert hint != "pipx install netexec"


@pytest.mark.parametrize("pm", ["apt", "pacman"])
def test_nuclei_is_not_claimed_where_it_is_unpackaged(pm):
    """Debian has no nuclei package, and it is in the AUR rather than Arch's own repos."""
    assert "install nuclei" not in _hint("nuclei", pm)


@pytest.mark.parametrize("pm,expected", [
    ("brew", "brew install nuclei"),
    ("dnf", "sudo dnf install nuclei"),
    ("apt", None),       # unpackaged -> falls back to the Go route
    ("pacman", None),    # AUR only, not the official repos
])
def test_nuclei_packaging_matches_reality(pm, expected):
    hint = _hint("nuclei", pm)
    assert hint == expected if expected else "go install" in hint


@pytest.mark.parametrize("pm,expected", [
    ("brew", "brew install exploitdb"),
    ("pacman", "sudo pacman -S exploitdb"),
    ("apt", None),       # Kali has it, plain Debian/Ubuntu does not
    ("dnf", None),
])
def test_exploitdb_packaging_matches_reality(pm, expected):
    """Homebrew, Arch and Kali package exploitdb; plain Debian/Ubuntu and Fedora do not."""
    hint = _hint("searchsploit", pm)
    assert hint == expected if expected else "exploit-database/exploitdb" in hint


def test_kerbrute_hint_mentions_a_route_that_exists_on_arm64():
    """Upstream ships linux_386 and linux_amd64 only, so arm64 users need the Go route."""
    assert "go install" in _hint("kerbrute", "apt")


# ── dependency_status shape ──────────────────────────────────────────────────

def test_status_covers_every_tool_with_a_complete_record():
    st = dependency_status()
    assert {t["name"] for t in st} == set(TOOLS)
    for t in st:
        assert set(t) == {"name", "installed", "install", "core", "enables"}
        assert isinstance(t["installed"], bool)
        assert t["enables"].strip() and t["install"].strip()


def test_nmap_is_the_only_core_dependency():
    assert [t["name"] for t in dependency_status() if t["core"]] == ["nmap"]


# ── the doctor command ───────────────────────────────────────────────────────

def test_doctor_exits_zero_when_core_is_present(monkeypatch, capsys):
    monkeypatch.setattr("pwner.tools.dependency_status", lambda: [
        {"name": "nmap", "installed": True, "install": "x", "core": True, "enables": "scans"},
        {"name": "hydra", "installed": False, "install": "apt install hydra", "core": False,
         "enables": "hydra_brute"},
    ])
    assert cli._run_doctor() == 0
    out = capsys.readouterr().out
    assert "✓ nmap" in out and "✗ hydra" in out
    assert "apt install hydra" in out, "the install command for a missing tool must be shown"


def test_doctor_exits_nonzero_when_nmap_is_missing(monkeypatch, capsys):
    """Usable as a setup check in a script or a container build."""
    monkeypatch.setattr("pwner.tools.dependency_status", lambda: [
        {"name": "nmap", "installed": False, "install": "apt install nmap", "core": True,
         "enables": "scans"},
    ])
    assert cli._run_doctor() == 1
    assert "nmap is required" in capsys.readouterr().out


def test_doctor_json_is_machine_readable(monkeypatch, capsys):
    import json
    rows = [{"name": "nmap", "installed": True, "install": "x", "core": True, "enables": "y"}]
    monkeypatch.setattr("pwner.tools.dependency_status", lambda: rows)
    cli._run_doctor(as_json=True)
    assert json.loads(capsys.readouterr().out) == rows

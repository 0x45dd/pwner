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
from pwner.tools.report import _hint, _is_kali, _package_manager

MANAGERS = ["brew", "apt", "kali", "pacman", "dnf"]
TOOLS = ["nmap", "nuclei", "hydra", "snmpwalk", "hashcat", "searchsploit",
         "impacket", "netexec", "certipy", "bloodhound-python", "kerbrute"]

# Kali is its own ecosystem in the hint tables but drives the same binary as Debian, so
# "sudo apt install" is the correct command for both and is not a cross-ecosystem leak.
COMMAND_FAMILY = {"brew": "brew", "apt": "apt", "kali": "apt", "pacman": "pacman", "dnf": "dnf"}


# ── package-manager detection ────────────────────────────────────────────────

def test_detects_the_package_manager_present(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda c: "/usr/bin/" + c if c == "pacman" else None)
    assert _package_manager() == "pacman"


def test_no_package_manager_is_not_an_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda c: None)
    assert _package_manager() is None


# ── Kali is detected as its own ecosystem, not as Debian ─────────────────────

def _os_release(tmp_path, body: str) -> str:
    p = tmp_path / "os-release"
    p.write_text(body, encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("body,expected", [
    ('ID=kali\nID_LIKE=debian\n', True),
    ('ID="kali"\n', True),                               # quoted, as Kali actually writes it
    ('NAME="Kali GNU/Linux"\nID=kali\n', True),
    ('ID=debian\n', False),
    ('ID=ubuntu\nID_LIKE=debian\n', False),
    ('ID_LIKE=kali\n', False),                           # derivative, not Kali itself
    ('PRETTY_NAME="Kali but lying"\nID=debian\n', False),  # only ID counts
    ('', False),
])
def test_kali_is_identified_from_os_release(tmp_path, monkeypatch, body, expected):
    monkeypatch.setattr("pwner.tools.report._OS_RELEASE", _os_release(tmp_path, body))
    assert _is_kali() is expected


def test_missing_os_release_is_not_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr("pwner.tools.report._OS_RELEASE", str(tmp_path / "nope"))
    assert _is_kali() is False


def test_apt_on_kali_reports_kali(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda c: "/usr/bin/" + c if c == "apt" else None)
    monkeypatch.setattr("pwner.tools.report._is_kali", lambda: True)
    assert _package_manager() == "kali"


def test_apt_on_plain_debian_still_reports_apt(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda c: "/usr/bin/" + c if c == "apt" else None)
    monkeypatch.setattr("pwner.tools.report._is_kali", lambda: False)
    assert _package_manager() == "apt"


# ── every tool produces a usable hint on every platform ──────────────────────

@pytest.mark.parametrize("pm", MANAGERS + [None])
@pytest.mark.parametrize("name", TOOLS)
def test_hint_is_non_empty_and_names_no_other_manager(name, pm):
    """A hint has to be paste-ready on the platform it is shown for: 'brew install nmap'
    on a Debian box is noise, which is the bug this replaced."""
    hint = _hint(name, pm)
    assert hint.strip()
    mine = COMMAND_FAMILY.get(pm)
    for other in set(COMMAND_FAMILY.values()):
        if other != mine:
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
    """netexec is NOT on PyPI — `pipx install netexec` fails. Everywhere but Kali, which
    packages it, the only working route is the git repository."""
    hint = _hint("netexec", pm)
    assert hint != "pipx install netexec"
    if hint.startswith("pipx"):
        assert "github.com/Pennyw0rth/NetExec" in hint


@pytest.mark.parametrize("pm", ["apt", "pacman"])
def test_nuclei_is_not_claimed_where_it_is_unpackaged(pm):
    """Debian has no nuclei package, and it is in the AUR rather than Arch's own repos."""
    assert "install nuclei" not in _hint("nuclei", pm)


@pytest.mark.parametrize("pm,expected", [
    ("brew", "brew install nuclei"),
    ("dnf", "sudo dnf install nuclei"),
    ("kali", "sudo apt install nuclei"),
    ("apt", None),       # unpackaged -> falls back to the Go route
    ("pacman", None),    # AUR only, not the official repos
])
def test_nuclei_packaging_matches_reality(pm, expected):
    hint = _hint("nuclei", pm)
    assert hint == expected if expected else "go install" in hint


@pytest.mark.parametrize("pm,expected", [
    ("brew", "brew install exploitdb"),
    ("pacman", "sudo pacman -S exploitdb"),
    ("kali", "sudo apt install exploitdb"),
    ("apt", None),       # plain Debian/Ubuntu does not package it
    ("dnf", None),
])
def test_exploitdb_packaging_matches_reality(pm, expected):
    """Homebrew, Arch and Kali package exploitdb; plain Debian/Ubuntu and Fedora do not."""
    hint = _hint("searchsploit", pm)
    assert hint == expected if expected else "exploit-database/exploitdb" in hint


def test_kerbrute_hint_mentions_a_route_that_exists_on_arm64():
    """Upstream ships linux_386 and linux_amd64 only, so arm64 users need the Go route."""
    assert "go install" in _hint("kerbrute", "apt")


# ── Kali's own repository, checked against the kali-rolling package index ────
#
# Verified against dists/kali-rolling/main/binary-amd64/Packages and Contents-amd64:
# every package below exists and installs the binary pwner probes for. All but nuclei
# and bloodhound.py are already present after a default (kali-linux-default) install.

@pytest.mark.parametrize("tool,expected", [
    ("nmap",              "sudo apt install nmap"),
    ("nuclei",            "sudo apt install nuclei"),
    ("hydra",             "sudo apt install hydra"),
    ("snmpwalk",          "sudo apt install snmp"),
    ("searchsploit",      "sudo apt install exploitdb"),
    ("hashcat",           "sudo apt install hashcat"),
    ("impacket",          "sudo apt install impacket-scripts"),
    ("certipy",           "sudo apt install certipy-ad"),
    ("bloodhound-python", "sudo apt install bloodhound.py"),
    ("netexec",           "sudo apt install netexec"),
])
def test_kali_uses_its_own_packages(tool, expected):
    assert _hint(tool, "kali") == expected


@pytest.mark.parametrize("tool", ["impacket", "certipy", "bloodhound-python", "netexec"])
def test_kali_never_falls_back_to_pipx(tool):
    """These four are the ones Kali packages and every other distro does not. Sending a
    Kali user to pipx would build a second copy of something already on their PATH."""
    assert not _hint(tool, "kali").startswith("pipx")


def test_kerbrute_is_not_packaged_on_kali_either():
    """kerbrute is absent from kali-rolling, so Kali gets the same manual route."""
    assert "github.com/ropnop/kerbrute" in _hint("kerbrute", "kali")


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

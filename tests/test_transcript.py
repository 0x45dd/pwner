"""Tests for where and how a session transcript is written.

A transcript is the most sensitive artefact pwner produces: it records the whole session,
so every credential, session cookie and hash the engagement turned up is in it in
cleartext. Two things have to hold — it must not land in the working directory by
default, and it must not be readable by other users on the machine.
"""
from __future__ import annotations

import os
import stat

import pytest

from pwner import config as pwner_config
from pwner.repl import ReplSession
from pwner.tools import ScanContext


@pytest.fixture
def session(tmp_path, monkeypatch):
    """A ReplSession with just enough wired up to dump a transcript."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    cwd = tmp_path / "cwd"          # stand somewhere empty, so a leak into it is visible
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    s = object.__new__(ReplSession)
    s.ctx = ScanContext(target="10.0.0.5")
    s.ctx.findings = [{"title": "weak creds", "host": "10.0.0.5"}]
    s.model = "test-model"
    s.tui = type("T", (), {"transcript": ["line one", "password=hunter2"]})()
    return s


def mode_of(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# ── default location ─────────────────────────────────────────────────────────

def test_default_location_is_the_user_data_dir_not_the_cwd(session, tmp_path):
    """The regression this exists for: transcripts used to default to os.getcwd(), which
    is how three of them ended up sitting in the project root waiting to be committed."""
    path = session._dump_transcript()
    assert path.startswith(str(tmp_path / "data" / "pwner" / "sessions"))
    assert os.listdir(tmp_path / "cwd") == [], "transcript leaked into the working directory"


def test_default_filename_is_timestamped(session):
    path = session._dump_transcript()
    name = os.path.basename(path)
    assert name.startswith("pwner-session-") and name.endswith(".txt")


def test_sessions_dir_honours_xdg_data_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert pwner_config.sessions_dir() == str(tmp_path / "xdg" / "pwner" / "sessions")


def test_sessions_dir_falls_back_to_local_share(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert pwner_config.sessions_dir().endswith("/.local/share/pwner/sessions")


# ── permissions ──────────────────────────────────────────────────────────────

def test_transcript_is_owner_only(session):
    assert mode_of(session._dump_transcript()) == 0o600


def test_containing_directory_is_owner_only(session):
    assert mode_of(os.path.dirname(session._dump_transcript())) == 0o700


def test_an_explicit_path_is_also_owner_only(session, tmp_path):
    """Content is just as sensitive wherever the operator puts it."""
    target = tmp_path / "out" / "engagement.txt"
    assert mode_of(session._dump_transcript(str(target))) == 0o600


def test_rewriting_an_existing_loose_file_tightens_it(session, tmp_path):
    """O_CREAT's mode is ignored for an existing file, so without the explicit chmod a
    transcript would silently inherit world-readable permissions from an earlier run."""
    loose = tmp_path / "loose.txt"
    loose.write_text("old")
    loose.chmod(0o644)
    assert mode_of(session._dump_transcript(str(loose))) == 0o600


# ── explicit paths and content ───────────────────────────────────────────────

def test_explicit_file_path_is_honoured(session, tmp_path):
    target = tmp_path / "mine.txt"
    assert session._dump_transcript(str(target)) == str(target)
    assert "password=hunter2" in target.read_text()


def test_explicit_directory_gets_a_timestamped_file_inside(session, tmp_path):
    d = tmp_path / "reports"
    d.mkdir()
    path = session._dump_transcript(str(d))
    assert os.path.dirname(path) == str(d)
    assert os.path.basename(path).startswith("pwner-session-")


def test_tilde_in_an_explicit_path_is_expanded(session, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    path = session._dump_transcript("~/dump.txt")
    assert path == str(tmp_path / "home" / "dump.txt")


def test_header_records_the_engagement_and_warns_about_cleartext(session):
    text = open(session._dump_transcript()).read()
    assert "10.0.0.5" in text and "test-model" in text and "findings: 1" in text
    assert "UNREDACTED" in text, "the file must say what it contains"
    assert "do not commit it" in text


def test_body_is_the_transcript_verbatim(session):
    """Not redacted on purpose: the credentials are the engagement's deliverable. The
    protection is the location and the file mode, not mangled content."""
    text = open(session._dump_transcript()).read()
    body = text.split("=" * 70, 1)[1]
    assert body.strip().splitlines() == ["line one", "password=hunter2"]

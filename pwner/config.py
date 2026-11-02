"""Where pwner keeps things on disk: the provider/key config and saved transcripts.

Both hold secrets — the config holds an API key, a transcript holds whatever the
engagement turned up (credentials, session cookies, hashes) — so both are written
owner-only, into the user's own directories rather than the working directory.
"""
from __future__ import annotations

import json
import os

CONFIG_PATH = os.path.expanduser("~/.config/pwner/config.json")


def sessions_dir() -> str:
    """Default directory for saved session transcripts (honours XDG_DATA_HOME).

    Deliberately NOT the working directory: a transcript records the credentials and
    cookies the engagement turned up, and writing that into whatever repo you happen to
    be standing in is how it ends up in a commit.
    """
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "pwner", "sessions")


def open_private(path: str) -> int:
    """Open `path` for writing, owner-only (0600), creating or truncating it.

    Returns a raw fd for os.fdopen. The chmod matters for a file that already exists:
    O_CREAT's mode is ignored then, so without it a transcript could inherit
    world-readable permissions from an earlier run.
    """
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)
    return fd


def load() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(cfg: dict) -> None:
    with os.fdopen(open_private(CONFIG_PATH), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def get(name: str, default: str = "") -> str:
    v = load().get(name, default)
    return str(v) if v is not None else default

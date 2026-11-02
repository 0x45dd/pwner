"""Persistent pwner config (~/.config/pwner/config.json) for the LLM provider/key."""
from __future__ import annotations

import json
import os

CONFIG_PATH = os.path.expanduser("~/.config/pwner/config.json")


def load() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(cfg: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    # the file holds an API key — create it owner-only (0600), and tighten an existing one
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CONFIG_PATH, 0o600)


def get(name: str, default: str = "") -> str:
    v = load().get(name, default)
    return str(v) if v is not None else default

"""Shared test setup.

The suite is offline by design, and this is what enforces it rather than trusting every
test to remember. Real DNS, outbound sockets and subprocess spawns all fail loudly here,
so a test that forgets to stub something gets an explicit error instead of quietly
resolving a name, scanning a host or shelling out to nmap on whoever runs it.

This matters more than usual for pwner: an unstubbed tool call does not just make the
suite slow or flaky, it sends real packets at a real host.
"""
from __future__ import annotations

import asyncio
import socket
import subprocess

import pytest


class NetworkAccessInTests(AssertionError):
    """A test tried to touch the network or spawn a process."""


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Block every route to the outside world for the duration of each test."""
    def blocked(what: str):
        def fail(*args, **kwargs):
            raise NetworkAccessInTests(
                f"test tried to use {what} for real — stub it at the module that looks it "
                f"up (e.g. monkeypatch.setattr('pwner.tools.core._resolve_ips', ...)), "
                f"not at the pwner.tools re-export, which the callers do not read."
            )
        return fail

    monkeypatch.setattr(socket, "getaddrinfo", blocked("socket.getaddrinfo"))
    monkeypatch.setattr(socket, "create_connection", blocked("socket.create_connection"))
    monkeypatch.setattr(socket.socket, "connect", blocked("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", blocked("socket.connect_ex"))
    monkeypatch.setattr(subprocess, "run", blocked("subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", blocked("subprocess.Popen"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        blocked("asyncio.create_subprocess_exec"))
    monkeypatch.setattr(asyncio, "open_connection", blocked("asyncio.open_connection"))

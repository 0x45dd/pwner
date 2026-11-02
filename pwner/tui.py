"""Colored console output + network topology for pwner.

Rich markup in every log line (colored in a terminal, plain when piped) — no
alternate-screen Live panel, so interactive input (steering + consent prompts)
stays visible and working, OpenCode-style.
"""
from __future__ import annotations

import io
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree


def _to_plain(item) -> str:
    """Best-effort plain text for a log item (markup string or any Rich renderable),
    so the session transcript is readable/greppable with no ANSI or markup tags."""
    if isinstance(item, str):
        try:
            return Text.from_markup(item).plain
        except Exception:  # noqa: BLE001
            return item
    if isinstance(item, Text):
        return item.plain
    try:  # Panel / Tree / other renderable
        tmp = Console(width=120, record=True, file=io.StringIO())
        tmp.print(item)
        return tmp.export_text().rstrip("\n")
    except Exception:  # noqa: BLE001
        return str(item)

# Rough USD per 1M tokens (input, output), matched by substring of the model id. Unknown -> no $.
_PRICES: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60), "gpt-4o": (2.5, 10.0),
    "gpt-4.1-mini": (0.40, 1.60), "gpt-4.1-nano": (0.10, 0.40), "gpt-4.1": (2.0, 8.0),
    "gpt-5-mini": (0.25, 2.0), "gpt-5": (1.25, 10.0),
    "o4-mini": (1.10, 4.40), "o3-mini": (1.10, 4.40), "o3": (2.0, 8.0),
    "claude-3-5-haiku": (0.80, 4.0), "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-opus": (15.0, 75.0), "claude": (3.0, 15.0),
    "llama": (0.0, 0.0), "qwen": (0.0, 0.0),
}


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float | None:
    m = (model or "").lower()
    for key, (pin, pout) in _PRICES.items():
        if key in m:
            return prompt_tokens / 1e6 * pin + completion_tokens / 1e6 * pout
    return None


class Topology:
    """Discovered network map: host -> open ports (service/version) + notes."""

    def __init__(self):
        self.hosts: dict[str, dict] = {}

    def record_host(self, host: str) -> None:
        host = (host or "").strip()
        if host and host not in self.hosts:
            self.hosts[host] = {"ports": {}, "notes": []}

    def record_port(self, host: str, port: int, service: str = "", version: str = "") -> None:
        self.record_host(host)
        p = self.hosts[host]["ports"].setdefault(port, {"service": service, "version": version})
        if service:
            p["service"] = service
        if version:
            p["version"] = version

    def note(self, host: str, text: str) -> None:
        self.record_host(host)
        self.hosts[host]["notes"].append(text)

    def tree(self) -> Tree:
        t = Tree("network", guide_style="dim")
        for host in sorted(self.hosts):
            data = self.hosts[host]
            h = t.add(f"[cyan]{host}[/]")
            for port in sorted(data["ports"]):
                p = data["ports"][port]
                label = f"[green]{port}[/]  {p['service']} {p['version']}".strip()
                h.add(label)
            for n in data["notes"][-8:]:
                h.add(f"[yellow]{n}[/]")
        return t


class TUI:
    """Colored, streaming output + an inline topology tree. No screen takeover."""

    def __init__(self, enabled: bool = True, force_terminal: bool | None = None):
        self.enabled = enabled
        # force_terminal keeps ANSI colors when stdout is wrapped/redirected and rich would
        # otherwise detect a non-tty and strip them.
        self.console = Console(highlight=False, force_terminal=force_terminal)
        self.topo = Topology()
        self.activity = ""   # current action label, shown next to the live spinner
        self.sink = None     # when set (by the Textual TUI), log() routes here instead of stdout
        self.transcript: list[str] = []  # plain-text record of everything shown (for /dump)
        # live metrics for the status line (set by the session / agent loop)
        self.steps = 0              # tool-calls in the current turn
        self.phase = ""             # discovery / scanning / enum / vuln / brute / report
        self.model = ""             # for the cost estimate
        self.prompt_tokens = 0      # cumulative this session
        self.completion_tokens = 0

    def __enter__(self) -> "TUI":
        return self

    def __exit__(self, *exc) -> None:
        pass

    def record(self, item) -> None:
        """Append a shown item to the session transcript (plain text, capped)."""
        try:
            self.transcript.append(_to_plain(item))
            if len(self.transcript) > 100_000:  # keep memory bounded on very long sessions
                del self.transcript[:10_000]
        except Exception:  # noqa: BLE001 — recording must never break output
            pass

    def log(self, markup: str) -> None:
        if self.sink is not None:
            try:
                self.sink(markup)  # the sink (app._write) records into the transcript
                return
            except Exception:  # noqa: BLE001 — fall back to stdout rather than lose the line
                pass
        self.record(markup)
        self.console.print(markup)

    def topology_tree(self):
        """The discovered network map as a Rich renderable (for the Textual panel)."""
        return self.topo.tree()

    # ---- live metrics -------------------------------------------------------
    def add_usage(self, usage: dict) -> None:
        self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
        self.completion_tokens += int(usage.get("completion_tokens") or 0)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def cost_usd(self) -> float | None:
        return estimate_cost(self.model, self.prompt_tokens, self.completion_tokens)

    def record_host(self, host: str) -> None:
        self.topo.record_host(host)

    def record_port(self, host: str, port: int, service: str = "", version: str = "") -> None:
        self.topo.record_port(host, port, service, version)

    def note(self, host: str, text: str) -> None:
        self.topo.note(host, text)

    def render_topology(self) -> None:
        if not self.topo.hosts:
            self.log("[dim]no hosts discovered yet.[/dim]")
            return
        panel = Panel(self.topo.tree(), title="network topology", border_style="cyan")
        if self.sink is not None:
            try:
                self.sink(panel)
                return
            except Exception:  # noqa: BLE001
                pass
        self.console.print(panel)

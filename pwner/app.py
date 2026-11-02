"""Full-screen Textual TUI for pwner — the OpenCode / Claude-Code-style front-end.

Left: a scrolling log of the agent's reasoning + tool activity (color).
Right: a live "command center" side panel — the discovered network map (hosts → ports/
services) on top and a severity-colored findings strip below, both updating as the agent works.
Bottom: an animated status line (spinner · action · step · elapsed · cost · phase) above a fixed
input box. The input never drifts; output scrolls inside the log panel. Drives a `ReplSession`.
"""
from __future__ import annotations

import time

from rich.panel import Panel
from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.suggester import SuggestFromList
from textual.widgets import Footer, Header, Input, RichLog, Static

from .repl import SPINNER_FRAMES, _COMMANDS

# phase -> icon for the status line; severity -> color for findings/notes.
_PHASE_ICON = {
    "discovery": "🔍", "scanning": "📡", "enum": "🔎",
    "vuln": "🧪", "brute": "🔑", "report": "📝", "": "🧠",
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {
    "critical": "bright_red", "high": "red", "medium": "orange3",
    "low": "yellow", "info": "blue",
}
_SEV_DOT = "●"


def _cost_text(tui) -> str:
    cost = tui.cost_usd()
    if cost is not None:
        return f"~${cost:.2f}"
    tok = tui.total_tokens
    return f"{tok / 1000:.1f}k tok" if tok else "—"


class HistoryInput(Input):
    """Input with ↑/↓ recall of previously submitted lines (session-scoped)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.history: list[str] = []
        self._hidx = 0

    def remember(self, line: str) -> None:
        if line.strip() and (not self.history or self.history[-1] != line):
            self.history.append(line)
        self._hidx = len(self.history)

    def on_key(self, event: events.Key) -> None:
        if event.key == "up" and self.history:
            self._hidx = max(0, self._hidx - 1)
            self.value = self.history[self._hidx]
            self.cursor_position = len(self.value)
            event.stop(); event.prevent_default()
        elif event.key == "down" and self.history:
            self._hidx = min(len(self.history), self._hidx + 1)
            self.value = self.history[self._hidx] if self._hidx < len(self.history) else ""
            self.cursor_position = len(self.value)
            event.stop(); event.prevent_default()


class PwnerApp(App):
    CSS = """
    Screen { background: #000000; }
    Header { background: #0a0a0a; color: #9e9e9e; }
    Footer { background: #0a0a0a; }
    #body { height: 1fr; }
    #log {
        width: 1fr;
        padding: 0 1;
        border: round #303030;
        background: #000000;
        color: #d0d0d0;
        scrollbar-size-vertical: 1;
    }
    #side { width: 46; height: 1fr; }
    #map {
        height: 1fr;
        border: round #005f87;
        background: #000000;
        padding: 0 1;
        overflow-y: auto;
    }
    #findings {
        height: auto;
        max-height: 45%;
        border: round #303030;
        background: #000000;
        padding: 0 1;
        overflow-y: auto;
    }
    #status { height: 1; padding: 0 1; color: #5fd7ff; background: #000000; }
    #prompt {
        height: 3;
        border: round #00afff;
        background: #000000;
        color: #ffffff;
        padding: 0 1;
    }
    #prompt:focus { border: round #5fd7ff; }
    """

    BINDINGS = [
        Binding("ctrl+c", "cancel_or_quit", "copy / stop / quit", priority=True, show=True),
        Binding("escape", "cancel", "stop turn", show=True),
        Binding("ctrl+t", "toggle_panel", "panel", show=True),
        Binding("ctrl+q", "quit_app", "quit", priority=True, show=True),
    ]

    def __init__(self, session):
        super().__init__()
        self.session = session
        self._frame = 0
        self._turn_start: float | None = None
        self.rich_log: RichLog | None = None
        self.status_bar: Static | None = None
        self.map_panel: Static | None = None
        self.findings_panel: Static | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield RichLog(id="log", highlight=False, markup=True, wrap=True, auto_scroll=True)
            with Vertical(id="side"):
                yield Static("", id="map")
                yield Static("", id="findings")
        yield Static("", id="status")
        prompt = HistoryInput(id="prompt",
                              placeholder="message the agent, or /command  (/help · /map · /exit)",
                              suggester=SuggestFromList(list(_COMMANDS), case_sensitive=False))
        prompt.border_title = "you"
        yield prompt
        yield Footer()

    # ---- lifecycle ----------------------------------------------------------
    def on_mount(self) -> None:
        self.title = "pwner"
        self.rich_log = self.query_one("#log", RichLog)
        self.status_bar = self.query_one("#status", Static)
        self.map_panel = self.query_one("#map", Static)
        self.findings_panel = self.query_one("#findings", Static)
        self.session.tui.sink = self._write
        self.session.on_refresh = self._refresh_status
        self._banner()
        mode = "agent" if self.session.client is not None else "deterministic (/scan only — no API key)"
        self._write(f"[dim]mode: {mode} · talk to the agent, it scans when you ask · "
                    f"ctrl+t panel · /help · /exit[/dim]")
        self._refresh_status()
        self._refresh_panels()
        self.set_interval(0.12, self._tick)
        self.set_interval(0.6, self._refresh_panels)
        self.query_one("#prompt", Input).focus()

    def _banner(self) -> None:
        logo = Text()
        logo.append("  ██▌ ", style="bold #5fd7ff")
        logo.append("pwner", style="bold white")
        logo.append("  ▐██\n", style="bold #5fd7ff")
        logo.append("  autonomous agentic network pentest — authorized use only", style="dim #5fd7ff")
        self._write(logo)

    def _write(self, item) -> None:
        """Sink for ReplSession/TUI output: markup string or any Rich renderable.
        Everything shown (banner, operator messages, agent output, tool results) funnels
        through here, so this is where the session transcript is captured for /dump."""
        self.session.tui.record(item)
        if self.rich_log is None:
            return
        self.rich_log.write(Text.from_markup(item) if isinstance(item, str) else item)

    def _refresh_status(self) -> None:
        ctx = self.session.ctx
        tui = self.session.tui
        tgt = ctx.target or "no target"
        consent = "ON" if ctx.auto_consent else "off"
        n_find = len(ctx.findings)
        ch = ctx.operator_channel
        pending = ch is not None and ch.consent_pending()
        state = "working" if self.session.busy else ("consent" if pending else "ready")
        self.sub_title = f"{tgt} · {self.session.model} · {n_find} finding(s) · consent {consent} · {state}"
        if self.status_bar is None:
            return
        if pending:
            self.status_bar.update(Text("consent required — type  y  or  n", style="bold #ffd75f"))
        elif self.session.busy:
            spin = SPINNER_FRAMES[self._frame % len(SPINNER_FRAMES)]
            phase = (tui.phase or "").strip()
            icon = _PHASE_ICON.get(phase, _PHASE_ICON[""])
            act = (getattr(tui, "activity", "") or "thinking").strip()
            elapsed = int(time.monotonic() - self._turn_start) if self._turn_start else 0
            line = Text(f"{spin} {icon} ", style="bold #5fd7ff")
            line.append(act, style="#5fd7ff")
            meta = f"   step {tui.steps} · {elapsed}s · {_cost_text(tui)}"
            if phase:
                meta += f" · {phase}"
            line.append(meta, style="dim")
            line.append("   esc to stop", style="dim")
            self.status_bar.update(line)
        else:
            cost = _cost_text(tui)
            self.status_bar.update(Text(f"ready · {cost} this session", style="dim") if tui.total_tokens
                                   else Text(""))

    def _refresh_panels(self) -> None:
        tui = self.session.tui
        if self.map_panel is not None:
            hosts = getattr(tui.topo, "hosts", {})
            body = tui.topology_tree() if hosts else Text("no hosts discovered yet", style="dim")
            n = len(hosts)
            self.map_panel.update(Panel(body, title=f"network · {n} host(s)", border_style="#005f87"))
        if self.findings_panel is not None:
            self.findings_panel.update(Panel(self._findings_body(), title=self._findings_title(),
                                             border_style="#303030"))

    def _findings_title(self) -> str:
        fs = self.session.ctx.findings
        if not fs:
            return "findings · 0"
        counts: dict[str, int] = {}
        for f in fs:
            counts[str(f.get("severity", "info")).lower()] = counts.get(str(f.get("severity", "info")).lower(), 0) + 1
        hi = next((s for s in ("critical", "high", "medium", "low", "info") if counts.get(s)), None)
        extra = f" · {counts[hi]} {hi}" if hi else ""
        return f"findings · {len(fs)}{extra}"

    def _findings_body(self) -> Text:
        fs = sorted(self.session.ctx.findings, key=lambda f: _SEV_ORDER.get(str(f.get("severity", "")).lower(), 5))
        if not fs:
            return Text("none yet", style="dim")
        body = Text()
        for f in fs[:40]:
            sev = str(f.get("severity", "info")).lower()
            color = _SEV_COLOR.get(sev, "white")
            loc = str(f.get("host", ""))
            if f.get("port"):
                loc += f":{f['port']}"
            body.append(f"{_SEV_DOT} ", style=color)
            body.append(f"{sev.upper():<8} ", style=f"bold {color}")
            title = str(f.get("title", ""))
            body.append(title if len(title) <= 28 else title[:27] + "…", style="white")
            if loc:
                body.append(f"\n   {loc}\n", style="dim cyan")
            else:
                body.append("\n")
        return body

    def _tick(self) -> None:
        busy = self.session.busy
        pending = (self.session.ctx.operator_channel is not None
                   and self.session.ctx.operator_channel.consent_pending())
        if busy and self._turn_start is None:
            self._turn_start = time.monotonic()
        if not busy:
            self._turn_start = None
        if busy or pending:
            self._frame += 1
        self._refresh_status()

    # ---- input --------------------------------------------------------------
    @on(Input.Submitted, "#prompt")
    def _on_submit(self, event: Input.Submitted) -> None:
        line = event.value
        event.input.value = ""
        if not line.strip():
            return
        if isinstance(event.input, HistoryInput):
            event.input.remember(line)
        # panel toggles are handled locally so they don't spam the log
        head = line.strip().split()[0].lower()
        if head in ("/map", "/topology", "/topo", "/findings"):
            self.action_toggle_panel(show=True)
            return
        echo = Text("❯ ", style="bold #5fd7ff")
        echo.append(line, style="bold white")
        self._write(echo)
        self.run_worker(self._handle(line), exclusive=False)

    async def _handle(self, line: str) -> None:
        try:
            if await self.session.submit(line):
                self.exit(0)
        except Exception as e:  # noqa: BLE001 — a handler error must not kill the app
            self._write(f"[red][!] {type(e).__name__}: {str(e)[:300]}[/red]")
        self._refresh_status()

    # ---- actions ------------------------------------------------------------
    def action_toggle_panel(self, show: bool | None = None) -> None:
        side = self.query_one("#side")
        side.display = (not side.display) if show is None else True
        self._refresh_panels()

    def action_cancel(self) -> None:
        if self.session.cancel_turn():
            self._write("[yellow]cancelling…[/yellow]")

    def action_cancel_or_quit(self) -> None:
        # Ctrl-C is overloaded. Textual binds ctrl+c to "copy selected text", but this
        # binding shadows it — so first honor a live mouse selection: copy it and stop.
        # (Drag to select over the log already works; RichLog.allow_select is True.)
        # With no selection it falls back to the stop/quit reflex. A running turn can
        # always be stopped with Esc regardless.
        try:
            selected = self.screen.get_selected_text()
        except Exception:  # noqa: BLE001
            selected = None
        if selected:
            self._copy_text(selected)
            try:
                self.screen.clear_selection()
            except Exception:  # noqa: BLE001
                pass
            self.notify(f"copied {len(selected)} chars to clipboard", timeout=2)
            return
        # No selection: stop the agent if it's working, otherwise leave.
        if self.session.busy:
            self.action_cancel()
        else:
            self.exit(0)

    def _copy_text(self, text: str) -> None:
        """Copy to the clipboard by two paths: Textual's OSC52 (reaches the clipboard over
        SSH and in modern terminals) AND the local OS clipboard tool (reliable even where
        OSC52 is unsupported, e.g. macOS Terminal.app). Both are best-effort."""
        try:
            self.copy_to_clipboard(text)  # OSC52
        except Exception:  # noqa: BLE001
            pass
        import shutil
        import subprocess
        tool = (["pbcopy"] if shutil.which("pbcopy")
                else ["wl-copy"] if shutil.which("wl-copy")
                else ["xclip", "-selection", "clipboard"] if shutil.which("xclip")
                else ["xsel", "--clipboard", "--input"] if shutil.which("xsel")
                else None)
        if tool:
            try:
                subprocess.run(tool, input=text.encode("utf-8"), timeout=5, check=False)
            except Exception:  # noqa: BLE001
                pass

    def action_quit_app(self) -> None:
        self.session.cancel_turn()
        self.exit(0)


async def run_app(session) -> int:
    app = PwnerApp(session)
    await app.run_async()
    # screen is restored now — leave a short trail on the normal terminal
    n = len(session.ctx.findings)
    session.tui.sink = None
    cost = session.tui.cost_usd()
    tail = f" · ~${cost:.2f}" if cost is not None else ""
    session.tui.console.print(f"[dim]session ended · {n} finding(s){tail}. bye.[/dim]")
    return 0

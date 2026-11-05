"""Interactive agent session for pwner — persistent, conversational chat.

`ReplSession` holds the conversation + findings and knows how to run one agent turn
and handle slash commands; all its output goes through `self.tui.log`. Two front-ends
drive it:
  • pwner/app.py — a full-screen Textual TUI (fixed bottom input, scrolling log) when
    we have a real terminal. This is the OpenCode / Claude-Code-style experience.
  • `_loop_plain` here — a plain sequential prompt for piped/non-TTY use.
"""
from __future__ import annotations

import asyncio

from rich.markup import escape

from . import tools
from .agent import _emit_call, _emit_step, _emit_thought, run_deterministic
from .llm import (
    LOCAL_PROVIDERS,
    PRESETS,
    AIUnavailable,
    LLMClient,
    LLMError,
    discover_models,
    is_local_endpoint,
)
from .prompts import SYSTEM
from .tools import ScanContext

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# tool name -> phase label shown in the live status line
_PHASE = {
    "ping_sweep": "discovery", "dns_enum": "discovery", "port_scan": "scanning",
    "service_detect": "enum", "os_detect": "enum", "nuclei_scan": "vuln",
    "vuln_scripts": "vuln", "hydra_brute": "brute", "report_finding": "report",
}

# slash commands (command -> one-line description) — also used for TUI autocompletion
_COMMANDS: dict[str, str] = {
    "/scan": "deterministic suite (no LLM) on the target",
    "/target": "set / replace the authorized target",
    "/model": "show or switch the model on the current provider",
    "/provider": "show or switch the AI provider",
    "/effort": "how hard the model thinks (low|medium|high|off)",
    "/findings": "list findings reported so far",
    "/topology": "print the discovered network map",
    "/consent": "toggle auto-approve for high-impact actions (on|off)",
    "/stop": "cancel the currently running agent turn",
    "/clear": "reset the conversation (keeps target + findings)",
    "/dump": "save the full session transcript (default: ~/.local/share/pwner/sessions)",
    "/doctor": "show which external tools are installed / missing + how to install",
    "/help": "show help",
    "/exit": "leave the session",
    "/quit": "leave the session",
}

HELP = r"""[bold]pwner[/bold] — talk to the agent, or use a /command:

  [cyan]<message>[/cyan]            chat / steer the agent (e.g. "scan it", "go deeper on MySQL")
  [cyan]/target <t>[/cyan]          set / replace the authorized target (host · IP · CIDR · domain)
  [cyan]/model \[n|name][/cyan]      show the models this provider serves, or switch to one
  [cyan]/provider \[name][/cyan]     show the providers, or switch to one
  [cyan]/scan \[target][/cyan]       run the deterministic suite (no LLM) on the target
  [cyan]/findings[/cyan]            list the findings reported so far
  [cyan]/topology[/cyan]            print the discovered network map
  [cyan]/consent on|off[/cyan]      toggle auto-approve for high-impact actions (authorized only)
  [cyan]/stop[/cyan]                cancel the agent turn that's currently running (Ctrl-C too)
  [cyan]/clear[/cyan]               reset the conversation (keeps target + findings)
  [cyan]/dump \[path][/cyan]         save the transcript (default: ~/.local/share/pwner/sessions, 0600)
  [cyan]/doctor[/cyan]              show which external tools are installed / missing + install commands
  [cyan]/help[/cyan]                show this help
  [cyan]/exit[/cyan] · [cyan]/quit[/cyan]         leave the session
"""

SPINNER_FRAMES = "⣾⣽⣻⢿⡿⣟⣯⣷"
# slash commands allowed to run while a turn is in-flight (read-only / control)
_BUSY_OK = {"/findings", "/topology", "/topo", "/map", "/help", "/h", "/?", "/consent", "/stop", "/cancel",
            "/model", "/models", "/provider", "/effort",
            "/dump", "/save", "/doctor", "/tools", "/deps"}


def _provider_of(client: LLMClient | None) -> str:
    """Best-effort preset name for a client, by matching its base URL.

    The session is handed a built client rather than a provider name, and a custom
    --base-url matches no preset at all, so this is a label for display and never a
    decision input.
    """
    if client is None:
        return ""
    base = (getattr(client, "base_url", "") or "").rstrip("/")
    for name, preset in PRESETS.items():
        if str(preset.get("base_url", "")).rstrip("/") == base:
            return name
    return ""


def _persist(**fields: str) -> bool:
    """Merge `fields` into the saved config, keeping everything else in it.

    load/update/save rather than save alone: the config file holds the API key too, and
    writing only the changed keys would drop it. Best effort — a session that cannot
    write to disk still works for the rest of its life, so this reports rather than
    raises.
    """
    try:
        from . import config as pwner_config
        cfg = pwner_config.load()
        cfg.update({k: v for k, v in fields.items() if v})
        pwner_config.save(cfg)
        return True
    except OSError:
        return False


class ReplSession:
    """One persistent interactive agent session over a single ScanContext."""

    def __init__(self, ctx: ScanContext, client: LLMClient | None, tui,
                 max_steps: int | None = None, instructions: str = "",
                 provider: str = ""):
        self.ctx = ctx
        self.client = client            # None when no API key: /scan still works
        self.tui = tui
        self.max_steps = max_steps
        self.instructions = instructions
        self.dispatch = tools.build_dispatch(ctx)
        self.messages: list[dict] = []  # conversation history, built on first agent turn
        self.model = "deterministic" if client is None else getattr(client, "model", "?")
        self.provider = provider or _provider_of(client)
        self._busy = False
        self._turn: asyncio.Task | None = None
        self.on_refresh = lambda: None  # host hook (TUI sets this to repaint its status)

    @property
    def busy(self) -> bool:
        return self._busy

    def _refresh(self) -> None:
        try:
            self.on_refresh()
        except Exception:  # noqa: BLE001
            pass

    # ---- agent turn ---------------------------------------------------------
    async def _on_step(self, name: str, args: dict, result: dict) -> None:
        self.tui.steps += 1
        await _emit_step(self.ctx, name, args, result)
        self._refresh()

    async def _on_call(self, name: str, args: dict) -> None:
        self.tui.phase = _PHASE.get(name, self.tui.phase)
        await _emit_call(self.ctx, name, args)
        self._refresh()

    def _on_usage(self, usage: dict) -> None:
        self.tui.add_usage(usage)
        self._refresh()

    async def _on_thought(self, text: str) -> None:
        await _emit_thought(self.ctx, text)

    def _ensure_history(self) -> None:
        if not self.messages:
            tgt = self.ctx.target or "(none yet — set it with set_target from the operator's request)"
            seed = (f"We are in an INTERACTIVE session. Current scope: {tgt}. "
                    f"Respond to the operator conversationally and wait for their instructions — "
                    f"do NOT start scanning until they ask you to act. When they name what to scan "
                    f"(an IP, CIDR, domain, or an interface like 'en0'/'en0 /24'), call set_target "
                    f"to set the scope from their request, then proceed.")
            if self.instructions:
                seed += f"\nStanding operator instructions: {self.instructions}"
            seed += tools._env_note()  # tell the agent which external tools are missing here
            self.messages = [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": seed},
            ]

    async def _run_agent(self, user_text: str) -> None:
        if self.client is None:
            self.tui.log("[yellow]no API key configured — the chat agent needs one. "
                         "Use [bold]/scan[/bold] for a deterministic scan, or restart with "
                         "--api-key / `pwner` setup.[/yellow]")
            return
        # No hard "set a target first" gate: if the operator names what to scan in their message
        # (an IP/CIDR/domain or an interface like en0), the agent calls set_target itself.
        self._ensure_history()
        self.messages.append({"role": "user", "content": user_text})
        ch = self.ctx.operator_channel
        steer = ch.drain if ch is not None else None
        self._busy = True
        self.tui.activity = "thinking"
        self.tui.steps = 0           # per-turn step counter
        self.tui.phase = ""
        self.tui.model = self.model  # for the cost estimate
        self.tui.log("[dim]thinking…[/dim]")  # inline marker right under the operator's message
        self._refresh()
        try:
            interrupt = (lambda: ch.has_pending()) if ch is not None else None
            import os as _os
            reasoning_effort = ((self.ctx.reasoning_effort or "").strip()
                                or (_os.environ.get("PWNER_REASONING_EFFORT") or "").strip()
                                or None)
            text = await self.client.run_turn(
                self.messages, tools.tool_schemas(), self.dispatch,
                max_steps=self.max_steps, reasoning_effort=reasoning_effort, on_step=self._on_step,
                on_call=self._on_call, on_thought=self._on_thought,
                on_usage=self._on_usage, interrupt=interrupt, steer=steer,
                open_work=lambda: tools.open_work_report(self.ctx),
                effort_boost=tools.effort_boost(reasoning_effort or ""))
        except (AIUnavailable, LLMError) as e:
            self.tui.log(f"[red][!] LLM error: {e}[/red]")
            return
        except asyncio.CancelledError:
            self.tui.log("[yellow]turn cancelled[/yellow]")
            raise
        finally:
            self._busy = False
            self._refresh()
        if text:
            self.tui.log(f"[white]{escape(text)}[/white]")

    # ---- turn lifecycle (used by the Textual front-end) ---------------------
    def cancel_turn(self) -> bool:
        if self._turn is not None and not self._turn.done():
            self._turn.cancel()
            return True
        return False

    async def submit(self, line: str) -> bool:
        """Process one operator line. Returns True if the session should exit.

        Routes: a pending consent answer → steering (while busy) → /command → new turn.
        A new agent turn runs as a background task so input stays live meanwhile."""
        line = line.strip()
        if not line:
            return False
        ch = self.ctx.operator_channel

        if ch is not None and ch.consent_pending():
            ch.answer_consent(line)
            self._refresh()
            return False

        if self._turn is not None and not self._turn.done():
            head = line.split()[0].lower()
            if head in ("/stop", "/cancel"):
                self.cancel_turn()
            elif head in ("/exit", "/quit", "/q"):
                self.cancel_turn()
                return True
            elif line.startswith("/") and head in _BUSY_OK:
                await self._command(line)
            elif line.startswith("/"):
                self.tui.log("[dim](busy — /stop to cancel, or wait; plain text steers the agent)[/dim]")
            else:
                ch.push(line)
                self.tui.log(f"[dim]↳ steering: {line}[/dim]")
            return False

        if line.startswith("/"):
            try:
                return await self._command(line)
            except Exception as e:  # noqa: BLE001
                self.tui.log(f"[red][!] {type(e).__name__}: {str(e)[:300]}[/red]")
                return False

        def _reap(t: asyncio.Task) -> None:
            try:
                t.result()
            except asyncio.CancelledError:
                pass
            except Exception as e:  # noqa: BLE001
                self.tui.log(f"[red][!] {type(e).__name__}: {str(e)[:300]}[/red]")
            self._refresh()

        self._turn = asyncio.create_task(self._run_agent(line))
        self._turn.add_done_callback(_reap)
        return False

    # ---- slash commands -----------------------------------------------------
    def _print_findings(self) -> None:
        fs = sorted(self.ctx.findings, key=lambda f: _SEV_ORDER.get(f.get("severity"), 5))
        if not fs:
            self.tui.log("[dim]no findings reported yet.[/dim]")
            return
        self.tui.log(f"[bold]{len(fs)} finding(s):[/bold]")
        for i, f in enumerate(fs, 1):
            loc = f.get("host", "")
            if f.get("port"):
                loc += f":{f['port']}"
            sev = str(f.get("severity", "?")).upper()
            color = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "orange3",
                     "LOW": "yellow", "INFO": "blue"}.get(sev, "white")
            self.tui.log(f"  [{i}] [bold {color}][{sev}][/bold {color}] {f.get('title','')} "
                         f"[cyan]@ {loc}[/cyan]")

    def _doctor(self) -> None:
        """Show which external tools are installed vs missing, what each powers, and a
        paste-ready install block for the missing ones."""
        st = tools.dependency_status()
        self.tui.log("[bold]external tool status[/bold] [dim](pwner shells out to these)[/dim]")
        for t in st:
            mark = "[green]✓[/green]" if t["installed"] else "[red]✗[/red]"
            tag = " [dim](core)[/dim]" if t.get("core") else ""
            self.tui.log(f"  {mark} [bold]{t['name']}[/bold]{tag} [dim]— {t['enables']}[/dim]")
        missing = [t for t in st if not t["installed"]]
        if not missing:
            self.tui.log("[green]all tools present.[/green]")
            return
        self.tui.log(f"\n[yellow]{len(missing)} missing.[/yellow] Install (run these yourself, e.g. "
                     f"prefix with [bold]![/bold] in this prompt):")
        for t in missing:
            self.tui.log(f"  [dim]# {t['name']} → {t['enables']}[/dim]\n  {escape(t['install'])}")

    def _dump_transcript(self, arg: str = "") -> str:
        """Write the full session transcript (everything shown so far) to a text file.

        `arg` is an optional path or directory. With no argument the file goes to
        ~/.local/share/pwner/sessions/, NOT the working directory: the transcript records
        whatever the engagement turned up — credentials, session cookies, hashes — and
        dropping that into whatever repo you are standing in is how it reaches a commit.
        Written owner-only either way. Returns the absolute path written."""
        import datetime
        import os

        from . import config as pwner_config
        name = f"pwner-session-{datetime.datetime.now():%Y%m%d-%H%M%S}.txt"
        if arg.strip():
            path = os.path.expanduser(arg.strip())
            if os.path.isdir(path):
                path = os.path.join(path, name)
        else:
            path = os.path.join(pwner_config.sessions_dir(), name)
        header = (
            f"# pwner session transcript\n"
            f"# saved: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f"# target: {self.ctx.target or '(none)'} · model: {self.model} · "
            f"findings: {len(self.ctx.findings)}\n"
            f"#\n"
            f"# UNREDACTED. This records the whole session, so any credential, session\n"
            f"# cookie or hash the engagement turned up is in here in cleartext. The file\n"
            f"# is owner-only (0600); keep it that way, and do not commit it.\n"
            f"{'=' * 70}\n\n")
        body = "\n".join(self.tui.transcript)
        with os.fdopen(pwner_config.open_private(path), "w", encoding="utf-8") as f:
            f.write(header + body + "\n")
        return os.path.abspath(path)

    # ---- provider / model ---------------------------------------------------
    async def _cmd_model(self, arg: str) -> None:
        """Show the models this provider serves, or switch to one.

        Switching used to mean leaving the session, running `pwner setup` and starting
        over, which threw away the target, the findings and the conversation along with
        the model. Here only the model name changes; everything else survives.
        """
        if self.client is None:
            self.tui.log("[yellow]running without a model (--no-ai). Start a session with "
                         "a provider to use the agent.[/yellow]")
            return
        found = await discover_models(self.client.base_url, self.client.api_key)
        if not arg:
            self.tui.log(f"provider: [cyan]{self.provider or '(custom)'}[/cyan] "
                         f"[dim]{self.client.base_url}[/dim]")
            self.tui.log(f"model: [cyan]{self.client.model}[/cyan]")
            if found:
                for i, name in enumerate(found[:20], 1):
                    mark = " [green](current)[/green]" if name == self.client.model else ""
                    self.tui.log(f"  {i}. {escape(name)}{mark}")
                self.tui.log("[dim]switch with `/model <number|name>`[/dim]")
            else:
                self.tui.log(f"[dim]{self.client.base_url} did not answer /models — "
                             f"`/model <name>` still works if you know the name.[/dim]")
            return
        if self.busy:
            self.tui.log("[yellow]a turn is running — /stop it first, or wait.[/yellow]")
            return
        name = arg
        if arg.isdigit() and found and 1 <= int(arg) <= len(found):
            name = found[int(arg) - 1]
        elif found and name not in found:
            self.tui.log(f"[yellow]{escape(name)} is not on that server. "
                         f"`/model` lists what is.[/yellow]")
            return
        self.client.model = name
        self.model = name
        saved = _persist(model=name)
        self.tui.log(f"[cyan]model → {escape(name)}[/cyan]"
                     + ("" if saved else " [dim](not saved: config not writable)[/dim]"))
        self._refresh()

    def _cmd_effort(self, arg: str) -> None:
        """Show or set how hard the model is asked to think, for the rest of the session.

        Not persisted to the config on purpose: the right effort depends on what you are
        doing right now, and a saved "high" would quietly bill every later session for
        deliberation it did not need. It also stays unset by default, because a model that
        does not know `reasoning_effort` answers 400 to it rather than ignoring it.
        """
        cur = (self.ctx.reasoning_effort or "").strip()
        want = (arg or "").strip().lower()
        if not want:
            self.tui.log(f"effort: [cyan]{cur or '(unset — provider default)'}[/cyan] "
                         f"[dim]· low|medium|high|off · raised one notch for a few steps "
                         f"after a tool reports something significant[/dim]")
            return
        if want in ("off", "none", "unset", "default"):
            self.ctx.reasoning_effort = ""
            self.tui.log("[cyan]effort → unset[/cyan] [dim](the parameter is no longer sent)[/dim]")
            return
        if want not in tools.EFFORT_LEVELS:
            self.tui.log(f"[yellow]effort must be one of "
                         f"{', '.join(tools.EFFORT_LEVELS)}, or off.[/yellow]")
            return
        self.ctx.reasoning_effort = want
        self.tui.log(f"[cyan]effort → {want}[/cyan] [dim](boosts to "
                     f"{tools.effort_boost(want)} after a significant result)[/dim]")

    async def _cmd_provider(self, arg: str) -> None:
        """Show the providers, or switch to one."""
        if not arg:
            here = self.client.base_url if self.client else ""
            self.tui.log(f"provider: [cyan]{self.provider or '(custom)'}[/cyan] "
                         f"[dim]{here}[/dim]")
            for name in PRESETS:
                tag = " [green](current)[/green]" if name == self.provider else ""
                local = " [dim]local, no key needed[/dim]" if name in LOCAL_PROVIDERS else ""
                self.tui.log(f"  {name}{tag}{local}")
            self.tui.log("[dim]switch with `/provider <name>`; `pwner --pick` also asks "
                         "for a key and base URL[/dim]")
            return
        if self.busy:
            self.tui.log("[yellow]a turn is running — /stop it first, or wait.[/yellow]")
            return
        name = arg.lower()
        if name not in PRESETS:
            self.tui.log(f"[yellow]unknown provider {escape(name)}. "
                         f"known: {', '.join(PRESETS)}[/yellow]")
            return
        from . import config as pwner_config
        saved = pwner_config.load()
        preset = PRESETS[name]
        base = str(preset.get("base_url") or "")
        local = name in LOCAL_PROVIDERS
        # A saved key belongs to whichever provider it was saved under. Carrying it to a
        # different hosted provider is the most likely way this goes wrong, so it is
        # carried (the operator may well have one key for several) but said out loud.
        key = "" if local else str(saved.get("api_key") or "")
        reused_from = str(saved.get("provider") or "")
        model = str(preset.get("model") or "")
        if local or is_local_endpoint(base):
            found = await discover_models(base, key)
            if found:
                model = found[0]
            elif not model:
                self.tui.log(f"[yellow]{base} did not answer /models — is the server "
                             f"running? Provider not changed.[/yellow]")
                return
        try:
            client = LLMClient(key, base, model)
        except AIUnavailable as e:
            self.tui.log(f"[yellow]{e} for {name}. Set PWNER_API_KEY and restart, or run "
                         f"`pwner --pick`. Provider not changed.[/yellow]")
            return
        self.client = client
        self.provider = name
        self.model = model
        persisted = _persist(provider=name, base_url=base, model=model)
        self.tui.log(f"[cyan]provider → {name}[/cyan] [dim]{base}[/dim]")
        self.tui.log(f"[cyan]model → {escape(model)}[/cyan]"
                     + ("" if persisted else " [dim](not saved: config not writable)[/dim]"))
        if key and reused_from and reused_from != name:
            self.tui.log(f"[yellow]reusing the API key saved for {reused_from}. If it is not "
                         f"valid for {name} the first request will fail with 401.[/yellow]")
        self._refresh()

    async def _command(self, line: str) -> bool:
        """Handle a /command. Returns True if the session should exit."""
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("/exit", "/quit", "/q"):
            return True
        if cmd in ("/help", "/h", "/?"):
            self.tui.log(HELP)
        elif cmd == "/target":
            if arg:
                self.ctx.target = arg
                self.tui.log(f"[cyan]target → {arg}[/cyan] [dim](authorized-use only)[/dim]")
                if self.messages:  # keep the running agent in sync
                    self.messages.append({"role": "user",
                                          "content": f"[OPERATOR] The authorized target is now: {arg}"})
            else:
                self.tui.log(f"target: [cyan]{self.ctx.target or '(none)'}[/cyan]")
        elif cmd in ("/model", "/models"):
            await self._cmd_model(arg)
        elif cmd == "/provider":
            await self._cmd_provider(arg)
        elif cmd == "/effort":
            self._cmd_effort(arg)
        elif cmd == "/scan":
            target = arg or self.ctx.target
            if not target:
                self.tui.log("[yellow]no target — `/scan <target>` or `/target <t>` first.[/yellow]")
            else:
                self.ctx.target = target
                new, summary = await run_deterministic(self.ctx, "top-1000")
                seen = {(f.get("title"), f.get("host"), f.get("port")) for f in self.ctx.findings}
                for f in new:  # surface deterministic findings to /findings too
                    if (f.get("title"), f.get("host"), f.get("port")) not in seen:
                        self.ctx.findings.append(f)
                self.tui.log(f"[dim]{summary}[/dim]")
        elif cmd == "/findings":
            self._print_findings()
        elif cmd in ("/topology", "/topo", "/map"):
            self.tui.render_topology()
        elif cmd == "/consent":
            a = arg.lower()
            if a in ("on", "yes", "true"):
                self.ctx.auto_consent = True
                self.tui.log("[yellow]auto-consent ON — high-impact actions inside the scope are "
                             "auto-approved. A scope change still asks you. "
                             "Authorized targets only.[/yellow]")
            elif a in ("off", "no", "false"):
                self.ctx.auto_consent = False
                # Also drop remembered approvals: _consent() treats ANY earlier "approved"
                # as blanket consent for the rest of the session, so without this the
                # "will prompt" message below would be false whenever one was granted.
                retracted = sum(1 for r in self.ctx.consent_requests
                                if r.get("decision") == "approved")
                self.ctx.consent_requests.clear()
                extra = f" ({retracted} earlier approval(s) retracted)" if retracted else ""
                self.tui.log(f"[cyan]auto-consent OFF — high-impact actions will prompt "
                             f"[y/N].{extra}[/cyan]")
            else:
                state = "ON" if self.ctx.auto_consent else "OFF"
                self.tui.log(f"auto-consent: [bold]{state}[/bold]  (use `/consent on|off`)")
        elif cmd in ("/stop", "/cancel"):
            if not self.cancel_turn():
                self.tui.log("[dim]nothing running.[/dim]")
        elif cmd == "/clear":
            self.messages = []
            self.tui.log("[dim]conversation cleared (target + findings kept).[/dim]")
        elif cmd in ("/doctor", "/tools", "/deps"):
            self._doctor()
        elif cmd in ("/dump", "/save"):
            try:
                path = self._dump_transcript(arg)
                self.tui.log(f"[green]transcript saved → {path}[/green] "
                             f"[dim]({len(self.tui.transcript)} lines)[/dim]")
            except OSError as e:
                self.tui.log(f"[red][!] could not write transcript: {e}[/red]")
        else:
            self.tui.log(f"[yellow]unknown command {cmd} — try /help[/yellow]")
        return False

    # ---- plain fallback loop (non-TTY / piped) ------------------------------
    async def loop(self) -> int:
        """Run the full-screen Textual TUI when possible, else a plain sequential loop."""
        import sys
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                from .app import run_app
                return await run_app(self)
            except Exception as e:  # noqa: BLE001 — never trap the user in a broken TUI
                self.tui.log(f"[dim](TUI unavailable: {type(e).__name__}: {e} — plain mode)[/dim]")
        return await self._loop_plain()

    async def _loop_plain(self) -> int:
        mode = "agent" if self.client is not None else "deterministic (/scan only — no API key)"
        self.tui.log(f"[bold]interactive session[/bold] [dim]· {mode}[/dim]")
        self.tui.log("[dim]type a message · /help for commands · /exit to quit[/dim]\n")
        while True:
            tgt = self.ctx.target or "no target"
            self.tui.console.print(f"[bold cyan]pwner[/bold cyan] [dim]{tgt}[/dim] [bold]❯[/bold] ", end="")
            try:
                line = await asyncio.to_thread(input, "")
            except (EOFError, KeyboardInterrupt):
                self.tui.log("\n[dim]bye.[/dim]")
                return 0
            line = line.strip()
            if not line:
                continue
            try:
                if line.startswith("/"):
                    if await self._command(line):
                        self.tui.log("[dim]bye.[/dim]")
                        return 0
                else:
                    await self._run_agent(line)
            except KeyboardInterrupt:
                self.tui.log("\n[yellow][interrupted][/yellow]")
            except Exception as e:  # noqa: BLE001 — a turn error must not kill the session
                self.tui.log(f"[red][!] {type(e).__name__}: {str(e)[:300]}[/red]")

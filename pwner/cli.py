"""Terminal entry point for pwner."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__
from .agent import run_agentic, run_deterministic
from .llm import AIUnavailable, LLMClient, discover_models, is_local_endpoint, resolve_config
from .tools import ScanContext
from .tui import TUI

_BANNER = r"""
   ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗
   ██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗
   ██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
   ██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
   ██║     ╚███╔███╔╝██║ ╚████║███████╗██║  ██║
   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
   autonomous agentic NETWORK pentest · authorized use only
"""


def _add_common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("target", help="host, IP, CIDR, or domain to test (you MUST be authorized)")
    sp.add_argument("--ports", default="top-1000", help="port preset or list (default top-1000)")
    sp.add_argument("--rate", type=int, default=1000, help="nmap --max-rate (default 1000)")
    sp.add_argument("--timing", default="T4", help="nmap timing template (default T4)")
    sp.add_argument("--json", action="store_true", help="emit JSON instead of text")


def _add_llm(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--provider", default=None,
                    help="openai|deepseek|anthropic|gemini|ollama|lemonade (presets; default openai). Anything else OpenAI-compatible: use --base-url")
    sp.add_argument("--model", default=None, help="override model name")
    sp.add_argument("--api-key", default=None, help="override API key (or set PWNER_API_KEY)")
    sp.add_argument("--base-url", default=None, help="override base URL (or set PWNER_BASE_URL)")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwner", description="Autonomous agentic NETWORK penetration-testing tool. "
        "Authorized use only — never scan hosts you don't own or have written permission to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"pwner {__version__}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="agentic scan (the default command)")
    _add_common(scan)
    _add_llm(scan)
    scan.add_argument("--no-ai", action="store_true",
                      help="skip the LLM; run the deterministic full suite")
    scan.add_argument("--max-steps", type=int, default=0, help="max agent tool-calling steps (0 = unlimited, default)")
    scan.add_argument("--concurrency", type=int, default=20, help="parallel host scans for a range (default 20)")
    scan.add_argument("--range-cap", type=int, default=4096, help="max addresses in a CIDR before refusing (default 4096)")
    scan.add_argument("--auto-consent", action="store_true",
                      help="auto-approve consent gates for high-impact actions. Use ONLY on targets you are authorized to test.")
    scan.add_argument("-i", "--interactive", action="store_true",
                      help="prompt [y/N] before high-impact actions (brute-force etc.) instead of auto-deny")
    scan.add_argument("--instructions", default="",
                      help="operator steering for the agent (e.g. 'focus on the database, skip DNS')")
    scan.add_argument("--nuclei-severity", default="low,medium,high,critical",
                      help="nuclei severity filter (default low,medium,high,critical; use high,critical for a fast pass)")

    chat = sub.add_parser("chat", help="interactive agent session (OpenCode-style REPL)")
    chat.add_argument("target", nargs="?", default="",
                      help="optional target to start with (you can also set it later via /target)")
    _add_llm(chat)
    chat.add_argument("--no-ai", action="store_true",
                      help="start without the LLM (deterministic /scan only)")
    chat.add_argument("--max-steps", type=int, default=0, help="max agent tool-calling steps per turn (0 = unlimited, default)")
    chat.add_argument("--auto-consent", action="store_true",
                      help="auto-approve consent gates. Use ONLY on targets you are authorized to test.")
    chat.add_argument("--instructions", default="", help="operator steering injected into the agent's brief")
    chat.add_argument("--nuclei-severity", default="low,medium,high,critical",
                      help="nuclei severity filter (default low,medium,high,critical)")

    ports = sub.add_parser("ports", help="quick port scan only (no agent)")
    _add_common(ports)

    vuln = sub.add_parser("vuln", help="vulnerability scan only (no agent)")
    _add_common(vuln)

    dns = sub.add_parser("dns", help="DNS enumeration only")
    dns.add_argument("domain", help="domain to enumerate")
    dns.add_argument("--json", action="store_true")

    doc = sub.add_parser("doctor", help="check which external tools are installed")
    doc.add_argument("--json", action="store_true", help="machine-readable status")

    return p


def _run_doctor(as_json: bool = False) -> int:
    """Report which external binaries are present, what each one powers, and a paste-ready
    install command for the missing ones. Exit 0 if everything core is present, else 1 —
    so it is usable as a setup check in a script or a container build."""
    from . import tools
    st = tools.dependency_status()
    if as_json:
        print(json.dumps(st, indent=2))
    else:
        print("external tools pwner shells out to:\n")
        for t in st:
            mark = "✓" if t["installed"] else "✗"
            tag = "  (core)" if t.get("core") else ""
            print(f"  {mark} {t['name']}{tag}")
            print(f"      powers: {t['enables']}")
            if not t["installed"]:
                print(f"      install: {t['install']}")
        missing = [t for t in st if not t["installed"]]
        core_missing = [t for t in missing if t.get("core")]
        print()
        if not missing:
            print("all present — every tool is available.")
        else:
            print(f"{len(missing)} missing, {len(st) - len(missing)} present. "
                  f"Each only matters when its tools are used.")
            print("\ninstall the missing ones:\n")
            for t in missing:
                print(f"  {t['install']}")
            if any(t["name"] == "nuclei" for t in missing):
                print("\n  # then, one time, fetch the templates:\n  nuclei -update-templates")
        if core_missing:
            print("\nnmap is required and is missing — scanning will not work until it is "
                  "installed.")
    return 1 if any(t.get("core") for t in st if not t["installed"]) else 0


def _print_findings(findings: list[dict]) -> None:
    if not findings:
        print("\nNo findings reported.")
        return
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: order.get(f.get("severity"), 5))
    print("\n" + "=" * 60)
    print(f"FINDINGS ({len(findings)})")
    print("=" * 60)
    for i, f in enumerate(findings, 1):
        loc = f.get("host", "")
        if f.get("port"):
            loc += f":{f['port']}"
        print(f"\n[{i}] [{f.get('severity','?').upper()}] {f.get('title','')}")
        print(f"    host: {loc}   service: {f.get('service','')}   confidence: {f.get('confidence','')}")
        if f.get("evidence"):
            print(f"    evidence: {f['evidence'][:400]}")
        if f.get("remediation"):
            print(f"    fix: {f['remediation'][:300]}")


async def _run_chat(args: argparse.Namespace) -> int:
    """Open the OpenCode-style interactive agent session (persistent chat REPL)."""
    from .repl import ReplSession
    from .tools import OperatorChannel

    target = getattr(args, "target", "") or ""
    auto_consent = getattr(args, "auto_consent", False)
    # managed channel + force_terminal when we have a real TTY (live bottom-pinned input)
    live = sys.stdin.isatty() and sys.stdout.isatty()
    ctx = ScanContext(target=target, auto_consent=auto_consent, interactive=True,
                      operator_channel=OperatorChannel(managed=live),
                      nuclei_severity=getattr(args, "nuclei_severity", "low,medium,high,critical"))
    tui = TUI(enabled=True, force_terminal=True if live else None)
    ctx.tui = tui
    print(_BANNER)

    client: LLMClient | None = None
    if not getattr(args, "no_ai", False):
        try:
            key, base, model = resolve_config(args.provider, args.api_key, args.base_url, args.model)
        except Exception as e:  # noqa: BLE001
            tui.log(f"[red]config error: {e}[/red]")
            key = ""
        # A server on your own machine usually has no key at all, so the presence of a
        # key is not what decides whether the agent can run — reachability is.
        if key or is_local_endpoint(base):
            if not model:
                found = await discover_models(base, key)
                if found:
                    model = found[0]
                    tui.log(f"[dim]model not set — using {model} "
                            f"({len(found)} available on that server)[/dim]")
                else:
                    tui.log(f"[yellow]no model set and {base} did not answer /models — "
                            f"pass --model, or run `pwner setup`.[/yellow]")
            if model:
                try:
                    client = LLMClient(key, base, model)
                    tui.log(f"[dim]model={model} · provider base={base}[/dim]")
                except AIUnavailable as e:
                    tui.log(f"[yellow]{e}[/yellow]")
        else:
            tui.log("[yellow]no API key configured — deterministic mode. `/scan` works; "
                    "set a key (restart with --api-key, or run `pwner` to configure) for the chat agent.[/yellow]")

    session = ReplSession(ctx, client, tui, max_steps=(getattr(args, "max_steps", 0) or None),
                          instructions=getattr(args, "instructions", ""))
    return await session.loop()


async def _run(args: argparse.Namespace) -> int:
    if args.command == "doctor":
        return _run_doctor(getattr(args, "json", False))
    if args.command == "chat":
        return await _run_chat(args)
    target = getattr(args, "target", None) or getattr(args, "domain", None)
    auto_consent = getattr(args, "auto_consent", False)
    interactive = getattr(args, "interactive", False) or (sys.stdin.isatty() and not auto_consent)
    channel = None
    if interactive:
        from .tools import OperatorChannel
        channel = OperatorChannel()
    ctx = ScanContext(target=target, max_rate=getattr(args, "rate", 1000),
                      timing=getattr(args, "timing", "T4"),
                      concurrency=getattr(args, "concurrency", 20),
                      auto_consent=auto_consent,
                      interactive=interactive,
                      range_cap=getattr(args, "range_cap", 4096),
                      nuclei_severity=getattr(args, "nuclei_severity", "low,medium,high,critical"),
                      operator_channel=channel)
    print(_BANNER)
    if interactive:
        print("[i] live steering ON — type a message + Enter to steer the agent mid-run; "
              "answer y/N at consent prompts.\n")

    if args.command == "ports":
        from . import tools
        try:
            res = await tools.port_scan(ctx, {"target": args.target, "ports": args.ports})
        except tools.ToolError as e:
            print(f"[!] {e}")
            return 1
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            for h in res["hosts"]:
                print(f"\n=== {h['address']} ({h['status']}) ===")
                for p in h["open_ports"]:
                    s = p["service"]
                    print(f"  {p['port']}/{p['protocol']}  {s.get('name','')}  "
                          f"{s.get('product','')} {s.get('version','')}".rstrip())
        return 0

    if args.command == "vuln":
        from . import tools
        try:
            res = await tools.vuln_scan(ctx, {"target": args.target, "ports": args.ports})
        except tools.ToolError as e:
            print(f"[!] {e}")
            return 1
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            for h in res["hosts"]:
                print(f"\n=== {h['address']} ===")
                for p in h["open_ports"]:
                    for sc in p.get("scripts", []):
                        print(f"  [{p['port']}] {sc['id']}\n      {(sc['output'] or '').strip()[:600]}")
        return 0

    if args.command == "dns":
        from . import tools
        try:
            res = await tools.dns_enum(ctx, {"domain": args.domain})
        except tools.ToolError as e:
            print(f"[!] {e}")
            return 1
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"\n=== {res['domain']} ===")
            for rtype, vals in res["records"].items():
                print(f"  {rtype}: {', '.join(vals) if vals else '(none)'}")
        return 0

    # scan (agentic or deterministic) — wrapped in the live TUI (log + topology panel)
    use_tui = not getattr(args, "json", False) and sys.stdout.isatty()
    tui = TUI(enabled=use_tui)
    ctx.tui = tui
    with tui:
        if getattr(args, "no_ai", False):
            findings, summary = await run_deterministic(ctx, args.ports)
        else:
            try:
                cfg = resolve_config(args.provider, args.api_key, args.base_url, args.model)
            except Exception as e:  # noqa: BLE001
                tui.log(f"[!] config error: {e}")
                return 1
            key, base, model = cfg
            if not key:
                tui.log("[!] no API key configured — running the deterministic suite.")
                tui.log("    run `pwner` (no args) to set one, or pass --api-key.\n")
                findings, summary = await run_deterministic(ctx, args.ports)
            else:
                try:
                    findings, summary = await run_agentic(ctx, cfg, (args.max_steps or None),
                                                          getattr(args, "instructions", ""))
                except AIUnavailable as e:
                    tui.log(f"[!] {e}\n[!] falling back to the deterministic suite.")
                    findings, summary = await run_deterministic(ctx, args.ports)

    if args.json:
        print(json.dumps({"findings": findings, "summary": summary}, indent=2))
    else:
        _print_findings(findings)
        print("\n" + "=" * 60)
        print("AGENT SUMMARY")
        print("=" * 60)
        print(f"\n{summary}\n")
    return 0


def _launch_default() -> int:
    """`pwner` with no args in a terminal: run the one-time setup wizard the FIRST
    time (no saved key), then on every later run skip straight into the session using
    the saved provider/key — ask once, never again."""
    from . import config as pwner_config
    if pwner_config.load().get("api_key"):
        # already configured — no questions, straight into the interactive session
        args = _parser().parse_args(["chat"])  # provider/key resolve from saved config
        try:
            return asyncio.run(_run(args))
        except KeyboardInterrupt:
            print("\n[!] interrupted")
            return 130
    return _run_wizard()


def _run_wizard() -> int:
    """One-time interactive setup: provider + API key (saved), then open the session.
    Re-run any time with `pwner setup`."""
    from . import config as pwner_config
    from .llm import LOCAL_PROVIDERS, PRESETS
    saved = pwner_config.load()
    print(_BANNER)
    print("Welcome to pwner — one-time setup (re-run later with `pwner setup`).\n")
    provider = input(f"Provider [{'/'.join(PRESETS)}] "
                     f"(default {saved.get('provider', 'openai')}): ").strip().lower() \
               or saved.get("provider", "openai")

    local = provider in LOCAL_PROVIDERS
    preset = PRESETS.get(provider, {})
    base_url = ""
    model = ""
    if local:
        # A server on your own hardware is on whatever port and host you gave it, and
        # serves whatever models that machine has pulled — neither is guessable.
        default_base = str(saved.get("base_url") or preset.get("base_url", ""))
        base_url = input(f"Base URL (default {default_base}): ").strip() or default_base
        print("  looking for models on that server…")
        found = asyncio.run(discover_models(base_url))
        if found:
            for i, name in enumerate(found[:12], 1):
                print(f"    {i}. {name}")
            pick = input(f"Model [number or name] (default {found[0]}): ").strip()
            model = found[int(pick) - 1] if pick.isdigit() and 1 <= int(pick) <= len(found) \
                else (pick or found[0])
        else:
            print("  could not reach it — is the server running? You can set the model by hand.")
            model = input(f"Model (default {saved.get('model') or preset.get('model') or 'none'}): ")\
                .strip() or str(saved.get("model") or preset.get("model") or "")

    saved_key = saved.get("api_key", "")
    if local and is_local_endpoint(base_url):
        hint = "(optional — most local servers have none, Enter to skip)"
    else:
        hint = "(saved)" if saved_key else "(none — Enter to run deterministic)"
    api_key = input(f"API key {hint}: ").strip() or (saved_key if not local else "")
    target = input("Target (host / IP / CIDR / domain — optional, set later with /target): ").strip()

    if api_key or local:
        save_yn = input("Save settings to ~/.config/pwner/config.json? [Y/n]: ").strip().lower()
        if save_yn != "n":
            entry = {"provider": provider, "api_key": api_key}
            if base_url:
                entry["base_url"] = base_url
            if model:
                entry["model"] = model
            pwner_config.save(entry)
    argv = ["chat"]
    if target:
        argv.append(target)
    argv += ["--provider", provider]
    if api_key:
        argv += ["--api-key", api_key]
    if base_url:
        argv += ["--base-url", base_url]
    if model:
        argv += ["--model", model]
    args = _parser().parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        return 130


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        if sys.stdin.isatty() and sys.stdout.isatty():
            return _launch_default()
        _parser().print_help()
        return 0
    if argv[0] in ("setup", "config", "reconfigure"):
        return _run_wizard()  # force the setup prompts again (change provider/key)
    known = {"scan", "chat", "ports", "vuln", "dns", "doctor", "--version", "-h", "--help"}
    if argv[0] not in known and not argv[0].startswith("-"):
        argv = ["scan", *argv]  # `pwner <target>` == `pwner scan <target>`
    args = _parser().parse_args(argv)
    if args.command is None:
        _parser().print_help()
        return 0
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

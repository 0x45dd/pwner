# pwner

Autonomous, **agentic** NETWORK penetration-testing tool for the terminal.

![pwner session](demo/session.gif)

*A real session, unedited: the agent is told "the web service on 8080 is the target — get
authenticated access", reads the login page, notices the hint that the password is the
device serial, pulls the serial from an unauthenticated `/api/status`, logs in, and reports
what it found. The target is [`demo/target.py`](demo/target.py) — a deliberately weak
service that binds `127.0.0.1` and nothing else. Re-render it with
[`demo/session.tape`](demo/session.tape).*

`pwner` is an LLM-driven agent that plans and executes a full network pentest — live-host
discovery, port scanning, service/version fingerprinting, OS detection and known-CVE /
misconfiguration detection, and, when the target warrants it and you approve, **active
exploitation and post-exploitation**: credential attacks, remote command execution, reverse
shells, credential dumping and Active Directory attack paths. It reports confirmed findings
with severity, evidence and remediation. It wraps **nmap**, **nuclei**, **netexec**,
**impacket**, **hydra** and friends for the actions, and an **OpenAI-compatible** LLM for the
reasoning.

> ⚠️ **Authorized use only.** Only test hosts, IPs, CIDRs or domains you own or have explicit
> written permission to test. Discovery, fingerprinting and detection are read-only and run
> freely; everything active — brute-force, password spraying, exploitation, remote command
> execution, reverse shells, credential dumping and exfiltration — is **denied by default and
> runs only with your consent**, and every tool is locked to the scope you name. The safety
> model is consent + scope, not an absence of teeth: pwner *can* break in when you let it, so
> unauthorized use is both illegal and on you.

## Install

Python **3.10+**, and **nmap is the only hard requirement** — everything else is optional
and only matters when the tools that need it are used. Install pwner first, then run
**`pwner doctor`**: it tells you exactly what is missing, what each missing tool would
enable, and the install command *for the system you are on*.

```bash
git clone https://github.com/0x45dd/pwner.git && cd pwner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pwner doctor              # what's installed, what's missing, how to get it
```

<details>
<summary><b>uv / pipx instead of venv</b></summary>

```bash
uv venv && uv pip install -e .          # uv
pipx install -e .                        # pipx, if you only want the `pwner` command
```
</details>

### The external tools

`pwner doctor` prints this for your machine, with per-platform commands. The whole table
except nmap is optional:

| Tool | Enables | macOS | Debian/Ubuntu/Kali | Arch | Fedora |
|---|---|---|---|---|---|
| **nmap** *(required)* | all scanning | `brew install nmap` | `apt install nmap` | `pacman -S nmap` | `dnf install nmap` |
| nuclei | `nuclei_scan` | `brew install nuclei` | [binary](https://github.com/projectdiscovery/nuclei/releases) or `go install` | AUR (`nuclei-bin`) | `dnf install nuclei` |
| hydra | `hydra_brute` | `brew install hydra` | `apt install hydra` | `pacman -S hydra` | `dnf install hydra` |
| snmpwalk | `snmp_check` | `brew install net-snmp` | `apt install snmp` | `pacman -S net-snmp` | `dnf install net-snmp-utils` |
| hashcat | `hash_crack` | `brew install hashcat` | `apt install hashcat` | `pacman -S hashcat` | `dnf install hashcat` |
| searchsploit | `exploit_search` | `brew install exploitdb` | `apt install exploitdb` *(Kali only)* | `pacman -S exploitdb` | [clone it](https://gitlab.com/exploit-database/exploitdb) |
| impacket | AD roasting, `secretsdump`, `win_exec` | `pipx install impacket` | ← same | ← same | ← same |
| netexec | SMB/LDAP enum, spraying, WinRM/SSH exec | `pipx install git+https://github.com/Pennyw0rth/NetExec` | ← same | ← same | ← same |
| certipy | `adcs_find` | `pipx install certipy-ad` | ← same | ← same | ← same |
| bloodhound-python | `bloodhound_collect` | `pipx install bloodhound` | ← same | ← same | ← same |
| kerbrute | `kerbrute_userenum` | [prebuilt binary](https://github.com/ropnop/kerbrute/releases) | ← same | ← same | ← same |

After installing nuclei, fetch its templates once: `nuclei -update-templates` (~14k files).

**Gotchas worth knowing up front:**

- **netexec is not on PyPI.** `pipx install netexec` fails; install it from the repo as
  shown above.
- **searchsploit is packaged by Homebrew, Arch and Kali — but not by Debian/Ubuntu or
  Fedora.** There, clone [exploitdb](https://gitlab.com/exploit-database/exploitdb) and
  symlink `searchsploit` onto your `PATH`. Same story for **nuclei**, which Homebrew and
  Fedora carry but Debian and the official Arch repos do not.
- **kerbrute has no arm64 build** — only `linux_386` and `linux_amd64`. On Apple Silicon
  or arm64 Linux, build it with `go install github.com/ropnop/kerbrute@latest`.
- **macOS + pipx:** Homebrew Python 3.12/3.13 can report an empty `platform.mac_ver()`,
  which `uv` rejects with "Broken Python installation" and breaks `pipx install`. Pin an
  interpreter that works: `pipx install --python "$(brew --prefix python@3.11)/bin/python3.11" impacket`.
- **Run as root for real host discovery.** Unprivileged, nmap cannot send ICMP/ARP or SYN
  probes, so `ping_sweep` falls back to TCP-connect probes and misses hosts, and
  `os_detect` does not work at all. Use `sudo pwner` on a LAN sweep.

### Docker

The least-setup route: one image with the whole toolchain, nothing installed on your host.

```bash
docker build -t pwner .
docker run --rm -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v pwner-config:/root/.config/pwner \
  -v pwner-sessions:/root/.local/share/pwner \
  pwner
```

- `--net=host` and `NET_RAW`/`NET_ADMIN` are what let nmap do SYN scans and ICMP/ARP
  discovery. Without them nmap silently degrades to slower connect scans and finds fewer
  hosts — the container will *work*, just worse.
- The two volumes persist your saved API key and your `/dump` transcripts. Without them
  both vanish when the container exits.
- `searchsploit` is left out by default because it needs the full exploit corpus (~1 GB)
  for one optional tool; `exploit_search` falls back to the local nuclei template index.
  Add it with `docker build --build-arg WITH_EXPLOITDB=1 -t pwner .`.
- On arm64, kerbrute is skipped (no upstream build) — `pwner doctor` will say so.

> The Dockerfile is provided as-is and **has not been built and run end-to-end yet**; the
> package names and release assets in it were checked against the Debian archive and the
> upstream release APIs, but treat the first build as untested.

## First run — just type `pwner`

The **first** time you run `pwner` with no arguments it opens a **one-time setup wizard**
(provider, API key, optional target — the key is saved to `~/.config/pwner/config.json`).
**Every run after that skips the questions** and drops you straight into the session using
the saved key. Re-run the wizard any time with **`pwner setup`** to change provider/key.

The session itself is a **full-screen interactive TUI** (OpenCode / Claude-Code-style, built
on [Textual](https://textual.textualize.io/)): a **fixed input box docked at the bottom**, a
**scrolling log above it** that streams the agent's reasoning (🧠) and tool activity in plain
language, and a header showing `target · model` plus an **animated status** while it works.
The input never drifts — output scrolls inside the log panel, not the whole terminal.

It's **conversational**: greet it or ask a question and it just answers; it only scans when
you ask it to. You can **type while it's working** — plain text is injected as live steering;
`/stop` or `Ctrl-C` cancels the current turn; a consent `[y/N]` prompt is answered from the
box. `/`-commands have inline autocompletion, and the whole conversation + findings persist
across turns. Without a terminal (piped/scripted) it falls back to a plain sequential prompt.

```
$ pwner
   ██████╗ ...
   autonomous agentic NETWORK pentest · authorized use only

Welcome to pwner — one-time setup (re-run later with `pwner setup`).

Provider [openai/deepseek/anthropic/gemini/ollama] (default openai): deepseek
API key (none — Enter to run deterministic): sk-...
Target (host / IP / CIDR / domain — optional, set later with /target): 10.0.0.5
Save provider + key to ~/.config/pwner/config.json? [Y/n]: y

interactive session · agent
type a message to steer the agent · /help for commands · /exit to quit

pwner 10.0.0.5 ❯ scan it, focus on the database
  ▶ port_scan(...) ...
  🔍 [HIGH] MySQL 5.5 — known CVE-XXXX @ 10.0.0.5
pwner 10.0.0.5 ❯ what's the fastest way in?
  🧠 The MySQL instance accepts password auth with no lockout …
pwner 10.0.0.5 ❯ /findings
```

Leave the API key blank to run in deterministic mode — the chat agent needs a key, but
`/scan` (the no-LLM full suite) still works. The saved key/provider is also used on later runs.

### Interactive commands

| Type at the `❯` prompt | What it does |
|---|---|
| `<message>` | talk to / steer the agent (it keeps the full conversation) |
| `/scan [target]` | run the deterministic suite (no LLM) on the target |
| `/target <t>` | set / replace the authorized target (host · IP · CIDR · domain) |
| `/findings` | list the findings reported so far |
| `/topology` | print the discovered network map |
| `/consent on\|off` | toggle auto-approve for high-impact actions (authorized only) |
| `/stop` | cancel the agent turn currently running (`Ctrl-C` also works) |
| `/clear` | reset the conversation (keeps target + findings) |
| `/dump [path]` | save the full session transcript (see [Transcripts](#transcripts)) |
| `/doctor` | which external tools are installed / missing, and how to install them |
| *(type while it runs)* | plain text → live steering injected into the agent's next step |
| `/help` · `/exit` | help · leave (`Ctrl-Q` also quits; `Ctrl-C` stops the turn, then quits) |

Start a session directly (skipping the wizard) with **`pwner chat [target]`**:

```bash
pwner chat 10.0.0.5 --provider deepseek --api-key sk-...
pwner chat 10.0.0.0/24 --auto-consent --instructions "focus on exposed admin panels"
pwner chat                # no target yet — set it with /target inside the session
```

## Usage

```bash
# Give an IP RANGE -> find live hosts -> scan them all -> known CVEs via nuclei
pwner 10.0.0.0/24 --no-ai                       # deterministic, no LLM
pwner 10.0.0.0/24 --provider deepseek --api-key sk-...   # agentic

# Single host / domain
pwner 10.0.0.5 --provider openai
pwner dns example.com

# Fast, focused passes
pwner 10.0.0.0/24 --no-ai --nuclei-severity high,critical
pwner ports 10.0.0.5
pwner vuln 10.0.0.5 --ports 22,443

# Setup / environment
pwner setup                 # change provider or API key
pwner doctor                # external tools: installed, missing, how to install
pwner doctor --json         # same, machine-readable
```

`pwner doctor` exits non-zero only when a **core** dependency (nmap) is missing, so it
works as a setup check in a script or a container build.

### Common flags

| Flag | Meaning |
|------|---------|
| `--provider openai\|deepseek\|anthropic\|gemini\|ollama` | LLM provider preset (default `openai`) |
| `--model` / `--base-url` / `--api-key` | override provider settings |
| `--ports top-1000\|top-100\|common\|all\|"22,80,443"\|"1-1024"` | port selection |
| `--no-ai` | skip the LLM, run the deterministic suite |
| `--max-steps N` | cap on agent tool-calling turns (`0` = uncapped, the default) |
| `--concurrency N` | parallel host scans for a range (default 20) |
| `--range-cap N` | max addresses in a CIDR before refusing (default 4096) |
| `--nuclei-severity` | nuclei severity filter (default `low,medium,high,critical`) |
| `--auto-consent` | auto-approve consent gates (active exploitation) — authorized targets only |
| `-i` / `--interactive` | prompt `[y/N]` before high-impact actions instead of auto-deny |
| `--instructions "..."` | operator steering for the agent (e.g. "focus on the database") |
| `--rate N` / `--timing T4` | nmap `--max-rate` and timing template |
| `--json` | emit JSON output |

### LLM configuration (env vars)

```bash
export PWNER_API_KEY=sk-...      # or --api-key
export PWNER_BASE_URL=...        # or --base-url
export PWNER_MODEL=...           # or --model
```

Provider presets set the base URL and default model:

| `--provider` | base URL | default model |
|---|---|---|
| `openai` | `https://api.openai.com/v1` | `gpt-4o-mini` |
| `deepseek` | `https://api.deepseek.com` | `deepseek-v4-pro` |
| `anthropic` | `https://api.anthropic.com/v1` | `claude-sonnet-4-5` |
| `gemini` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-flash-latest` |
| `ollama` | `http://localhost:11434/v1` | `llama3.1` |

The model must support **function/tool calling** (all the presets above do). Without an
API key, `pwner` runs its deterministic suite — discovery → port scan → service detection →
vuln detection → OS fingerprint — so it's always functional.

## How it works

```
pwner <target>
   │
   ├─ LLM agent (run_tools function-calling loop)
   │     decides next action, calls tools, reads results, iterates
   │
   ├─ tools (scope-locked to the authorized target; active ones consent-gated *)
   │     recon/read-only:  ping_sweep · dns_enum · port_scan · service_detect
   │                       os_detect · banner_grab · vuln_scan · run_nmap
   │     web:              http_probe · content_discovery · web_request · http_download
   │     services:         ftp_anon · ftp_get · smb_enum · smb_shares · smb_get
   │                       ssl_info · tcp_send · snmp_check
   │     detection:        nuclei_scan · exploit_search
   │     active directory: kerbrute_userenum · asrep_roast · kerberoast · ldap_enum
   │                       rid_brute · bloodhound_collect · adcs_find · dc_vuln_check
   │     credentials:      cred_check · hash_crack · password_spray * · hydra_brute *
   │     exploitation:     win_exec * · ssh_exec * · secretsdump * · listener * ·
   │                       shell_exec * · exfil * · attacker_info
   │     bookkeeping:      set_target · ledger · note · report_finding · get_findings
   │                       request_consent
   │
   └─ report: confirmed findings (severity + evidence + remediation) + executive summary
```

Safety rails (enforced at the tool layer, regardless of what the model asks):

- **Scope lock** — enforced centrally: every tool is wrapped so each host-carrying
  argument (`target`, `host`, `dc_ip`, …) is checked against the authorized target
  before the tool body runs. Tools are in-scope-by-default, so one that forgets its own
  check is still guarded. URLs, `host:port`, CIDRs and target lists are all unwrapped
  first, and a network-valued argument must sit entirely inside the authorization — a
  `/24` scope cannot be widened to a `/16` by a tool argument. Enforced in code, not by
  the prompt: the model cannot talk its way past it.
- **Consent-gated by default** — anything active (brute-force, password spraying, remote
  command execution via `win_exec`/`ssh_exec`, `secretsdump`, reverse shells via
  `listener`/`shell_exec`, and the `exfil` channel) is denied unless you approve it
  (`--auto-consent`, or an interactive `[y/N]`). Discovery, fingerprinting and detection
  are read-only and run freely. The agent **cannot self-approve** — consent is resolved
  outside the model.
- **Read-only deterministic suite** — the no-LLM `/scan` (`--no-ai`) runs only the
  read-only discovery → fingerprint → detect pipeline; the active tools need the agent
  *and* your consent.
- **Guarded raw nmap** — the generic `run_nmap` escape hatch still blocks the intrusive
  NSE categories (`brute`, `dos`, `exploit`, `intrusive`, `broadcast`, `external`) no
  matter what the model asks.

### A real pentester's brain, not a checklist

pwner does **not** hardcode "FTP → brute-force" or any fixed service→action table. The agent
(and the tooling) reason from what the target actually reveals: it fingerprints the exact
service + version, checks for anonymous/unauthenticated access, then chooses the cheapest
highest-value probe first — anonymous check → known-CVE lookups for that exact version
(`exploit_search` + `nuclei`) → default/weak creds → brute-force only if the target genuinely
warrants it. `exploit_search(service, version)` finds public exploits (searchsploit, or the
local nuclei template index) for the specific version you observed, so the "exploit" step is
grounded in evidence rather than a reflex.

### Range scanning & the "exploitation" model

`pwner <cidr>` expands the range → discovers live hosts → deep-scans each in parallel →
runs **nuclei** (thousands of known-CVE / misconfig / exposed-panel templates) over every
discovered HTTP/network service → aggregates and ranks the findings.

By default "exploitation" starts as **validation** — confirming a finding is really
exploitable via signature (version, nmap script, nuclei template match), which is how
authorized pentest reports prove impact without touching anything. When the target warrants
it and **you approve**, pwner goes further: it sprays or brute-forces credentials, runs
commands over SMB/WinRM (`win_exec`) or SSH (`ssh_exec`), dumps secrets (`secretsdump`),
catches a reverse shell (`listener` + `shell_exec`) and reads blind-RCE output back over an
`exfil` channel. All of that is **denied by default and consent-gated** — the agent must get
your approval (`request_consent`, an interactive `[y/N]`, or `--auto-consent`) before any of
it runs.

### Interactive mode (OpenCode-style)

The richest interactive experience is the **full-screen session** (`pwner`, or `pwner chat`)
documented above: a Textual TUI where the agent remembers the whole conversation. The
behaviours below — live tool calls, `[y/N]` consent, mid-run steering — apply inside that
session; a one-shot `pwner scan <target>` streams the same colored output inline (no TUI).

In an interactive terminal, pwner shows every tool call live and **prompts you `[y/N]`
before high-impact actions** (like hydra brute-force) instead of silently denying them:

```bash
pwner 10.0.0.5 --provider deepseek --api-key sk-... --instructions "focus on the database"
# when the agent wants to brute-force FTP, it pauses:
#   ⚠️  pwner agent requests a HIGH-IMPACT action:
#      action: brute-force ftp on 10.0.0.5:21
#      approve? [y/N]
```

**Live steering** — while the agent runs, type a message and press Enter to steer it in
real time (it's injected into the agent's next step):

```
  🧠 scanning 10.0.0.5 — found FTP + SMB + MySQL
  go deeper on the MySQL instance          ← you type this mid-run
  ▶ service_detect(...) ...
```

**Live network topology** — in a terminal, a corner panel renders the discovered network
map as it grows (hosts → open ports → service/version → findings):

```
╭─ network topology ─────────────╮
│ network                        │
│ ├── 10.0.0.5                   │
│ │   ├── 22  ssh OpenSSH 8.9    │
│ │   ├── 80  http nginx 1.18    │
│ │   └── [HIGH] CVE-2021-XXXX   │
│ └── 10.0.0.8                   │
│     └── 445  smb               │
╰────────────────────────────────╯
```

Live steering, the `[y/N]` consent prompt, and the topology panel all share one stdin
channel, so there's a single reader and no input race: answer `y`/`n` at a consent prompt,
and any other line is treated as steering. Steer messages are injected as
`[OPERATOR STEERING] …` before the agent's next decision. In a non-TTY (piped/scripted)
context the TUI is disabled and output falls back to plain text.

Consent resolution order:
- `--auto-consent` → auto-approve (no prompt) — authorized targets only.
- an **earlier approval in this session** → auto-approve, see the caveat below.
- `-i` / TTY (default when interactive) → prompt `[y/N]`.
- non-TTY (piped/scripted) → auto-deny (safe default).

> ⚠️ **Approval is session-wide, not per action.** The first `y` you give approves *every*
> subsequent high-impact action for the rest of the session — approve an FTP brute-force and
> `secretsdump`, `win_exec`, `listener`/`shell_exec` and `exfil` will not ask again. This is
> deliberate (it avoids prompt fatigue mid-engagement) but it is blunt: treat the first `y`
> as consenting to the whole active toolset on that target, not to the one action in front of
> you. **`/consent off` retracts it** and makes the next high-impact action prompt again.

## Transcripts

`/dump` writes everything shown in the session to a text file. With no argument it goes to
**`~/.local/share/pwner/sessions/`** (or `$XDG_DATA_HOME/pwner/sessions/`), **not** the
working directory — a transcript records whatever the engagement turned up, so dropping it
into whichever repo you happen to be standing in is how it ends up in a commit. Pass a path
or a directory to put it somewhere specific.

The file is written **owner-only (0600)**, and so is its directory, wherever it lands. It is
**not redacted**, by design: on an authorized engagement those credentials are the
deliverable, and a redactor that catches most secrets is worse than none — it invites you to
treat the file as safe to share. The header says as much, in the file. Treat it like the
credential store it is.

Where pwner keeps things:

| Path | Contents | Mode |
|---|---|---|
| `~/.config/pwner/config.json` | saved provider + API key | `0600` |
| `~/.local/share/pwner/sessions/` | session transcripts from `/dump` | `0700` dir, `0600` files |

`--instructions` injects operator steering into the agent's brief so you can aim it before
it runs. The agent is **target-driven, not a checklist** — it fingerprints the exact
service + version, then picks the cheapest highest-value probe (anonymous check → known-CVE
lookups for that version → default creds → brute-force only if warranted and consented).

## Layout

```
pwner/
├── pyproject.toml      # pip install -e ".[dev]"  · ruff + pytest config
├── LICENSE             # AGPL-3.0-or-later
├── pwner/
│   ├── llm.py          # OpenAI-compatible client + agentic run_tools loop
│   ├── tools/          # the tools package — see the dependency star below
│   │   ├── core.py     #   scope guard · consent gate · @tool registry · ScanContext
│   │   ├── nmap.py     #   port/service/vuln/OS scans, host discovery, nuclei
│   │   ├── web.py      #   scheme probing, endpoint discovery, raw HTTP requests
│   │   ├── net.py      #   DNS, banners, raw TCP, SNMP, FTP
│   │   ├── ad.py       #   Active Directory + credentialed execution
│   │   ├── session.py  #   reverse-shell listener, exfil channel, shell_exec
│   │   ├── target.py   #   operator phrase -> authorized scope
│   │   └── report.py   #   findings, ledger, dependency status, the agent's brief
│   ├── prompts.py      # the agent's system prompt
│   ├── agent.py        # agentic orchestration + deterministic fallback
│   ├── repl.py         # interactive session logic (turns, commands) + plain fallback
│   ├── app.py          # full-screen Textual TUI (fixed input, scrolling log, status)
│   ├── tui.py          # inline renderer: log + live topology panel + status line
│   ├── config.py       # on-disk paths: config + transcripts, both owner-only
│   ├── cli.py          # terminal interface
│   └── __main__.py     # python -m pwner
├── tests/              # offline suite — no nmap, no sockets, no API calls
│   ├── conftest.py             # blocks real DNS/sockets/subprocesses during tests
│   ├── test_scope.py           # the authorization boundary
│   ├── test_consent.py         # the consent gate: granting, remembering, retracting
│   ├── test_registry.py        # @tool declarations and the schemas they generate
│   ├── test_package_layout.py  # the dependency star + every submodule stays imported
│   ├── test_nmap_parse.py      # nmap XML parsing against real -oX fixtures
│   ├── test_safety_rails.py    # NSE blocklist + target-spec resolution
│   ├── test_transcript.py      # /dump location + file permissions
│   ├── test_dependencies.py    # external-tool status + per-platform install hints
│   ├── test_html_parse.py      # what the agent actually reads off a web page
│   └── test_llm_json.py        # JSON recovery from fenced/prose model output
├── Dockerfile           # whole toolchain in one image (see Install → Docker)
├── demo/               # the README's demo: VHS tape + the loopback-only target it scans
├── .github/workflows/  # CI: ruff + pytest on Python 3.10–3.13
└── README.md
```

## Development

```bash
pip install -e ".[dev]"    # adds pytest + ruff
pytest                     # 410 tests, ~0.2s
ruff check .
```

The test suite is **offline by design** — it starts no nmap process, opens no sockets and
makes no API calls, so it runs anywhere in well under a second. That is enforced, not
merely intended: `tests/conftest.py` blocks `socket.getaddrinfo`, outbound connections and
subprocess spawns for the duration of every test, so a test that forgets to stub something
fails with an explicit error instead of quietly resolving a name or scanning a host on
whoever runs it. A test that genuinely needs the network belongs behind an explicit marker,
not in the default run.

Stub at the module that *looks a name up*, not at the `pwner.tools` re-export —
`monkeypatch.setattr("pwner.tools.core._resolve_ips", ...)`, because `in_scope` resolves
`_resolve_ips` in `core`'s own namespace and never reads the package-level alias.

### The tools package

`core` owns the authorization boundary — the scope guard, the consent gate and the `@tool`
registry — and imports no sibling. Every other module imports from `core` and from nothing
else, so the graph is a star and cannot form a cycle:

```
          nmap   web   net   ad   session   target   report
            └──────┴─────┴────┴──────┴────────┴────────┘
                              core
```

Importing `pwner.tools` imports all of them, and that is what fills the registry: a
submodule nobody imports registers no tools, so its tools would disappear from the agent's
toolset with no error anywhere. `tests/test_package_layout.py` enforces both the star and
the imports, and pins the tool count.

The parts worth keeping covered are `tests/test_scope.py` and `tests/test_consent.py` —
together they are the safety model. Scope decides *where* pwner may act, consent decides
*whether* it may do the destructive things there; everything else is replaceable.

### Adding a tool

One declaration site: decorate an async function with `@tool` and it is registered,
advertised to the model, dispatchable and scope-guarded by that fact alone.

```python
@tool("What the model should know about this tool, in its own words.",
      {"host": {"type": "string"}, "port": {"type": "integer"}},
      ["host"])
async def my_tool(ctx: ScanContext, args: dict) -> dict:
    return {"ok": True}
```

`tool_schemas()`, `build_dispatch()` and the scope-exemption set are all derived from the
registry, so there is no second or third list to update. Pass `scope_exempt=True` only for
a tool with no network target (local bookkeeping, offline work, our own listener/exfil
infrastructure) — it is the one way to opt out of the authorization boundary, and
`test_scope.py` pins the exempt set by name so gaining it is never quiet.

This replaced three hand-maintained declaration sites. A tool used to exist as a function,
an entry in `TOOL_SCHEMAS` and an entry in `build_dispatch`, each added by hand — which is
exactly how `ping_sweep`, `nuclei_scan` and `hydra_brute` ended up reaching the network
with no scope check at all.

## License

[GNU AGPL-3.0-or-later](LICENSE). Copyright (C) 2026 Berk D.

The network clause (§13) matters for a tool like this: if you modify pwner and let others
use it over a network, you have to offer them the modified source too.

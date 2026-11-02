# Contributing

## Setup

```bash
git clone https://github.com/0x45dd/pwner.git
cd pwner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"      # adds pytest + ruff
./scripts/install-deps.sh    # external tools
```

```bash
pytest           # 410 tests, ~0.2s
ruff check .
```

## The test suite is offline, and that is enforced

The suite starts no nmap process, opens no sockets and makes no API calls.
[`tests/conftest.py`](tests/conftest.py) blocks `socket.getaddrinfo`, outbound connections
and subprocess spawns for the duration of every test, so a test that forgets to stub
something fails with an explicit error instead of quietly scanning a host on whoever runs
it. For this tool that is not a hygiene preference: an unstubbed tool call sends real
packets at a real machine.

Stub at the module that *looks a name up*, not at the `pwner.tools` re-export:

```python
monkeypatch.setattr("pwner.tools.core._resolve_ips", fake)
```

`in_scope` resolves `_resolve_ips` in `core`'s own namespace and never reads the
package-level alias, so patching `pwner.tools._resolve_ips` silently does nothing. This has
already caused one round of tests that passed for the wrong reason.

A test that genuinely needs the network belongs behind an explicit marker, not in the
default run.

## What to keep covered

[`tests/test_scope.py`](tests/test_scope.py) and [`tests/test_consent.py`](tests/test_consent.py)
are the safety model — scope decides *where* pwner may act, consent decides *whether* it may
do the destructive things there. Everything else is replaceable; those two are not. If a
change touches the dispatch wrapper, the consent resolution order, or the scope-exempt set,
assume it is wrong until those tests say otherwise.

## The tools package

`core` owns the authorization boundary — the scope guard, the consent gate and the `@tool`
registry — and imports no sibling. Every other module imports from `core` and from nothing
else, so the graph is a star and cannot form a cycle:

```
nmap   web   net   ad   session   target   report
  └──────┴─────┴────┴──────┴────────┴────────┘
                    core
```

| Module | Holds |
|---|---|
| `core` | scope guard, consent gate, `@tool` registry, dispatch, `ScanContext` |
| `nmap` | port/service/vuln/OS scans, host discovery, nuclei |
| `web` | scheme probing, endpoint discovery, raw HTTP |
| `net` | DNS, banners, raw TCP, SNMP, FTP |
| `ad` | Active Directory and credentialed execution |
| `session` | reverse-shell listener, exfil channel, `shell_exec` |
| `target` | operator phrase to authorized scope |
| `report` | findings, ledger, dependency status, the agent brief |

Importing `pwner.tools` imports all of them, and that is what fills the registry: a
submodule nobody imports registers no tools, so its tools disappear from the agent's toolset
with no error anywhere. [`tests/test_package_layout.py`](tests/test_package_layout.py)
enforces both the star and the imports, and pins the tool count.

## Adding a tool

One declaration site. Decorate an async function with `@tool` and it is registered,
advertised to the model, dispatchable and scope-guarded by that fact alone.

```python
@tool("What the model should know about this tool, in its own words.",
      {"host": {"type": "string"}, "port": {"type": "integer"}},
      ["host"])
async def my_tool(ctx: ScanContext, args: dict) -> dict:
    return {"ok": True}
```

`tool_schemas()`, `build_dispatch()` and the scope-exemption set all derive from the
registry, so there is no second or third list to update. This replaced three hand-maintained
declaration sites; a tool used to exist as a function, an entry in `TOOL_SCHEMAS` and an
entry in `build_dispatch`, which is exactly how `ping_sweep`, `nuclei_scan` and
`hydra_brute` once ended up reaching the network with no scope check at all.

Pass `scope_exempt=True` only for a tool with no network target — local bookkeeping,
offline work, or our own listener/exfil infrastructure. It is the one way to opt out of the
authorization boundary, and `test_scope.py` pins the exempt set by name so gaining it is
never quiet.

## House rules for the agent's behaviour

**No hardcoded playbooks in the prompt.** No per-service "if FTP then brute-force" tables, and
no behavioural lessons learned from one engagement. The agent reasons from what each target
actually reveals. New capability goes in a **tool** plus its neutral description; it does not
go in the system prompt.

**Expose the knob, don't hardcode the value.** The nmap wrappers take an `nmap_args` string
the agent fills rather than baking in flags. Only the mechanism stays fixed: the scope guard
and the destructive-NSE-category block.

## Pull requests

- `ruff check .` and `pytest` both clean.
- A behaviour change comes with the test that fails without it. Say in the PR that you
  checked the test fails against the old behaviour — for this codebase that has caught
  several tests that asserted nothing.
- Say plainly what you did not verify. An untested claim in a commit message is worse than
  an admitted gap.

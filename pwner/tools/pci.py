"""PCI DSS network-layer testing: segmentation validation and exposure retest.

Two things PCI DSS v4.0.1 asks for are pure network-layer work, and both are among the
most often done by hand:

  11.4.5  If segmentation isolates the CDE, penetration-test the segmentation controls at
          least every 12 months and after any change to them, covering every segmentation
          method in use, and confirm they isolate the CDE from out-of-scope systems.
  11.4.6  The same test every six months, for service providers.
  11.4.4  Correct what the test found, then repeat the test to verify the correction.

`segmentation_test` answers 11.4.5/11.4.6 and `pci_retest` answers the repeat half of
11.4.4. Neither makes anyone compliant, and the module should not be read as claiming
otherwise: 11.4.2 and 11.4.3 require a qualified tester with organizational independence,
11.4.1 requires a documented methodology, and the quarterly external scan in 11.3.2 has to
come from an Approved Scanning Vendor. These are instruments a tester uses. What they do
contribute is the evidence an assessor asks for — when, from where, against what, and what
came back — attached to the result rather than reconstructed later from memory.

The reachability verdict is the whole point, and it is not the question a port scan asks.
A port scan wants to know what is listening. A segmentation test wants to know whether a
packet can get there at all, so a *closed* port that answers with a RST is a failure of
isolation rather than a pass: something on the path replied. Whether that RST came from
the host itself or from a firewall rejecting on its behalf cannot be told from a TCP
connect, so that case is reported as inconclusive instead of being guessed in either
direction. Calling it a pass would manufacture evidence of isolation that does not exist;
calling it a failure would invent a finding. An assessor can settle it from the firewall's
own logs in a minute, and the result says so.
"""
from __future__ import annotations

import asyncio
import errno
import time

from .core import (
    ScanContext,
    ToolError,
    _literal_in_scope,
    _require_scope,
    _source_ip_for,
    expand_hosts,
    tool,
)

# Default ports for a CDE reachability test. This is a default for a knob, not a playbook:
# `ports` overrides it entirely. The set is chosen for breadth of path rather than depth of
# service — remote access, file sharing, the databases cardholder data actually sits in, and
# the admin surfaces that most often survive a sloppy segmentation rule.
DEFAULT_CDE_PORTS = (21, 22, 23, 80, 135, 139, 443, 445, 1433, 1521,
                     3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017)

_PORT_CAP = 256        # ports per run
_PROBE_CAP = 20000     # host x port probes per run
_LIST_CAP = 50         # failures listed individually in the result

# A probe state means one of three things for isolation. Anything not in either set is
# inconclusive, which is deliberately the default for a state we have not reasoned about.
_REACHABLE = frozenset({"open"})
_BLOCKED = frozenset({"filtered", "unreachable"})

_INCONCLUSIVE_NOTE = (
    "A refused connection means something on the path answered, so isolation is not "
    "demonstrated — but a TCP connect cannot tell a host RST from a firewall reject. "
    "Settle these from the segmentation control's own logs before recording the boundary "
    "as effective."
)


def _require_cde_scope(cde: str, ctx: ScanContext) -> None:
    """Scope-check the CDE, which is usually a CIDR and may be a list of them.

    `_require_scope` resolves its argument as a hostname, so it cannot judge a network:
    a CIDR has to go through `_literal_in_scope`, which is the same check the dispatch
    wrapper applies and which requires the network to sit entirely inside the
    authorization rather than merely overlap it.
    """
    for part in (cde or "").split(","):
        part = part.strip()
        if part and not _literal_in_scope(part, ctx):
            raise ToolError(f"{part!r} is outside the authorized scope ({ctx.target!r})")


def parse_ports(spec: str | None) -> list[int]:
    """Parse '22,80,443', '1-1024' or '22,8000-8010' into a sorted port list.

    Empty or None gives DEFAULT_CDE_PORTS.
    """
    text = str(spec or "").strip()
    if not text:
        return list(DEFAULT_CDE_PORTS)
    out: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
            except ValueError:
                raise ToolError(f"bad port range {part!r}") from None
            if lo > hi:
                lo, hi = hi, lo
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ToolError(f"port out of range in {part!r}")
            out.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ToolError(f"bad port {part!r}") from None
            if not (1 <= p <= 65535):
                raise ToolError(f"port out of range: {p}")
            out.add(p)
    if not out:
        raise ToolError("no ports to test")
    if len(out) > _PORT_CAP:
        raise ToolError(
            f"{len(out)} ports is over the {_PORT_CAP} cap. A segmentation test asks "
            f"whether a path exists, not what is listening on every port — narrow the list.")
    return sorted(out)


def classify_error(exc: BaseException | None) -> str:
    """Map the outcome of one TCP connect to a probe state. None means it completed.

    Order matters: ConnectionRefusedError is an OSError, and so is the builtin
    TimeoutError, so both are matched before the generic OSError branch.

    Both timeout types are listed because they are not the same class on every version
    we support. On 3.11+ asyncio.TimeoutError *is* the builtin TimeoutError, but on 3.10
    it is concurrent.futures.TimeoutError, while the builtin one — what a socket-level
    timeout raises — is an OSError carrying no errno. Matching only the asyncio alias
    there sends a dropped packet into the generic branch and classifies it "error", which
    reads as inconclusive instead of blocked: the most common outcome on a working
    boundary, scored as the one thing it is not.
    """
    if exc is None:
        return "open"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "filtered"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, OSError):
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH,
                         errno.EHOSTDOWN, errno.ENETDOWN):
            return "unreachable"
        return "error"
    return "error"


def segmentation_verdict(states) -> str:
    """The overall verdict from the individual probe states.

    One reachable path is enough to fail — isolation is a property of the whole boundary,
    not an average over it. With nothing reachable but something inconclusive the honest
    answer is inconclusive, because a boundary is only evidenced by every probe being
    demonstrably blocked.
    """
    seen = set(states)
    if not seen:
        return "inconclusive"
    if seen & _REACHABLE:
        return "not_isolated"
    if seen - _BLOCKED:
        return "inconclusive"
    return "isolated"


def summarise_segmentation(probes: list[dict]) -> dict:
    """Collapse the probe list into something an assessor can read and a model can afford.

    A /24 across the default port set is nearly 5000 probes, and on a working boundary all
    of them are blocked and therefore identical. The failures are few and each one matters,
    so those are listed individually; the blocked bulk is only counted.
    """
    counts = {"reachable": 0, "blocked": 0, "inconclusive": 0}
    states: dict[str, int] = {}
    reachable: list[dict] = []
    inconclusive: list[dict] = []
    for p in probes:
        st = p.get("state", "error")
        states[st] = states.get(st, 0) + 1
        if st in _REACHABLE:
            counts["reachable"] += 1
            reachable.append(p)
        elif st in _BLOCKED:
            counts["blocked"] += 1
        else:
            counts["inconclusive"] += 1
            inconclusive.append(p)
    out = {
        "verdict": segmentation_verdict([p.get("state", "error") for p in probes]),
        "probes": len(probes),
        "counts": counts,
        "states": states,
        "reachable": reachable[:_LIST_CAP],
        "inconclusive": inconclusive[:_LIST_CAP],
    }
    if len(reachable) > _LIST_CAP:
        out["more_reachable"] = len(reachable) - _LIST_CAP
    if len(inconclusive) > _LIST_CAP:
        out["more_inconclusive"] = len(inconclusive) - _LIST_CAP
    return out


async def _probe(host: str, port: int, timeout: float) -> dict:
    """One TCP connect, classified. Never raises for a network outcome."""
    exc: Exception | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:        # noqa: BLE001 - teardown only; the handshake already told us
            pass
    except Exception as e:       # noqa: BLE001 - every outcome is classified below
        exc = e
    return {"host": host, "port": port, "state": classify_error(exc)}


def _gate(ctx: ScanContext) -> asyncio.Semaphore:
    """Probe concurrency. Higher than a scan's because almost every probe on a healthy
    boundary just waits out its timeout."""
    return asyncio.Semaphore(max(1, min(100, (ctx.concurrency or 20) * 5)))


def _file_reachable_findings(ctx: ScanContext, result: dict) -> int:
    """Record each reachable CDE path as a finding, deduped the way report_finding is.

    The tool files these itself rather than leaving it to the agent, because the
    deterministic `pwner pci` path has no agent and a reachable path is not a judgement
    call. Inconclusive probes are deliberately not filed — see the module docstring.
    """
    filed = 0
    for p in result.get("reachable", []):
        f = {
            "host": p["host"],
            "port": p["port"],
            "service": "",
            "title": "CDE reachable from an out-of-scope segment",
            "severity": "high",
            "confidence": "confirmed",
            "evidence": (f"TCP connect to {p['host']}:{p['port']} succeeded from "
                         f"{result['vantage_point']} at {result['tested_at']}. The "
                         f"segmentation controls between that vantage point and the CDE "
                         f"do not block this path."),
            "remediation": ("Deny this path at the segmentation control, then re-run the "
                            "test to verify the correction (PCI DSS 11.4.4)."),
        }
        if any((e.get("host"), e.get("port"), e.get("title"))
               == (f["host"], f["port"], f["title"]) for e in ctx.findings):
            continue
        ctx.findings.append(f)
        filed += 1
    return filed


@tool("PCI DSS 11.4.5/11.4.6 segmentation test: from wherever pwner is running, try to "
      "reach the CDE and report whether the boundary holds. Unlike a port scan this counts "
      "any answer as a path, so a refused port is a failure of isolation rather than a "
      "pass. Run it from an OUT-OF-SCOPE segment, with the CDE as the authorized target.",
      {"cde": {"type": "string",
               "description": "CDE host or CIDR that is supposed to be isolated"},
       "ports": {"type": "string",
                 "description": "ports to try, e.g. '22,443,3306' or '1-1024'. Default is "
                                "a broad CDE set covering remote access, file sharing, "
                                "databases and admin surfaces."},
       "timeout": {"type": "number", "description": "per-probe seconds, default 3"}},
      ["cde"])
async def segmentation_test(ctx: ScanContext, args: dict) -> dict:
    cde = str(args.get("cde") or ctx.target or "").strip()
    if not cde:
        raise ToolError("segmentation_test needs the CDE to test (cde=...)")
    _require_cde_scope(cde, ctx)
    ports = parse_ports(args.get("ports"))
    try:
        timeout = float(args.get("timeout") or 3.0)
    except (TypeError, ValueError):
        raise ToolError("timeout must be a number") from None
    timeout = min(max(timeout, 0.2), 30.0)

    hosts: list[str] = []
    for part in cde.split(","):
        part = part.strip()
        if part:
            hosts.extend(expand_hosts(part, ctx.range_cap))
    hosts = list(dict.fromkeys(h for h in hosts if h))
    if not hosts:
        raise ToolError(f"nothing to test in {cde!r}")
    total = len(hosts) * len(ports)
    if total > _PROBE_CAP:
        raise ToolError(
            f"{len(hosts)} hosts x {len(ports)} ports is {total} probes, over the "
            f"{_PROBE_CAP} cap. Narrow the CDE range or the port list.")

    sem = _gate(ctx)

    async def one(h: str, p: int) -> dict:
        async with sem:
            return await _probe(h, p, timeout)

    started = time.time()
    probes = await asyncio.gather(*[one(h, p) for h in hosts for p in ports])

    result = {
        "requirement": "PCI DSS 11.4.5 (11.4.6 for service providers)",
        "cde": cde,
        "vantage_point": _source_ip_for(hosts[0]),
        "tested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "duration_s": round(time.time() - started, 1),
        "hosts_tested": len(hosts),
        "ports_tested": len(ports),
        **summarise_segmentation(list(probes)),
    }
    if result["counts"]["inconclusive"]:
        result["inconclusive_note"] = _INCONCLUSIVE_NOTE
    filed = _file_reachable_findings(ctx, result)
    if filed:
        result["findings_filed"] = filed
    # A boundary that did not hold is worth more deliberation than one that did. Read by the
    # agent loop to raise the reasoning budget for the next few steps. `inconclusive` counts
    # too: not knowing whether a packet arrived is its own thing to reason about.
    result["significance"] = (
        "high" if result["verdict"] in ("not_isolated", "inconclusive") else "low")
    return result


@tool("PCI DSS 11.4.4 retest: re-probe the host:port of findings already on the record and "
      "report whether each exposure is gone. This verifies exposure only — a finding about "
      "a software version, a configuration or application logic is not settled by a port "
      "being closed, and those are returned as needing a real recheck rather than fixed.",
      {"findings": {"type": "array",
                    "description": "findings to retest, each {host, port}; omit to retest "
                                   "every finding on the record",
                    "items": {"type": "object"}},
       "timeout": {"type": "number", "description": "per-probe seconds, default 3"}},
      [])
async def pci_retest(ctx: ScanContext, args: dict) -> dict:
    raw = args.get("findings")
    items = raw if isinstance(raw, list) else [dict(f) for f in ctx.findings]
    if not items:
        return {"requirement": "PCI DSS 11.4.4", "retested": 0,
                "note": "no findings on the record to retest"}
    try:
        timeout = float(args.get("timeout") or 3.0)
    except (TypeError, ValueError):
        raise ToolError("timeout must be a number") from None
    timeout = min(max(timeout, 0.2), 30.0)

    rows: list[dict] = []
    todo: list[tuple[int, str, int]] = []
    for f in items:
        if not isinstance(f, dict):
            continue
        host = str(f.get("host") or "").strip()
        title = str(f.get("title") or "")
        if not host:
            rows.append({"title": title, "status": "needs_manual_recheck",
                         "reason": "the finding records no host"})
            continue
        # `findings` is not one of the centrally scoped argument names, so the hosts
        # inside it are checked here. Without this the tool would be a way around the
        # scope guard.
        _require_scope(host, ctx)
        try:
            port = int(f.get("port"))
        except (TypeError, ValueError):
            rows.append({"host": host, "title": title, "status": "needs_manual_recheck",
                         "reason": "the finding records no port, so there is no exposure "
                                   "to re-probe"})
            continue
        todo.append((len(rows), host, port))
        rows.append({"host": host, "port": port, "title": title})

    if todo:
        sem = _gate(ctx)

        async def one(h: str, p: int) -> dict:
            async with sem:
                return await _probe(h, p, timeout)

        started = time.time()
        probed = await asyncio.gather(*[one(h, p) for _, h, p in todo])
        for (idx, _, _), pr in zip(todo, probed, strict=True):
            st = pr["state"]
            rows[idx]["state"] = st
            rows[idx]["status"] = ("still_exposed" if st in _REACHABLE else
                                   "exposure_gone" if st in _BLOCKED else "inconclusive")
    else:
        started = time.time()

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    out = {
        "requirement": "PCI DSS 11.4.4",
        "verification": "exposure_only",
        "tested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "vantage_point": _source_ip_for(todo[0][1]) if todo else "",
        "retested": len(rows),
        "counts": counts,
        "findings": rows[:_LIST_CAP],
        "note": ("exposure_gone means the port no longer answers from this vantage point. "
                 "A finding about a version, a configuration or application logic is not "
                 "closed by that — recheck those directly."),
    }
    if len(rows) > _LIST_CAP:
        out["more"] = len(rows) - _LIST_CAP
    return out

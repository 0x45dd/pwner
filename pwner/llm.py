"""OpenAI-compatible LLM client for pwner.

Exposes chat(), chat_json() and an agentic run_tools() function-calling loop.
Provider presets cover OpenAI / DeepSeek / Anthropic (OpenAI-compat) / Gemini, and
two that run on your own hardware, Ollama and Lemonade. A local server usually has no
API key, so one is required only for a remote endpoint. When no model can be reached
at all, callers fall back to deterministic logic (see agent.py).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import random
import re
from collections import Counter
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

import httpx


class AIUnavailable(RuntimeError):
    """Raised when no API key is configured / auth-billing failure. Callers fall
    back to deterministic logic."""


class LLMError(RuntimeError):
    """A transient or permanent provider error the caller should surface."""


class ContextOverflow(LLMError):
    """The prompt no longer fits the model's context window.

    Separated from LLMError because it is the one 400 that is recoverable: the backend
    hands back both numbers needed to act (n_ctx, n_prompt_tokens), and a smaller prompt
    will succeed. Resending the same prompt never will, so the loop must shrink it."""

    def __init__(self, message: str, n_ctx: int = 0, n_prompt: int = 0):
        super().__init__(message)
        self.n_ctx = n_ctx
        self.n_prompt = n_prompt


# Backends word this differently; llama.cpp/Lemonade use the structured form below,
# OpenAI returns code "context_length_exceeded", others only say it in prose.
_OVERFLOW_MARKERS = ("context_length_exceeded", "exceed_context_size",
                     "maximum context length", "context size", "too many tokens",
                     "reduce the length of the messages")


def _as_overflow(status: int, body: str) -> ContextOverflow | None:
    """Recognise a context-window rejection and pull the numbers out of it."""
    if status != 400:
        return None
    low = body.lower()
    if not any(m in low for m in _OVERFLOW_MARKERS):
        return None
    n_ctx = n_prompt = 0
    for key, attr in (("n_ctx", "ctx"), ("n_prompt_tokens", "prompt")):
        m = re.search(rf'"{key}"\s*:\s*(\d+)', body)
        if m:
            if attr == "ctx":
                n_ctx = int(m.group(1))
            else:
                n_prompt = int(m.group(1))
    if not (n_ctx and n_prompt):
        # prose form: "request (67147 tokens) exceeds the available context size (65536 tokens)"
        nums = [int(n) for n in re.findall(r"\b(\d{3,7})\b(?=\s*tokens)", body)]
        if len(nums) >= 2:
            n_prompt, n_ctx = max(nums), min(nums)
    return ContextOverflow(body[:300], n_ctx=n_ctx, n_prompt=n_prompt)


PRESETS: dict[str, dict[str, str]] = {
    "openai":    {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "deepseek":  {"base_url": "https://api.deepseek.com",   "model": "deepseek-v4-pro"},
    "anthropic": {"base_url": "https://api.anthropic.com/v1", "model": "claude-sonnet-4-5"},
    "gemini":    {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
                  "model": "gemini-flash-latest"},
    "ollama":    {"base_url": "http://localhost:11434/v1",  "model": "llama3.1"},
    # Lemonade Server (AMD) fronts one llama.cpp process per model and speaks the
    # OpenAI API on /api/v1. Model names are whatever that install has pulled, so the
    # preset leaves it blank and the model is discovered from /models instead of
    # guessing a name that will not exist. Port is per-install: override --base-url.
    "lemonade":  {"base_url": "http://localhost:13305/api/v1", "model": ""},
}

# Providers that normally run on your own hardware with no auth at all.
LOCAL_PROVIDERS = frozenset({"ollama", "lemonade"})


def is_local_endpoint(base_url: str) -> bool:
    """True when the endpoint is on this machine or this network.

    Those servers — Ollama, Lemonade, llama.cpp, LM Studio, vLLM — usually have no API
    key, so requiring one would make a working setup look broken. Judged from the URL
    rather than the provider name, so a custom --base-url gets the same treatment."""
    try:
        host = (urlparse(base_url).hostname or "").strip("[]")
    except ValueError:
        return False
    if not host:
        return False
    if host == "localhost" or host.endswith((".local", ".internal", ".lan")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def resolve_config(provider: str, api_key: str, base_url: str, model: str) -> tuple[str, str, str]:
    """Return (api_key, base_url, model). Precedence: CLI args > env vars > saved
    config (~/.config/pwner/config.json) > provider preset."""
    from . import config as _cfg
    saved = _cfg.load()
    provider = (provider or "").strip().lower() or str(saved.get("provider", "")).strip().lower() or "openai"
    preset = PRESETS.get(provider, {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"})
    base = (base_url or os.environ.get("PWNER_BASE_URL")
            or str(saved.get("base_url", "")) or preset["base_url"]).rstrip("/")
    mod = (model or os.environ.get("PWNER_MODEL")
           or str(saved.get("model", "")) or preset["model"])
    key = (api_key
           or os.environ.get("PWNER_API_KEY")
           or os.environ.get("OPENAI_API_KEY")
           or os.environ.get("ANTHROPIC_API_KEY")
           or os.environ.get("GEMINI_API_KEY")
           or saved.get("api_key", "")
           or "").strip()
    return key, base, mod


#: Arguments that say WHERE a call acts, as opposed to what it sends. Repeating a tool
#: against the same place with a new payload every time is the loop the exact-match
#: checks cannot see, so the site is judged on these keys alone.
_SITE_KEYS = ("host", "hosts", "target", "targets", "port", "path", "url",
              "dc_ip", "server", "ip", "domain")
_SITE_WINDOW = 12   # how many recent calls to judge
_SITE_NUDGE = 6     # same site this often within the window -> tell the model
_SITE_STOP = 10     # and this often, after it was already told -> end the turn


def _call_site(tool_call: dict) -> str:
    """Tool name plus the place it is acting on, with the payload left out."""
    name = tool_call["function"]["name"]
    try:
        args = json.loads(tool_call["function"].get("arguments") or "{}")
    except Exception:  # noqa: BLE001 — malformed arguments still identify a site by tool
        args = {}
    if not isinstance(args, dict):
        args = {}
    where = {k: args[k] for k in _SITE_KEYS if k in args}
    return name + "|" + json.dumps(where, sort_keys=True, default=str)


def transcript_size(messages: list[dict]) -> int:
    """Rough size of a transcript, in characters. A proxy for tokens: the loop only needs
    to know that a compaction actually made the prompt smaller, not by how many tokens."""
    total = 0
    for m in messages:
        c = m.get("content")
        total += len(c) if isinstance(c, str) else len(json.dumps(c or ""))
        for tc in m.get("tool_calls") or []:
            total += len(json.dumps(tc))
    return total


def compact_messages(messages: list[dict], keep_recent: int = 6,
                     max_tool_chars: int = 600) -> list[dict]:
    """Shrink a transcript that no longer fits, oldest tool output first.

    What a run cannot lose is the task and what just happened, so the system message, the
    first user message and the last `keep_recent` entries are left untouched. Everything
    older is where the bulk sits: tool results. Those get cut to a prefix with an explicit
    marker, so the model can see that detail existed and ask for it again rather than
    silently reasoning over a hole.

    Returns a new list; the caller decides whether the result is small enough to use."""
    if len(messages) <= keep_recent + 2:
        return list(messages)

    head = messages[:2]                     # system + the original task
    tail = messages[len(messages) - keep_recent:]
    middle = messages[2:len(messages) - keep_recent]

    out = list(head)
    for m in middle:
        content = m.get("content")
        if m.get("role") == "tool" and isinstance(content, str) and len(content) > max_tool_chars:
            dropped = len(content) - max_tool_chars
            trimmed = dict(m)
            trimmed["content"] = (content[:max_tool_chars]
                                  + f"\n[{dropped} characters dropped to fit the context window"
                                    f" — run the tool again if you need the rest]")
            out.append(trimmed)
        else:
            out.append(m)
    out.extend(tail)
    return out


async def discover_models(base_url: str, api_key: str = "", timeout: float = 6.0) -> list[str]:
    """Model ids the server actually has, from the OpenAI-compatible /models endpoint.

    A local server is named after whatever that machine happens to have pulled, so any
    hardcoded default is wrong somewhere. Returns [] if the endpoint is unreachable or
    does not answer in the OpenAI shape; callers treat that as "ask the operator"
    rather than guessing."""
    url = f"{base_url.rstrip('/')}/models"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception:  # noqa: BLE001 — unreachable or odd server is not an error here
        return []
    items = data.get("data") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    return [str(m["id"]) for m in items if isinstance(m, dict) and m.get("id")]


def _strip_code_fence(s: str) -> str:
    """Recover raw JSON from a model that ignored response_format=json_object
    (e.g. Claude via an OpenAI-compat shim wraps in a ```json fence)."""
    t = (s or "").strip()
    if t.startswith("```"):
        nl = t.find("\n")
        if nl != -1:
            t = t[nl + 1:]
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
        t = t.strip()
    # Carve out the JSON span. Done unconditionally: a model puts prose BEFORE the JSON
    # ("Here is the result:") or AFTER it ("Hope that helps!"), and the trailing case used
    # to be missed because text already starting with { or [ skipped this block entirely.
    # When t is clean JSON the span is the whole string, so this is a no-op.
    i_obj, i_arr = t.find("{"), t.find("[")
    cands = [i for i in (i_obj, i_arr) if i != -1]
    if cands:
        start = min(cands)
        close_ch = "}" if t[start] == "{" else "]"
        end = t.rfind(close_ch)
        if end > start:
            t = t[start:end + 1]
    return t.strip()


class LLMClient:
    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        # A key is required for a hosted provider and optional for a server on your own
        # machine or network, which is how Ollama, Lemonade and llama.cpp normally run.
        # Without this, `--provider ollama` failed unless you invented a fake key.
        if not self.api_key and not is_local_endpoint(self.base_url):
            raise AIUnavailable("no API key configured")

    @property
    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def _post(self, payload: dict, attempts: int = 3, timeout: float = 180.0) -> dict:
        url = f"{self.base_url}/chat/completions"
        delay = 1.0
        last = ""
        for a in range(attempts):
            try:
                async with httpx.AsyncClient(timeout=timeout) as c:
                    r = await c.post(url, headers=self._headers, json=payload)
            except (httpx.ConnectError, httpx.ReadError, httpx.ReadTimeout,
                    httpx.RemoteProtocolError) as e:
                last = f"{type(e).__name__}: {e}"
                if a < attempts - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                raise LLMError(f"connection failed after {attempts} attempts: {last}") from e
            if r.status_code in (429, 500, 502, 503, 529) and a < attempts - 1:
                await asyncio.sleep(delay + random.uniform(0, delay * 0.25))
                delay *= 2
                continue
            if r.status_code >= 400:
                body = r.text[:600]
                if r.status_code in (401, 402, 403):
                    raise AIUnavailable(f"auth/billing error {r.status_code}: {body[:300]}")
                overflow = _as_overflow(r.status_code, body)
                if overflow is not None:
                    raise overflow
                raise LLMError(f"LLM {r.status_code}: {body[:300]}")
            return r.json()
        raise LLMError(f"LLM unavailable after retries: {last}")

    async def chat_json(self, system: str, user: str, *, model: str | None = None,
                        temperature: float = 0.1, max_tokens: int | None = None) -> Any:
        sys_prompt = system + "\n\nRespond with a single valid JSON object only."
        payload: dict[str, Any] = {
            "model": model or self.model,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user},
            ],
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        data = await self._post(payload)
        content = _strip_code_fence(data["choices"][0]["message"]["content"] or "{}")
        return json.loads(content)

    async def run_tools(
        self,
        system: str,
        user: str,
        tools: list[dict],
        dispatch: dict[str, Callable[[dict], Awaitable[dict]]],
        *,
        max_steps: int | None = None,
        stall_limit: int = 8,
        model: str | None = None,
        temperature: float = 0.2,
        reasoning_effort: str | None = None,
        tool_timeout: float = 600.0,
        on_step: Callable[[str, dict, dict], Awaitable[None]] | None = None,
        on_call: Callable[[str, dict], Awaitable[None]] | None = None,
        on_thought: Callable[[str], Awaitable[None]] | None = None,
        on_usage: Callable[[dict], None] | None = None,
        interrupt: Callable[[], bool] | None = None,
        steer: Callable[[], list[str]] | None = None,
    ) -> str:
        """Agentic function-calling loop. Returns the model's final text.

        `steer`, if given, is called at the top of every step and any returned
        operator messages are injected as user messages — live steering mid-run."""
        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        return await self.run_turn(
            messages, tools, dispatch, max_steps=max_steps, stall_limit=stall_limit, model=model,
            temperature=temperature, reasoning_effort=reasoning_effort, tool_timeout=tool_timeout,
            on_step=on_step, on_call=on_call, on_thought=on_thought, on_usage=on_usage,
            interrupt=interrupt, steer=steer)

    async def _run_tool(self, name, fn, args, tool_timeout, interrupt):
        """Run one tool, but let the operator interrupt a long one so their next message is acted on
        right away (instead of only after the tool finishes). Returns the tool result dict."""
        task = asyncio.ensure_future(fn(args))
        waited = 0.0
        try:
            while True:
                done, _ = await asyncio.wait({task}, timeout=0.3)
                if task in done:
                    try:
                        return task.result()
                    except Exception as e:  # noqa: BLE001 — a tool error must not kill the run
                        return {"error": f"tool {name} raised {type(e).__name__}: {str(e)[:300]}"}
                waited += 0.3
                if interrupt is not None and interrupt():
                    task.cancel()
                    try:
                        await task
                    except BaseException:  # noqa: BLE001
                        pass
                    return {"interrupted": True,
                            "note": f"operator sent new input — stopped {name} to act on it"}
                if waited >= tool_timeout:
                    task.cancel()
                    try:
                        await task
                    except BaseException:  # noqa: BLE001
                        pass
                    return {"error": f"tool {name} timed out after {tool_timeout:.0f}s"}
        except asyncio.CancelledError:
            task.cancel()
            try:
                await task
            except BaseException:  # noqa: BLE001
                pass
            raise

    async def run_turn(
        self,
        messages: list[dict],
        tools: list[dict],
        dispatch: dict[str, Callable[[dict], Awaitable[dict]]],
        *,
        max_steps: int | None = None,
        stall_limit: int = 8,
        model: str | None = None,
        temperature: float = 0.2,
        reasoning_effort: str | None = None,
        tool_timeout: float = 600.0,
        on_step: Callable[[str, dict, dict], Awaitable[None]] | None = None,
        on_call: Callable[[str, dict], Awaitable[None]] | None = None,
        on_thought: Callable[[str], Awaitable[None]] | None = None,
        on_usage: Callable[[dict], None] | None = None,
        interrupt: Callable[[], bool] | None = None,
        steer: Callable[[], list[str]] | None = None,
    ) -> str:
        """Run the function-calling loop over an EXISTING `messages` list, which is
        mutated in place (assistant/tool turns appended). This is what makes a
        persistent interactive session possible: the caller owns `messages` and keeps
        it across turns, so the agent remembers the whole conversation. Returns the
        model's final text for this turn (when it stops calling tools)."""
        step = 0
        stall_sig: str | None = None
        stall = 0
        # Where each call acted, payload excluded, for the last few steps. The exact-repeat
        # checks below all key on the arguments, so an agent that hammers one endpoint with a
        # slightly different payload every time slips past every one of them: the signature
        # changes, the counter resets, and nothing trips. Judging by call SITE instead catches
        # that, and a window catches it even when the repeats are not consecutive.
        call_sites: list[str] = []
        site_nudged: set[str] = set()
        # Per-(tool,args) no-progress tracking: if a call keeps returning the IDENTICAL result it is
        # producing no new information — nudge the model to change approach instead of letting it
        # spin. Tools whose whole job is to be polled repeatedly are exempt.
        _POLL_TOOLS = {"exfil", "listener", "get_findings"}
        last_result: dict[str, str] = {}
        repeats: dict[str, int] = {}
        nudged: set[str] = set()
        # No step budget: runs until the model stops calling tools (it decides it's done).
        # max_steps None or <= 0 means unbounded.
        while max_steps is None or max_steps <= 0 or step < max_steps:
            step += 1
            if steer is not None:
                for m in steer():
                    messages.append({"role": "user", "content": "[OPERATOR STEERING] " + str(m)})
            payload: dict[str, Any] = {
                "model": model or self.model,
                "temperature": temperature,
                "tools": tools,
                "messages": messages,
            }
            # Opt-in deliberate reasoning for providers that honor it (OpenAI o-series/gpt-5,
            # Gemini thinking via the OpenAI-compat layer). deepseek-reasoner ignores this and
            # thinks unconditionally, so it's left unset there. Only sent when explicitly asked,
            # since non-reasoning models (e.g. gpt-4o-mini) 400 on an unknown param.
            if reasoning_effort:
                payload["reasoning_effort"] = reasoning_effort
            try:
                data = await self._post(payload)
            except ContextOverflow as overflow:
                # Recoverable, but only if the prompt actually gets smaller. Compact in
                # increasing steps and give up rather than resend something that cannot fit.
                data = None
                before = transcript_size(messages)
                for keep, cap in ((6, 600), (4, 240), (2, 80)):
                    shrunk = compact_messages(messages, keep_recent=keep, max_tool_chars=cap)
                    after = transcript_size(shrunk)
                    if after >= before:
                        continue
                    messages[:] = shrunk
                    payload["messages"] = messages
                    if on_thought is not None:
                        pct = 100 * (before - after) // max(before, 1)
                        over = (f" ({overflow.n_prompt} tokens against a {overflow.n_ctx} window)"
                                if overflow.n_ctx else "")
                        await on_thought(f"context full{over} — dropped {pct}% of the older tool "
                                         f"output and retrying; ask again for any detail you need")
                    try:
                        data = await self._post(payload)
                        break
                    except ContextOverflow:
                        before = after
                        continue
                if data is None:
                    raise ContextOverflow(
                        "the prompt will not fit this model's context window even after "
                        "compaction. Start a new session, narrow the scope, or raise the "
                        f"backend's context size. {overflow}",
                        n_ctx=overflow.n_ctx, n_prompt=overflow.n_prompt) from overflow
            if on_usage is not None:
                try:
                    on_usage(data.get("usage") or {})
                except Exception:  # noqa: BLE001 — metrics must never break the run
                    pass
            msg = data["choices"][0]["message"]
            # Reasoning models (deepseek-reasoner, and some OpenAI-compat shims) return the
            # chain-of-thought in a SEPARATE field. Surface it to the live "thinking" feed, but
            # DO NOT keep it in history: DeepSeek rejects reasoning_content on input (400), and it
            # bloats context. Store only the standard role/content/tool_calls.
            reasoning = str(msg.get("reasoning_content") or msg.get("reasoning") or "").strip()
            clean = {k: v for k, v in msg.items() if k not in ("reasoning_content", "reasoning")}
            messages.append(clean)
            if reasoning and on_thought is not None:
                try:
                    await on_thought(reasoning if len(reasoning) <= 2000 else reasoning[:2000] + " …")
                except Exception:  # noqa: BLE001
                    pass
            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                return msg.get("content") or ""
            # The only backstop (not a step budget): stop if the agent is genuinely stuck,
            # repeating the identical tool-call batch stall_limit times in a row.
            sig = json.dumps(
                [[tc["function"]["name"], tc["function"].get("arguments")] for tc in tool_calls],
                sort_keys=True, default=str,
            )
            if stall_limit and sig == stall_sig:
                stall += 1
                if stall >= stall_limit:
                    return f"stopped: agent repeated the same action {stall_limit}x in a row (stuck)."
            else:
                stall, stall_sig = 0, sig

            # Same tool, same place, different payload, same lack of progress. Nudge once,
            # then stop if it carries on regardless.
            for tc in tool_calls:
                if tc["function"]["name"] not in _POLL_TOOLS:
                    call_sites.append(_call_site(tc))
            del call_sites[:-_SITE_WINDOW]
            if len(call_sites) >= _SITE_WINDOW:
                site, hits = Counter(call_sites).most_common(1)[0]
                if hits >= _SITE_STOP and site in site_nudged:
                    where = site.split("|", 1)[0]
                    return (f"stopped: agent kept calling {where} against the same target "
                            f"{hits} times in the last {_SITE_WINDOW} steps without progress.")
                if hits >= _SITE_NUDGE and site not in site_nudged:
                    site_nudged.add(site)
                    where = site.split("|", 1)[0]
                    messages.append({"role": "user", "content":
                        f"[SYSTEM NOTE] You have called '{where}' against the same target {hits} "
                        f"times in the last {_SITE_WINDOW} steps, varying the payload and learning "
                        f"nothing new. Whatever you were trying is not going to work this way. "
                        f"Record anything you have already confirmed, then do something materially "
                        f"different or move to another target."})
            # surface the model's reasoning it wrote alongside this batch of tool calls
            thought = (msg.get("content") or "").strip()
            if thought and on_thought is not None:
                try:
                    await on_thought(thought)
                except Exception:
                    pass
            # Every tool_call in this assistant message MUST get a matching tool
            # response, or the provider rejects the next request (400). We track which
            # ids we've answered and, if the turn is cancelled mid-batch, fill the rest
            # with a synthetic response so the conversation history stays valid.
            answered: set[str] = set()
            try:
                for tc in tool_calls:
                    name = tc["function"]["name"]
                    raw = tc["function"].get("arguments")
                    try:
                        args = json.loads(raw) if isinstance(raw, str) else (raw or {})
                    except (json.JSONDecodeError, TypeError):
                        args = None
                    if on_call is not None:  # announce the action before it runs (slow tools!)
                        try:
                            await on_call(name, args or {})
                        except Exception:
                            pass
                    fn = dispatch.get(name)
                    if args is None:
                        result = {"error": f"arguments for {name} were not valid JSON — resend valid JSON"}
                    elif fn is None:
                        result = {"error": f"unknown tool {name}"}
                    else:
                        result = await self._run_tool(name, fn, args, tool_timeout, interrupt)
                    # record the response BEFORE on_step, so a cancel during on_step still counts
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": json.dumps(result, default=str)[:12000],
                    })
                    answered.add(tc["id"])
                    # Track identical-result repeats (no new information) per (tool, args).
                    if name not in _POLL_TOOLS and args is not None:
                        csig = name + ":" + json.dumps(args, sort_keys=True, default=str)
                        rjson = json.dumps(result, default=str)[:4000]
                        repeats[csig] = repeats.get(csig, 0) + 1 if last_result.get(csig) == rjson else 1
                        last_result[csig] = rjson
                    if on_step is not None:
                        try:
                            await on_step(name, args or {}, result)
                        except Exception:
                            pass
            except asyncio.CancelledError:
                for tc in tool_calls:  # close out any unanswered tool_calls -> valid history
                    if tc["id"] not in answered:
                        messages.append({"role": "tool", "tool_call_id": tc["id"],
                                         "content": json.dumps({"error": "cancelled by operator"})})
                raise
            # Nudge (once per signature) when a call has returned the same result 3+ times: it is
            # spinning. This steers the model to change approach without dictating WHAT to do.
            for csig, cnt in repeats.items():
                if cnt >= 3 and csig not in nudged:
                    nudged.add(csig)
                    tname = csig.split(":", 1)[0]
                    messages.append({"role": "user", "content":
                        f"[SYSTEM NOTE] Your '{tname}' call has returned the same result several times "
                        f"— it is giving you no new information. Stop repeating it: change the arguments, "
                        f"switch to a different tool or technique, or move on with what you already know."})
        return "Reached max reasoning steps."

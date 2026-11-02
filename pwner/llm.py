"""OpenAI-compatible LLM client for pwner.

Exposes chat(), chat_json() and an agentic run_tools() function-calling loop.
Provider presets cover OpenAI / DeepSeek / Anthropic (OpenAI-compat) / Gemini /
Ollama. When no API key is configured, callers fall back to deterministic logic
(see agent.py) — so pwner still works without a key.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
from typing import Any, Awaitable, Callable

import httpx


class AIUnavailable(RuntimeError):
    """Raised when no API key is configured / auth-billing failure. Callers fall
    back to deterministic logic."""


class LLMError(RuntimeError):
    """A transient or permanent provider error the caller should surface."""


PRESETS: dict[str, dict[str, str]] = {
    "openai":    {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "deepseek":  {"base_url": "https://api.deepseek.com",   "model": "deepseek-v4-pro"},
    "anthropic": {"base_url": "https://api.anthropic.com/v1", "model": "claude-sonnet-4-5"},
    "gemini":    {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
                  "model": "gemini-flash-latest"},
    "ollama":    {"base_url": "http://localhost:11434/v1",  "model": "llama3.1"},
}


def resolve_config(provider: str, api_key: str, base_url: str, model: str) -> tuple[str, str, str]:
    """Return (api_key, base_url, model). Precedence: CLI args > env vars > saved
    config (~/.config/pwner/config.json) > provider preset."""
    from . import config as _cfg
    saved = _cfg.load()
    provider = (provider or "").strip().lower() or str(saved.get("provider", "")).strip().lower() or "openai"
    preset = PRESETS.get(provider, {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"})
    base = (base_url or os.environ.get("PWNER_BASE_URL") or preset["base_url"]).rstrip("/")
    mod = model or os.environ.get("PWNER_MODEL") or preset["model"]
    key = (api_key
           or os.environ.get("PWNER_API_KEY")
           or os.environ.get("OPENAI_API_KEY")
           or os.environ.get("ANTHROPIC_API_KEY")
           or os.environ.get("GEMINI_API_KEY")
           or saved.get("api_key", "")
           or "").strip()
    return key, base, mod


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
    if t[:1] not in ("{", "["):
        i_obj, i_arr = t.find("{"), t.find("[")
        cands = [i for i in (i_obj, i_arr) if i != -1]
        if cands:
            start = min(cands)
            open_ch = t[start]
            close_ch = "}" if open_ch == "{" else "]"
            end = t.rfind(close_ch)
            if end > start:
                t = t[start:end + 1]
    return t.strip()


class LLMClient:
    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        if not self.api_key:
            raise AIUnavailable("no API key configured")

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

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
                body = r.text[:300]
                if r.status_code in (401, 402, 403):
                    raise AIUnavailable(f"auth/billing error {r.status_code}: {body}")
                raise LLMError(f"LLM {r.status_code}: {body}")
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
            data = await self._post(payload)
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

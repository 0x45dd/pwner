"""Tests for the @tool registry.

The registry exists so a tool is declared once instead of three times. These tests
cover the validation it does at import time (a bad declaration should fail loudly,
not produce a tool the model can see but not call) and the invariants every registered
tool has to satisfy.
"""
from __future__ import annotations

import inspect

import pytest

from pwner import tools
from pwner.tools import ScanContext, build_dispatch, tool, tool_schemas


@pytest.fixture
def clean_registry():
    """Register throwaway tools without leaking them into the real registry."""
    saved = dict(tools._REGISTRY)
    try:
        yield
    finally:
        tools._REGISTRY.clear()
        tools._REGISTRY.update(saved)


# ── what the decorator rejects ───────────────────────────────────────────────

def test_a_duplicate_tool_name_is_rejected(clean_registry):
    @tool("first", {})
    async def demo_tool(ctx, args):
        return {}

    with pytest.raises(RuntimeError, match="already registered"):
        @tool("second", {})
        async def demo_tool(ctx, args):  # noqa: F811 — same name on purpose
            return {}


def test_a_sync_tool_is_rejected(clean_registry):
    """Dispatch awaits every tool, and the scope guard relies on the call being a
    coroutine to surface refusals as recoverable results."""
    with pytest.raises(RuntimeError, match="must be async"):
        @tool("not async", {})
        def sync_tool(ctx, args):
            return {}


def test_required_parameter_must_be_declared(clean_registry):
    """A required name absent from properties produces a schema the model cannot
    satisfy — it would be told to send a field that does not exist."""
    with pytest.raises(RuntimeError, match="undeclared parameter"):
        @tool("typo", {"target": {"type": "string"}}, ["taget"])
        async def typo_tool(ctx, args):
            return {}


def test_a_registered_tool_becomes_dispatchable(clean_registry):
    @tool("demo", {"host": {"type": "string"}}, ["host"])
    async def demo_tool(ctx, args):
        return {"ok": True}

    d = build_dispatch(ScanContext(target="10.0.0.5"))
    assert "demo_tool" in d
    names = {s["function"]["name"] for s in tool_schemas()}
    assert "demo_tool" in names


def test_a_new_tool_is_scope_guarded_without_opting_in(clean_registry):
    """The point of the registry: registering a tool is all it takes to be guarded.
    This one never calls _require_scope and never declares scope_exempt."""
    reached = []

    @tool("demo", {"host": {"type": "string"}}, ["host"])
    async def unguarded_newcomer(ctx, args):
        reached.append(args)
        return {}

    d = build_dispatch(ScanContext(target="10.0.0.0/24"))
    with pytest.raises(tools.ToolError, match="outside the authorized scope"):
        import asyncio
        asyncio.run(d["unguarded_newcomer"]({"host": "8.8.8.8"}))
    assert reached == [], "tool body ran despite an out-of-scope host"


# ── invariants over the real 47 tools ────────────────────────────────────────

def test_registry_is_not_empty():
    assert len(tools._REGISTRY) == 47


@pytest.mark.parametrize("name", sorted(tools._REGISTRY))
def test_every_tool_is_well_formed(name):
    entry = tools._REGISTRY[name]
    assert entry.name == entry.fn.__name__, "registry key must be the function's own name"
    assert inspect.iscoroutinefunction(entry.fn)
    assert entry.description.strip(), "an empty description gives the model nothing to go on"
    assert isinstance(entry.properties, dict)
    assert set(entry.required) <= set(entry.properties)


@pytest.mark.parametrize("schema", tool_schemas(), ids=lambda s: s["function"]["name"])
def test_every_schema_is_openai_shaped(schema):
    assert schema["type"] == "function"
    fn = schema["function"]
    assert set(fn) == {"name", "description", "parameters"}
    params = fn["parameters"]
    assert params["type"] == "object"
    assert isinstance(params["properties"], dict)
    assert isinstance(params["required"], list)
    for prop in params["properties"].values():
        assert "type" in prop, "every parameter needs a JSON-schema type"


def test_schema_order_is_declaration_order():
    assert [s["function"]["name"] for s in tool_schemas()] == list(tools._REGISTRY)

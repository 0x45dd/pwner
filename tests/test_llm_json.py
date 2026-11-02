"""Tests for recovering JSON from a model that ignored response_format=json_object.

Providers behind an OpenAI-compat shim wrap JSON in a ```json fence or add prose
around it. _strip_code_fence is what keeps that from becoming a hard parse failure.
"""
from __future__ import annotations

import json

import pytest

from pwner.llm import _strip_code_fence


@pytest.mark.parametrize("raw", [
    '{"a": 1}',
    '  {"a": 1}  ',
    '```json\n{"a": 1}\n```',
    '```JSON\n{"a": 1}\n```',
    '```\n{"a": 1}\n```',
    '```json\n{"a": 1}',                       # unterminated fence
    'Here is the result:\n{"a": 1}',           # leading prose
    '{"a": 1}\nHope that helps!',              # trailing prose
    'Sure thing:\n```json\n{"a": 1}\n```\nDone.',
])
def test_object_is_recovered(raw):
    assert json.loads(_strip_code_fence(raw)) == {"a": 1}


@pytest.mark.parametrize("raw", [
    '[1, 2]',
    '```json\n[1, 2]\n```',
    'Result: [1, 2]',
])
def test_array_is_recovered(raw):
    assert json.loads(_strip_code_fence(raw)) == [1, 2]


def test_nested_braces_are_not_truncated():
    payload = {"findings": [{"host": "10.0.0.5", "ports": [22, 443], "meta": {"ok": True}}]}
    assert json.loads(_strip_code_fence(f"```json\n{json.dumps(payload)}\n```")) == payload


def test_array_is_preferred_when_it_comes_first():
    """Picks the earliest opening bracket, so a '{' in later prose cannot mislead it."""
    assert json.loads(_strip_code_fence('[{"a": 1}] and some {notes}')) == [{"a": 1}]


def test_json_containing_a_fence_in_a_string_survives():
    payload = {"note": "run ```nmap``` first"}
    assert json.loads(_strip_code_fence(json.dumps(payload))) == payload


@pytest.mark.parametrize("raw", ["", "   ", None])
def test_empty_input_is_handled(raw):
    assert _strip_code_fence(raw) == ""


def test_prose_with_no_json_is_returned_as_is_not_crashed():
    """The caller reports a parse error; _strip_code_fence itself must not raise."""
    assert _strip_code_fence("I could not complete that.") == "I could not complete that."

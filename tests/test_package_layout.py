"""Tests for the tools package's structure.

Two properties keep the split honest, and neither is visible from reading one file:

1. The dependency graph is a star — `core` owns the authorization boundary and depends on
   no sibling; everything else imports from `core` and nothing else. Break this and you
   get import cycles, or a tool module that quietly becomes load-order dependent.
2. Every submodule is imported by the package. A submodule nobody imports registers no
   tools, and its tools disappear from the agent's toolset with no error anywhere.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from pwner import tools

PKG = pathlib.Path(tools.__file__).parent
SUBMODULES = ["core", "nmap", "web", "net", "ad", "session", "target", "report"]


def sibling_imports(module: str) -> set[str]:
    """Which sibling modules `module` imports from."""
    tree = ast.parse((PKG / f"{module}.py").read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
            found.add(node.module.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None:
            found.update(a.name for a in node.names)
    return found & set(SUBMODULES)


def test_core_depends_on_no_sibling():
    """core is the base of the star: it holds the scope guard, the consent gate and the
    registry, so anything it imported would be able to import it back."""
    assert sibling_imports("core") == set()


@pytest.mark.parametrize("module", [m for m in SUBMODULES if m != "core"])
def test_every_other_module_depends_only_on_core(module):
    assert sibling_imports(module) <= {"core"}, (
        f"{module}.py imports from a sibling other than core — that is how an import "
        f"cycle starts; move the shared helper into core instead"
    )


@pytest.mark.parametrize("module", SUBMODULES)
def test_submodule_is_reachable_from_the_package(module):
    assert hasattr(tools, module), (
        f"pwner.tools does not import {module} — its @tool declarations never run, so "
        f"its tools silently vanish from the agent's toolset"
    )


def test_every_tool_module_actually_registers_tools():
    """Each module that holds tools should contribute some. A module contributing zero
    is the symptom of a dropped import or a lost decorator."""
    by_module = {}
    for name, entry in tools._REGISTRY.items():
        by_module.setdefault(entry.fn.__module__.rsplit(".", 1)[-1], []).append(name)
    assert set(by_module) == set(SUBMODULES) - {"core"}, (
        f"tool-bearing modules changed: {sorted(by_module)}")
    assert sum(len(v) for v in by_module.values()) == 47


def test_package_reexports_every_submodule_name():
    """`from .tools import X` has to keep working for every name the submodules define —
    this package replaced one flat module and the rest of the codebase imports from it."""
    for module in SUBMODULES:
        tree = ast.parse((PKG / f"{module}.py").read_text())
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names = [node.name]
            elif isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            else:
                continue
            for n in names:
                assert hasattr(tools, n), f"{module}.{n} is not re-exported from pwner.tools"

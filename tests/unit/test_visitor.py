from __future__ import annotations

import sys
from importlib import util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import ida_hexrays

if not hasattr(ida_hexrays, "ctree_parentee_t"):
    ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {})

if "ida_idaapi" not in sys.modules:
    sys.modules["ida_idaapi"] = ModuleType("ida_idaapi")
import ida_idaapi
ida_idaapi.BADADDR = -1


def _load_visitor_module():
    visitor_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "visitor.py"
    spec = util.spec_from_file_location("forge.api.visitor_real", visitor_path)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _stub_visitor_deps(monkeypatch):
    import ida_funcs

    monkeypatch.setattr(ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}", raising=False)
    yield


def test_recursive_downwards_object_visitor_skips_missing_parent(monkeypatch):
    visitor_module = _load_visitor_module()
    cfunc = SimpleNamespace(entry_ea=0x401000)
    obj = SimpleNamespace(
        id=visitor_module.ObjectType.local_variable,
        ea=0x5000,
        name="arg0",
    )

    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = cfunc
    monkeypatch.setattr(visitor, "parent_expr", lambda: None, raising=False)
    visitor._check_call(SimpleNamespace(op=visitor_module.ctype.var))


def test_recursive_downwards_object_visitor_skips_invalid_callee_ordinal(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._new_for_visit = {(0x402000, 0)}
    monkeypatch.setattr(visitor_module.RecursiveObjectVisitor, "_recursive_process", lambda self: None)
    monkeypatch.setattr(
        visitor_module,
        "decompile",
        lambda _ea: SimpleNamespace(entry_ea=0x402000, argidx=[], get_lvars=lambda: []),
    )
    prepared_calls = []
    monkeypatch.setattr(visitor, "prepare_new_scan", lambda *args, **kwargs: prepared_calls.append(args), raising=False)

    visitor._recursive_process()

    assert prepared_calls == []

from __future__ import annotations

import sys
from importlib import import_module
from types import ModuleType, SimpleNamespace

import pytest

import ida_hexrays

if not hasattr(ida_hexrays, "ctree_parentee_t"):
    ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {})

if "ida_idaapi" not in sys.modules:
    sys.modules["ida_idaapi"] = ModuleType("ida_idaapi")
import ida_idaapi
ida_idaapi.BADADDR = -1

hexrays_api = import_module("forge.api.hexrays")
if not hasattr(hexrays_api, "find_expr_address"):
    setattr(hexrays_api, "find_expr_address", lambda *_args, **_kwargs: 0)

visitor_api = import_module("forge.api.visitor")


class _DummyRecursiveUpwardsObjectVisitor:
    def __init__(self, cfunc, obj, data=None, skip_until_object=False, visited=None):
        self._cfunc = cfunc
        self.parents = []
        self._skip = skip_until_object
        self._init_obj = obj

    def parent_expr(self):
        return None

    def get_line(self):
        return ""

visitor_api.RecursiveUpwardsObjectVisitor = _DummyRecursiveUpwardsObjectVisitor

from forge.api.scan_object import ObjectType

guess_allocation_module = import_module("forge.features.guess_allocation.guess_allocation")


@pytest.fixture(autouse=True)
def _stub_guess_allocation_dependencies(monkeypatch):
    ida_funcs = import_module("ida_funcs")
    monkeypatch.setattr(ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}", raising=False)
    yield


def test_guess_allocation_matches_object_without_base_helper(monkeypatch):
    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        body=SimpleNamespace(find_parent_of=lambda expr: None),
    )
    obj = SimpleNamespace(id=ObjectType.local_variable, ea=0x5000, name="arg0")

    visitor = guess_allocation_module.GuessAllocationVisitor(cfunc, obj)
    monkeypatch.setattr(
        guess_allocation_module,
        "find_expr_address",
        lambda _cexpr, _parents: 0x5000,
    )

    assert visitor._matches_object(obj, SimpleNamespace(ea=0x5000)) is True


def test_guess_allocation_records_heap_assignment(monkeypatch):
    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        body=SimpleNamespace(find_parent_of=lambda expr: None),
    )
    obj = SimpleNamespace(id=ObjectType.local_variable, ea=0x5000, name="v1")

    visitor = guess_allocation_module.GuessAllocationVisitor(cfunc, obj)
    monkeypatch.setattr(
        guess_allocation_module,
        "ctype",
        SimpleNamespace(asg=1, ref=2),
    )
    monkeypatch.setattr(
        visitor,
        "parent_expr",
        lambda: SimpleNamespace(op=guess_allocation_module.ctype.asg, y=SimpleNamespace()),
    )
    monkeypatch.setattr(
        guess_allocation_module.MemoryAllocationObject,
        "create",
        lambda _cfunc, _expr: SimpleNamespace(ea=0x401010),
    )
    monkeypatch.setattr(visitor, "get_line", lambda: "v1 = calloc(...)")

    visitor._manipulate(SimpleNamespace(), obj)

    assert visitor._data == [[0x401010, "v1", "v1 = calloc(...)", "HEAP"]]


def test_guess_allocation_skips_when_parent_expression_is_missing(monkeypatch):
    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        body=SimpleNamespace(find_parent_of=lambda expr: None),
    )
    obj = SimpleNamespace(id=ObjectType.local_variable, ea=0x5000, name="arg0")

    visitor = guess_allocation_module.GuessAllocationVisitor(cfunc, obj)
    monkeypatch.setattr(visitor, "parent_expr", lambda: None)
    monkeypatch.setattr(visitor, "get_line", lambda: "line 1")

    visitor._manipulate(SimpleNamespace(), obj)

    assert visitor._data == []

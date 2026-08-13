from __future__ import annotations

import sys
from importlib import import_module
from types import ModuleType, SimpleNamespace

import ida_hexrays
import pytest

if not hasattr(ida_hexrays, "ctree_parentee_t"):
    ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {})

if "ida_idaapi" not in sys.modules:
    sys.modules["ida_idaapi"] = ModuleType("ida_idaapi")
import ida_idaapi

ida_idaapi.BADADDR = -1

hexrays_api = import_module("forge.api.hexrays")
if not hasattr(hexrays_api, "find_expr_address"):
    hexrays_api.find_expr_address = lambda *_args, **_kwargs: 0

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
        lambda _cfunc, _expr: SimpleNamespace(ea=0x401010, size=32),
    )
    monkeypatch.setattr(visitor, "get_line", lambda: "v1 = calloc(...)")

    visitor._manipulate(SimpleNamespace(), obj)

    assert visitor._data == [[0x401010, "v1", "v1 = calloc(...)", "HEAP", 32, None]]


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


@pytest.fixture
def _real_hexrays(monkeypatch):
    """Real forge.api.hexrays module so call-time imports resolve (facade
    pattern from test_forge_api)."""
    import sys as _sys
    from importlib import util as _util
    from pathlib import Path

    hexrays_path = (
        Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "hexrays.py"
    )
    spec = _util.spec_from_file_location("forge.api.hexrays", hexrays_path)
    assert spec is not None and spec.loader is not None
    module = _util.module_from_spec(spec)
    saved = _sys.modules.get("forge.api.hexrays")
    _sys.modules["forge.api.hexrays"] = module
    spec.loader.exec_module(module)
    yield module
    if saved is not None:
        _sys.modules["forge.api.hexrays"] = saved
    else:
        _sys.modules.pop("forge.api.hexrays", None)


def test_guess_allocation_follows_helper_callee_for_allocation(monkeypatch, _real_hexrays):
    """I.25: a non-allocator helper assignment resolves through a one-level
    decompile of the callee: `return vec = malloc(...)` gives a HEAP row
    tagged with the callee EA."""
    import ida_funcs

    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        body=SimpleNamespace(find_parent_of=lambda expr: None),
    )
    obj = SimpleNamespace(id=ObjectType.local_variable, ea=0x5000, name="items")

    visitor = guess_allocation_module.GuessAllocationVisitor(cfunc, obj)
    monkeypatch.setattr(
        guess_allocation_module,
        "ctype",
        SimpleNamespace(asg=1, ref=2, ret=3, call=5),
    )
    monkeypatch.setattr(visitor, "parent_expr", lambda: SimpleNamespace(op=1, y=SimpleNamespace(
        op=5, x=SimpleNamespace(obj_ea=0x402000)
    )))
    monkeypatch.setattr(visitor, "get_line", lambda: "items = MakeArray(...)")

    def _fake_create(_cfunc, _expr):
        called_for = getattr(getattr(_expr, "x", None), "obj_ea", None)
        if called_for == 0x402000:  # MakeArray itself is not an allocator
            return None
        return SimpleNamespace(ea=0x401200, size=64)

    monkeypatch.setattr(
        guess_allocation_module.MemoryAllocationObject, "create", _fake_create
    )
    monkeypatch.setattr(
        ida_funcs, "get_func", lambda ea: SimpleNamespace(start_ea=0x402000), raising=False
    )
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: SimpleNamespace(
            treeitems=[
                SimpleNamespace(to_specific_type=None, op=3, x=SimpleNamespace(ea=0x402010)),
                SimpleNamespace(
                    to_specific_type=None,
                    op=1,
                    x=SimpleNamespace(ea=0x402010),
                    y=SimpleNamespace(op=5, x=SimpleNamespace(obj_ea=0x5000)),
                ),
                SimpleNamespace(to_specific_type=None, op=3, x=SimpleNamespace(ea=0x402020)),
            ]
        ),
    )

    visitor._manipulate(SimpleNamespace(), obj)

    # the matching return; the unrelated return is skipped
    assert visitor._data == [
        [0x401200, "items", "items = MakeArray(...)", "HEAP", 64, 0x402000]
    ]


def test_guess_allocation_callee_descent_failure_degrades_to_no_row(monkeypatch, _real_hexrays):
    """I.25: a broken callee decompile must not crash the visitor."""
    import ida_funcs

    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        body=SimpleNamespace(find_parent_of=lambda expr: None),
    )
    obj = SimpleNamespace(id=ObjectType.local_variable, ea=0x5000, name="items")

    visitor = guess_allocation_module.GuessAllocationVisitor(cfunc, obj)
    monkeypatch.setattr(
        guess_allocation_module,
        "ctype",
        SimpleNamespace(asg=1, ref=2, ret=3, call=5),
    )
    monkeypatch.setattr(
        visitor,
        "parent_expr",
        lambda: SimpleNamespace(op=1, y=SimpleNamespace(op=5, x=SimpleNamespace(obj_ea=0x402000))),
    )
    monkeypatch.setattr(
        guess_allocation_module.MemoryAllocationObject,
        "create",
        lambda _cfunc, _expr: None,
    )
    monkeypatch.setattr(
        ida_funcs, "get_func", lambda ea: SimpleNamespace(start_ea=0x402000), raising=False
    )
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    visitor._manipulate(SimpleNamespace(), obj)

    assert visitor._data == []


def test_facade_guess_allocation_surface_size_hint_and_callee(monkeypatch, _real_hexrays):
    """I.24/I.25: facade rows carry size_hint/callee from the visitor rows."""
    import forge_api
    from forge.features.guess_allocation.guess_allocation import (
        GuessAllocationVisitor as _RealVisitor,
    )

    rows_payload = [[0x401200, "v1", "v1 = f()", "HEAP", 64, 0x402000]]
    monkeypatch.setattr(
        _real_hexrays, "decompile", lambda ea: SimpleNamespace(entry_ea=0x401000), raising=False
    )
    monkeypatch.setattr(
        forge_api,
        "_resolve_scan_root",
        lambda cfunc, **kw: SimpleNamespace(id=1, name="v1"),
        raising=False,
    )
    monkeypatch.setattr(
        _RealVisitor,
        "__init__",
        lambda self, *a, **k: setattr(self, "_data", rows_payload),
        raising=False,
    )
    monkeypatch.setattr(_RealVisitor, "process", lambda self: None, raising=False)

    rows = forge_api.guess_allocation(0x401000, var_name="v1")

    assert rows == [
        {
            "ea": 0x401200,
            "var": "v1",
            "line": "v1 = f()",
            "kind": "HEAP",
            "size_hint": 64,
            "callee": 0x402000,
        }
    ]

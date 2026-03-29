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


def test_recursive_downwards_object_visitor_leave_expr_checks_calls(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._skip = False
    visitor._recurse_calls = True
    seen = []

    monkeypatch.setattr(visitor, "_check_call", lambda cexpr: seen.append(cexpr), raising=False)


    monkeypatch.setattr(
        visitor_module.DownwardsObjectVisitor,
        "leave_expr",
        lambda self, cexpr: "downwards",
    )

    result = visitor.leave_expr(SimpleNamespace(op=visitor_module.ctype.var))

    assert seen and seen[0].op == visitor_module.ctype.var
    assert result == "downwards"


def test_recursive_downwards_object_visitor_retries_deferred_child_arguments(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._new_for_visit = {(0x402000, 0), (0x403000, 0)}

    prepared_calls = []
    monkeypatch.setattr(
        visitor_module.RecursiveObjectVisitor,
        "_recursive_process",
        lambda self: None,
    )

    call_counts = {0x401000: 0, 0x402000: 0, 0x403000: 0}
    ready = {"value": False}

    def fake_decompile(ea):
        call_counts[ea] += 1
        if ea == 0x401000:
            return SimpleNamespace(
                entry_ea=ea,
                argidx=[0],
                get_lvars=lambda: [SimpleNamespace(name="this", type=lambda: SimpleNamespace(dstr=lambda: "FixtureScene *"))],
            )
        if ea == 0x403000:
            ready["value"] = True
            return SimpleNamespace(
                entry_ea=ea,
                argidx=[0],
                get_lvars=lambda: [SimpleNamespace(name="arg0", type=lambda: SimpleNamespace(dstr=lambda: "FixtureScene *"))],
            )
        if ea == 0x402000:
            if call_counts[ea] == 1:
                return SimpleNamespace(
                    entry_ea=ea,
                    argidx=[],
                    get_lvars=lambda: [SimpleNamespace(name="arg0", type=lambda: SimpleNamespace(dstr=lambda: "FixtureScene *"))],
                )
            return SimpleNamespace(
                entry_ea=ea,
                argidx=[0] if ready["value"] else [],
                get_lvars=lambda: [SimpleNamespace(name="arg0", type=lambda: SimpleNamespace(dstr=lambda: "FixtureScene *"))],
            )
        return None

    monkeypatch.setattr(visitor_module, "decompile", fake_decompile)
    monkeypatch.setattr(
        visitor_module,
        "get_argument",
        lambda cfunc, idx: (cfunc.get_lvars()[0], 0),
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "prepare_new_scan",
        lambda cfunc, arg_idx, obj, skip=False: prepared_calls.append(
            (cfunc.entry_ea, arg_idx, obj.name)
        ),
        raising=False,
    )

    visitor._recursive_process()

    assert (0x403000, 0, "arg0") in prepared_calls
    assert (0x402000, 0, "arg0") in prepared_calls
    assert call_counts[0x402000] >= 2

def test_recursive_downwards_object_visitor_refreshes_tree_before_scanning(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._new_for_visit = {(0x402000, 0)}

    prepared_calls = []
    refresh_calls = []
    ready = {"value": False}

    monkeypatch.setattr(
        visitor_module.RecursiveObjectVisitor,
        "_recursive_process",
        lambda self: None,
    )

    def fake_refresh(cfunc):
        refresh_calls.append(cfunc.entry_ea)
        if cfunc.entry_ea == 0x401000:
            ready["value"] = True
        return cfunc

    def fake_decompile(ea):
        if ea == 0x402000:
            return SimpleNamespace(
                entry_ea=ea,
                argidx=[0] if ready["value"] else [],
                get_lvars=lambda: [SimpleNamespace(name="arg0", type=lambda: SimpleNamespace(dstr=lambda: "FixtureScene *"))],
            )
        if ea == 0x401000:
            return SimpleNamespace(
                entry_ea=ea,
                argidx=[0],
                get_lvars=lambda: [SimpleNamespace(name="this", type=lambda: SimpleNamespace(dstr=lambda: "FixtureScene *"))],
            )
        return None

    monkeypatch.setattr(visitor_module, "decompile", fake_decompile)
    monkeypatch.setattr(visitor_module, "refresh_function_tree_postorder", fake_refresh)
    monkeypatch.setattr(
        visitor_module,
        "get_argument",
        lambda cfunc, idx: (cfunc.get_lvars()[0], 0),
        raising=False,
    )

    def fake_prepare_new_scan(cfunc, arg_idx, obj, skip=False):
        visitor._cfunc = cfunc
        prepared_calls.append((cfunc.entry_ea, arg_idx, obj.name))

    monkeypatch.setattr(visitor, "prepare_new_scan", fake_prepare_new_scan, raising=False)

    visitor._recursive_process()

    assert refresh_calls[:2] == [0x401000, 0x402000]
    assert prepared_calls == [(0x402000, 0, "arg0")]




def test_refresh_function_tree_postorder_refreshes_parent_after_child_decompilation(monkeypatch):
    visitor_module = _load_visitor_module()
    refresh_order = []
    child_ready = {"value": False}
    parent_ready = {"value": False}

    call_graph = {
        0x401000: [0x402000],
        0x402000: [0x403000],
        0x403000: [],
    }

    class FakeCollector:
        def __init__(self, cfunc):
            self._cfunc = cfunc
            self._functions = set()

        def apply_to(self, _body, _parent):
            self._functions = set(call_graph.get(self._cfunc.entry_ea, []))

    def fake_decompile(ea):
        refresh_order.append(ea)
        if ea == 0x403000:
            child_ready["value"] = True
            return SimpleNamespace(entry_ea=ea, body=SimpleNamespace(), argidx=[0], get_lvars=lambda: [])
        if ea == 0x402000:
            if child_ready["value"]:
                parent_ready["value"] = True
                return SimpleNamespace(entry_ea=ea, body=SimpleNamespace(), argidx=[0], get_lvars=lambda: [])
            return SimpleNamespace(entry_ea=ea, body=SimpleNamespace(), argidx=[], get_lvars=lambda: [])
        if ea == 0x401000:
            return SimpleNamespace(
                entry_ea=ea,
                body=SimpleNamespace(),
                argidx=[0] if parent_ready["value"] else [],
                get_lvars=lambda: [SimpleNamespace(name="this", type=lambda: SimpleNamespace(dstr=lambda: "FixtureScene *"))],
            )
        return None

    monkeypatch.setattr(visitor_module, "FunctionTouchVisitor", FakeCollector)
    monkeypatch.setattr(visitor_module, "decompile", fake_decompile)
    monkeypatch.setattr(visitor_module, "is_imported", lambda _ea: False)

    refreshed = visitor_module.refresh_function_tree_postorder(SimpleNamespace(entry_ea=0x401000))

    assert refreshed.entry_ea == 0x401000
    assert refreshed.argidx == [0]
    assert parent_ready["value"] is True
    assert refresh_order == [0x401000, 0x402000, 0x403000, 0x402000, 0x401000]



def test_refresh_function_tree_postorder_redecompiles_revisited_parent(monkeypatch):
    visitor_module = _load_visitor_module()
    decompile_order = []
    call_graph = {
        0x401000: [0x402000],
        0x402000: [0x401000],
    }

    class FakeCollector:
        def __init__(self, cfunc):
            self._cfunc = cfunc
            self._functions = set()

        def apply_to(self, _body, _parent):
            self._functions = set(call_graph.get(self._cfunc.entry_ea, []))

    def fake_decompile(ea):
        decompile_order.append(ea)
        return SimpleNamespace(entry_ea=ea, body=SimpleNamespace(), argidx=[0], get_lvars=lambda: [])

    monkeypatch.setattr(visitor_module, "FunctionTouchVisitor", FakeCollector)
    monkeypatch.setattr(visitor_module, "decompile", fake_decompile)
    monkeypatch.setattr(visitor_module, "is_imported", lambda _ea: False)

    refreshed = visitor_module.refresh_function_tree_postorder(SimpleNamespace(entry_ea=0x401000))

    assert refreshed.entry_ea == 0x401000
    assert decompile_order.count(0x401000) >= 2
    assert decompile_order.count(0x402000) >= 1



def test_refresh_function_tree_postorder_discovers_new_root_callees_after_child_refresh(monkeypatch):
    visitor_module = _load_visitor_module()
    touched = []
    child_refreshed = {"value": False}
    class FakeCollector:
        def __init__(self, cfunc):
            self._cfunc = cfunc
            self._functions = set()

        def apply_to(self, _body, _parent):
            if self._cfunc.entry_ea == 0x401000 and child_refreshed["value"]:
                self._functions = {0x402000, 0x404000}
            elif self._cfunc.entry_ea == 0x401000:
                self._functions = {0x402000}
            elif self._cfunc.entry_ea == 0x402000:
                self._functions = {0x403000}
            else:
                self._functions = set()


    def fake_decompile(ea):
        touched.append(ea)
        if ea == 0x403000:
            child_refreshed["value"] = True
        return SimpleNamespace(entry_ea=ea, body=SimpleNamespace(), argidx=[0], get_lvars=lambda: [])

    monkeypatch.setattr(visitor_module, "FunctionTouchVisitor", FakeCollector)
    monkeypatch.setattr(visitor_module, "decompile", fake_decompile)
    monkeypatch.setattr(visitor_module, "is_imported", lambda _ea: False)

    refreshed = visitor_module.refresh_function_tree_postorder(SimpleNamespace(entry_ea=0x401000))

    assert refreshed.entry_ea == 0x401000
    assert 0x404000 in touched
    assert touched.count(0x401000) >= 2


from __future__ import annotations

import sys
from importlib import util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import ida_hexrays
import pytest

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


def test_recursive_downwards_object_visitor_inherits_scan_root(monkeypatch):
    visitor_module = _load_visitor_module()
    root_obj = SimpleNamespace(
        scan_root_function_ea=0x401000,
        scan_root_ea=0x401234,
        scan_root_function_name="sub_401000",
        is_target=lambda expr: expr.name == "target",
    )
    child_obj = SimpleNamespace(
        scan_root_function_ea=ida_idaapi.BADADDR,
        scan_root_ea=ida_idaapi.BADADDR,
        scan_root_function_name=None,
        inherit_scan_root_from=lambda other: (
            setattr(child_obj, "scan_root_function_ea", other.scan_root_function_ea),
            setattr(child_obj, "scan_root_ea", other.scan_root_ea),
            setattr(child_obj, "scan_root_function_name", other.scan_root_function_name),
        ),
    )
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(visitor_module.RecursiveDownwardsObjectVisitor)
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._objects = [root_obj]
    visitor._skip = False
    visitor._recurse_calls = False

    x_expr = SimpleNamespace(name="new")
    y_expr = SimpleNamespace(op=999, name="target")
    asg_op = getattr(visitor_module.ctype, "asg", 1)
    monkeypatch.setattr(visitor_module.ctype, "asg", asg_op, raising=False)
    asg_expr = SimpleNamespace(op=asg_op, x=x_expr, y=y_expr)

    monkeypatch.setattr(
        visitor_module.ScanObject,
        "create",
        staticmethod(lambda _cfunc, expr: child_obj if expr is x_expr else None),
    )

    visitor.visit_expr(asg_expr)

    assert child_obj.scan_root_function_ea == 0x401000
    assert child_obj.scan_root_ea == 0x401234
    assert child_obj.scan_root_function_name == "sub_401000"


def test_recursive_downwards_object_visitor_adds_child_from_assigned_member(monkeypatch):
    visitor_module = _load_visitor_module()
    root_obj = SimpleNamespace(
        scan_root_function_ea=0x401000,
        scan_root_ea=0x401234,
        scan_root_function_name="sub_401000",
        is_target=lambda expr: expr.name == "member",
    )
    child_obj = SimpleNamespace(
        scan_root_function_ea=ida_idaapi.BADADDR,
        scan_root_ea=ida_idaapi.BADADDR,
        scan_root_function_name=None,
        func_ea=0x401000,
        is_target=lambda _expr: False,
        inherit_scan_root_from=lambda other: (
            setattr(child_obj, "scan_root_function_ea", other.scan_root_function_ea),
            setattr(child_obj, "scan_root_ea", other.scan_root_ea),
            setattr(child_obj, "scan_root_function_name", other.scan_root_function_name),
        ),
    )
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(visitor_module.RecursiveDownwardsObjectVisitor)
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._objects = [root_obj]
    visitor._skip = False
    visitor._recurse_calls = False
    visitor._rescan_current_function = False

    x_expr = SimpleNamespace(name="member")
    y_expr = SimpleNamespace(op=999, name="child_var")
    asg_op = getattr(visitor_module.ctype, "asg", 1)
    monkeypatch.setattr(visitor_module.ctype, "asg", asg_op, raising=False)
    asg_expr = SimpleNamespace(op=asg_op, x=x_expr, y=y_expr)

    monkeypatch.setattr(
        visitor_module.ScanObject,
        "create",
        staticmethod(lambda _cfunc, expr: child_obj if expr is y_expr else None),
    )

    visitor.visit_expr(asg_expr)

    assert child_obj.scan_root_function_ea == 0x401000
    assert child_obj.scan_root_ea == 0x401234
    assert child_obj.scan_root_function_name == "sub_401000"
    assert visitor._objects == [root_obj, child_obj]
    assert visitor._rescan_current_function is True

def test_initial_object_accepts_legacy_scanned_variable_without_is_target(monkeypatch):
    visitor_module = _load_visitor_module()
    monkeypatch.setattr(visitor_module, "ctype", SimpleNamespace(asg=1, cast=2, var=3), raising=False)
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(visitor_module.RecursiveDownwardsObjectVisitor)
    visitor.parents = []
    visitor._start_ea = 0x402000
    visitor._init_obj = SimpleNamespace(ea=0x402000)

    monkeypatch.setattr(visitor_module, "find_expr_address", lambda _cexpr, _parents: 0x402000)

    assert visitor._is_initial_object(SimpleNamespace(op=visitor_module.ctype.var, ea=0x402000)) is True



def test_leave_expr_accepts_legacy_scanned_variable_without_is_target(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(visitor_module.RecursiveDownwardsObjectVisitor)
    visitor._skip = False
    visitor._objects = [SimpleNamespace(ea=0x402000, id=visitor_module.ObjectType.local_variable)]

    seen = []
    monkeypatch.setattr(visitor, "_manipulate", lambda cexpr, obj: seen.append((cexpr.ea, obj.ea)), raising=False)
    monkeypatch.setattr(visitor_module, "find_expr_address", lambda _cexpr, _parents: 0x402000)

    assert visitor.leave_expr(SimpleNamespace(op=999, ea=0x402000)) == 0
    assert seen == [(0x402000, 0x402000)]


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
    monkeypatch.setattr(
        visitor,
        "prepare_new_scan",
        lambda cfunc, arg_idx, obj, skip=False: prepared_calls.append(
            (cfunc.entry_ea, arg_idx, obj.name)
        ),
        raising=False,
    )

    visitor._recursive_process()

    assert (0x402000, 0, "arg0") in prepared_calls
    assert refresh_calls[0] == 0x401000
    assert 0x402000 in refresh_calls


def test_recursive_downwards_object_visitor_init_sets_downwards_state(monkeypatch):
    visitor_module = _load_visitor_module()
    calls = []

    def fake_recursive_init(self, cfunc, obj, data, skip_until_object, visited, recurse_calls=False):
        calls.append((cfunc, obj, data, skip_until_object, visited, recurse_calls))
        self._cfunc = cfunc
        self._objects = [obj]
        self._init_obj = obj
        self._data = data
        self._skip = skip_until_object
        self._visited = visited if visited else set()
        self._new_for_visit = set()
        self.crippled = False
        self._arg_index = -1
        self._debug_scan_tree = {}
        self._debug_scan_tree_root = "root"
        self._debug_message = []
        self.cv_flags = 0

    monkeypatch.setattr(visitor_module.RecursiveObjectVisitor, "__init__", fake_recursive_init)
    monkeypatch.setattr(visitor_module.ida_hexrays, "CV_POST", 1, raising=False)

    cfunc = SimpleNamespace(entry_ea=0x401000)
    obj = SimpleNamespace(id=visitor_module.ObjectType.local_variable, ea=0x5000, name="arg0")

    visitor = visitor_module.RecursiveDownwardsObjectVisitor(
        cfunc,
        obj,
        data="payload",
        skip_until_object=True,
        visited={(0x402000, 0)},
        recurse_calls=True,
    )

    assert calls == [(cfunc, obj, "payload", True, {(0x402000, 0)}, False)]
    assert visitor._recurse_calls is True
    assert visitor._rescan_current_function is False
    assert visitor.cv_flags & getattr(visitor_module.ida_hexrays, "CV_POST", 0)
    assert visitor._objects == [obj]




def test_recursive_upwards_object_visitor_init_sets_upwards_state(monkeypatch):
    visitor_module = _load_visitor_module()
    calls = []

    def fake_recursive_init(self, cfunc, obj, data, skip_until_object, visited):
        calls.append((cfunc, obj, data, skip_until_object, visited))
        self._cfunc = cfunc
        self._objects = [obj]
        self._init_obj = obj
        self._data = data
        self._skip = skip_until_object
        self._visited = visited if visited else set()
        self._new_for_visit = set()
        self.crippled = False
        self._arg_index = -1
        self._debug_scan_tree = {}
        self._debug_scan_tree_root = "root"
        self._debug_message = []
        self.cv_flags = 0

    monkeypatch.setattr(visitor_module.RecursiveObjectVisitor, "__init__", fake_recursive_init)

    cfunc = SimpleNamespace(entry_ea=0x401000)
    obj = SimpleNamespace(id=visitor_module.ObjectType.call_argument, ea=0x5000, name="arg0")

    visitor = visitor_module.RecursiveUpwardsObjectVisitor(
        cfunc,
        obj,
        data="payload",
        skip_until_object=True,
        visited={(0x402000, 0)},
    )

    assert calls == [(cfunc, obj, "payload", True, {(0x402000, 0)})]
    assert visitor._stage == visitor_module.RecursiveUpwardsObjectVisitor.STAGE_PREPARE
    assert visitor._tree == {}
    assert visitor._call_obj is obj
    assert visitor._objects == [obj]

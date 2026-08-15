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
    SimpleNamespace(
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



def test_execute_visit_drops_varargs_callees(monkeypatch):
    """Varargs callees (printf-style loggers) must not be scanned: their
    bodies frame every argument list as format input and pollute members
    (2026-08-11 format-string pollution regression guard)."""
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._max_depth = None
    visitor._current_depth = 0
    varargs_callee = SimpleNamespace(
        entry_ea=0x402000,
        argidx=[0],
        type=SimpleNamespace(is_vararg_cc=lambda: True),
        get_lvars=lambda: [SimpleNamespace(name="fmt")],
    )
    monkeypatch.setattr(
        visitor_module, "decompile", lambda _ea: varargs_callee, raising=False
    )
    monkeypatch.setattr(
        visitor, "_refresh_decompilation_tree", lambda c: c, raising=False
    )
    argument_queries = []
    monkeypatch.setattr(
        visitor_module,
        "get_argument",
        lambda *args, **kwargs: argument_queries.append(args) or (None, None),
        raising=False,
    )
    result = visitor._execute_visit(0x402000, 0, 0)
    assert result is None
    assert argument_queries == []

def test_recursive_downwards_object_visitor_skips_invalid_callee_ordinal(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._max_depth = None
    visitor._current_depth = 0
    visitor._new_for_visit = {(0x402000, 0)}
    visitor._visit_base_offsets = {}
    monkeypatch.setattr(visitor_module.RecursiveObjectVisitor, "_recursive_process", lambda self: None)
    monkeypatch.setattr(
        visitor_module,
        "decompile",
        lambda _ea: SimpleNamespace(entry_ea=0x402000, argidx=[], get_lvars=list),
    )
    prepared_calls = []
    monkeypatch.setattr(visitor, "prepare_new_scan", lambda *args, **kwargs: prepared_calls.append(args), raising=False)

    visitor._recursive_process()

    assert prepared_calls == []


def test_recursive_downwards_check_call_only_tracks_matched_argument(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._objects = [SimpleNamespace(name="tracked")]
    visitor.parents = SimpleNamespace(size=lambda: 1)
    visitor._visit_base_offsets = {}
    call_expr = SimpleNamespace(
        op=visitor_module.ctype.call,
        x=SimpleNamespace(obj_ea=0x402000),
    )
    matched_expr = SimpleNamespace(name="tracked")
    other_expr = SimpleNamespace(name="other")
    recorded_visits = []
    recorded_tree_edges = []
    argument_queries = []

    monkeypatch.setattr(visitor, "parent_expr", lambda: call_expr, raising=False)
    monkeypatch.setattr(
        visitor,
        "_matches_object",
        lambda _obj, cexpr: cexpr is matched_expr,
        raising=False,
    )
    monkeypatch.setattr(
        visitor_module,
        "get_func_argument_info",
        lambda call, arg: argument_queries.append((call, arg)) or (0, None),
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_visit",
        lambda func_ea, arg_idx: recorded_visits.append((func_ea, arg_idx)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_scan_tree_info",
        lambda func_ea, arg_idx: recorded_tree_edges.append((func_ea, arg_idx)),
        raising=False,
    )

    visitor._check_call(other_expr)
    visitor._check_call(matched_expr)

    assert argument_queries == [(call_expr, matched_expr)]
    assert recorded_visits == [(0x402000, 0)]
    assert recorded_tree_edges == [(0x402000, 0)]

def test_recursive_downwards_check_call_follows_offset_expression(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._objects = [SimpleNamespace(name="a1")]
    visitor.parents = SimpleNamespace(size=lambda: 1)
    visitor._visit_base_offsets = {}
    call_expr = SimpleNamespace(
        op=visitor_module.ctype.call,
        x=SimpleNamespace(obj_ea=0x402000),
    )
    a1_var = SimpleNamespace(op=visitor_module.ctype.var, name="a1")
    offset_num = SimpleNamespace(op=visitor_module.ctype.num, name="12", numval=lambda: 12)
    add_expr = SimpleNamespace(op=visitor_module.ctype.add, x=a1_var, y=offset_num)
    unrelated_expr = SimpleNamespace(op=visitor_module.ctype.var, name="other")
    recorded_visits = []

    monkeypatch.setattr(visitor, "parent_expr", lambda: call_expr, raising=False)
    monkeypatch.setattr(
        visitor,
        "_matches_object",
        lambda _obj, cexpr: cexpr is a1_var,
        raising=False,
    )
    monkeypatch.setattr(
        visitor_module,
        "get_func_argument_info",
        lambda call, arg: (0, None),
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_visit",
        lambda func_ea, arg_idx: recorded_visits.append((func_ea, arg_idx)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_scan_tree_info",
        lambda func_ea, arg_idx: None,
        raising=False,
    )

    visitor._check_call(unrelated_expr)
    visitor._check_call(add_expr)

    assert recorded_visits == [(0x402000, 0)]
    assert visitor._visit_base_offsets[(0x402000, 0)] == 12


def test_extract_offset_expression_scales_pointer_add_by_element_size():
    visitor_module = _load_visitor_module()
    ops = SimpleNamespace(
        cast=1, ref=2, memref=3, memptr=4, ptr=5, idx=6, add=7, sub=8, num=9
    )
    a1_var = SimpleNamespace(op=ops.num + 1, name="a1")
    qword_num = SimpleNamespace(op=ops.num, numval=lambda: 1)
    add_node = SimpleNamespace(
        op=ops.add,
        x=a1_var,
        y=qword_num,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )

    base, offset = visitor_module._extract_offset_expression(add_node, ctype_ops=ops)

    assert base is a1_var
    assert offset == 8


def test_extract_offset_expression_byte_pointer_add_is_unscaled():
    visitor_module = _load_visitor_module()
    ops = SimpleNamespace(
        cast=1, ref=2, memref=3, memptr=4, ptr=5, idx=6, add=7, sub=8, num=9
    )
    a1_var = SimpleNamespace(op=ops.num + 1, name="a1")
    byte_num = SimpleNamespace(op=ops.num, numval=lambda: 0x38)
    add_node = SimpleNamespace(
        op=ops.add,
        x=a1_var,
        y=byte_num,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
    )

    base, offset = visitor_module._extract_offset_expression(add_node, ctype_ops=ops)

    assert base is a1_var
    assert offset == 0x38

def test_recursive_downwards_check_call_follows_member_address(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._objects = [SimpleNamespace(name="a1")]
    visitor.parents = SimpleNamespace(size=lambda: 1)
    visitor._visit_base_offsets = {}
    call_expr = SimpleNamespace(
        op=visitor_module.ctype.call,
        x=SimpleNamespace(obj_ea=0x402000),
    )
    a1_var = SimpleNamespace(op=visitor_module.ctype.var, name="a1")
    member_expr = SimpleNamespace(op=visitor_module.ctype.memptr, x=a1_var, m=0x33b0)
    ref_expr = SimpleNamespace(op=visitor_module.ctype.ref, x=member_expr)
    recorded_visits = []

    monkeypatch.setattr(visitor, "parent_expr", lambda: call_expr, raising=False)
    monkeypatch.setattr(
        visitor,
        "_matches_object",
        lambda _obj, cexpr: cexpr is a1_var,
        raising=False,
    )
    monkeypatch.setattr(
        visitor_module,
        "get_func_argument_info",
        lambda call, arg: (0, None),
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_visit",
        lambda func_ea, arg_idx: recorded_visits.append((func_ea, arg_idx)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_scan_tree_info",
        lambda func_ea, arg_idx: None,
        raising=False,
    )

    visitor._check_call(ref_expr)

    assert recorded_visits == [(0x402000, 0)]
    assert visitor._visit_base_offsets[(0x402000, 0)] == 0x33b0


def test_expression_references_object_ignores_bare_member_dereference(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._objects = [SimpleNamespace(name="a1")]
    a1_var = SimpleNamespace(op=visitor_module.ctype.var, name="a1")
    member_expr = SimpleNamespace(op=visitor_module.ctype.memptr, x=a1_var, m=0x10)

    monkeypatch.setattr(
        visitor,
        "_matches_object",
        lambda _obj, cexpr: cexpr is a1_var,
        raising=False,
    )

    assert visitor._expression_references_object(member_expr) is False
    assert visitor._expression_references_object(a1_var) is True



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
        staticmethod(lambda _cfunc, expr, *, promote_root=True: child_obj if expr is x_expr else None),
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
        staticmethod(lambda _cfunc, expr, *, promote_root=True: child_obj if expr is y_expr else None),
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
    visitor._objects = [SimpleNamespace(ea=0x402000)]

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
    visitor._max_depth = None
    visitor._current_depth = 0
    visitor._new_for_visit = {(0x402000, 0), (0x403000, 0)}
    visitor._visit_base_offsets = {}
    visitor._callee_base_offset = 0

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
    visitor._max_depth = None
    visitor._current_depth = 0
    visitor._new_for_visit = {(0x402000, 0)}
    visitor._visit_base_offsets = {}
    visitor._callee_base_offset = 0

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
    monkeypatch.setattr(visitor_module, "refresh_function_tree", fake_refresh)
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


def test_refresh_function_tree_decompiles_only_target_function(monkeypatch):
    visitor_module = _load_visitor_module()
    decompiled = []
    dirtied = []

    monkeypatch.setattr(visitor_module, "is_imported", lambda _ea: False)
    monkeypatch.setattr(
        visitor_module,
        "_mark_cfunc_dirty",
        lambda ea: dirtied.append(ea),
    )
    monkeypatch.setattr(
        visitor_module,
        "decompile",
        lambda ea: decompiled.append(ea) or SimpleNamespace(entry_ea=ea),
    )

    result = visitor_module.refresh_function_tree(SimpleNamespace(entry_ea=0x401000))

    assert result.entry_ea == 0x401000
    assert dirtied == [0x401000]
    assert decompiled == [0x401000]


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

_VISITOR_MODULE_FOR_SHIM = _load_visitor_module()

class _AllocVar(_VISITOR_MODULE_FOR_SHIM.ScanObject):
    """Minimal ScanObject shim for the size-aware closure test."""
    def __init__(self, name, alloc_size=None):
        super().__init__()
        self.name = name
        self.alloc_size = alloc_size
        # any non-call_argument value — the closure only short-circuits on
        # ObjectType.call_argument specifically.
        self.id = object()




def test_upwards_prepare_merges_lvars_without_alloc_size():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveUpwardsObjectVisitor.__new__(
        visitor_module.RecursiveUpwardsObjectVisitor
    )
    v0 = _AllocVar("v0")
    v2 = _AllocVar("v2")
    v4 = _AllocVar("v4")
    visitor._objects = [v0]
    visitor._tree = {v0: {v4}, v4: {v2}}
    visitor._prepare()
    names = sorted(o.name for o in visitor._objects)
    assert names == ["v0", "v2", "v4"]


def test_upwards_prepare_refuses_transitive_merge_when_alloc_sizes_disagree():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveUpwardsObjectVisitor.__new__(
        visitor_module.RecursiveUpwardsObjectVisitor
    )
    # v0 = calloc(0x38);  v2 = calloc(0x2C);  v4 = v0;  v4 = v2;  ->  the
    # closure path v2 -> v4 -> v0 should be rejected because v0 and v2
    # have different alloc sizes (R3.12).
    v0 = _AllocVar("v0", alloc_size=0x38)
    v2 = _AllocVar("v2", alloc_size=0x2C)
    v4 = _AllocVar("v4")  # unknown
    visitor._objects = [v0]
    visitor._tree = {v0: {v4}, v4: {v2}}
    visitor._prepare()
    names = sorted(o.name for o in visitor._objects)
    # v0 and v4 stay; v2 is rejected because v4->v2 conflicts v0's size.
    assert "v0" in names
    assert "v4" in names
    assert "v2" not in names


def test_upwards_prepare_merges_lvars_with_matching_alloc_sizes():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveUpwardsObjectVisitor.__new__(
        visitor_module.RecursiveUpwardsObjectVisitor
    )
    v1 = _AllocVar("v1", alloc_size=0x2C)
    v2 = _AllocVar("v2", alloc_size=0x2C)
    visitor._objects = [v1]
    visitor._tree = {v1: {v2}}
    visitor._prepare()
    names = sorted(o.name for o in visitor._objects)
    assert names == ["v1", "v2"]


def test_recursive_upwards_check_call_only_tracks_matched_argument(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveUpwardsObjectVisitor.__new__(
        visitor_module.RecursiveUpwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(
        entry_ea=0x401000,
        get_lvars=lambda: [
            SimpleNamespace(is_arg_var=True),
            SimpleNamespace(is_arg_var=True),
        ],
    )
    visitor._objects = [SimpleNamespace(name="arg0") ]
    recorded_visits = []
    recorded_tree_edges = []

    monkeypatch.setattr(
        visitor,
        "_matches_object",
        lambda _obj, cexpr: cexpr.v.idx == 0,
        raising=False,
    )
    monkeypatch.setattr(
        visitor_module,
        "get_argument_index",
        lambda _cfunc, idx: idx,
        raising=False,
    )
    monkeypatch.setattr(
        visitor_module,
        "get_funcs_calling_address",
        lambda _ea: {0x402000},
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_visit",
        lambda func_ea, arg_idx: recorded_visits.append((func_ea, arg_idx)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_scan_tree_info",
        lambda func_ea, arg_idx: recorded_tree_edges.append((func_ea, arg_idx)),
        raising=False,
    )

    visitor._check_call(SimpleNamespace(op=visitor_module.ctype.var, v=SimpleNamespace(idx=1)))
    visitor._check_call(SimpleNamespace(op=visitor_module.ctype.var, v=SimpleNamespace(idx=0)))

    assert recorded_visits == [(0x401000, 0)]
    assert recorded_tree_edges == [(0x402000, 0)]


class _ScanT:
    def __init__(self, name: str):
        self._name = name

    def __repr__(self):
        return self._name

    def clone(self):
        return _ScanT(self._name)


def test_memory_writer_synthesizes_field_member(monkeypatch):
    """E1/I.20: strcpy(root + 0x10, ...) synthesizes a member at 0x10; the
    writer name comes from ida_name."""
    visitor_module = _load_visitor_module()
    import ida_name as _ida_name

    monkeypatch.setattr(_ida_name, "get_name", lambda ea: "strcpy", raising=False)

    class _TypesStub:
        width = 8

        def __getitem__(self, key):
            return SimpleNamespace(type=_ScanT(key))

        @staticmethod
        def convert_to_simple_type(t):
            return t

    monkeypatch.setattr(visitor_module, "types", _TypesStub(), raising=False)
    monkeypatch.setattr(
        visitor_module.ida_typeinf,
        "tinfo_t",
        lambda value=None: SimpleNamespace(_name=getattr(value, "_name", "?")),
        raising=False,
    )

    added = []
    calls = {}

    class _WriterVisitor(visitor_module.RecursiveDownwardsObjectVisitor):
        def __init__(self):
            self._structure = SimpleNamespace(add_member=added.append)
            self._callee_base_offset = 0
            self.crippled = False
            self._origin = 0
            self._objects = [
                SimpleNamespace(
                    is_target=lambda e: getattr(e, "op", None) == visitor_module.ctype.var,
                    name="root",
                )
            ]
            self._get_member = self._fake_get_member

        # pylint: disable-next=arguments-differ
        def _fake_get_member(self, offset, cexpr, obj, tinfo, obj_ea=None):
            calls["get_member"] = (offset, obj.name)
            return SimpleNamespace(name="synth")

    v = _WriterVisitor()
    dest = SimpleNamespace(
        op=visitor_module.ctype.add,
        x=SimpleNamespace(op=visitor_module.ctype.var),
        y=SimpleNamespace(op=visitor_module.ctype.num, numval=lambda: 0x10),
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
    )
    call = SimpleNamespace(
        x=SimpleNamespace(obj_ea=0x5000),
        a=[dest, SimpleNamespace(op=visitor_module.ctype.var)],
    )

    v._maybe_add_memory_writer_member(call, dest)

    assert calls["get_member"] == (0x10, "root")
    assert len(added) == 1


def test_memory_writer_literal_source_sizes_char_array(monkeypatch):
    """E1/I.20: a string-literal source gives char[len+1] for the member."""
    visitor_module = _load_visitor_module()
    import ida_name as _ida_name

    monkeypatch.setattr(_ida_name, "get_name", lambda ea: "strcpy", raising=False)

    class _TypesStub:
        width = 8

        def __getitem__(self, key):
            return SimpleNamespace(type=_ScanT(key))

        @staticmethod
        def convert_to_simple_type(t):
            return t

    monkeypatch.setattr(visitor_module, "types", _TypesStub(), raising=False)
    made = {}
    monkeypatch.setattr(
        visitor_module.ida_typeinf,
        "array_type_data_t",
        lambda: SimpleNamespace(base=0),
        raising=False,
    )
    monkeypatch.setattr(
        visitor_module.ida_typeinf,
        "tinfo_t",
        lambda value=None: SimpleNamespace(
            _name=getattr(value, "_name", "char"),
            create_array=lambda data: made.update(nelems=data.nelems),
        ),
        raising=False,
    )
    added = []

    class _WriterVisitor(visitor_module.RecursiveDownwardsObjectVisitor):
        def __init__(self):
            self._structure = SimpleNamespace(add_member=added.append)
            self._callee_base_offset = 0
            self.crippled = False
            self._origin = 0
            self._objects = [
                SimpleNamespace(
                    is_target=lambda e: getattr(e, "op", None) == visitor_module.ctype.var,
                    name="root",
                )
            ]
            self._get_member = lambda offset, cexpr, obj, tinfo, obj_ea=None: tinfo

    v = _WriterVisitor()
    # the source literal is detected via a `str` op in the ctype namespace:
    # patch ctype onto the module-global binding
    monkeypatch.setattr(visitor_module, "ctype", SimpleNamespace(**vars(visitor_module.ctype), str=99), raising=False)
    dest = SimpleNamespace(
        op=visitor_module.ctype.add,
        x=SimpleNamespace(op=visitor_module.ctype.var),
        y=SimpleNamespace(op=visitor_module.ctype.num, numval=lambda: 0),
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
    )
    call = SimpleNamespace(
        x=SimpleNamespace(obj_ea=0x5000),
        a=[dest, SimpleNamespace(op=visitor_module.ctype.str, string="literal")],
    )
    v._maybe_add_memory_writer_member(call, dest)

    assert made == {"nelems": 8}  # 7 chars + NUL
    assert len(added) == 1


def test_memory_writer_allowlist_excludes_printf(monkeypatch):
    """E1/I.20: printf-style calls are not memory writers — no member."""
    visitor_module = _load_visitor_module()
    import ida_name as _ida_name

    monkeypatch.setattr(_ida_name, "get_name", lambda ea: "printf", raising=False)
    added = []
    calls = []

    class _WriterVisitor(visitor_module.RecursiveDownwardsObjectVisitor):
        def __init__(self):
            self._structure = SimpleNamespace(add_member=added.append)
            self._callee_base_offset = 0
            self.crippled = False
            self._origin = 0
            self._objects = [
                SimpleNamespace(
                    is_target=lambda e: getattr(e, "op", None) == visitor_module.ctype.var,
                    name="root",
                )
            ]
            self._get_member = lambda offset, cexpr, obj, tinfo, obj_ea=None: calls.append(
                (offset, tinfo)
            ) or SimpleNamespace(name="m")

    v = _WriterVisitor()
    dest = SimpleNamespace(
        op=visitor_module.ctype.add,
        x=SimpleNamespace(op=visitor_module.ctype.var),
        y=SimpleNamespace(op=visitor_module.ctype.num, numval=lambda: 0),
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
    )
    call = SimpleNamespace(x=SimpleNamespace(obj_ea=0x6000), a=[dest])

    v._maybe_add_memory_writer_member(call, dest)

    assert added == []
    assert calls == []

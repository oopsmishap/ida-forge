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


def _root_frame(visitor_module, function_ea=0x401000):
    return visitor_module.RecursiveCallFrame(
        frame_id=0,
        parent_frame_id=None,
        function_ea=function_ea,
        argument_index=-1,
        call_site_ea=ida_idaapi.BADADDR,
        base_offset=0,
        depth=0,
    )


def _child_frame(visitor_module, frame_id, function_ea, argument_index, base_offset):
    return visitor_module.RecursiveCallFrame(
        frame_id=frame_id,
        parent_frame_id=0,
        function_ea=function_ea,
        argument_index=argument_index,
        call_site_ea=ida_idaapi.BADADDR,
        base_offset=base_offset,
        depth=1,
    )


def _load_visitor_module():
    visitor_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "visitor.py"
    spec = util.spec_from_file_location("forge.api.visitor_real", visitor_path)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    # Python 3.14 dataclass processing resolves KW_ONLY sentinels through
    # sys.modules[cls.__module__]; register the freshly-created module before
    # executing it (same pattern as test_scanner.py's loader).
    sys.modules["forge.api.visitor_real"] = module
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
    visitor._current_frame = _root_frame(visitor_module)
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
    result = visitor._execute_visit(
        _child_frame(visitor_module, 1, 0x402000, 0, 0)
    )
    assert result is None
    assert argument_queries == []

def test_recursive_downwards_object_visitor_skips_invalid_callee_ordinal(monkeypatch):
    """A deferred callee whose ordinal never resolves (argidx still empty
    after decompilation) must never reach prepare_new_scan: the frame is
    deferred, retried once without progress, and finally dropped without
    being scanned (ported from the pre-frame-API coverage on main)."""
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._max_depth = None
    visitor._current_frame = _root_frame(visitor_module)
    visitor._callee_base_offset = 0
    visitor._new_for_visit = []
    frame = _child_frame(visitor_module, 1, 0x402000, 0, 0)

    invalid_callee = SimpleNamespace(entry_ea=0x402000, argidx=[], get_lvars=list)
    monkeypatch.setattr(
        visitor_module, "decompile", lambda _ea: invalid_callee, raising=False
    )
    monkeypatch.setattr(
        visitor, "_refresh_decompilation_tree", lambda cfunc: cfunc, raising=False
    )
    prepared_calls = []
    monkeypatch.setattr(
        visitor,
        "prepare_new_scan",
        lambda *args, **kwargs: prepared_calls.append(args),
        raising=False,
    )

    # Direct: an unresolved ordinal defers the visit without preparing it.
    assert visitor._execute_visit(frame) is visitor._VISIT_DEFERRED
    assert prepared_calls == []

    # Loop-level: the deferred frame is retried once, makes no progress,
    # and the scan terminates without ever preparing the visit.
    visitor._scan_single_function = lambda: None
    visitor._recursive_process()
    assert prepared_calls == []
    assert visitor._new_for_visit == []


def test_recursive_visitor_preserves_empty_visited_set(monkeypatch):
    visitor_module = _load_visitor_module()
    supplied = set()
    visitor = object.__new__(visitor_module.RecursiveObjectVisitor)
    monkeypatch.setattr(
        visitor_module.ObjectVisitor,
        "__init__",
        lambda self, cfunc, obj, data, skip_until_object: setattr(self, "_cfunc", cfunc),
    )
    visitor_module.RecursiveObjectVisitor.__init__(
        visitor, SimpleNamespace(entry_ea=0), SimpleNamespace(), visited=supplied
    )

    assert visitor._visited is supplied


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
        lambda func_ea, arg_idx, *args: recorded_visits.append((func_ea, arg_idx)) or True,
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
        lambda func_ea, arg_idx, *args: recorded_visits.append((func_ea, arg_idx)) or True,
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

def test_recursive_downwards_check_call_skips_unplaceable_member_address(monkeypatch):
    """``&a1->field`` / ``a1->field`` call arguments contain a ``memptr`` node
    and cannot be pinned to a fixed offset of the scanned object: the deep
    scan must NOT track the callee from them (fork behavior — the tracked
    pointer inside such an expression is followed through the hierarchy
    machinery instead). Only an argument whose value IS the tracked scan
    object (``f(this->u32_28)`` during a sub-object scan) qualifies.
    """
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
        lambda func_ea, arg_idx, *args: recorded_visits.append((func_ea, arg_idx)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        visitor,
        "_add_scan_tree_info",
        lambda func_ea, arg_idx: None,
        raising=False,
    )

    visitor._check_call(ref_expr)
    visitor._check_call(member_expr)

    assert recorded_visits == []
    assert visitor._visit_base_offsets == {}


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
    visitor._current_frame = _root_frame(visitor_module)
    visitor._new_for_visit = [
        _child_frame(visitor_module, 1, 0x402000, 0, 0),
        _child_frame(visitor_module, 2, 0x403000, 0, 0),
    ]
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



def test_scan_tree_cycle_terminates(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {
        ("root", -1): {("child", 0)},
        ("child", 0): {("root", -1)},
    }

    visitor._prepare_scan_tree()

    assert visitor._debug_message == [
        "\n--- Scan Tree ---\nroot",
        " |_ child(idx: 0)",
        " |  |_ root(idx: -1)",
    ]

def test_process_finishes_after_recursive_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    error = RuntimeError("recursive failure")
    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: (events.append("recursive"), (_ for _ in ()).throw(error))[1]
    visitor._finish = lambda: events.append("finish")
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(RuntimeError) as raised:
        visitor.process()

    assert raised.value is error
    assert events == ["start", "recursive", "finish"]

def test_process_does_not_finish_when_start_fails(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    error = RuntimeError("start failure")
    visitor._start = lambda: (events.append("start"), (_ for _ in ()).throw(error))[1]
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: events.append("finish")
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(RuntimeError) as raised:
        visitor.process()

    assert raised.value is error
    assert events == ["start"]

def test_recursive_process_does_not_finish_when_iteration_start_fails(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    error = RuntimeError("iteration start failure")
    visitor._start_iteration = lambda: (events.append("start"), (_ for _ in ()).throw(error))[1]
    visitor._finish_iteration = lambda: events.append("finish")
    monkeypatch.setattr(
        visitor_module.RecursiveObjectVisitor,
        "process",
        lambda self: events.append("process"),
    )
    with pytest.raises(RuntimeError) as raised:
        visitor_module.RecursiveObjectVisitor._recursive_process(visitor)

    assert raised.value is error
    assert events == ["start"]


def test_iteration_finish_failure_takes_precedence(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    pass_error = RuntimeError("pass failure")
    finish_error = ValueError("finish failure")
    monkeypatch.setattr(
        visitor_module.ObjectVisitor,
        "process",
        lambda self: (_ for _ in ()).throw(pass_error),
    )
    visitor._finish_iteration = lambda: (_ for _ in ()).throw(finish_error)

    with pytest.raises(ValueError) as raised:
        visitor_module.RecursiveObjectVisitor._recursive_process(visitor)

    assert raised.value is finish_error
def test_recursive_process_propagates_iteration_finish_failure_after_pass(
    monkeypatch,
):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    error = ValueError("iteration finish failure")
    visitor._start_iteration = lambda: events.append("start")
    visitor._finish_iteration = lambda: (
        events.append("finish"), (_ for _ in ()).throw(error)
    )[1]
    monkeypatch.setattr(
        visitor_module.ObjectVisitor,
        "process",
        lambda self: events.append("process"),
    )

    with pytest.raises(ValueError) as raised:
        visitor_module.RecursiveObjectVisitor._recursive_process(visitor)

    assert raised.value is error
    assert events == ["start", "process", "finish"]

def test_recursive_finish_failure_takes_precedence_with_pass_failure(
    monkeypatch,
):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    pass_error = RuntimeError("pass failure")
    finish_error = ValueError("finish failure")
    visitor._start_iteration = lambda: events.append("start")
    visitor._finish_iteration = lambda: (
        events.append("finish"), (_ for _ in ()).throw(finish_error)
    )[1]
    monkeypatch.setattr(
        visitor_module.ObjectVisitor,
        "process",
        lambda self: (
            events.append("process"), (_ for _ in ()).throw(pass_error)
        )[1],
    )

    with pytest.raises(ValueError) as raised:
        visitor_module.RecursiveObjectVisitor._recursive_process(visitor)

    assert raised.value is finish_error
    assert events == ["start", "process", "finish"]

def test_process_finish_failure_precedes_recursive_and_dump_failures(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    recursive_error = RuntimeError("recursive failure")
    finish_error = ValueError("finish failure")
    dump_error = LookupError("dump failure")
    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: (
        events.append("recursive"), (_ for _ in ()).throw(recursive_error)
    )[1]
    visitor._finish = lambda: (
        events.append("finish"), (_ for _ in ()).throw(finish_error)
    )[1]
    visitor.dump_scan_tree = lambda: (
        events.append("dump"), (_ for _ in ()).throw(dump_error)
    )[1]

    with pytest.raises(ValueError) as raised:
        visitor.process()

    assert raised.value is finish_error
    assert events == ["start", "recursive", "finish"]

def test_scan_tree_shared_descendant_renders_per_path(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {
        ("root", -1): {("left", 0), ("right", 0)},
        ("left", 0): {("shared", 1)},
        ("right", 0): {("shared", 1)},
    }

    visitor._prepare_scan_tree()

    assert visitor._debug_message.count(" |  |_ shared(idx: 1)") == 2

def test_process_skips_dump_when_finish_fails(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    error = ValueError("finish failure")
    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: (events.append("finish"), (_ for _ in ()).throw(error))[1]
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(ValueError) as raised:
        visitor.process()

    assert raised.value is error
    assert events == ["start", "recursive", "finish"]
def test_process_start_failure_short_circuits_all_later_callbacks(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    start_error = RuntimeError("start failure")
    visitor._start = lambda: (
        events.append("start"), (_ for _ in ()).throw(start_error)
    )[1]
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: events.append("finish")

    with pytest.raises(RuntimeError) as raised:
        visitor.process()

    assert raised.value is start_error
    assert events == ["start"]

def test_process_start_failure_precedes_cleanup_failures(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    start_error = RuntimeError("start failure")
    visitor._start = lambda: (
        events.append("start"), (_ for _ in ()).throw(start_error)
    )[1]
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: (
        events.append("finish"), (_ for _ in ()).throw(ValueError("finish"))
    )[1]
    visitor.dump_scan_tree = lambda: (
        events.append("dump"), (_ for _ in ()).throw(LookupError("dump"))
    )[1]

    with pytest.raises(RuntimeError) as raised:
        visitor.process()

    assert raised.value is start_error
    assert events == ["start"]

def test_process_finish_failure_precedes_recursive_failure_after_start(
    monkeypatch,
):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    recursive_error = RuntimeError("recursive failure")
    finish_error = ValueError("finish failure")
    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: (
        events.append("recursive"), (_ for _ in ()).throw(recursive_error)
    )[1]
    visitor._finish = lambda: (
        events.append("finish"), (_ for _ in ()).throw(finish_error)
    )[1]
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(ValueError) as raised:
        visitor.process()

    assert raised.value is finish_error
    assert events == ["start", "recursive", "finish"]

def test_process_orders_finish_before_dump_on_success(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: events.append("finish")
    visitor.dump_scan_tree = lambda: events.append("dump")

    visitor.process()

    assert events == ["start", "recursive", "finish", "dump"]

def test_process_propagates_dump_failure_after_finish(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    error = RuntimeError("dump failure")
    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: events.append("finish")
    visitor.dump_scan_tree = lambda: (
        events.append("dump"), (_ for _ in ()).throw(error)
    )[1]

    with pytest.raises(RuntimeError) as raised:
        visitor.process()

    assert raised.value is error
    assert events == ["start", "recursive", "finish", "dump"]
def test_process_retries_full_lifecycle_after_dump_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    dump_calls = 0
    dump_error = RuntimeError("dump failure")

    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: events.append("finish")

    def dump():
        nonlocal dump_calls
        dump_calls += 1
        events.append("dump")
        if dump_calls == 1:
            raise dump_error

    visitor.dump_scan_tree = dump

    with pytest.raises(RuntimeError) as raised:
        visitor.process()
    visitor.process()

    assert raised.value is dump_error
    assert events == [
        "start",
        "recursive",
        "finish",
        "dump",
        "start",
        "recursive",
        "finish",
        "dump",
    ]

def test_process_retries_full_lifecycle_after_recursive_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    recursive_calls = 0
    recursive_error = RuntimeError("recursive failure")

    visitor._start = lambda: events.append("start")

    def recursive():
        nonlocal recursive_calls
        recursive_calls += 1
        events.append("recursive")
        if recursive_calls == 1:
            raise recursive_error

    visitor._recursive_process = recursive
    visitor._finish = lambda: events.append("finish")
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(RuntimeError) as raised:
        visitor.process()
    visitor.process()

    assert raised.value is recursive_error
    assert events == [
        "start",
        "recursive",
        "finish",
        "start",
        "recursive",
        "finish",
        "dump",
    ]

def test_process_retries_full_lifecycle_after_finish_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    finish_calls = 0
    finish_error = ValueError("finish failure")

    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")

    def finish():
        nonlocal finish_calls
        finish_calls += 1
        events.append("finish")
        if finish_calls == 1:
            raise finish_error

    visitor._finish = finish
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(ValueError) as raised:
        visitor.process()
    visitor.process()

    assert raised.value is finish_error
    assert events == [
        "start",
        "recursive",
        "finish",
        "start",
        "recursive",
        "finish",
        "dump",
    ]

def test_process_retries_after_recursive_and_finish_failures(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    recursive_calls = 0
    finish_calls = 0
    recursive_error = RuntimeError("recursive failure")
    finish_error = ValueError("finish failure")

    visitor._start = lambda: events.append("start")

    def recursive():
        nonlocal recursive_calls
        recursive_calls += 1
        events.append("recursive")
        if recursive_calls == 1:
            raise recursive_error

    def finish():
        nonlocal finish_calls
        finish_calls += 1
        events.append("finish")
        if finish_calls == 1:
            raise finish_error

    visitor._recursive_process = recursive
    visitor._finish = finish
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(ValueError) as raised:
        visitor.process()
    visitor.process()

    assert raised.value is finish_error
    assert events == [
        "start",
        "recursive",
        "finish",
        "start",
        "recursive",
        "finish",
        "dump",
    ]

@pytest.mark.parametrize("failure_count", [1, 2, 3])
def test_process_retries_after_repeated_finish_failures(monkeypatch, failure_count):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    finish_calls = 0
    finish_errors = [ValueError(f"finish failure {index}") for index in range(failure_count)]

    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")

    def finish():
        nonlocal finish_calls
        events.append("finish")
        if finish_calls < failure_count:
            error = finish_errors[finish_calls]
            finish_calls += 1
            raise error
        finish_calls += 1

    visitor._finish = finish
    visitor.dump_scan_tree = lambda: events.append("dump")

    for error in finish_errors:
        with pytest.raises(ValueError) as raised:
            visitor.process()
        assert raised.value is error

    visitor.process()

    assert events == [
        *sum((["start", "recursive", "finish"] for _ in range(failure_count)), []),
        "start",
        "recursive",
        "finish",
        "dump",
    ]

@pytest.mark.parametrize("failure_count", [1, 2, 3])
def test_process_retries_after_repeated_recursive_failures(
    monkeypatch, failure_count
):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    recursive_calls = 0
    recursive_errors = [
        RuntimeError(f"recursive failure {index}") for index in range(failure_count)
    ]

    visitor._start = lambda: events.append("start")

    def recursive():
        nonlocal recursive_calls
        events.append("recursive")
        if recursive_calls < failure_count:
            error = recursive_errors[recursive_calls]
            recursive_calls += 1
            raise error
        recursive_calls += 1

    visitor._recursive_process = recursive
    visitor._finish = lambda: events.append("finish")
    visitor.dump_scan_tree = lambda: events.append("dump")

    for error in recursive_errors:
        with pytest.raises(RuntimeError) as raised:
            visitor.process()
        assert raised.value is error

    visitor.process()

    assert events == [
        *sum((["start", "recursive", "finish"] for _ in range(failure_count)), []),
        "start",
        "recursive",
        "finish",
        "dump",
    ]

@pytest.mark.parametrize("failure_count", [1, 2, 3])
def test_process_retries_after_repeated_dump_failures(monkeypatch, failure_count):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    dump_calls = 0
    dump_errors = [
        RuntimeError(f"dump failure {index}") for index in range(failure_count)
    ]

    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: events.append("finish")

    def dump():
        nonlocal dump_calls
        events.append("dump")
        if dump_calls < failure_count:
            error = dump_errors[dump_calls]
            dump_calls += 1
            raise error
        dump_calls += 1

    visitor.dump_scan_tree = dump

    for error in dump_errors:
        with pytest.raises(RuntimeError) as raised:
            visitor.process()
        assert raised.value is error

    visitor.process()
    assert events == [
        event
        for _ in range(failure_count + 1)
        for event in ["start", "recursive", "finish", "dump"]
    ]

def test_process_retry_callback_counts_after_dump_failures(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    counts = {"start": 0, "recursive": 0, "finish": 0, "dump": 0}
    dump_errors = [RuntimeError("first dump failure"), RuntimeError("second dump failure")]

    def callback(name):
        def run():
            counts[name] += 1
            events.append(name)

        return run

    visitor._start = callback("start")
    visitor._recursive_process = callback("recursive")
    visitor._finish = callback("finish")

    def dump():
        counts["dump"] += 1
        events.append("dump")
        if dump_errors:
            raise dump_errors.pop(0)

    visitor.dump_scan_tree = dump

    for expected in ["first dump failure", "second dump failure"]:
        with pytest.raises(RuntimeError, match=expected):
            visitor.process()
    visitor.process()

    assert counts == {"start": 3, "recursive": 3, "finish": 3, "dump": 3}
    assert events == [
        "start",
        "recursive",
        "finish",
        "dump",
        "start",
        "recursive",
        "finish",
        "dump",
        "start",
        "recursive",
        "finish",
        "dump",
    ]

def test_process_recovers_after_mixed_lifecycle_failures(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    recursive_calls = 0
    finish_calls = 0
    dump_calls = 0
    recursive_error = RuntimeError("recursive failure")
    finish_error = ValueError("finish failure")
    dump_error = OSError("dump failure")

    visitor._start = lambda: events.append("start")

    def recursive():
        nonlocal recursive_calls
        recursive_calls += 1
        events.append("recursive")
        if recursive_calls == 1:
            raise recursive_error

    def finish():
        nonlocal finish_calls
        finish_calls += 1
        events.append("finish")
        if finish_calls == 2:
            raise finish_error

    def dump():
        nonlocal dump_calls
        dump_calls += 1
        events.append("dump")
        if dump_calls == 1:
            raise dump_error

    visitor._recursive_process = recursive
    visitor._finish = finish
    visitor.dump_scan_tree = dump

    with pytest.raises(RuntimeError) as raised:
        visitor.process()
    assert raised.value is recursive_error

    with pytest.raises(ValueError) as raised:
        visitor.process()
    assert raised.value is finish_error

    with pytest.raises(OSError) as raised:
        visitor.process()
    assert raised.value is dump_error

    visitor.process()

    assert events == [
        "start", "recursive", "finish",
        "start", "recursive", "finish",
        "start", "recursive", "finish", "dump",
        "start", "recursive", "finish", "dump",
    ]

def test_process_retries_cleanup_precedence_until_recovery(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    recursive_calls = 0
    finish_calls = 0
    recursive_error = RuntimeError("recursive failure")
    finish_errors = [ValueError("first finish failure"), ValueError("second finish failure")]

    visitor._start = lambda: events.append("start")

    def recursive():
        nonlocal recursive_calls
        recursive_calls += 1
        events.append("recursive")
        if recursive_calls == 1:
            raise recursive_error

    def finish():
        nonlocal finish_calls
        events.append("finish")
        if finish_calls < len(finish_errors):
            error = finish_errors[finish_calls]
            finish_calls += 1
            raise error
        finish_calls += 1

    visitor._recursive_process = recursive
    visitor._finish = finish
    visitor.dump_scan_tree = lambda: events.append("dump")

    with pytest.raises(ValueError) as raised:
        visitor.process()
    assert raised.value is finish_errors[0]

    with pytest.raises(ValueError) as raised:
        visitor.process()
    assert raised.value is finish_errors[1]

    visitor.process()

    assert events == [
        "start", "recursive", "finish",
        "start", "recursive", "finish",
        "start", "recursive", "finish", "dump",
    ]

def test_process_finish_failure_takes_precedence_over_dump_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    events = []
    finish_error = ValueError("finish failure")
    dump_error = RuntimeError("dump failure")
    visitor._start = lambda: events.append("start")
    visitor._recursive_process = lambda: events.append("recursive")
    visitor._finish = lambda: (
        events.append("finish"), (_ for _ in ()).throw(finish_error)
    )[1]
    visitor.dump_scan_tree = lambda: (
        events.append("dump"), (_ for _ in ()).throw(dump_error)
    )[1]

    with pytest.raises(ValueError) as raised:
        visitor.process()

    assert raised.value is finish_error
    assert events == ["start", "recursive", "finish"]

def test_dump_scan_tree_propagates_logging_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    error = RuntimeError("logger failure")
    monkeypatch.setattr(
        visitor_module,
        "log_info",
        lambda _message: (_ for _ in ()).throw(error),
    )

    with pytest.raises(RuntimeError) as raised:
        visitor.dump_scan_tree()

    assert raised.value is error
    assert visitor._debug_message == ["\n--- Scan Tree ---\nroot"]

def test_dump_scan_tree_recovers_after_logging_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    calls = []
    error = RuntimeError("logger failure")

    def log_info(message):
        calls.append(message)
        if len(calls) == 1:
            raise error

    monkeypatch.setattr(visitor_module, "log_info", log_info)

    with pytest.raises(RuntimeError) as raised:
        visitor.dump_scan_tree()
    visitor.dump_scan_tree()

    assert raised.value is error
    assert len(calls) == 2
    assert visitor._debug_message == ["\n--- Scan Tree ---\nroot"]

def test_dump_scan_tree_preserves_debug_message_identity(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    original = visitor._debug_message
    visitor._debug_scan_tree = {}
    monkeypatch.setattr(visitor_module, "log_info", lambda _message: None)

    visitor.dump_scan_tree()

    assert visitor._debug_message is original
    assert original == ["\n--- Scan Tree ---\nroot"]

def test_dump_scan_tree_recovers_after_render_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    error = RuntimeError("render failure")
    original_prepare = visitor._prepare_scan_tree
    calls = []

    def prepare(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise error
        return original_prepare(*args, **kwargs)

    monkeypatch.setattr(visitor, "_prepare_scan_tree", prepare)
    monkeypatch.setattr(visitor_module, "log_info", lambda _message: None)

    with pytest.raises(RuntimeError) as raised:
        visitor.dump_scan_tree()
    visitor.dump_scan_tree()

    assert raised.value is error
    assert visitor._debug_message == ["\n--- Scan Tree ---\nroot"]

def test_prepare_scan_tree_cleans_path_after_nested_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    path = set()
    original = visitor._prepare_scan_tree
    def prepare(*args, **kwargs):
        raise RuntimeError("nested render failure")
    monkeypatch.setattr(visitor, "_prepare_scan_tree", prepare)
    with pytest.raises(RuntimeError, match="nested render failure"):
        visitor._prepare_scan_tree(_path=path)
    assert path == set()
    monkeypatch.setattr(visitor, "_prepare_scan_tree", original)
    visitor._debug_message.clear()
    visitor._prepare_scan_tree(_path=path)
    assert path == set()

def test_prepare_scan_tree_cleans_path_after_cyclic_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    path = set()
    original = visitor._prepare_scan_tree
    monkeypatch.setattr(visitor, "_prepare_scan_tree", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("cyclic render failure")))
    with pytest.raises(RuntimeError, match="cyclic render failure"):
        visitor._prepare_scan_tree(_path=path)
    assert path == set()
    monkeypatch.setattr(visitor, "_prepare_scan_tree", original)

def test_prepare_scan_tree_retries_shared_cyclic_paths_after_failure():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {
        ("root", -1): {("left", 0), ("right", 0)},
        ("left", 0): {("shared", 0)},
        ("right", 0): {("shared", 0)},
        ("shared", 0): {("root", -1)},
    }
    path = set()
    visitor._prepare_scan_tree(_path=path)
    assert path == set()

def test_prepare_scan_tree_deep_shared_cycle_retry_preserves_formatting():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {
        ("root", -1): {("a", 0), ("b", 0)},
        ("a", 0): {("shared", 0)},
        ("b", 0): {("shared", 0)},
        ("shared", 0): {("deep", 0)},
        ("deep", 0): {("root", -1)},
    }
    path = set()
    visitor._prepare_scan_tree(_path=path)
    assert path == set()
def test_prepare_scan_tree_renders_deep_chain_and_cleans_path():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {
        (f"node-{index}", 0): {(f"node-{index + 1}", 0)}
        for index in range(99)
    }
    visitor._debug_scan_tree[("root", -1)] = {("node-0", 0)}
    path = set()

    visitor._prepare_scan_tree(_path=path)

    assert path == set()
    assert len(visitor._debug_message) == 101
    assert visitor._debug_message[0] == "\n--- Scan Tree ---\nroot"
    assert visitor._debug_message[1] == " |_ node-0(idx: 0)"
    assert visitor._debug_message[-1].endswith("node-99(idx: 0)")

def test_prepare_scan_tree_exceeds_python_recursion_depth():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    depth = 1500
    visitor._debug_scan_tree = {
        (f"node-{index}", 0): {(f"node-{index + 1}", 0)}
        for index in range(depth - 1)
    }
    visitor._debug_scan_tree[("root", -1)] = {("node-0", 0)}

    visitor._prepare_scan_tree()

    assert len(visitor._debug_message) == depth + 1
    assert visitor._debug_message[-1].endswith(f"node-{depth - 1}(idx: 0)")


def test_prepare_scan_tree_preserves_caller_path_keys():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    caller_key = ("caller", 7)
    path = {caller_key}

    visitor._prepare_scan_tree(_path=path)

    assert path == {caller_key}
    assert visitor._debug_message[-1] == " |_ child(idx: 0)"


def test_prepare_scan_tree_restores_caller_path_keys_on_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    caller_key = ("caller", 7)
    path = {caller_key}
    original_prepare = visitor._prepare_scan_tree

    def fail(*args, **kwargs):
        raise RuntimeError("message failure")

    monkeypatch.setattr(visitor, "_prepare_scan_tree", fail)
    with pytest.raises(RuntimeError, match="message failure"):
        visitor._prepare_scan_tree(_path=path)
    assert path == {caller_key}
    monkeypatch.setattr(visitor, "_prepare_scan_tree", original_prepare)

def test_prepare_scan_tree_cleans_path_after_message_failure():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    visitor._debug_message = []
    caller_key = ("caller", 7)
    path = {caller_key}

    class FailingMessage(list):
        def append(self, value):
            if value.startswith(" |_"):
                raise RuntimeError("message failure")
            super().append(value)

    visitor._debug_message = FailingMessage()
    with pytest.raises(RuntimeError, match="message failure"):
        visitor._prepare_scan_tree(_path=path)

    assert visitor._debug_message == ["\n--- Scan Tree ---\nroot"]
def test_dump_scan_tree_retry_uses_current_tree_after_logger_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root", -1): {("old", 0)}}
    messages = []
    error = RuntimeError("logger failure")

    def log_info(message):
        messages.append(message)
        if len(messages) == 1:
            raise error

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(RuntimeError) as raised:
        visitor.dump_scan_tree()

    visitor._debug_scan_tree = {("root", -1): {("new", 0)}}
    original_message = visitor._debug_message
    visitor.dump_scan_tree()

    assert raised.value is error
    assert visitor._debug_message is original_message
    assert "old(idx: 0)" not in messages[1]
    assert "new(idx: 0)" in messages[1]

def test_dump_scan_tree_retry_uses_current_root_after_logger_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "old-root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("old-root", -1): {("old", 0)}}
    messages = []

    def log_info(message):
        messages.append(message)
        if len(messages) == 1:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()

    visitor._debug_scan_tree_root = "new-root"
    visitor._debug_scan_tree = {("new-root", -1): {("new", 0)}}
    visitor.dump_scan_tree()

    assert "new-root" in messages[1]
    assert "old-root" not in messages[1]
    assert "new(idx: 0)" in messages[1]
    assert "old(idx: 0)" not in messages[1]

def test_dump_scan_tree_retry_uses_current_root_after_render_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "old-root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("old-root", -1): {("old", 0)}}
    original_prepare = visitor._prepare_scan_tree
    calls = []

    def prepare(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("render failure")
        return original_prepare(*args, **kwargs)

    monkeypatch.setattr(visitor, "_prepare_scan_tree", prepare)
    with pytest.raises(RuntimeError, match="render failure"):
        visitor.dump_scan_tree()

    visitor._debug_scan_tree_root = "new-root"
    visitor._debug_scan_tree = {("new-root", -1): {("new", 0)}}
    messages = []
    monkeypatch.setattr(visitor_module, "log_info", messages.append)
    visitor.dump_scan_tree()

    assert visitor._debug_message is not None
    assert "new-root" in messages[0]
    assert "old-root" not in messages[0]
    assert "new(idx: 0)" in messages[0]
    assert "old(idx: 0)" not in messages[0]

def test_dump_scan_tree_recovers_after_render_and_logger_failures(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "old-root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("old-root", -1): {("old", 0)}}
    original_message = visitor._debug_message
    original_prepare = visitor._prepare_scan_tree
    prepare_calls = []
    log_calls = []

    def prepare(*args, **kwargs):
        prepare_calls.append(True)
        if len(prepare_calls) == 1:
            raise RuntimeError("render failure")
        return original_prepare(*args, **kwargs)

    def log_info(message):
        log_calls.append(message)
        if len(log_calls) == 1:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor, "_prepare_scan_tree", prepare)
    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(RuntimeError, match="render failure"):
        visitor.dump_scan_tree()

    visitor._debug_scan_tree_root = "new-root"
    visitor._debug_scan_tree = {("new-root", -1): {("new", 0)}}
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "new-root" in log_calls[-1]
    assert "new(idx: 0)" in log_calls[-1]
    assert "old-root" not in log_calls[-1]
    assert "old(idx: 0)" not in log_calls[-1]

def test_dump_scan_tree_retry_uses_final_mutated_state(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "first-root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("first-root", -1): {("first", 0)}}
    original_message = visitor._debug_message
    messages = []
    failures = iter(("first failure", "second failure"))

    def log_info(message):
        messages.append(message)
        try:
            failure = next(failures)
        except StopIteration:
            return
        raise RuntimeError(failure)

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(RuntimeError, match="first failure"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "second-root"
    visitor._debug_scan_tree = {("second-root", -1): {("second", 0)}}
    with pytest.raises(RuntimeError, match="second failure"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "final-root"
    visitor._debug_scan_tree = {("final-root", -1): {("final", 0)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "final-root" in messages[-1]
    assert "final(idx: 0)" in messages[-1]
    assert all(value not in messages[-1] for value in ("first", "second"))

def test_dump_scan_tree_retry_handles_empty_current_tree(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    original_message = visitor._debug_message
    messages = []

    def log_info(message):
        messages.append(message)
        if len(messages) == 1:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()

    visitor._debug_scan_tree = {}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert messages[-1].startswith("\n--- Scan Tree ---\nroot\n---------------")
    assert "child(idx: 0)" not in messages[-1]

def test_dump_scan_tree_retry_handles_absent_current_root(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    original_message = visitor._debug_message
    messages = []

    def log_info(message):
        messages.append(message)
        if len(messages) == 1:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()

    visitor._debug_scan_tree = {("other", -1): {("other-child", 0)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert messages[-1].startswith("\n--- Scan Tree ---\nroot\n---------------")
    assert "child(idx: 0)" not in messages[-1]
    assert "other-child(idx: 0)" not in messages[-1]

def test_prepare_scan_tree_propagates_null_mapping_error_and_preserves_path():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = None
    caller_key = ("caller", 7)
    path = {caller_key}

    with pytest.raises(AttributeError):
        visitor._prepare_scan_tree(_path=path)

    assert path == {caller_key}
    assert visitor._debug_message == ["\n--- Scan Tree ---\nroot"]

def test_dump_scan_tree_recovers_after_null_mapping_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = None
    original_message = visitor._debug_message
    messages = []
    monkeypatch.setattr(visitor_module, "log_info", messages.append)

    with pytest.raises(AttributeError):
        visitor.dump_scan_tree()

    visitor._debug_scan_tree = {("root", -1): {("recovered", 0)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "recovered(idx: 0)" in messages[0]
    assert "stale" not in messages[0]

def test_dump_scan_tree_repeated_null_failures_reset_diagnostics(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = None
    original_message = visitor._debug_message
    messages = []
    monkeypatch.setattr(visitor_module, "log_info", messages.append)

    for _ in range(2):
        with pytest.raises(AttributeError):
            visitor.dump_scan_tree()
        assert visitor._debug_message is original_message
        assert visitor._debug_message == ["\n--- Scan Tree ---\nroot"]

    visitor._debug_scan_tree = {("root", -1): {("recovered", 0)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert len(messages) == 1
    assert "recovered(idx: 0)" in messages[0]

def test_dump_scan_tree_recovers_null_root_and_logger_transitions(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "old-root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = None
    original_message = visitor._debug_message
    messages = []

    def log_info(message):
        messages.append(message)
        if len(messages) == 1:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(AttributeError):
        visitor.dump_scan_tree()

    visitor._debug_scan_tree_root = "new-root"
    visitor._debug_scan_tree = {("new-root", -1): {("new", 0)}}
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "new-root" in messages[-1]
    assert "new(idx: 0)" in messages[-1]
    assert "old-root" not in messages[-1]

def test_dump_scan_tree_null_root_logger_then_empty_final_state(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = None
    original_message = visitor._debug_message
    messages = []

    def log_info(message):
        messages.append(message)
        if len(messages) == 1:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    with pytest.raises(AttributeError):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree = {}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert messages[-1] == "\n--- Scan Tree ---\nroot\n---------------"
    assert "child(idx: 0)" not in messages[-1]

def test_dump_scan_tree_recovery_then_repeated_success_has_no_duplicates(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = None
    original_message = visitor._debug_message
    messages = []
    monkeypatch.setattr(visitor_module, "log_info", messages.append)

    with pytest.raises(AttributeError):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root", -1): {("child", 0)}}
    visitor.dump_scan_tree()
    first = messages[-1]
    visitor.dump_scan_tree()
    second = messages[-1]

    assert visitor._debug_message is original_message
    assert second == first
    assert second.count("root") == 1
    assert second.count("child(idx: 0)") == 1

def test_dump_scan_tree_successive_mutations_use_current_output(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    original_message = visitor._debug_message
    messages = []
    monkeypatch.setattr(visitor_module, "log_info", messages.append)

    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-a", -1): {("child-b", 0)}}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-c"
    visitor._debug_scan_tree = {("root-c", -1): {("child-c", 0)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "child-a(idx: 0)" in messages[0]
    assert "child-b(idx: 0)" in messages[1]
    assert "child-a(idx: 0)" not in messages[1]
    assert "root-c" in messages[2]
    assert "child-c(idx: 0)" in messages[2]
    assert "root-a" not in messages[2]

def test_dump_scan_tree_empty_then_restored_tree_uses_current_output(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root", -1): {("old", 0)}}
    original_message = visitor._debug_message
    messages = []
    monkeypatch.setattr(visitor_module, "log_info", messages.append)

    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root", -1): {("restored", 1)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "old(idx: 0)" in messages[0]
    assert messages[1] == "\n--- Scan Tree ---\nroot\n---------------"
    assert "restored(idx: 1)" in messages[2]
    assert "old(idx: 0)" not in messages[2]

def test_dump_scan_tree_repeated_empty_restore_root_cycles_are_current(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    original_message = visitor._debug_message
    messages = []
    monkeypatch.setattr(visitor_module, "log_info", messages.append)

    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    visitor._debug_scan_tree = {}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert messages[0] == "\n--- Scan Tree ---\nroot-a\n---------------"
    assert "child-a(idx: 0)" in messages[1]
    assert messages[2] == "\n--- Scan Tree ---\nroot-b\n---------------"
    assert "child-a(idx: 0)" not in messages[2]
    assert "child-b(idx: 1)" in messages[3]
    assert "root-a" not in messages[3]

def test_dump_scan_tree_late_logger_failure_retry_is_current(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls == 3:
            raise RuntimeError("late logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    with pytest.raises(RuntimeError, match="late logger failure"):
        visitor.dump_scan_tree()
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "root-b" in messages[-1]
    assert "child-b(idx: 1)" in messages[-1]
    assert "root-a" not in messages[-1]
    assert "child-a(idx: 0)" not in messages[-1]

def test_dump_scan_tree_multiple_logger_failures_rebuild_current_state(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls in {2, 3}:
            raise RuntimeError(f"logger failure {calls}")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    with pytest.raises(RuntimeError, match="logger failure 2"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-c"
    visitor._debug_scan_tree = {}
    with pytest.raises(RuntimeError, match="logger failure 3"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-c", -1): {("child-c", 2)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "root-c" in messages[-1]
    assert "child-c(idx: 2)" in messages[-1]
    assert "root-a" not in messages[-1]
    assert "root-b" not in messages[-1]
    assert "child-b(idx: 1)" not in messages[-1]

def test_dump_scan_tree_empty_logger_failures_then_restore_current_state(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls in {2, 3}:
            raise RuntimeError(f"logger failure {calls}")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {}
    with pytest.raises(RuntimeError, match="logger failure 2"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    with pytest.raises(RuntimeError, match="logger failure 3"):
        visitor.dump_scan_tree()
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "root-b" in messages[-1]
    assert "child-b(idx: 1)" in messages[-1]
    assert "root-a" not in messages[-1]
    assert "child-a(idx: 0)" not in messages[-1]

def test_dump_scan_tree_mutated_empty_root_logger_retry_is_current(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls == 2:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert messages[0] == "\n--- Scan Tree ---\nroot-a\n---------------"
    assert "root-b" in messages[-1]
    assert "child-b(idx: 1)" in messages[-1]
    assert "root-a" not in messages[-1]

def test_dump_scan_tree_logger_failure_then_restoration_cycle_is_current(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls == 3:
            raise RuntimeError("logger failure")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-c"
    visitor._debug_scan_tree = {}
    with pytest.raises(RuntimeError, match="logger failure"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-d"
    visitor._debug_scan_tree = {("root-d", -1): {("child-d", 2)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "root-d" in messages[-1]
    assert "child-d(idx: 2)" in messages[-1]
    assert "root-a" not in messages[-1]
    assert "root-b" not in messages[-1]
    assert "root-c" not in messages[-1]

def test_dump_scan_tree_repeated_restoration_failures_use_latest_state(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls in {3, 5}:
            raise RuntimeError(f"logger failure {calls}")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-c"
    visitor._debug_scan_tree = {}
    with pytest.raises(RuntimeError, match="logger failure 3"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-d"
    visitor._debug_scan_tree = {("root-d", -1): {("child-d", 2)}}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-e"
    visitor._debug_scan_tree = {}
    with pytest.raises(RuntimeError, match="logger failure 5"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-e", -1): {("child-e", 3)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "root-e" in messages[-1]
    assert "child-e(idx: 3)" in messages[-1]
    for stale_root in ("root-a", "root-b", "root-c", "root-d"):
        assert stale_root not in messages[-1]

def test_dump_scan_tree_three_recovery_cycles_keep_latest_state(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls in {2, 4, 6}:
            raise RuntimeError(f"logger failure {calls}")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-a", -1): {("child-a", 0)}}
    with pytest.raises(RuntimeError, match="logger failure 2"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-b"
    visitor._debug_scan_tree = {}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-b", -1): {("child-b", 1)}}
    with pytest.raises(RuntimeError, match="logger failure 4"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree_root = "root-c"
    visitor._debug_scan_tree = {}
    visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-c", -1): {("child-c", 2)}}
    with pytest.raises(RuntimeError, match="logger failure 6"):
        visitor.dump_scan_tree()
    visitor._debug_scan_tree = {("root-c", -1): {("child-final", 3)}}
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "root-c" in messages[-1]
    assert "child-final(idx: 3)" in messages[-1]
    for stale in ("root-a", "root-b", "child-a", "child-b", "child-c(idx: 2)"):
        assert stale not in messages[-1]

def test_dump_scan_tree_four_recovery_cycles_keep_latest_state(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root-a"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls in {2, 4, 6, 8}:
            raise RuntimeError(f"logger failure {calls}")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    visitor.dump_scan_tree()
    for number, failure_call in enumerate((2, 4, 6, 8), start=0):
        root = chr(ord("a") + number)
        child = f"child-{root}"
        visitor._debug_scan_tree_root = f"root-{root}"
        visitor._debug_scan_tree = {}
        with pytest.raises(RuntimeError, match=f"logger failure {failure_call}"):
            visitor.dump_scan_tree()
        visitor._debug_scan_tree = {
            (f"root-{root}", -1): {(child, number)}
        }
        if number < 3:
            visitor.dump_scan_tree()
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert "root-d" in messages[-1]
    assert "child-d(idx: 3)" in messages[-1]
    for stale in ("root-a", "root-b", "root-c", "child-a", "child-b", "child-c"):
        assert stale not in messages[-1]

@pytest.mark.parametrize("failure_call", [1, 2, 3, 4])
def test_dump_scan_tree_parametrized_failure_rebuilds_current_state(
    monkeypatch, failure_call
):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "initial"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {("initial", -1): {("old", 0)}}
    original_message = visitor._debug_message
    messages = []
    calls = 0

    def log_info(message):
        nonlocal calls
        calls += 1
        messages.append(message)
        if calls == failure_call:
            raise RuntimeError(f"logger failure {failure_call}")

    monkeypatch.setattr(visitor_module, "log_info", log_info)
    for call in range(1, failure_call + 1):
        visitor._debug_scan_tree_root = f"root-{call}"
        visitor._debug_scan_tree = {}
        if call == failure_call:
            with pytest.raises(
                RuntimeError, match=f"logger failure {failure_call}"
            ):
                visitor.dump_scan_tree()
        else:
            visitor.dump_scan_tree()
    visitor._debug_scan_tree = {
        (f"root-{failure_call}", -1): {("final", failure_call)}
    }
    visitor.dump_scan_tree()

    assert visitor._debug_message is original_message
    assert f"root-{failure_call}" in messages[-1]
    assert f"final(idx: {failure_call})" in messages[-1]
    assert "initial" not in messages[-1]
    assert "old(idx: 0)" not in messages[-1]

def test_scan_tree_debug_output_is_deterministic(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = []
    visitor._debug_scan_tree = {
        ("root", -1): {("zeta", 2), ("alpha", 1)},
    }

    visitor._prepare_scan_tree()

    assert visitor._debug_message == [
        "\n--- Scan Tree ---\nroot",
        " |_ alpha(idx: 1)",
        " |_ zeta(idx: 2)",
    ]

def test_recursive_downwards_object_visitor_processes_deferred_children(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._new_for_visit = [
        _child_frame(visitor_module, 1, 0x403000, 1, 4),
        _child_frame(visitor_module, 2, 0x402000, 0, 2),
    ]
    calls = []

    def execute(frame):
        calls.append((frame.function_ea, frame.argument_index, frame.base_offset))
        return []

    visitor._execute_visit = execute
    visitor._scan_single_function = lambda: None

    visitor._recursive_process()

    assert calls == [(0x403000, 1, 4), (0x402000, 0, 2)]
    assert visitor._new_for_visit == []


def test_dump_scan_tree_resets_debug_message(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._debug_scan_tree_root = "root"
    visitor._debug_message = ["stale"]
    visitor._debug_scan_tree = {}
    rendered = []
    monkeypatch.setattr(visitor_module, "log_info", rendered.append)

    visitor.dump_scan_tree()
    first = list(visitor._debug_message)
    visitor.dump_scan_tree()

    assert visitor._debug_message == first
    assert len(rendered) == 2

def test_recursive_downwards_object_visitor_stops_permanently_deferred_visit(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._new_for_visit = [_child_frame(visitor_module, 1, 0x402000, 0, 0)]
    visitor._execute_visit = lambda *args: visitor._VISIT_DEFERRED
    visitor._scan_single_function = lambda: None

    visitor._recursive_process()

    assert visitor._new_for_visit == []

def test_recursive_downwards_object_visitor_clears_queue_on_scan_failure(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._new_for_visit = [_child_frame(visitor_module, 1, 0x402000, 0, 0)]
    error = RuntimeError("scan failed")

    def fail_scan():
        visitor._new_for_visit.append(_child_frame(visitor_module, 2, 0x403000, 1, 0))
        raise error

    monkeypatch.setattr(visitor, "_scan_single_function", fail_scan)

    with pytest.raises(RuntimeError) as raised:
        visitor._recursive_process()

    assert raised.value is error
    assert visitor._new_for_visit == []
def test_recursive_downwards_object_visitor_refreshes_tree_before_scanning(monkeypatch):
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveDownwardsObjectVisitor.__new__(
        visitor_module.RecursiveDownwardsObjectVisitor
    )
    visitor._cfunc = SimpleNamespace(entry_ea=0x401000)
    visitor._max_depth = None
    visitor._current_frame = _root_frame(visitor_module)
    visitor._new_for_visit = [_child_frame(visitor_module, 1, 0x402000, 0, 0)]
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

def test_upwards_prepare_rejects_phi_parent_with_conflicting_child_sizes():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveUpwardsObjectVisitor.__new__(
        visitor_module.RecursiveUpwardsObjectVisitor
    )
    # void *p; if (c) p = a(0x2C); else p = b(0x38);  ->  the unknown-size
    # phi parent p must NOT batch-accept two DIFFERENT known sizes into
    # the closure (R3.12 fold); its propagation is rejected entirely.
    p = _AllocVar("p")  # unknown (phi)
    a = _AllocVar("a", alloc_size=0x2C)
    b = _AllocVar("b", alloc_size=0x38)
    visitor._objects = [p]
    visitor._tree = {p: {a, b}}
    visitor._prepare()
    names = [o.name for o in visitor._objects]
    assert names == ["p"]


def test_upwards_prepare_accepts_phi_parent_with_consistent_child_sizes():
    visitor_module = _load_visitor_module()
    visitor = visitor_module.RecursiveUpwardsObjectVisitor.__new__(
        visitor_module.RecursiveUpwardsObjectVisitor
    )
    # Same shape but consistent known sizes: both children merge.
    p = _AllocVar("p")  # unknown (phi)
    a = _AllocVar("a", alloc_size=0x2C)
    b = _AllocVar("b", alloc_size=0x2C)
    visitor._objects = [p]
    visitor._tree = {p: {a, b}}
    visitor._prepare()
    names = sorted(o.name for o in visitor._objects)
    assert names == ["a", "b", "p"]


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

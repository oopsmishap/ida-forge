from __future__ import annotations

from importlib import import_module, util
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import ClassVar

import ida_hexrays

if not hasattr(ida_hexrays, "ctree_parentee_t"):
    ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {"__init__": lambda self: None})

import sys as _sys

if "ida_idaapi" not in _sys.modules:
    _sys.modules["ida_idaapi"] = ModuleType("ida_idaapi")
import ida_hexrays

# The conftest ida_hexrays stub's ctree_parentee_t has no cv_flags; give the
# base a real __init__ so visitor constructors can run headless.
ida_hexrays.ctree_parentee_t = type(
    "ctree_parentee_t",
    (),
    {"__init__": lambda self: setattr(self, "cv_flags", 0)},
)

def _load_real_modules():
    """Reload the real visitor and scanner modules over the conftest stubs
    (same spec_from_file_location pattern as test_scanner.py)."""
    root = Path(__file__).resolve().parents[2] / "src"

    visitor_path = root / "forge" / "api" / "visitor.py"
    visitor_spec = util.spec_from_file_location("forge.api.visitor", visitor_path)
    assert visitor_spec is not None and visitor_spec.loader is not None
    visitor_module = util.module_from_spec(visitor_spec)
    # Python 3.14 dataclass processing needs sys.modules[cls.__module__].
    _sys.modules["forge.api.visitor"] = visitor_module
    # The conftest hexrays stub lacks a few names scanner.py imports;
    # fill them in first (same as test_scanner.py).
    hexrays_api = import_module("forge.api.hexrays")
    hexrays_api.ctype_to_str = lambda *_args, **_kwargs: ""
    hexrays_api.decompile = lambda *_args, **_kwargs: None
    hexrays_api.find_expr_address = lambda *_args, **_kwargs: 0
    hexrays_api.get_func_argument_info = lambda *_args, **_kwargs: (0, None)
    hexrays_api.get_funcs_calling_address = lambda *_args, **_kwargs: set()
    hexrays_api.is_code = lambda *_args, **_kwargs: False
    hexrays_api.is_legal_type = lambda *_args, **_kwargs: True
    hexrays_api.to_hex = lambda value: hex(value)

    visitor_spec.loader.exec_module(visitor_module)

    scanner_path = root / "forge" / "api" / "scanner.py"
    scanner_spec = util.spec_from_file_location("forge.api.scanner", scanner_path)
    assert scanner_spec is not None and scanner_spec.loader is not None
    scanner_module = util.module_from_spec(scanner_spec)
    _sys.modules["forge.api.scanner"] = scanner_module
    scanner_spec.loader.exec_module(scanner_module)
    return visitor_module, scanner_module


visitor_module, scanner_module = _load_real_modules()


class FakeType:
    def __init__(self, name: str, *, ptr: bool = False, element_size: int | None = None):
        self._name = name
        self._ptr = ptr
        self._element_size = element_size

    def dstr(self):
        return self._name

    def is_ptr(self):
        return self._ptr

    def is_funcptr(self):
        return False

    def get_ptrarr_objsize(self):
        return self._element_size or 1

    def get_pointed_object(self):
        return FakeType(self._name[:-2] if self._ptr else self._name)


def _make_visitor(monkeypatch, *, member_sink=None, structure=None):
    structure = structure if structure is not None else SimpleNamespace(
        name="Root", add_member=lambda member: None
    )
    obj = SimpleNamespace(ea=0x5000, name="a1")
    return scanner_module.NewDeepScanVisitor(
        SimpleNamespace(entry_ea=0x401000),
        0,
        obj,
        structure,
        recurse_calls=True,
        skip_until_object=False,
        member_sink=member_sink,
    )


def test_recursive_call_frame_tree_tracks_frames_and_aliases(monkeypatch):
    visitor = _make_visitor(monkeypatch)
    root = visitor.current_frame
    assert root.frame_id == 0 and root.parent_frame_id is None
    assert root.function_ea == 0x401000 and root.base_offset == 0

    # First call site: a fresh frame at base 8 is queued and registered.
    assert visitor._add_visit(0x402000, 0, 0x401100, 8) is True
    child = visitor._new_for_visit[-1]
    assert child.parent_frame_id == 0
    assert child.function_ea == 0x402000 and child.call_site_ea == 0x401100
    assert child.base_offset == 8 and child.depth == 1
    assert visitor.call_frames == (root, child)

    # Same (callee, argument) at a NEW call site with the same base offset:
    # deduplicated and aliased onto the canonical frame.
    assert visitor._add_visit(0x402000, 0, 0x401200, 8) is False
    alias_ids = [
        frame_id
        for frame_id in visitor._call_frames
        if frame_id in visitor._frame_aliases
        and visitor._frame_aliases[frame_id] == child.frame_id
    ]
    assert len(alias_ids) == 1
    assert visitor.canonical_frame_id(alias_ids[0]) == child.frame_id

    # A nested call seen from inside the child frame accumulates the base.
    visitor._current_frame = child
    assert visitor._add_visit(0x404000, 1, 0x402100, 4) is True
    grandchild = visitor._new_for_visit[-1]
    assert grandchild.parent_frame_id == child.frame_id
    assert grandchild.base_offset == 12 and grandchild.depth == 2
    assert visitor.frame_aliases == {alias_ids[0]: child.frame_id}

    # An active (callee, argument) ancestor is never re-visited.
    assert visitor._add_visit(0x402000, 0, 0x402200, 0) is False


def test_member_sink_receives_frame_observations(monkeypatch):
    structure_members = []
    structure = SimpleNamespace(name="Root", add_member=structure_members.append)
    visitor = _make_visitor(monkeypatch, structure=structure)
    member = SimpleNamespace(name="field_8", offset=8)

    # Without a sink the member lands in the structure as before.
    visitor._emit_member(member)
    assert structure_members == [member]

    # With a sink the observation is routed with the CURRENT scan frame.
    observed = []
    sink_visitor = _make_visitor(
        monkeypatch, member_sink=lambda member, frame: observed.append((member, frame))
    )
    nested_frame = visitor_module.RecursiveCallFrame(
        frame_id=1,
        parent_frame_id=0,
        function_ea=0x402000,
        argument_index=0,
        call_site_ea=0x401100,
        base_offset=8,
        depth=1,
    )
    observed.clear()

    lvar = SimpleNamespace(name="arg0", type=lambda: SimpleNamespace(dstr=lambda: "T *"))
    monkeypatch.setattr(
        visitor_module, "decompile", lambda _ea: SimpleNamespace(
            entry_ea=0x402000,
            argidx=[0],
            get_lvars=lambda: [lvar],
            body=SimpleNamespace(cblock=SimpleNamespace(size=lambda: 2)),
        ),
        raising=False,
    )
    monkeypatch.setattr(
        visitor_module, "get_argument", lambda cfunc, idx: (lvar, 0), raising=False
    )
    monkeypatch.setattr(
        sink_visitor, "_refresh_decompilation_tree", lambda c: c, raising=False
    )

    def fake_scan():
        sink_visitor._emit_member(member)

    sink_visitor._scan_single_function = fake_scan
    outcome = sink_visitor._execute_visit(nested_frame)
    assert outcome == []
    # The observation carries the frame it was observed under, not the root.
    assert observed == [(member, nested_frame)]
    assert sink_visitor.current_frame.frame_id == 0


class _FakeScanVariable:
    def __init__(self, name: str, ea: int):
        self.name = name
        self.ea = ea

    def __hash__(self):
        return hash((self.name, self.ea))

    def __eq__(self, other):
        return (
            isinstance(other, _FakeScanVariable)
            and (self.name, self.ea) == (other.name, other.ea)
        )


def test_pointer_child_structures_group_pointee_members(monkeypatch):
    from forge.api.members import Member, VoidMember
    from forge.api.structure import Structure

    structure = Structure("Root")
    visitor = _make_visitor(monkeypatch, structure=structure)
    assert visitor.pointer_child_structures == {}

    member = Member(0, None, _FakeScanVariable("scan", 0x5000), 0)
    visitor._record_pointer_child_member(0, member)
    child = visitor.pointer_child_structures[0]
    assert child.name == "Root_field_0"
    assert member in child.members

    # Another observation through the same field lands in the same child.
    member2 = Member(8, None, _FakeScanVariable("scan", 0x5000), 0)
    visitor._record_pointer_child_member(0, member2)
    assert visitor.pointer_child_structures[0] is child
    assert member2 in child.members

    # Void members are never recorded. VoidMember needs a subscriptable
    # types map; the conftest stub provides a plain namespace.
    members_module = import_module("forge.api.members")
    monkeypatch.setattr(
        members_module,
        "types",
        {
            "u8": SimpleNamespace(type=None),
            "i8": SimpleNamespace(type=None),
        },
        raising=False,
    )
    void = VoidMember(0, _FakeScanVariable("void", 0x5000), 0)
    visitor._record_pointer_child_member(4, void)
    assert 4 not in visitor.pointer_child_structures


def test_pointer_child_field_access_detects_double_dereference(monkeypatch):
    ctype = scanner_module.ctype
    visitor = _make_visitor(monkeypatch)

    # `*(_QWORD *)(*(_QWORD *)a1 + 8) = ...` — parents of the a1 leaf,
    # innermost first.
    cast1 = SimpleNamespace(op=ctype.cast)
    ptr1 = SimpleNamespace(op=ctype.ptr)
    add = SimpleNamespace(
        op=ctype.add,
        x=ptr1,
        y=SimpleNamespace(op=ctype.num, numval=lambda: 8),
        type=FakeType("_QWORD *", ptr=True, element_size=8),
    )
    cast2 = SimpleNamespace(op=ctype.cast, type=FakeType("_QWORD *", ptr=True))
    ptr2 = SimpleNamespace(op=ctype.ptr)
    monkeypatch.setattr(
        visitor,
        "_get_parent_context",
        lambda: scanner_module.ParentExpressionContext([cast1, ptr1, add, cast2, ptr2]),
        raising=False,
    )

    observation = visitor._pointer_child_field_access(
        SimpleNamespace(op=ctype.var, name="a1")
    )
    assert observation is not None
    _field_offset, _pointee_offset, element, access_expr = observation
    assert element is not None and element.dstr() == "_QWORD"
    assert access_expr is ptr2

    # A plain single dereference is NOT a pointer child.
    monkeypatch.setattr(
        visitor,
        "_get_parent_context",
        lambda: scanner_module.ParentExpressionContext([cast1, ptr1]),
        raising=False,
    )
    assert visitor._pointer_child_field_access(
        SimpleNamespace(op=ctype.var, name="a1")
    ) is None

    # Dynamic (non-numeric) addressing is not recordable.
    dynamic_add = SimpleNamespace(
        op=ctype.add, x=ptr1, y=SimpleNamespace(op=ctype.var, name="i")
    )
    monkeypatch.setattr(
        visitor,
        "_get_parent_context",
        lambda: scanner_module.ParentExpressionContext([cast1, ptr1, dynamic_add, cast2, ptr2]),
        raising=False,
    )
    assert visitor._pointer_child_field_access(
        SimpleNamespace(op=ctype.var, name="a1")
    ) is None


def test_child_scan_module_exposes_hierarchy_contract():
    child_scan = import_module("forge.features.structure_builder.child_scan")

    request = child_scan.HierarchyScanRequest(cfunc=object(), obj=object(), source_base=16)
    assert request.source_base == 16
    assert child_scan.HierarchyScanRequest(cfunc=object(), obj=object()).source_base == 0

    mixin = child_scan.ChildScanMixin
    assert hasattr(mixin, "_run_deep_hierarchy_scan")
    assert hasattr(mixin, "_link_pointer_children")

    hierarchy = import_module("forge.features.structure_builder.hierarchy")
    assert hasattr(hierarchy, "StructureHierarchySession")
    assert hasattr(hierarchy, "HierarchyCommitResult")
    assert hasattr(hierarchy.StructureHierarchySession, "member_sink")
    assert hasattr(hierarchy.StructureHierarchySession, "finish_scan")
    assert hasattr(hierarchy.StructureHierarchySession, "commit")


def test_child_scan_plan_carries_source_base():
    child_scan = import_module("forge.features.structure_builder.child_scan")
    plan = child_scan.ChildScanPlan(
        scan_object=SimpleNamespace(name="member"),
        function_eas=(0x401000,),
        relation_kind="embedded",
        root_object_name="Parent.member",
        root_object_ea=None,
        root_function_ea=None,
        has_multiple_roots=False,
        source_base=48,
    )
    assert plan.source_base == 48
    default_plan = child_scan.ChildScanPlan(
        scan_object=SimpleNamespace(name="member"),
        function_eas=(0x401000,),
        relation_kind="pointer",
        root_object_name="Parent.member",
        root_object_ea=None,
        root_function_ea=None,
        has_multiple_roots=False,
    )
    assert default_plan.source_base == 0


def test_run_deep_hierarchy_scan_runs_recursive_sink_visitors(monkeypatch):
    """The hierarchy runner constructs every request's visitor with
    recurse_calls=True, the requested depth, and the session's member_sink;
    finishing registers committed structures and restores the selection."""
    form_module = import_module("forge.features.structure_builder.form")
    child_scan = import_module("forge.features.structure_builder.child_scan")

    structure_form = form_module.StructureBuilderForm()
    structure_form.structures = {}
    structure_form.current_structure = None
    monkeypatch.setattr(structure_form, "update_action_states", lambda: None)
    monkeypatch.setattr(structure_form, "update_structure_fields", lambda: None)
    monkeypatch.setattr(structure_form, "reload_structure_list", lambda: None)

    captured = {}

    class FakeVisitor:
        def __init__(
            self,
            cfunc,
            origin,
            obj,
            structure,
            recurse_calls=False,
            max_depth=None,
            member_sink=None,
            **_kwargs,
        ):
            captured["visitor"] = (
                cfunc.entry_ea,
                origin,
                obj.name,
                structure.name,
                recurse_calls,
                max_depth,
                callable(member_sink),
            )
            captured["visitor_instance"] = self
        pointer_child_structures: ClassVar[dict] = {}

        def process(self):
            return None

    class FakeSession:
        def __init__(self, root_structure, structures_by_name=None, make_unique_name=None):
            captured["session"] = (
                root_structure.name,
                sorted(structures_by_name or {}),
                callable(make_unique_name),
            )
            captured["session_instance"] = self

        @staticmethod
        def member_sink(_member, _frame):
            return None

        @property
        def has_observations(self):
            return True

        def finish_scan(self, visitor, *, source_base=0):
            captured["finish"] = (source_base, visitor is captured["visitor_instance"])

        def commit(self):
            return SimpleNamespace(plan=None, structures=())

    monkeypatch.setattr(child_scan, "NewDeepScanVisitor", FakeVisitor)
    monkeypatch.setattr(child_scan, "StructureHierarchySession", FakeSession)

    structure = SimpleNamespace(name="Root")
    structure_form.current_structure = structure
    request = child_scan.HierarchyScanRequest(
        cfunc=SimpleNamespace(entry_ea=0x401000),
        obj=SimpleNamespace(name="a1"),
        source_base=0,
    )

    result = structure_form._run_deep_hierarchy_scan(
        structure, [request], max_depth=7
    )

    assert result is not None
    root_name, working_names, unique_callback = captured["session"]
    assert root_name == "Root"
    assert working_names == ["Root"]
    assert unique_callback is True
    assert captured["visitor"] == (0x401000, 0, "a1", "Root", True, 7, True)
    assert captured["finish"] == (0, True)


def test_run_deep_hierarchy_scan_without_observations_returns_none(monkeypatch):
    form_module = import_module("forge.features.structure_builder.form")
    child_scan = import_module("forge.features.structure_builder.child_scan")

    structure_form = form_module.StructureBuilderForm()
    structure_form.structures = {}
    structure_form.current_structure = None
    monkeypatch.setattr(structure_form, "update_action_states", lambda: None)
    monkeypatch.setattr(structure_form, "update_structure_fields", lambda: None)
    monkeypatch.setattr(structure_form, "reload_structure_list", lambda: None)

    class FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        @staticmethod
        def member_sink(_member, _frame):
            return None

        @property
        def has_observations(self):
            return False

        def finish_scan(self, visitor, *, source_base=0):
            pass

        def commit(self):  # pragma: no cover - must not be reached
            raise AssertionError("commit must not run without observations")

    monkeypatch.setattr(child_scan, "NewDeepScanVisitor", lambda *a, **k: SimpleNamespace(
        process=lambda: None, pointer_child_structures={}
    ))
    monkeypatch.setattr(child_scan, "StructureHierarchySession", FakeSession)

    structure = SimpleNamespace(name="Root")
    structure_form.current_structure = structure
    request = child_scan.HierarchyScanRequest(
        cfunc=SimpleNamespace(entry_ea=0x401000),
        obj=SimpleNamespace(name="a1"),
    )

    assert (
        structure_form._run_deep_hierarchy_scan(structure, [request], max_depth=None)
        is None
    )

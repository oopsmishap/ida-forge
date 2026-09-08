"""Focused tests for subobject-rooted rebasing (forge.api.scan_subobject).

Guards the mandatory deterministic rebase contract: a scan rooted at a
nested subobject must record members in CHILD coordinates. Hand-crafted
parent access ``World + 0x1B60 + 0x08`` yields child-relative offset
``0x08`` — never ``0x1B68`` (the parent-relative address of the same
field). Also asserts the scan-root provenance carries the parent variable
identity and the subobject's base offset, and that parent-relative
offsets do not leak into the child structure.
"""

from __future__ import annotations

import pytest

from forge.api.hexrays import ctype
from forge.api.scan_object import VariableObject
from forge.api.scan_subobject import (
    SubobjectRoot,
    SubobjectScanObject,
    rebase_to_subobject,
)

# The canonical fixture: a nested subobject living 0x1B60 bytes into a
# parent object, with a field at subobject + 0x08.
BASE_OFFSET = 0x1B60
FIELD_OFFSET = 0x08
PARENT_RELATIVE_FIELD = BASE_OFFSET + FIELD_OFFSET  # 0x1B68


class FakeType:
    def __init__(self, name: str, pointed=None, array_element=None):
        self._name = name
        self._pointed = pointed
        self._array_element = array_element

    def dstr(self):
        return self._name

    def is_ptr(self):
        return self._pointed is not None

    def is_array(self):
        return self._array_element is not None

    def get_pointed_object(self):
        return self._pointed

    def get_array_element(self):
        return self._array_element


class FakeLvar:
    def __init__(self, name: str, type_name: str = "World *"):
        self.name = name
        self._type = FakeType(type_name, pointed=FakeType("World"))

    def type(self):
        return self._type


class FakeExpr:
    def __init__(self, op, **kwargs):
        self.op = op
        self.ea = kwargs.pop("ea", 0x401000)
        self.type = kwargs.pop("type", FakeType("World *", pointed=FakeType("World")))
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeNumberExpr(FakeExpr):
    def __init__(self, value: int):
        super().__init__(ctype.num, type=FakeType("__int64"))
        self._value = value

    def numval(self):
        return self._value


def make_parent_var_expr(index: int = 0):
    """A bare ``a1`` lvar expression that a VariableObject matches."""
    return FakeExpr(ctype.var, v=SimpleNamespaceVarIdx(index), type=FakeType("World *", pointed=FakeType("World")))


class SimpleNamespaceVarIdx:
    def __init__(self, index):
        self.idx = index


def make_parent_scan_object(lvar_name: str = "a1", index: int = 0):
    """A real VariableObject bound to a hand-crafted parent lvar."""
    return VariableObject(FakeLvar(lvar_name, "World *"), index)


def make_memptr_subobject(parent_expr, member_offset: int):
    """``parent->m`` carrying the subobject's member offset (memptr)."""
    return FakeExpr(ctype.memptr, m=member_offset, x=parent_expr)


def make_add_subobject(parent_expr, value: int):
    """``(child_t *)(parent + VALUE)`` — pointer arithmetic landing on the subobject."""
    add_expr = FakeExpr(ctype.add, x=parent_expr, y=FakeNumberExpr(value))
    return FakeExpr(ctype.cast, x=add_expr, type=FakeType("Child *", pointed=FakeType("Child")))


# --------------------------------------------------------------------------- #
# deterministic rebasing
# --------------------------------------------------------------------------- #
def test_rebase_to_subobject_maps_parent_relative_to_child_offset():
    """Parent base + 0x1B60 + 0x08 is 0x1B68; against the 0x1B60 subobject
    the child offset is 0x08 — never 0x1B68."""
    assert rebase_to_subobject(PARENT_RELATIVE_FIELD, BASE_OFFSET) == FIELD_OFFSET
    assert rebase_to_subobject(PARENT_RELATIVE_FIELD, BASE_OFFSET) != PARENT_RELATIVE_FIELD


def test_rebase_to_subobject_fixture_world_base_plus_member():
    """Hand-crafted parent access ``World + 0x1B60 + 0x08`` yields 0x08."""
    child_offset = rebase_to_subobject(0x1B60 + 0x08, 0x1B60)
    assert child_offset == 0x08
    assert child_offset != 0x1B68


def test_rebase_to_subobject_identity_when_already_child_relative():
    # A zero base offset means the subobject is the root itself.
    assert rebase_to_subobject(0x08, 0) == 0x08


def test_rebase_to_subobject_rejects_non_int_offset():
    with pytest.raises(TypeError):
        rebase_to_subobject("0x1B68", 0x1B60)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        rebase_to_subobject(True, 0x1B60)  # type: ignore[arg-type]


def test_rebase_to_subobject_allows_negative_result_recording_pre_subobject_offset():
    # An offset located before the subobject is not part of the child; the
    # rebase reports it as negative so callers can reject it rather than
    # silently recording parent-relative leakage.
    assert rebase_to_subobject(0x1B30, 0x1B60) == -0x30


# --------------------------------------------------------------------------- #
# root descriptor
# --------------------------------------------------------------------------- #
def test_subobject_root_validates_base_offset():
    with pytest.raises(ValueError):
        SubobjectRoot(base_offset=-1)
    with pytest.raises(ValueError):
        SubobjectRoot(base_offset=True)  # type: ignore[arg-type]


def test_subobject_root_rejects_multiple_parent_criteria():
    with pytest.raises(ValueError):
        SubobjectRoot(base_offset=0x1B60, var_name="a1", var_index=0)


def test_subobject_root_from_dict_roundtrip():
    root = SubobjectRoot.from_dict(
        {"base_offset": 0x1B60, "var_name": "a1", "parent_type": "World"}
    )
    assert root.base_offset == 0x1B60
    assert root.var_name == "a1"
    assert root.parent_type == "World"
    assert root.var_index is None
    assert root.item_ea is None


def test_subobject_root_from_dict_rejects_unknown_fields():
    with pytest.raises(ValueError):
        SubobjectRoot.from_dict({"base_offset": 0x1B60, "leak": 1})


# --------------------------------------------------------------------------- #
# scan-object provenance: parent variable + base offset
# --------------------------------------------------------------------------- #
def test_subobject_scan_object_carries_parent_variable_and_base_offset():
    parent = make_parent_scan_object("v", index=2)
    parent.ea = 0x401010
    parent.func_ea = 0x401000
    parent.set_scan_root(0x401000, expression_ea=0x401010, function_name="sub_401000")
    obj = SubobjectScanObject(
        parent, SubobjectRoot(base_offset=0x1B60, var_name="v")
    )

    # Provenance: the child object must keep the parent variable identity
    # and the subobject base offset, not silently detach from the parent.
    assert obj.base_offset == 0x1B60
    assert obj.name == "v"
    assert obj.index == 2
    assert obj.lvar is parent.lvar
    assert obj.ea == 0x401010
    assert obj.func_ea == 0x401000
    assert obj.scan_root_ea == 0x401010
    assert obj.scan_root_function_ea == 0x401000
    assert obj.scan_root_function_name == "sub_401000"
    assert obj.root.base_offset == 0x1B60
    assert obj.root.var_name == "v"


def test_subobject_scan_object_matches_memptr_at_base_offset():
    parent = make_parent_scan_object("a1")
    obj = SubobjectScanObject(
        parent, SubobjectRoot(base_offset=0x1B60, var_name="a1", parent_type="World")
    )
    expr = make_memptr_subobject(make_parent_var_expr(0), 0x1B60)
    assert obj.is_target(expr) is True


def test_subobject_scan_object_matches_pointer_arithmetic_at_base_offset():
    parent = make_parent_scan_object("a1")
    obj = SubobjectScanObject(
        parent, SubobjectRoot(base_offset=0x1B60, var_name="a1", parent_type="World")
    )
    expr = make_add_subobject(make_parent_var_expr(0), 0x1B60)
    assert obj.is_target(expr) is True


def test_subobject_scan_object_rejects_other_offsets_no_parent_leak():
    """An access at a different parent offset is NOT the subobject root; the
    shared visitor returns None/False rather than mis-rooting and recording
    the parent-relative offset against the child type."""
    parent = make_parent_scan_object("a1")
    obj = SubobjectScanObject(
        parent, SubobjectRoot(base_offset=0x1B60, var_name="a1", parent_type="World")
    )
    assert obj.is_target(make_memptr_subobject(make_parent_var_expr(0), 0x1B58)) is False
    assert obj.is_target(make_memptr_subobject(make_parent_var_expr(0), 0x1B68)) is False


def test_subobject_scan_object_rejects_other_parent_variable():
    parent = make_parent_scan_object("a1", index=0)
    obj = SubobjectScanObject(parent, SubobjectRoot(base_offset=0x1B60, var_name="a1"))
    other_lvar_expr = make_parent_var_expr(index=3)
    assert obj.is_target(make_memptr_subobject(other_lvar_expr, 0x1B60)) is False


def test_subobject_scan_object_field_offset_is_child_relative():
    """The whole point: a field at parent 0x1B68 (World+0x1B60+0x08) must
    rebase to child offset 0x08, and the scan object's offset arithmetic
    (base + field) lands there — never 0x1B68."""
    # The subobject root captures the base; any field found above the
    # matched node is child-relative by construction.
    child_offset = rebase_to_subobject(0x1B68, BASE_OFFSET)
    assert child_offset == 0x08
    # And the root itself resolves to exactly the subobject base.
    assert BASE_OFFSET + child_offset == 0x1B68  # parent coordinate of the field


# --------------------------------------------------------------------------- #
# visitor-style integration: a real deep-scan visitor rooted at the
# subobject expression must record members in CHILD coordinates
# --------------------------------------------------------------------------- #
import sys
from importlib import import_module
from importlib import util as _util
from pathlib import Path as _Path
from types import ModuleType as _ModuleType
from types import SimpleNamespace as _SimpleNS

import ida_hexrays
import ida_idaapi

if not hasattr(ida_hexrays, "ctree_parentee_t"):
    ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {})
if "ida_idaapi" not in sys.modules:
    sys.modules["ida_idaapi"] = _ModuleType("ida_idaapi")
import ida_idaapi  # noqa: F811
import ida_typeinf

ida_idaapi.BADADDR = -1

hexrays_api = import_module("forge.api.hexrays")
hexrays_api.ctype_to_str = lambda *_a, **_k: ""
hexrays_api.decompile = lambda *_a, **_k: None
hexrays_api.find_expr_address = lambda *_a, **_k: 0
hexrays_api.get_func_argument_info = lambda *_a, **_k: (0, None)
hexrays_api.get_funcs_calling_address = lambda *_a, **_k: set()
hexrays_api.is_code = lambda *_a, **_k: False
hexrays_api.is_legal_type = lambda *_a, **_k: True
hexrays_api.to_hex = lambda value: hex(value)
import_module("forge.api.visitor")


def _load_scanner_module():
    """Load the real visitor+scanner modules as ``forge.api.*`` (test_scanner
    pattern), overriding the conftest's no-op stubs, so a genuine
    ``NewDeepScanVisitor`` walks hand-crafted ctrees."""
    here = _Path(__file__).resolve().parents[2]
    visitor_spec = _util.spec_from_file_location(
        "forge.api.visitor", here / "src" / "forge" / "api" / "visitor.py"
    )
    assert visitor_spec is not None and visitor_spec.loader is not None
    visitor_module = _util.module_from_spec(visitor_spec)
    sys.modules["forge.api.visitor"] = visitor_module
    visitor_spec.loader.exec_module(visitor_module)

    scanner_spec = _util.spec_from_file_location(
        "forge.api.scanner", here / "src" / "forge" / "api" / "scanner.py"
    )
    assert scanner_spec is not None and scanner_spec.loader is not None
    module = _util.module_from_spec(scanner_spec)
    sys.modules["forge.api.scanner"] = module
    scanner_spec.loader.exec_module(module)
    return module


class _ScanT:
    """tinfo double covering the member-creation path (test_scanner pattern)."""

    def __init__(self, name, pointed=None, size=4):
        self._name = name
        self._pointed = pointed
        self._size = size

    def clone(self):
        return _ScanT(self._name, self._pointed, self._size)

    def dstr(self):
        return self._name

    def is_ptr(self):
        return self._pointed is not None

    def get_pointed_object(self):
        return self._pointed

    def get_ptrarr_objsize(self):
        return None if self._pointed is None else self._size

    def is_udt(self):
        return False

    def is_array(self):
        return False

    def is_func(self):
        return False

    def is_funcptr(self):
        return False

    def is_void(self):
        return False

    def is_integral(self):
        return False

    def is_signed(self):
        return False

    def is_float(self):
        return False

    def is_floating(self):
        return False

    def clr_const(self):
        return None

    def equals_to(self, other):
        return isinstance(other, _ScanT) and self.dstr() == other.dstr()

    def get_size(self):
        return self._size


class _ScanNode:
    def __init__(self, op, *, x=None, y=None, m=None, type=None, ea=-1, numval=None, obj_ea=-1, v=None):
        self.op = op
        self.x = x
        self.y = y
        self.m = m
        self.type = type
        self.ea = ea
        self._numval = numval
        self.obj_ea = obj_ea
        self.v = v
        self.a = []

    def numval(self):
        return self._numval

    @property
    def opname(self):
        return f"op{self.op}"


class _ScanParents(list):
    def size(self):
        return len(self)

    def at(self, index):
        return self[index]


def _scan_wrap(node):
    return _SimpleNS(cexpr=node, ea=node.ea, op=node.op)


def _drive_scan_visitor(visitor, nodes):
    """Simulate pre-order visit_expr / post-order leave_expr traversal."""
    parents = []
    visitor.parent_expr = lambda: (parents[-1].cexpr if parents else None)
    for node in nodes:
        visitor.parents = _ScanParents(parents)
        visitor.visit_expr(node)
        parents.append(_scan_wrap(node))
    for node in reversed(nodes):
        parents.pop()
        visitor.parents = _ScanParents(parents)
        visitor.leave_expr(node)


def _subobject_scan_harness(monkeypatch):
    """Load the real scanner and build a World+0x1B60+0x08 ctree.

    Returns ``(scanner_module, _ScanNode, ctype, world_ptr, obj, structure,
    nodes)`` where ``obj`` is a ``SubobjectScanObject`` (parent ``a1`` of
    type ``World *``, base 0x1B60) and ``nodes`` is the pre-order traversal
    of ``a1->m(0x1B60)->field(0x08)``.
    """
    world = _ScanT("World", size=0x40)
    world_ptr = _ScanT("World *", pointed=world, size=8)
    field_i64 = _ScanT("__int64", size=8)

    def walker(cexpr, parents):
        if getattr(cexpr, "ea", -1) != -1:
            return cexpr.ea
        for p in reversed(parents):
            if getattr(p, "ea", -1) != -1:
                return p.ea
        return -1

    class _FakeParentee:
        def __init__(self):
            self.cv_flags = 0

    monkeypatch.setattr(ida_hexrays, "ctree_parentee_t", _FakeParentee, raising=False)
    monkeypatch.setattr(hexrays_api, "find_expr_address", walker, raising=False)
    monkeypatch.setattr(
        hexrays_api,
        "print_expr_address",
        lambda cexpr, parents: hex(getattr(cexpr, "ea", -1)),
        raising=False,
    )
    monkeypatch.setattr(hexrays_api, "is_legal_type", lambda *_a, **_k: True, raising=False)

    class _TypesStub:
        width = 8

        def __getitem__(self, key):
            return _SimpleNS(type=_ScanT(key), ptr=_ScanT(f"{key} *", size=8), name=key)

        @staticmethod
        def convert_to_simple_type(t):
            return t

        @staticmethod
        def get_ptr_tinfo():
            return _ScanT("void *", size=8)

    types_module = sys.modules.get("forge.api.types")
    monkeypatch.setattr(types_module, "types", _TypesStub(), raising=False)
    monkeypatch.setattr(
        ida_typeinf,
        "tinfo_t",
        lambda value=None: value.clone() if isinstance(value, _ScanT) else _ScanT("tmp"),
        raising=False,
    )
    monkeypatch.setattr(
        ida_hexrays, "lvar_locator_t", lambda *_a: _SimpleNS(), raising=False
    )

    scanner_module = _load_scanner_module()
    ctype = scanner_module.ctype
    if not hasattr(ctype, "asg"):
        ctype.asg = 13

    # The parent lvar (a1 : World *).
    lvar = _SimpleNS(type=lambda: world_ptr, name="a1", location="loc", defea=0x1400014F0)
    parent_obj = VariableObject(lvar, 0)
    parent_obj.func_ea = 0x1400014F0
    parent_obj.tinfo = world_ptr

    obj = SubobjectScanObject(
        parent_obj, SubobjectRoot(base_offset=BASE_OFFSET, var_name="a1", parent_type="World")
    )

    from forge.api.structure import Structure

    structure = Structure("World")

    var = _ScanNode(ctype.var, type=world_ptr, v=_SimpleNS(idx=0), ea=0x401010)
    sub = _ScanNode(ctype.memptr, x=var, m=BASE_OFFSET, type=world, ea=0x401014)
    field = _ScanNode(ctype.memptr, x=sub, m=FIELD_OFFSET, type=field_i64, ea=0x401018)
    # Enclosing statement/call so the member-access parent is not the lone
    # root of the expression (the visitor's parent context needs >=2 levels).
    call = _ScanNode(ctype.call, x=_ScanNode(ctype.obj, obj_ea=0x1400019B0), type=field_i64, ea=0x401020)
    nodes = [call, field, sub, var]

    cfunc = _SimpleNS(entry_ea=0x1400014F0, argidx=(), body=_SimpleNS())
    visitor = scanner_module.NewDeepScanVisitor(
        cfunc, BASE_OFFSET, obj, structure, recurse_calls=True,
        skip_until_object=False,
    )
    return scanner_module, _ScanNode, ctype, world_ptr, obj, structure, nodes, visitor


def test_visitor_records_child_relative_field_offset_via_subobject_root(monkeypatch):
    """Visitor-style integration: a real NewDeepScanVisitor rooted at the
    subobject expression ``a1->m(0x1B60)->field`` must record the field under
    the CHILD (World) in child coordinates — offset 0x08, never the
    parent-relative 0x1B68."""
    _scanner_module, _ScanNode, _ctype, _world_ptr, _obj, structure, nodes, visitor = (
        _subobject_scan_harness(monkeypatch)
    )
    _drive_scan_visitor(visitor, nodes)

    offsets = sorted(m.offset for m in structure.members)
    assert offsets == [FIELD_OFFSET], (
        f"expected child-relative offset {hex(FIELD_OFFSET)}, "
        f"got {[hex(o) for o in offsets]}"
    )
    assert PARENT_RELATIVE_FIELD not in offsets
    # Scan-site provenance: the member carries the scan-root base offset
    # (subobject origin) and lands at the child-relative offset.
    assert structure.members, "expected a child member to be recorded"
    member = structure.members[0]
    assert member.offset == FIELD_OFFSET
    for scan_obj in getattr(member, "scanned_variables", None) or ():
        assert scan_obj.origin == 0x1B60

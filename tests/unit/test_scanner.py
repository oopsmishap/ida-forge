from __future__ import annotations

from importlib import import_module, util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import ida_hexrays
import pytest

if not hasattr(ida_hexrays, "ctree_parentee_t"):
    ida_hexrays.ctree_parentee_t = type("ctree_parentee_t", (), {})

import sys

if "ida_idaapi" not in sys.modules:
    sys.modules["ida_idaapi"] = ModuleType("ida_idaapi")
import ida_idaapi

ida_idaapi.BADADDR = -1

hexrays_api = import_module("forge.api.hexrays")
hexrays_api.ctype_to_str = lambda *_args, **_kwargs: ""
hexrays_api.decompile = lambda *_args, **_kwargs: None
hexrays_api.find_expr_address = lambda *_args, **_kwargs: 0
hexrays_api.get_func_argument_info = lambda *_args, **_kwargs: (0, None)
hexrays_api.get_funcs_calling_address = lambda *_args, **_kwargs: set()
hexrays_api.is_code = lambda *_args, **_kwargs: False
hexrays_api.is_legal_type = lambda *_args, **_kwargs: True
hexrays_api.to_hex = lambda value: hex(value)
import_module("forge.api.visitor")


def _load_scanner_module():
    visitor_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "visitor.py"
    visitor_spec = util.spec_from_file_location("forge.api.visitor", visitor_path)
    assert visitor_spec is not None and visitor_spec.loader is not None
    visitor_module = util.module_from_spec(visitor_spec)
    sys.modules["forge.api.visitor"] = visitor_module
    visitor_spec.loader.exec_module(visitor_module)

    scanner_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "scanner.py"
    spec = util.spec_from_file_location("forge.api.scanner", scanner_path)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    sys.modules["forge.api.scanner"] = module
    spec.loader.exec_module(module)
    return module


class FakeType:
    def __init__(self, name: str, *, ptr: bool = False, udt: bool = False):
        self._name = name
        self._ptr = ptr
        self._udt = udt

    def dstr(self):
        return self._name

    def is_ptr(self):
        return self._ptr

    def get_pointed_object(self):
        return FakeType(self._name[: -2] if self._ptr else self._name)

    def is_udt(self):
        return self._udt


@pytest.mark.parametrize(
    "obj_tinfo, call_tinfo, expected_name",
    [
        # A complete scalar member type (e.g. __int64 from a cast/ptr node in a
        # typed function) must survive: clobbering it with the root struct
        # type made every typed-scan member come back as the struct itself.
        (FakeType("FixtureScene *", ptr=True), FakeType("__int64"), "__int64"),
        (FakeType("FixtureScene", udt=True), FakeType("__int64"), "__int64"),
        # Unknown member types fall back to the object's structure-like type.
        (FakeType("FixtureScene", udt=True), FakeType("?"), "FixtureScene"),
        (FakeType("FixtureScene *", ptr=True), FakeType("?"), "FixtureScene *"),
        # Structure-like member types always win over the object's.
        (FakeType("FixtureScene *", ptr=True), FakeType("Other *", ptr=True), "Other *"),
        # No object type -> passthrough.
        (None, FakeType("__int64"), "__int64"),
    ],
)
def test_prefer_object_tinfo_only_falls_back_to_object_type_for_unknown_members(
    obj_tinfo, call_tinfo, expected_name
):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    obj = SimpleNamespace(tinfo=obj_tinfo)

    preferred = visitor._prefer_object_tinfo(obj, call_tinfo)

    assert preferred.dstr() == expected_name


def test_parse_left_assignee_handles_cast_pointer_assignment():
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=2, add=3, num=4, asg=5, var=6)

    leaf = SimpleNamespace(op=scanner_module.ctype.var)
    cast = SimpleNamespace(op=scanner_module.ctype.cast, x=leaf)
    ptr = SimpleNamespace(op=scanner_module.ctype.ptr, x=cast)

    parsed = visitor._parse_left_assignee(ptr, 0)

    assert parsed is not None
    base, offset = parsed
    assert base is leaf
    assert offset == 0

def test_parse_left_assignee_scales_nested_index_offsets():
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=2, add=3, num=4, asg=5, var=6)

    leaf = SimpleNamespace(op=scanner_module.ctype.var)
    idx = SimpleNamespace(
        op=scanner_module.ctype.idx,
        x=leaf,
        y=SimpleNamespace(op=scanner_module.ctype.num, numval=lambda: 2),
    )
    cast = SimpleNamespace(op=scanner_module.ctype.cast, x=idx)
    ptr = SimpleNamespace(
        op=scanner_module.ctype.ptr,
        x=cast,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )

    parsed = visitor._parse_left_assignee(ptr, 0)

    assert parsed is not None
    base, offset = parsed
    assert base is leaf
    assert offset == 16


def test_scanned_structure_member_applies_type_via_udt(monkeypatch):
    """F.1: ScannedStructureMemberObject.apply_type finds the udt member
    by struct_offset, sets its type and commits via set_udt_details."""
    import ida_typeinf

    scanner_module = _load_scanner_module()
    calls = []

    class _FakeStructTinfo:
        def __init__(self, *a, **k):
            pass

        def get_named_type(self, til, name):
            calls.append(("get_named_type", name))
            return True

        def is_udt(self):
            return True

        def get_udt_details(self, udt):
            calls.append(("details",))
            udt.extend(
                [
                    SimpleNamespace(
                        offset=8,
                        name="member_8",
                        set_type=lambda t: calls.append(("set_type", t.dstr())),
                    )
                ]
            )
            return True

        def set_udt_details(self, udt):
            calls.append(("set_udt_details",))
            return True

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeStructTinfo, raising=False)

    obj = scanner_module.ScannedStructureMemberObject(
        "World", 8, "member_8", 0x401000, 0
    )
    obj.apply_type(FakeType("u32"))

    assert ("get_named_type", "World") in calls
    assert ("set_type", "u32") in calls
    assert ("set_udt_details",) in calls


def test_scanned_structure_member_not_applicable_skips(monkeypatch):
    """F.1: the _applicable guard keeps failed-scan remnants inert."""
    import ida_typeinf

    scanner_module = _load_scanner_module()
    monkeypatch.setattr(
        ida_typeinf,
        "tinfo_t",
        lambda *a, **k: SimpleNamespace(
            get_named_type=lambda til, name: (_ for _ in ()).throw(
                AssertionError("must not load the struct for a !applicable obj")
            ),
            get_udt_details=lambda udt: False,
            set_udt_details=lambda udt: False,
        ),
        raising=False,
    )

    obj = scanner_module.ScannedStructureMemberObject(
        "World", 8, "member_8", 0x401000, 0, applicable=False
    )
    obj.apply_type(FakeType("u32"))  # must not raise / must not touch IDB


def test_scanned_structure_member_apply_skips_missing_offset(monkeypatch):
    """F.1: an offset that is not a udt member applies nothing — no crash."""
    import ida_typeinf

    scanner_module = _load_scanner_module()

    class _FakeStructTinfo:
        def __init__(self, *a, **k):
            pass

        def get_named_type(self, til, name):
            return True

        def is_udt(self):
            return True

        def get_udt_details(self, udt):
            return True  # empty udt

        def set_udt_details(self, udt):
            return True

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeStructTinfo, raising=False)

    obj = scanner_module.ScannedStructureMemberObject(
        "World", 8, "member_8", 0x401000, 0
    )
    obj.apply_type(FakeType("u32"))  # must not raise


def test_scanned_structure_member_integral_pointee_skips_silently(monkeypatch):
    """F.1/R3.7: integral pointees (_DWORD casts) carry no udt — the apply
    skips at debug level instead of warning that the "structure" is not a
    known type (IDA's til has no _DWORD named type; it's cast syntax)."""
    import ida_typeinf

    scanner_module = _load_scanner_module()

    def _fail_load(*a, **k):
        raise AssertionError("integral pointee must not load a struct")

    monkeypatch.setattr(
        ida_typeinf,
        "tinfo_t",
        lambda *a, **k: SimpleNamespace(
            get_named_type=lambda til, name: False,
            is_udt=_fail_load,
            get_udt_details=_fail_load,
            set_udt_details=_fail_load,
        ),
        raising=False,
    )

    for name in ("_DWORD", "_QWORD", "unsigned __int32"):
        obj = scanner_module.ScannedStructureMemberObject(
            name, 4, "member_4", 0x401000, 0
        )
        obj.apply_type(FakeType("u32"))  # must not raise, no IDB touch


def test_scanned_structure_member_named_scalar_skips(monkeypatch):
    """R3.7: a named type that exists but is not a struct/union applies
    nothing (scalar typedef pointees) — debug-level skip, no warning."""
    import ida_typeinf

    scanner_module = _load_scanner_module()

    class _FakeScalarTinfo:
        def get_named_type(self, til, name):
            return name == "MyDword"

        def is_udt(self):
            return False

        def get_udt_details(self, udt):
            raise AssertionError("scalar pointee must not read udt details")

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeScalarTinfo, raising=False)

    obj = scanner_module.ScannedStructureMemberObject(
        "MyDword", 4, "member_4", 0x401000, 0
    )
    obj.apply_type(FakeType("u32"))  # must not raise


def _make_variable_object(scanner_module, lvar, **kwargs):
    """Build a ScannedVariableObject with a stub env suitable for apply_type."""

    class FakeLocator:
        def __init__(self, location, defea):
            self.location = location
            self.defea = defea

    class FakeSavedInfo:
        def __init__(self):
            self.ll = None
            self.type = None

    scanner_module.ida_hexrays.lvar_locator_t = lambda location, defea: FakeLocator(
        location, defea
    )
    scanner_module.ida_hexrays.lvar_saved_info_t = FakeSavedInfo
    scanner_module.ida_hexrays.MLI_TYPE = 0x10
    scanner_module.ida_funcs.get_func = lambda ea: SimpleNamespace(start_ea=0x401000)
    return scanner_module.ScannedVariableObject(lvar, "a1", 0x401000, 0, **kwargs)


def test_scanned_variable_apply_type_uses_modify_user_lvar_info(monkeypatch):
    """apply_type commits the type headless via modify_user_lvar_info.

    Regression: the old GUI path (open_pseudocode + vdui_t.set_lvar_type)
    crashes native in idalib workers; the headless path must be used.
    """
    scanner_module = _load_scanner_module()
    obj = _make_variable_object(
        scanner_module, SimpleNamespace(location=7, defea=0x401010)
    )

    seen = {}

    def fake_modify(ea, flags, lvi):
        seen["ea"] = ea
        seen["flags"] = flags
        seen["ll_location"] = lvi.ll.location
        seen["ll_defea"] = lvi.ll.defea
        seen["type"] = lvi.type

    monkeypatch.setattr(
        scanner_module.ida_hexrays, "modify_user_lvar_info", fake_modify, raising=False
    )
    scanner_module.decompile = lambda ea: SimpleNamespace(
        entry_ea=0x401000,
        get_lvars=lambda: [SimpleNamespace(location=7, defea=0x401010)],
    )

    captured_type = object()
    obj.apply_type(captured_type)

    assert seen["ea"] == 0x401000
    assert seen["flags"] == 0x10
    assert seen["ll_location"] == 7
    assert seen["ll_defea"] == 0x401010
    assert seen["type"] is captured_type


def test_scanned_variable_apply_type_skips_when_lvar_missing(monkeypatch):
    """A scanned variable that no longer matches any lvar is skipped safely."""
    scanner_module = _load_scanner_module()
    obj = _make_variable_object(
        scanner_module, SimpleNamespace(location=7, defea=0x401010)
    )

    calls = []

    def fake_modify(ea, flags, lvi):
        calls.append(ea)

    monkeypatch.setattr(
        scanner_module.ida_hexrays, "modify_user_lvar_info", fake_modify, raising=False
    )
    scanner_module.decompile = lambda ea: SimpleNamespace(
        entry_ea=0x401000,
        get_lvars=lambda: [SimpleNamespace(location=99, defea=0x401020)],
    )

    # Must not raise, and must not commit a type against the wrong variable.
    obj.apply_type(object())
    assert calls == []


def test_scanned_variable_apply_type_respects_applicable(monkeypatch):
    """Inapplicable scan objects never re-decompile or commit."""
    scanner_module = _load_scanner_module()
    obj = _make_variable_object(
        scanner_module,
        SimpleNamespace(location=7, defea=0x401010),
        applicable=False,
    )

    def failure(_ea):
        raise AssertionError("decompile must not run for inapplicable objects")

    scanner_module.decompile = failure
    obj.apply_type(object())




def test_extract_member_from_ptr_uses_raw_add_offsets(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=3, add=4, num=5, var=6)

    captured = {}

    def fake_extract_member(cexpr, obj, offset, context):
        captured["cexpr"] = cexpr
        captured["offset"] = offset
        return "member"

    leaf = SimpleNamespace(
        op=scanner_module.ctype.var,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: -1),
    )
    add_expr = SimpleNamespace(
        op=scanner_module.ctype.add,
        x=leaf,
        y=SimpleNamespace(op=scanner_module.ctype.num, numval=lambda: 24),
    )

    visitor._extract_member = fake_extract_member
    visitor._get_parent_context = lambda: scanner_module.ParentExpressionContext([add_expr])
    visitor.parent_expr = lambda: add_expr

    result = visitor._extract_member_from_ptr(leaf, SimpleNamespace(name="v2"))

    assert result == "member"
    assert captured["cexpr"] is add_expr
    assert captured["offset"] == 24


def test_extract_member_from_ptr_scales_index_offsets_only(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=3, add=4, num=5, var=6)

    captured = {}

    def fake_extract_member(cexpr, obj, offset, context):
        captured["cexpr"] = cexpr
        captured["offset"] = offset
        return "member"

    leaf = SimpleNamespace(
        op=scanner_module.ctype.var,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )
    idx_expr = SimpleNamespace(
        op=scanner_module.ctype.idx,
        x=leaf,
        y=SimpleNamespace(op=scanner_module.ctype.num, numval=lambda: 2),
    )

    visitor._extract_member = fake_extract_member
    visitor._get_parent_context = lambda: scanner_module.ParentExpressionContext([idx_expr])
    visitor.parent_expr = lambda: idx_expr

    result = visitor._extract_member_from_ptr(leaf, SimpleNamespace(name="v2"))

    assert result == "member"
    assert captured["cexpr"] is idx_expr
    assert captured["offset"] == 16


def test_extract_member_from_ptr_uses_raw_cast_add_offsets(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=3, add=4, num=5, var=6)

    captured = {}

    def fake_extract_member(cexpr, obj, offset, context):
        captured["cexpr"] = cexpr
        captured["offset"] = offset
        return "member"

    leaf = SimpleNamespace(op=scanner_module.ctype.var)
    cast_expr = SimpleNamespace(
        op=scanner_module.ctype.cast,
        x=leaf,
        type=SimpleNamespace(is_ptr=lambda: True, get_ptrarr_objsize=lambda: -1),
    )
    num_expr = SimpleNamespace(op=scanner_module.ctype.num, numval=lambda: 24)
    add_expr = SimpleNamespace(
        op=scanner_module.ctype.add,
        x=cast_expr,
        y=num_expr,
        theother=lambda other: num_expr if other is cast_expr else cast_expr,
    )

    visitor._extract_member = fake_extract_member
    visitor._get_parent_context = lambda: scanner_module.ParentExpressionContext([cast_expr, add_expr])

    result = visitor._extract_member_from_ptr(leaf, SimpleNamespace(name="v2"))

    assert result == "member"
    assert captured["cexpr"] is add_expr
    assert captured["offset"] == 24

def test_extract_member_recognizes_cast_pointer_assignment_on_left_hand_side():
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=2, add=3, num=4, asg=5, var=6)

    captured = {}

    def fake_get_member(offset, cexpr, obj, tinfo, obj_ea=None):
        captured["offset"] = offset
        captured["tinfo"] = tinfo
        captured["obj_ea"] = obj_ea
        return "member"

    visitor._get_member = fake_get_member
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()
    visitor._deref_tinfo = lambda tinfo: tinfo
    visitor._parse_call = lambda *_args, **_kwargs: None
    visitor._extract_obj_ea = lambda *_args, **_kwargs: None

    leaf = SimpleNamespace(op=scanner_module.ctype.var, type=SimpleNamespace(dstr=lambda: "void *"))
    cast = SimpleNamespace(op=scanner_module.ctype.cast, x=leaf, type=SimpleNamespace(dstr=lambda: "u64 *"))
    ptr = SimpleNamespace(op=scanner_module.ctype.ptr, x=cast, type=SimpleNamespace(dstr=lambda: "u64 **"))
    asg = SimpleNamespace(op=scanner_module.ctype.asg, x=ptr, y=SimpleNamespace(op=scanner_module.ctype.num))

    context = scanner_module.ParentExpressionContext([asg])
    result = visitor._extract_member(leaf, SimpleNamespace(name="v2"), 0, context)

    assert result == "member"
    assert captured["offset"] == 0
    assert captured["tinfo"].dstr() == "u64 **"


def test_extract_member_passes_assignment_source_object_address():
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(
        cast=1,
        ref=2,
        ptr=3,
        idx=3,
        add=4,
        num=5,
        asg=6,
        var=7,
        obj=8,
    )

    captured = {}

    def fake_get_member(offset, cexpr, obj, tinfo, obj_ea=None):
        captured["offset"] = offset
        captured["tinfo"] = tinfo
        captured["obj_ea"] = obj_ea
        return "member"

    visitor._get_member = fake_get_member

    leaf = SimpleNamespace(
        op=scanner_module.ctype.var,
        type=SimpleNamespace(dstr=lambda: "void *"),
    )
    cast = SimpleNamespace(
        op=scanner_module.ctype.cast,
        x=leaf,
        type=SimpleNamespace(dstr=lambda: "u64 *"),
    )
    ptr = SimpleNamespace(
        op=scanner_module.ctype.ptr,
        x=cast,
        type=SimpleNamespace(dstr=lambda: "u64 **"),
    )
    vtable_obj = SimpleNamespace(op=scanner_module.ctype.obj, obj_ea=0x5000)
    ref = SimpleNamespace(op=scanner_module.ctype.ref, x=vtable_obj)
    rhs_cast = SimpleNamespace(op=scanner_module.ctype.cast, x=ref)
    asg = SimpleNamespace(op=scanner_module.ctype.asg, x=ptr, y=rhs_cast)

    context = scanner_module.ParentExpressionContext([cast, ptr, asg])
    result = visitor._extract_member(leaf, SimpleNamespace(name="this"), 0, context)

    assert result == "member"
    assert captured["offset"] == 0
    assert captured["tinfo"] is ptr.type
    assert captured["obj_ea"] == 0x5000


def test_get_member_creates_virtual_table_from_assignment_source(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)

    class FakeVirtualTable:
        def __init__(self, offset, address, scanned_variable=None, origin=None):
            self.offset = offset
            self.address = address
            self.scanned_variable = scanned_variable
            self.origin = origin

        @staticmethod
        def is_virtual_table(address):
            return 3 if address == 0x5000 else 0

    import forge.api.members as members_module
    monkeypatch.setattr(members_module, "VirtualTable", FakeVirtualTable, raising=False)
    monkeypatch.setattr(
        scanner_module.ScannedObject,
        "create",
        lambda obj, ea, origin, applicable: SimpleNamespace(
            obj=obj,
            ea=ea,
            origin=origin,
            applicable=applicable,
        ),
    )

    visitor._origin = 0x10
    visitor.parents = []
    visitor.crippled = False
    visitor._callee_base_offset = 0
    obj = SimpleNamespace(id=scanner_module.ObjectType.local_variable, name="this")

    member = visitor._get_member(0, SimpleNamespace(ea=0x401234), obj, None, 0x5000)

    assert isinstance(member, FakeVirtualTable)
    assert member.offset == 0
    assert member.address == 0x5000
    assert member.origin == 0x10


def test_get_member_applies_callee_base_offset(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)

    class FakeVirtualTable:
        def __init__(self, offset, address, scanned_variable=None, origin=None):
            self.offset = offset
            self.address = address
            self.scanned_variable = scanned_variable

        @staticmethod
        def is_virtual_table(address):
            return 3 if address == 0x5000 else 0

    import forge.api.members as members_module
    monkeypatch.setattr(members_module, "VirtualTable", FakeVirtualTable, raising=False)
    monkeypatch.setattr(
        scanner_module.ScannedObject,
        "create",
        lambda obj, ea, origin, applicable: SimpleNamespace(
            obj=obj, ea=ea, origin=origin, applicable=applicable,
        ),
    )

    visitor._origin = 0x10
    visitor.parents = []
    visitor.crippled = False
    visitor._callee_base_offset = 8
    obj = SimpleNamespace(id=scanner_module.ObjectType.local_variable, name="this")

    member = visitor._get_member(0, SimpleNamespace(ea=0x401234), obj, None, 0x5000)

    assert isinstance(member, FakeVirtualTable)
    assert member.offset == 8
    assert member.scanned_variable.applicable is False


def test_get_member_discards_negative_offset():
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)

    visitor.parents = []
    visitor._origin = 0x10
    visitor.crippled = False
    visitor._callee_base_offset = 0

    result = visitor._get_member(-32, SimpleNamespace(ea=0x1000), SimpleNamespace(id=scanner_module.ObjectType.local_variable, name="a1"), None)

    assert result is None


def test_manipulate_prefers_pointer_context_even_without_pointer_tinfo(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(ptr=1, idx=2, add=3, asg=4)

    monkeypatch.setattr(scanner_module.ObjectVisitor, "_manipulate", lambda self, cexpr, obj: None)

    ptr_calls = []
    expr_calls = []
    structure_adds = []
    visitor._structure = SimpleNamespace(add_member=lambda member: structure_adds.append(member))
    visitor._extract_member_from_ptr = lambda cexpr, obj: ptr_calls.append((cexpr, obj)) or "member"
    visitor._extract_member_from_expr = lambda cexpr, obj: expr_calls.append((cexpr, obj)) or "expr"
    visitor._get_parent_context = lambda: scanner_module.ParentExpressionContext(
        [SimpleNamespace(op=scanner_module.ctype.ptr), SimpleNamespace(op=scanner_module.ctype.asg)]
    )

    cexpr = SimpleNamespace(type=SimpleNamespace(is_ptr=lambda: False), dstr=lambda: "v2")
    obj = SimpleNamespace(tinfo=SimpleNamespace(dstr=lambda: "void *"), name="v2")

    visitor._manipulate(cexpr, obj)

    assert len(ptr_calls) == 1
    assert expr_calls == []
    assert structure_adds == ["member"]


def test_manipulate_falls_back_to_expr_when_no_pointer_context(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(ptr=1, idx=2, add=3, asg=4)

    monkeypatch.setattr(scanner_module.ObjectVisitor, "_manipulate", lambda self, cexpr, obj: None)

    ptr_calls = []
    expr_calls = []
    structure_adds = []
    visitor._structure = SimpleNamespace(add_member=lambda member: structure_adds.append(member))
    visitor._extract_member_from_ptr = lambda cexpr, obj: ptr_calls.append((cexpr, obj)) or None
    visitor._extract_member_from_expr = lambda cexpr, obj: expr_calls.append((cexpr, obj)) or "expr"
    visitor._get_parent_context = lambda: scanner_module.ParentExpressionContext([SimpleNamespace(op=1234)])

    cexpr = SimpleNamespace(type=SimpleNamespace(is_ptr=lambda: False), dstr=lambda: "v2")
    obj = SimpleNamespace(tinfo=SimpleNamespace(dstr=lambda: "void *"), name="v2")

    visitor._manipulate(cexpr, obj)

    assert ptr_calls == []
    assert len(expr_calls) == 1
    assert structure_adds == ["expr"]

def test_manipulate_handles_missing_object_tinfo(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(ptr=1, idx=2, add=3, asg=4)

    monkeypatch.setattr(scanner_module.ObjectVisitor, "_manipulate", lambda self, cexpr, obj: None)

    ptr_calls = []
    expr_calls = []
    structure_adds = []
    visitor._structure = SimpleNamespace(add_member=lambda member: structure_adds.append(member))
    visitor._extract_member_from_ptr = lambda cexpr, obj: ptr_calls.append((cexpr, obj)) or "member"
    visitor._extract_member_from_expr = lambda cexpr, obj: expr_calls.append((cexpr, obj)) or "expr"
    visitor._get_parent_context = lambda: scanner_module.ParentExpressionContext(
        [SimpleNamespace(op=scanner_module.ctype.ptr), SimpleNamespace(op=scanner_module.ctype.asg)]
    )

    cexpr = SimpleNamespace(type=SimpleNamespace(is_ptr=lambda: False), dstr=lambda: "v2")
    obj = SimpleNamespace(name="v2", tinfo=None)

    visitor._manipulate(cexpr, obj)

    assert len(ptr_calls) == 1
    assert expr_calls == []
    assert structure_adds == ["member"]



def test_scanned_object_create_inherits_scan_root_metadata(monkeypatch):
    scanner_module = _load_scanner_module()
    scan_object_module = import_module("forge.api.scan_object")
    import ida_funcs

    monkeypatch.setattr(ida_funcs, "get_func", lambda _ea: SimpleNamespace(start_ea=0x401000), raising=False)

    source = SimpleNamespace(
        id=scan_object_module.ObjectType.global_object,
        object_ea=0x5000,
        name="g_root",
        scan_root_function_ea=0x401000,
        scan_root_ea=0x401234,
        scan_root_function_name="sub_401000",
    )

    scanned = scanner_module.ScannedObject.create(source, 0x401234, 0x0)

    assert scanned.scan_root_function_ea == 0x401000
    assert scanned.scan_root_ea == 0x401234
    assert scanned.scan_root_function_name == "sub_401000"

def test_scanned_object_create_rejects_unknown_object_type(monkeypatch):
    """The legacy migration shim is gone: an object with an unknown id must
    fail loudly instead of guessing a ScannedObject kind."""
    scanner_module = _load_scanner_module()

    from forge.api.scan_object import ObjectType

    bogus = SimpleNamespace(id=ObjectType.unknown, name="?", ea=0x402000)

    with pytest.raises(AssertionError):
        scanner_module.ScannedObject.create(bogus, 0x402000, 0x10)


def test_scanned_object_identity_dedupes_duplicate_evidence(monkeypatch):
    scanner_module = _load_scanner_module()
    monkeypatch.setattr(
        scanner_module.ida_funcs,
        "get_func",
        lambda _ea: SimpleNamespace(start_ea=0x401000),
        raising=False,
    )

    left = scanner_module.ScannedGlobalObject(0x5000, "g_data", 0x401234, 0x20)
    right = scanner_module.ScannedGlobalObject(0x5000, "g_data", 0x401234, 0x20)
    legacy = SimpleNamespace(
        func_ea=0x401000,
        ea=0x401234,
        id=None,
        name="g_data",
    )

    assert left == right
    assert left == legacy
    assert len({left, right}) == 1


def test_extract_member_uses_argument_expression_type_without_warning(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=2, add=3, num=4, asg=5, var=6, call=7)

    captured = {}

    def fake_get_member(offset, cexpr, obj, tinfo, obj_ea=None):
        captured["offset"] = offset
        captured["tinfo"] = tinfo
        captured["obj_ea"] = obj_ea
        return "member"

    def fake_warning(message=None, display_messagebox=False):
        captured["warning"] = message
        captured["display_messagebox"] = display_messagebox

    visitor._get_member = fake_get_member
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()
    visitor._deref_tinfo = lambda tinfo: tinfo
    monkeypatch.setattr(scanner_module, "log_warning", fake_warning)
    monkeypatch.setattr(scanner_module, "get_func_argument_info", lambda *_args, **_kwargs: (0, None))

    class _FakeTypes:
        def get_ptr_tinfo(self):
            return SimpleNamespace(dstr=lambda: "void *")

        def __getitem__(self, key):
            return SimpleNamespace(type=SimpleNamespace(dstr=lambda: key), ptr=SimpleNamespace(dstr=lambda: f"{key} *"))

    monkeypatch.setattr(scanner_module, "types", _FakeTypes())

    leaf = SimpleNamespace(op=scanner_module.ctype.var, type=SimpleNamespace(dstr=lambda: "void *"))
    first_expr = SimpleNamespace(op=scanner_module.ctype.ptr, x=leaf, type=SimpleNamespace(dstr=lambda: "void **"))
    second_expr = SimpleNamespace(
        op=scanner_module.ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[leaf],
        ea=0x401234,
        dstr=lambda: "callee(arg)",
        type=SimpleNamespace(dstr=lambda: "__int64"),
    )
    context = scanner_module.ParentExpressionContext([first_expr, second_expr])

    result = visitor._extract_member(leaf, SimpleNamespace(name="v2"), 0, context)

    assert result == "member"
    assert captured["offset"] == 0
    assert captured["tinfo"] is first_expr.type
    assert "warning" not in captured

def test_extract_member_does_not_double_count_pointer_assignment_offset(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    monkeypatch.setattr(
        scanner_module,
        "ctype",
        SimpleNamespace(cast=1, ptr=2, idx=3, add=4, num=5, asg=6, var=7, obj=8, ref=9),
    )

    captured = {}

    def fake_get_member(offset, cexpr, obj, tinfo, obj_ea=None):
        captured["offset"] = offset
        captured["obj_ea"] = obj_ea
        return "member"

    visitor._get_member = fake_get_member
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()

    a1_var = SimpleNamespace(op=scanner_module.ctype.var, name="a1")
    offset_num = SimpleNamespace(op=scanner_module.ctype.num, numval=lambda: 0x38)
    add_node = SimpleNamespace(op=scanner_module.ctype.add, x=a1_var, y=offset_num)
    lhs = SimpleNamespace(op=scanner_module.ctype.ptr, x=add_node, type=SimpleNamespace(dstr=lambda: "void *"))
    rhs = SimpleNamespace(op=scanner_module.ctype.obj, obj_ea=0x5000)
    asg_node = SimpleNamespace(op=scanner_module.ctype.asg, x=lhs, y=rhs)
    ptr_parent = SimpleNamespace(op=scanner_module.ctype.ptr, x=add_node)
    context = scanner_module.ParentExpressionContext([ptr_parent, asg_node])

    result = visitor._extract_member(a1_var, SimpleNamespace(name="a1"), 0x38, context)

    assert result == "member"
    assert captured["offset"] == 0x38
    assert captured["obj_ea"] == 0x5000




def test_extract_member_prefers_explicit_cast_type_for_call_arguments(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=2, add=3, num=4, asg=5, var=6, call=7)

    captured = {}

    def fake_get_member(offset, cexpr, obj, tinfo, obj_ea=None):
        captured["offset"] = offset
        captured["tinfo"] = tinfo
        return "member"

    def forbidden_parse_call(*_args, **_kwargs):
        raise AssertionError("parse_call should not run when an explicit cast is present")

    visitor._get_member = fake_get_member
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()
    visitor._deref_tinfo = lambda tinfo: SimpleNamespace(dstr=lambda: "u64") if getattr(tinfo, "dstr", lambda: "")() == "u64 *" else tinfo
    visitor._parse_call = forbidden_parse_call
    monkeypatch.setattr(scanner_module, "get_func_argument_info", lambda *_args, **_kwargs: (0, None))

    leaf = SimpleNamespace(op=scanner_module.ctype.var, type=SimpleNamespace(dstr=lambda: "void *"))
    cast_expr = SimpleNamespace(op=scanner_module.ctype.cast, x=leaf, type=SimpleNamespace(dstr=lambda: "u64 *"))
    ptr_expr = SimpleNamespace(op=scanner_module.ctype.ptr, x=cast_expr, type=SimpleNamespace(dstr=lambda: "u64 **"))
    call_expr = SimpleNamespace(
        op=scanner_module.ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[leaf],
        ea=0x401234,
        dstr=lambda: "callee(arg)",
        type=SimpleNamespace(dstr=lambda: "__int64"),
    )
    context = scanner_module.ParentExpressionContext([cast_expr, ptr_expr, call_expr])

    result = visitor._extract_member(leaf, SimpleNamespace(name="v2"), 8, context)

    assert result == "member"
    assert captured["offset"] == 8
    assert captured["tinfo"].dstr() == "u64"

def test_extract_member_falls_back_to_char_for_direct_call_context(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=2, add=3, num=4, asg=5, var=6, call=7)

    captured = {}

    def fake_get_member(offset, cexpr, obj, tinfo, obj_ea=None):
        captured["tinfo"] = tinfo
        return "member"

    def fake_warning(message=None, display_messagebox=False):
        captured["warning"] = message
        captured["display_messagebox"] = display_messagebox

    visitor._get_member = fake_get_member
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()
    visitor._deref_tinfo = lambda tinfo: tinfo
    monkeypatch.setattr(scanner_module, "log_warning", fake_warning)
    monkeypatch.setattr(scanner_module, "get_func_argument_info", lambda *_args, **_kwargs: (0, None))

    class _FakeTypes:
        def get_ptr_tinfo(self):
            return SimpleNamespace(dstr=lambda: "void *")

        def __getitem__(self, key):
            return SimpleNamespace(type=SimpleNamespace(dstr=lambda: key), ptr=SimpleNamespace(dstr=lambda: f"{key} *"))

    monkeypatch.setattr(scanner_module, "types", _FakeTypes())

    unknown_type = SimpleNamespace(dstr=lambda: "?", get_size=lambda: scanner_module.ida_typeinf.BADSIZE)
    leaf = SimpleNamespace(
        op=scanner_module.ctype.var,
        type=unknown_type,
        dstr=lambda: "leaf",
    )
    call_expr = SimpleNamespace(
        op=scanner_module.ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[leaf],
        ea=0x401234,
        dstr=lambda: "callee(arg)",
        type=SimpleNamespace(dstr=lambda: "__int64"),
    )
    context = scanner_module.ParentExpressionContext([call_expr])

    result = visitor._extract_member(leaf, SimpleNamespace(name="v2"), 0, context)

    assert result == "member"
    assert captured["tinfo"].dstr() == "char"
    assert captured["warning"] == "Argument 0 at 0x401234 has incomplete upstream type info; falling back to char"
    assert captured["display_messagebox"] is False


def test_extract_member_uses_pointer_fallback_for_call_context(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    scanner_module.ctype = SimpleNamespace(cast=1, ptr=2, idx=2, add=3, num=4, asg=5, var=6, call=7)

    captured = {}

    def fake_get_member(offset, cexpr, obj, tinfo, obj_ea=None):
        captured["tinfo"] = tinfo
        return "member"

    def fake_warning(message=None, display_messagebox=False):
        captured["warning"] = message
        captured["display_messagebox"] = display_messagebox

    visitor._get_member = fake_get_member
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()
    visitor._deref_tinfo = lambda tinfo: tinfo
    monkeypatch.setattr(scanner_module, "log_warning", fake_warning)
    monkeypatch.setattr(scanner_module, "get_func_argument_info", lambda *_args, **_kwargs: (0, None))

    class _FakeTypes:
        def get_ptr_tinfo(self):
            return SimpleNamespace(dstr=lambda: "void *")

        def __getitem__(self, key):
            return SimpleNamespace(type=SimpleNamespace(dstr=lambda: key), ptr=SimpleNamespace(dstr=lambda: f"{key} *"))

    monkeypatch.setattr(scanner_module, "types", _FakeTypes())

    unknown_type = SimpleNamespace(dstr=lambda: "?", get_size=lambda: scanner_module.ida_typeinf.BADSIZE)
    leaf = SimpleNamespace(op=scanner_module.ctype.var, type=SimpleNamespace(dstr=lambda: "void *"))
    ptr_expr = SimpleNamespace(op=scanner_module.ctype.ptr, x=leaf, type=unknown_type)
    call_expr = SimpleNamespace(
        op=scanner_module.ctype.call,
        x=SimpleNamespace(obj_ea=0x5000),
        a=[leaf],
        ea=0x401234,
        dstr=lambda: "callee(arg)",
        type=SimpleNamespace(dstr=lambda: "__int64"),
    )
    context = scanner_module.ParentExpressionContext([ptr_expr, call_expr])

    result = visitor._extract_member(leaf, SimpleNamespace(name="v2"), 0, context)

    assert result == "member"
    assert captured["tinfo"].dstr() == "u8 *"
    assert captured["warning"] == "Argument 0 at 0x401234 has incomplete upstream type info; falling back to u8 *"
    assert captured["display_messagebox"] is False



def test_parse_call_uses_expression_type_after_incomplete_prototype(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    visitor._deref_tinfo = lambda tinfo: tinfo
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()
    debug_messages = []

    incomplete_proto = SimpleNamespace(
        dstr=lambda: "FixtureScene *",
        is_ptr=lambda: True,
        get_pointed_object=lambda: SimpleNamespace(
            dstr=lambda: "?",
            get_size=lambda: scanner_module.ida_typeinf.BADSIZE,
        ),
    )
    arg_tinfo = SimpleNamespace(dstr=lambda: "u64 *", get_size=lambda: 8)

    monkeypatch.setattr(scanner_module, "get_func_argument_info", lambda *_args, **_kwargs: (0, incomplete_proto))
    monkeypatch.setattr(scanner_module, "log_debug", lambda message: debug_messages.append(message))

    result = visitor._parse_call(
        SimpleNamespace(ea=0x401234),
        SimpleNamespace(type=arg_tinfo),
    )

    assert result is arg_tinfo
    assert debug_messages == [
        "Prototype type for argument 0 at 0x401234 is incomplete: FixtureScene *",
        "Using expression type u64 * for argument 0 at 0x401234 after incomplete prototype type",
    ]


def test_infer_data_object_tinfo_uses_sized_byte_array_after_incomplete_guess(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)
    visitor._describe_tinfo = lambda tinfo: getattr(tinfo, "dstr", lambda: str(tinfo))()
    debug_messages = []

    guessed_tinfo = SimpleNamespace(
        dstr=lambda: "?",
        get_size=lambda: scanner_module.ida_typeinf.BADSIZE,
    )
    current_tinfo = SimpleNamespace(
        dstr=lambda: "forward_decl *",
        is_ptr=lambda: True,
        get_pointed_object=lambda: SimpleNamespace(
            dstr=lambda: "struct Widget",
            get_size=lambda: scanner_module.ida_typeinf.BADSIZE,
            is_forward_decl=lambda: True,
        ),
    )
    fallback_tinfo = SimpleNamespace(dstr=lambda: "u8[16]")

    monkeypatch.setattr(scanner_module, "log_debug", lambda message: debug_messages.append(message))
    monkeypatch.setattr(scanner_module.ida_typeinf, "tinfo_t", lambda: guessed_tinfo)
    monkeypatch.setattr(
        scanner_module.ida_typeinf,
        "guess_tinfo",
        lambda out, _ea: out is guessed_tinfo,
        raising=False,
    )
    monkeypatch.setattr(scanner_module.ida_bytes, "get_item_size", lambda _ea: 16, raising=False)
    visitor._create_byte_array_tinfo = lambda size: fallback_tinfo if size == 16 else None

    result = visitor._infer_data_object_tinfo(0x5000, current_tinfo)

    assert result is fallback_tinfo
    assert debug_messages == [
        "Object type at 0x5000 is incomplete: forward_decl *",
        "Guessed object type from 0x5000 remained incomplete: ?",
        "Object type for 0x5000 remained incomplete; falling back to sized byte array u8[16]",
    ]

def test_to_function_offset_str_uses_stable_fallback_for_non_function():
    hexrays_path = Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "hexrays.py"
    spec = util.spec_from_file_location("forge.api.hexrays_test", hexrays_path)
    assert spec is not None and spec.loader is not None
    hexrays_module = util.module_from_spec(spec)
    spec.loader.exec_module(hexrays_module)

    def monkeypatch_get_func(_ea):
        return SimpleNamespace(start_ea=0x401000)
    hexrays_module.ida_funcs.get_func = monkeypatch_get_func
    hexrays_module.ida_name.get_name = lambda _ea: "sub_401000"

    assert hexrays_module.to_function_offset_str(0x401234) == "sub_401000+0x234"

    hexrays_module.ida_funcs.get_func = lambda _ea: None
    assert hexrays_module.to_function_offset_str(0x401234) == "<no-function>"


def test_new_deep_scan_visitor_initializes_recursive_state(monkeypatch):
    scanner_module = _load_scanner_module()
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

    monkeypatch.setattr(scanner_module.RecursiveDownwardsObjectVisitor, "__init__", fake_recursive_init)

    cfunc = SimpleNamespace(entry_ea=0x401000)
    obj = SimpleNamespace(id=scanner_module.ObjectType.local_variable, ea=0x5000, name="arg0")
    structure = SimpleNamespace()

    visitor = scanner_module.NewDeepScanVisitor(cfunc, 0x10, obj, structure, recurse_calls=True)

    assert calls == [(cfunc, obj, None, True, None, True)]
    assert visitor._origin == 0x10
    assert visitor._structure is structure
    assert visitor._new_for_visit == set()


# ---------------------------------------------------------------------------
# Child-scan member-rooted regressions (skip-gating on unmatchable anchors)
# ---------------------------------------------------------------------------

class _ScanT:
    """tinfo double covering the member-creation probes."""

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
    return SimpleNamespace(cexpr=node, ea=node.ea, op=node.op)


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


def _make_member_scan_harness(monkeypatch):
    """Real scanner/visitor with the exact member-use ctree shape:
    ``(const char *)(v2->u64_18 + 28)`` and ``*(_DWORD *)v2->u64_18``."""
    import ida_typeinf

    class _FakeParentee:
        def __init__(self):
            self.cv_flags = 0

    monkeypatch.setattr(ida_hexrays, "ctree_parentee_t", _FakeParentee, raising=False)

    def walker(cexpr, parents):
        if getattr(cexpr, "ea", -1) != -1:
            return cexpr.ea
        for p in reversed(parents):
            if getattr(p, "ea", -1) != -1:
                return p.ea
        return -1

    # Must run BEFORE _load_scanner_module: the visitor binds these names at
    # import time from the conftest stub module.
    monkeypatch.setattr(hexrays_api, "find_expr_address", walker, raising=False)
    monkeypatch.setattr(hexrays_api, "print_expr_address", lambda cexpr, parents: hex(getattr(cexpr, "ea", -1)), raising=False)
    monkeypatch.setattr(hexrays_api, "is_legal_type", lambda *_a, **_k: True, raising=False)

    class _TypesStub:
        width = 8

        def __getitem__(self, key):
            return SimpleNamespace(type=_ScanT(key), ptr=_ScanT(f"{key} *", size=8), name=key)

        @staticmethod
        def convert_to_simple_type(t):
            return t

        @staticmethod
        def get_ptr_tinfo():
            return _ScanT("void *", size=8)

    types_module = sys.modules.get("forge.api.types")
    monkeypatch.setattr(types_module, "types", _TypesStub(), raising=False)
    monkeypatch.setattr(ida_typeinf, "tinfo_t", lambda value=None: value.clone() if isinstance(value, _ScanT) else _ScanT("tmp"), raising=False)

    scanner_module = _load_scanner_module()
    ctype = scanner_module.ctype
    if not hasattr(ctype, "asg"):
        ctype.asg = 13

    class _FakeParentee:
        def __init__(self):
            self.cv_flags = 0

    monkeypatch.setattr(ida_hexrays, "ctree_parentee_t", _FakeParentee, raising=False)

    class _TypesStub:
        width = 8

        def __getitem__(self, key):
            return SimpleNamespace(type=_ScanT(key), ptr=_ScanT(f"{key} *", size=8), name=key)

        @staticmethod
        def convert_to_simple_type(t):
            return t

        @staticmethod
        def get_ptr_tinfo():
            return _ScanT("void *", size=8)

    types_module = sys.modules.get("forge.api.types")
    monkeypatch.setattr(types_module, "types", _TypesStub(), raising=False)
    monkeypatch.setattr(ida_typeinf, "tinfo_t", lambda value=None: value.clone() if isinstance(value, _ScanT) else _ScanT("tmp"), raising=False)

    test_ptr = _ScanT("test *", pointed=_ScanT("test", size=8), size=8)
    char_ptr = _ScanT("char *", size=8)
    dword_ptr = _ScanT("_DWORD *", pointed=_ScanT("_DWORD", size=4), size=8)
    i64 = _ScanT("__int64", size=8)

    var = _ScanNode(ctype.var, type=test_ptr)

    memptr_str = _ScanNode(ctype.memptr, x=var, m=0x18, type=i64)
    add28 = _ScanNode(ctype.add, x=memptr_str, y=_ScanNode(ctype.num, numval=28), type=char_ptr)
    cast_str = _ScanNode(ctype.cast, x=add28, type=char_ptr)

    memptr_dw = _ScanNode(ctype.memptr, x=var, m=0x18, type=i64)
    cast_dw = _ScanNode(ctype.cast, x=memptr_dw, type=dword_ptr)
    ptr_dw = _ScanNode(ctype.ptr, x=cast_dw, type=i64)

    call = _ScanNode(ctype.call, x=_ScanNode(ctype.obj, obj_ea=0x1400019B0), type=_ScanT("void", size=0))
    call.ea = 0x140001575
    call.a = [SimpleNamespace(cexpr=cast_str), SimpleNamespace(cexpr=ptr_dw)]

    nodes = [
        call,
        cast_str,
        add28,
        memptr_str,
        ptr_dw,
        cast_dw,
        memptr_dw,
    ]
    return scanner_module, _ScanNode, ctype, test_ptr, nodes


def _member_scan(monkeypatch, *, skip_until_object, seed_ea):
    from forge.api.scan_object import StructureReferenceObject
    from forge.api.structure import Structure

    scanner_module, _ScanNode, _ctype, _test_ptr, nodes = _make_member_scan_harness(monkeypatch)

    structure = Structure("Child")
    obj = StructureReferenceObject("test", 0x18)
    obj.ea = seed_ea
    obj.func_ea = 0x1400014F0
    obj.tinfo = None

    cfunc = SimpleNamespace(entry_ea=0x1400014F0, argidx=(), body=SimpleNamespace())
    visitor = scanner_module.NewDeepScanVisitor(
        cfunc, 0x18, obj, structure, recurse_calls=True,
        skip_until_object=skip_until_object,
    )
    _drive_scan_visitor(visitor, nodes)
    return structure, visitor


def _typed_var_scan(monkeypatch, node_builder):
    """Var-rooted parent scan over typed ctrees (memptr member uses).

    Reuses the member-scan harness' tinfo doubles; the root variable is
    struct-typed (``test *``), mimicking a function whose lvars carry the
    applied parent structure. ``node_builder(scanner_module, _ScanNode,
    ctype, test_ptr)`` returns the pre-order node list."""
    from forge.api.scan_object import VariableObject
    from forge.api.structure import Structure

    scanner_module, _ScanNode, ctype, test_ptr, _nodes = _make_member_scan_harness(monkeypatch)
    nodes = node_builder(scanner_module, _ScanNode, ctype, test_ptr)

    monkeypatch.setattr(
        ida_hexrays, "lvar_locator_t", lambda *_a: SimpleNamespace(), raising=False
    )

    structure = Structure("Parent")
    lvar = SimpleNamespace(type=lambda: test_ptr, name="v2", location="loc", defea=0x1400014F0)
    obj = VariableObject(lvar, 0)
    obj.func_ea = 0x1400014F0
    obj.tinfo = test_ptr

    cfunc = SimpleNamespace(entry_ea=0x1400014F0, argidx=(), body=SimpleNamespace())
    visitor = scanner_module.NewDeepScanVisitor(
        cfunc, 0x18, obj, structure, recurse_calls=True,
        skip_until_object=False,
    )
    _drive_scan_visitor(visitor, nodes)
    return structure, scanner_module, _ScanNode, ctype, test_ptr


def test_typed_parent_scan_reads_member_at_memptr_offset(monkeypatch):
    """``v2->u64_18`` — the typed ctree's memptr node is the var's first
    parent. The member must land at the memptr delta (0x18), not 0: the
    untyped-only extraction used to collapse typed parent scans to
    ``field_0``."""
    def nodes(m, N, c, tp):
        var = N(c.var, type=tp, v=SimpleNamespace(idx=0))
        return [
            N(c.call, x=N(c.obj, obj_ea=0x1400019B0), type=_ScanT("void", size=0)),
            N(c.memptr, x=var, m=0x18, type=_ScanT("__int64", size=8)),
            var,
        ]

    structure, _s, _n, _c, _t = _typed_var_scan(monkeypatch, nodes)

    offsets = sorted(m.offset for m in structure.members)
    assert offsets == [0x18], f"expected the 0x18 member, got offsets {offsets}"


def test_typed_parent_scan_cast_add_shape_preserves_offset_and_type(monkeypatch):
    """``(const char *)(v2->u64_18 + 28)`` — the +28 arithmetic rides on the
    member VALUE; the member still lands at 0x18 with the cast's type.
    Regression: this shape used to produce a member at 0 whose type was the
    root struct (test *) instead of the member type (char *)."""
    def nodes(m, N, c, tp):
        i64 = _ScanT("__int64", size=8)
        char_ptr = _ScanT("char *", size=8)
        var = N(c.var, type=tp, v=SimpleNamespace(idx=0))
        memptr = N(c.memptr, x=var, m=0x18, type=i64)
        add28 = N(c.add, x=memptr, y=N(c.num, numval=28), type=char_ptr)
        cast_str = N(c.cast, x=add28, type=char_ptr)
        return [
            N(c.call, x=N(c.obj, obj_ea=0x1400019B0), type=_ScanT("void", size=0)),
            N(c.ptr, x=cast_str, type=i64),
            cast_str,
            add28,
            memptr,
            var,
        ]

    structure, _s, _n, _c, _t = _typed_var_scan(monkeypatch, nodes)

    offsets = sorted(m.offset for m in structure.members)
    assert offsets == [0x18], f"expected the 0x18 member, got offsets {offsets}"
    assert structure.members[0].tinfo.dstr() == "char *", structure.members[0].tinfo.dstr()
    assert structure.members[0].tinfo.dstr() != "test *"


def test_typed_parent_scan_assignment_uses_memptr_offset(monkeypatch):
    """``v2->u64_18 = x`` — assignment through a memptr lands at 0x18."""
    def nodes(m, N, c, tp):
        i64 = _ScanT("__int64", size=8)
        var = N(c.var, type=tp, v=SimpleNamespace(idx=0))
        memptr = N(c.memptr, x=var, m=0x18, type=i64)
        return [
            N(c.asg, x=memptr, y=N(c.num, numval=1)),
            memptr,
            var,
        ]

    structure, _s, _n, _c, _t = _typed_var_scan(monkeypatch, nodes)

    offsets = sorted(m.offset for m in structure.members)
    assert offsets == [0x18], f"expected the 0x18 member, got offsets {offsets}"


def test_untyped_parent_scan_add_shape_keeps_working(monkeypatch):
    """Untyped regression guard: ``*(v2 + 0x18) + 28`` (add-carrying layout)
    must still produce the 0x18 member — the memptr handling must not disturb
    the raw arithmetic path."""
    def nodes(m, N, c, tp):
        i64 = _ScanT("__int64", size=8)
        char_ptr = _ScanT("char *", size=8)
        var = N(c.var, type=i64, v=SimpleNamespace(idx=0))
        add18 = N(c.add, x=var, y=N(c.num, numval=0x18), type=i64)
        ptr = N(c.ptr, x=add18, type=i64)
        add28 = N(c.add, x=ptr, y=N(c.num, numval=28), type=char_ptr)
        cast_str = N(c.cast, x=add28, type=i64)
        return [
            N(c.call, x=N(c.obj, obj_ea=0x1400019B0), type=_ScanT("void", size=0)),
            cast_str,
            add28,
            ptr,
            add18,
            var,
        ]

    structure, _s, _n, _c, _t = _typed_var_scan(monkeypatch, nodes)

    offsets = sorted(m.offset for m in structure.members)
    assert offsets == [0x18], f"expected the 0x18 member, got offsets {offsets}"


def test_member_rooted_scan_skip_gating_swallows_unmatchable_anchor(monkeypatch):
    """Child-scan evidence anchors at instructions that never satisfy the
    member matcher (var/assignment eas). Skip-gating used to silently swallow
    the entire scan: zero members and no error."""
    structure, visitor = _member_scan(monkeypatch, skip_until_object=True, seed_ea=0x1400014F4)

    assert visitor._skip is True
    assert structure.members == []


def test_member_rooted_scan_with_skip_disabled_creates_members_from_stale_anchor(monkeypatch):
    """The fix: member-rooted scans run body-wide (the matcher is precise),
    so a stale anchor cannot gate out the whole function."""
    structure, visitor = _member_scan(monkeypatch, skip_until_object=False, seed_ea=0x1400014F4)

    assert visitor._skip is False
    offsets = sorted(m.offset for m in structure.members)
    assert 0x1C in offsets, f"expected the +28 member, got offsets {offsets}"
    assert 0x00 in offsets, f"expected the +0 member, got offsets {offsets}"


def test_member_rooted_scan_anchored_at_use_instruction_still_works(monkeypatch):
    """Anchored evidence (memptr instruction ea) keeps working with defaults."""
    structure, visitor = _member_scan(monkeypatch, skip_until_object=True, seed_ea=0x140001575)

    assert visitor._skip is False  # cleared at the memptr use
    offsets = sorted(m.offset for m in structure.members)
    assert 0x00 in offsets, f"expected the +0 member, got offsets {offsets}"
    assert 0x1C in offsets, f"expected the +28 member, got offsets {offsets}"

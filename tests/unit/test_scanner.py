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
setattr(hexrays_api, "ctype_to_str", lambda *_args, **_kwargs: "")
setattr(hexrays_api, "decompile", lambda *_args, **_kwargs: None)
setattr(hexrays_api, "find_expr_address", lambda *_args, **_kwargs: 0)
setattr(hexrays_api, "get_func_argument_info", lambda *_args, **_kwargs: (0, None))
setattr(hexrays_api, "get_funcs_calling_address", lambda *_args, **_kwargs: set())
setattr(hexrays_api, "is_code", lambda *_args, **_kwargs: False)
setattr(hexrays_api, "is_legal_type", lambda *_args, **_kwargs: True)
setattr(hexrays_api, "to_hex", lambda value: hex(value))
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

    def is_udt(self):
        return self._udt


@pytest.mark.parametrize(
    "obj_tinfo, call_tinfo, expected_name",
    [
        (FakeType("FixtureScene *", ptr=True), FakeType("__int64"), "FixtureScene *"),
        (FakeType("FixtureScene", udt=True), FakeType("__int64"), "FixtureScene"),
        (FakeType("FixtureScene *", ptr=True), FakeType("Other *", ptr=True), "Other *"),
    ],
)
def test_prefer_object_tinfo_keeps_structure_like_members(obj_tinfo, call_tinfo, expected_name):
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


def test_get_member_preserves_negative_offset(monkeypatch):
    scanner_module = _load_scanner_module()
    visitor = scanner_module.ScanVisitor.__new__(scanner_module.ScanVisitor)

    class FakeMember:
        def __init__(self, offset, tinfo, scan_obj, origin):
            self.offset = offset
            self.tinfo = tinfo
            self.scan_obj = scan_obj
            self.origin = origin

    class FakeTinfo:
        def __init__(self, name):
            self._name = name

        def dstr(self):
            return self._name

        def clr_const(self):
            return None

        def equals_to(self, other):
            return False

    import forge.api.members as members_module
    monkeypatch.setattr(members_module, "Member", FakeMember, raising=False)
    monkeypatch.setattr(members_module, "VoidMember", type("VoidMember", (), {}), raising=False)
    monkeypatch.setattr(
        scanner_module.ScannedObject,
        "create",
        lambda obj, ea, origin, applicable: SimpleNamespace(obj=obj, ea=ea, origin=origin, applicable=applicable),
    )
    monkeypatch.setattr(scanner_module.ida_typeinf, "tinfo_t", lambda value=None: value if value is not None else FakeTinfo("u32"))

    class FakeTypes:
        def convert_to_simple_type(self, t):
            return t

        def __getitem__(self, key):
            return SimpleNamespace(type=FakeTinfo(key))

    monkeypatch.setattr(scanner_module, "types", FakeTypes())
    monkeypatch.setattr(scanner_module, "is_code", lambda *_args, **_kwargs: False)

    visitor.parents = []
    visitor._origin = 0x10
    visitor._structure = SimpleNamespace(add_member=lambda *_args, **_kwargs: None)
    visitor.crippled = False

    member = visitor._get_member(-32, SimpleNamespace(ea=0x1000), SimpleNamespace(id=scanner_module.ObjectType.local_variable, name="a1"), FakeTinfo("u32"))

    assert isinstance(member, FakeMember)
    assert member.offset == -32


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
    obj = SimpleNamespace(name="v2")

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

def test_scanned_object_create_accepts_legacy_scanned_variable_object(monkeypatch):
    scanner_module = _load_scanner_module()
    monkeypatch.setattr(
        scanner_module.ida_funcs,
        "get_func",
        lambda _ea: SimpleNamespace(start_ea=0x401000),
        raising=False,
    )

    monkeypatch.setattr(
        scanner_module.ida_hexrays,
        "lvar_locator_t",
        lambda location, defea: SimpleNamespace(location=location, defea=defea),
        raising=False,
    )

    source = SimpleNamespace(
        name="arg0",
        ea=0x402000,
        func_ea=0x401000,
        scan_root_function_ea=0x401000,
        scan_root_ea=0x402000,
        scan_root_function_name="sub_401000",
        _ScannedVariableObject__lvar=SimpleNamespace(location="stack", defea=0x1234),
    )

    scanned = scanner_module.ScannedObject.create(source, 0x401234, 0x0)

    assert scanned.name == "arg0"
    assert scanned.ea == 0x401234
    assert scanned.scan_root_function_ea == 0x401000
    assert scanned.scan_root_ea == 0x402000
    assert scanned.scan_root_function_name == "sub_401000"



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
        def get_ptr(self):
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
        def get_ptr(self):
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
        def get_ptr(self):
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

    monkeypatch_get_func = lambda _ea: SimpleNamespace(start_ea=0x401000)
    hexrays_module.ida_funcs.get_func = monkeypatch_get_func
    hexrays_module.idc.get_name = lambda _ea: "sub_401000"

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

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


def test_extract_member_normalizes_negative_offset(monkeypatch):
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
    monkeypatch.setattr(scanner_module.ScannedObject, "create", lambda obj, ea, origin, applicable: SimpleNamespace(obj=obj, ea=ea, origin=origin, applicable=applicable))
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
    assert member.offset == 32


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
            return SimpleNamespace(type=SimpleNamespace(dstr=lambda: key))

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


def test_extract_member_warns_when_call_argument_type_is_unknown(monkeypatch):
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
            return SimpleNamespace(type=SimpleNamespace(dstr=lambda: key))

    monkeypatch.setattr(scanner_module, "types", _FakeTypes())

    unknown_type = SimpleNamespace(dstr=lambda: "?", get_size=lambda: scanner_module.ida_typeinf.BADSIZE)
    leaf = SimpleNamespace(op=scanner_module.ctype.var, type=unknown_type)
    first_expr = SimpleNamespace(op=scanner_module.ctype.ptr, x=leaf, type=unknown_type)
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
    assert captured["tinfo"].dstr() == "char"
    assert captured["warning"] == "Could not infer argument type from call expression; falling back to char for argument 0 at 0x401234"
    assert captured["display_messagebox"] is False


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

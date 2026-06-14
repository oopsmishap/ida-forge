from __future__ import annotations

from forge.api import members
from forge.util.cxx_to_c_name import demangled_name_to_c_str



def test_normalize_type_declaration_rewrites_known_aliases():
    assert members.normalize_type_declaration("_DWORD *") == "u32 *"
    assert members.normalize_type_declaration("unsigned __int64") == "u64"
    assert members.normalize_type_declaration("  BOOL  ") == "bool"


def test_parse_user_tinfo_uses_parse_decl_attempts_before_fallbacks(monkeypatch):
    attempts = []
    sentinel = object()

    def fake_parse_decl_attempt(declaration: str):
        attempts.append(declaration)
        return None

    monkeypatch.setattr(members, "_parse_decl_attempt", fake_parse_decl_attempt)
    monkeypatch.setattr(members, "_parse_named_like_type", lambda declaration: sentinel)
    monkeypatch.setattr(
        members,
        "_parse_idc_decl_attempt",
        lambda declaration: (_ for _ in ()).throw(AssertionError("IDC fallback should not be used")),
    )

    result = members.parse_user_tinfo(" _DWORD * ")

    assert result is sentinel
    assert attempts == ["u32 *", "u32 *;", "u32 * __forge_member;"]


def test_parse_user_tinfo_falls_back_to_idc_parser(monkeypatch):
    parse_attempts = []
    idc_attempts = []
    sentinel = object()

    monkeypatch.setattr(
        members,
        "_parse_decl_attempt",
        lambda declaration: parse_attempts.append(declaration) or None,
    )
    monkeypatch.setattr(members, "_parse_named_like_type", lambda declaration: None)
    monkeypatch.setattr(
        members,
        "_parse_idc_decl_attempt",
        lambda declaration: idc_attempts.append(declaration) or (sentinel if declaration.endswith(";") else None),
    )

    result = members.parse_user_tinfo("BOOL")

    assert result is sentinel
    assert parse_attempts == ["bool", "bool;", "bool __forge_member;"]
    assert idc_attempts == ["bool", "bool;"]


def test_parse_named_like_type_routes_arrays_and_pointers(monkeypatch):
    array_calls = []
    pointer_calls = []
    array_sentinel = object()
    pointer_sentinel = object()

    monkeypatch.setattr(
        members,
        "_build_array_tinfo",
        lambda base, count: array_calls.append((base, count)) or array_sentinel,
    )
    monkeypatch.setattr(
        members,
        "_build_pointer_tinfo",
        lambda base, depth: pointer_calls.append((base, depth)) or pointer_sentinel,
    )

    assert members._parse_named_like_type("Widget[0x10]") is array_sentinel
    assert members._parse_named_like_type("Thing **") is pointer_sentinel
    assert array_calls == [("Widget", 16)]
    assert pointer_calls == [("Thing", 2)]


def test_parse_named_like_type_returns_named_type_when_available(monkeypatch):
    class FakeNamedType:
        def __init__(self):
            self.requested_name = None

        def get_named_type(self, _idati, name):
            self.requested_name = name
            return name == "MyType"

    monkeypatch.setattr(members.ida_typeinf, "tinfo_t", FakeNamedType)
    result = members._parse_named_like_type("MyType")

    assert isinstance(result, FakeNamedType)
    assert result.requested_name == "MyType"



def test_parse_named_like_type_returns_none_when_type_cannot_be_resolved(monkeypatch):
    class FakeNamedType:
        def get_named_type(self, _idati, name):
            return False

    monkeypatch.setattr(members.ida_typeinf, "tinfo_t", FakeNamedType)

    assert members._parse_named_like_type("DefinitelyMissing") is None



def test_parse_user_tinfo_returns_none_when_all_strategies_fail(monkeypatch):
    monkeypatch.setattr(members, "_parse_decl_attempt", lambda declaration: None)
    monkeypatch.setattr(members, "_parse_named_like_type", lambda declaration: None)
    monkeypatch.setattr(members, "_parse_idc_decl_attempt", lambda declaration: None)

    assert members.parse_user_tinfo("MissingType") is None



def test_normalize_type_declaration_does_not_replace_partial_identifier_matches():
    assert members.normalize_type_declaration("BYTECODE") == "BYTECODE"
    assert members.normalize_type_declaration("myDWORDValue") == "myDWORDValue"


def test_demangled_name_to_c_str_removes_template_and_quote_symbols():
    assert (
        demangled_name_to_c_str("fixture::Interface<std::vector<int> >::_vftable")
        == "fixture_Interface_std_vector_int_vftable"
    )
    assert demangled_name_to_c_str("std::less<int>::operator()") == "std_less_int_operator_call"


def test_parse_vtable_name_sanitizes_demangled_vtable_symbols(monkeypatch):
    vtable = members.VirtualTable.__new__(members.VirtualTable)
    vtable.address = 0x5000

    monkeypatch.setattr(
        members.ida_name,
        "get_name",
        lambda _ea: "??_7?$Interface@H@@6B@",
        raising=False,
    )
    monkeypatch.setattr(
        members.ida_name,
        "is_valid_typename",
        lambda _name: False,
        raising=False,
    )
    monkeypatch.setattr(
        members.ida_name,
        "demangle_name",
        lambda _name, _flags: "fixture::Interface<std::vector<int> >::`vftable'",
        raising=False,
    )
    monkeypatch.setattr(members.idc, "get_inf_attr", lambda _attr: 0, raising=False)
    monkeypatch.setattr(members.idc, "INF_SHORT_DN", 0, raising=False)

    name, nice = vtable._parse_vtable_name()

    assert nice is True
    assert name == "fixture_Interface_std_vector_int_vtbl"


def test_virtual_table_init_wires_origin_and_scanned_variable(monkeypatch):
    monkeypatch.setattr(
        members.VirtualTable, "populate_virtual_functions", lambda self: None
    )
    monkeypatch.setattr(
        members.VirtualTable, "_parse_vtable_name", lambda self: ("Cls_vtbl", True)
    )

    scan_obj = object()
    vtable = members.VirtualTable(0x38, 0x5000, scan_obj, 0x10)

    assert vtable.offset == 0x38
    assert vtable.address == 0x5000
    assert vtable.origin == 0x10
    assert vtable.scanned_variables == {scan_obj}


def _make_vfunc(address=0x1000, offset=16, table_name="TestVtbl"):
    vf = members.VirtualFunction.__new__(members.VirtualFunction)
    vf.address = address
    vf.offset = offset
    vf.vtable_name = table_name
    vf.visited = False
    return vf


def test_virtual_function_name_returns_generated_when_get_func_name_is_none(monkeypatch):
    vf = _make_vfunc()
    monkeypatch.setattr(members.ida_funcs, "get_func_name", lambda _ea: None, raising=False)

    assert vf.name == "TestVtbl_function_2"


def test_virtual_function_name_returns_generated_when_demangle_fails(monkeypatch):
    vf = _make_vfunc()
    monkeypatch.setattr(
        members.ida_funcs, "get_func_name", lambda _ea: "?mangled@@invalid", raising=False
    )
    monkeypatch.setattr(members.ida_name, "is_valid_typename", lambda _name: False, raising=False)
    monkeypatch.setattr(members.idc, "demangle_name", lambda _name, _flags: None, raising=False)
    monkeypatch.setattr(members.idc, "get_inf_attr", lambda _attr: 0, raising=False)
    monkeypatch.setattr(members.idc, "INF_SHORT_DN", 0, raising=False)

    assert vf.name == "TestVtbl_function_2"


def test_virtual_function_repr_does_not_crash_with_none_func_name(monkeypatch):
    vf = _make_vfunc(address=0x140043300, offset=0, table_name="SomeClass")
    monkeypatch.setattr(members.ida_funcs, "get_func_name", lambda _ea: None, raising=False)

    result = repr(vf)

    assert "SomeClass_function_0" in result
    assert "0x140043300" in result


def test_virtual_function_name_returns_valid_typename_directly(monkeypatch):
    vf = _make_vfunc()
    monkeypatch.setattr(members.ida_funcs, "get_func_name", lambda _ea: "MyMethod", raising=False)
    monkeypatch.setattr(members.ida_name, "is_valid_typename", lambda _name: True, raising=False)

    assert vf.name == "MyMethod"


def test_virtual_function_name_returns_generated_for_sub_prefix(monkeypatch):
    vf = _make_vfunc()
    monkeypatch.setattr(members.ida_funcs, "get_func_name", lambda _ea: "sub_1400A0", raising=False)
    monkeypatch.setattr(members.ida_name, "is_valid_typename", lambda _name: True, raising=False)

    assert vf.name == "TestVtbl_function_2"


def test_virtual_function_try_rename_to_is_conservative(monkeypatch):
    vf = _make_vfunc(address=0x1000)
    renamed = []
    monkeypatch.setattr(members.ida_funcs, "get_func_name", lambda _ea: "sub_1000", raising=False)
    monkeypatch.setattr(members.ida_name, "get_name_ea", lambda *_args: members.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(members.ida_name, "set_name", lambda ea, name: renamed.append((ea, name)) or True, raising=False)

    assert vf.try_rename_to("Derived_slot_0") is True
    assert renamed == [(0x1000, "Derived_slot_0")]

    monkeypatch.setattr(members.ida_funcs, "get_func_name", lambda _ea: "UserNamed", raising=False)
    assert vf.try_rename_to("Derived_slot_1") is False

    monkeypatch.setattr(members.ida_funcs, "get_func_name", lambda _ea: "sub_1000", raising=False)
    monkeypatch.setattr(members.ida_name, "get_name_ea", lambda *_args: 0x2000, raising=False)
    assert vf.try_rename_to("Collision") is False
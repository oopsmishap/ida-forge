from __future__ import annotations

from types import SimpleNamespace

from forge.api import members
from forge.util.cxx_to_c_name import demangled_name_to_c_str


def test_normalize_type_declaration_rewrites_known_aliases():
    assert members.normalize_type_declaration("_DWORD *") == "unsigned __int32 *"
    assert members.normalize_type_declaration("unsigned __int64") == "unsigned __int64"
    assert members.normalize_type_declaration("  BOOL  ") == "bool"


def test_parse_user_tinfo_uses_parse_decl_attempts_before_fallbacks(monkeypatch):
    attempts = []
    sentinel = object()

    def fake_parse_decl_attempt(declaration: str):
        attempts.append(declaration)

    monkeypatch.setattr(members, "_parse_decl_attempt", fake_parse_decl_attempt)
    monkeypatch.setattr(members, "_parse_named_like_type", lambda declaration: sentinel)
    monkeypatch.setattr(
        members,
        "_parse_idc_decl_attempt",
        lambda declaration: (_ for _ in ()).throw(AssertionError("IDC fallback should not be used")),
    )

    result = members.parse_user_tinfo(" _DWORD * ")

    assert result is sentinel
    assert attempts == [
        "unsigned __int32 *",
        "unsigned __int32 *;",
        "unsigned __int32 * __forge_member;",
    ]


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




def test_parse_user_tinfo_prefers_domain_parser(monkeypatch):
    sentinel = object()
    calls = []

    class Types:
        def parse_one_declaration(self, library, declaration):
            calls.append((library, declaration))
            return sentinel

    monkeypatch.setattr(
        members,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(types=Types()),
    )
    assert members.parse_user_tinfo("u32") is sentinel
    assert calls == [(None, "unsigned __int32")]

def test_normalize_type_declaration_does_not_replace_partial_identifier_matches():
    assert members.normalize_type_declaration("BYTECODE") == "BYTECODE"
    assert members.normalize_type_declaration("myDWORDValue") == "myDWORDValue"


def test_pointer_array_construction_records_domain_fallback(monkeypatch):
    from forge.api import domain

    domain.clear_fallback_records()
    monkeypatch.setattr(members, "parse_user_tinfo", lambda _decl: object())
    class TInfo:
        def __init__(self, *args):
            self.elem_type = None

        def create_ptr(self, _value):
            return True

        def create_array(self, _value):
            return True

    monkeypatch.setattr(members.ida_typeinf, "tinfo_t", TInfo)
    members._build_pointer_tinfo("Widget", 1)
    members._build_array_tinfo("Widget", 2)
    assert any(
        item.capability == "types.pointer_array_construction"
        for item in domain.fallback_records()
    )


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


def test_parse_vtable_name_falls_back_to_hex_name_when_unnamed(monkeypatch):
    """E2 (eval review 2026-08-13): an unnamed pointer table must not
    AssertionError — it falls back to ``vtbl_<addr>`` like the GUI's
    auto-naming."""
    vtable = members.VirtualTable.__new__(members.VirtualTable)
    vtable.address = 0x140006128

    monkeypatch.setattr(
        members.ida_name,
        "get_name",
        lambda _ea: "",
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
        lambda _name, _flags: None,
        raising=False,
    )

    name, nice = vtable._parse_vtable_name()

    assert nice is False
    assert name == "vtbl_140006128"

def test_is_virtual_table_stops_on_invalid_effective_address(monkeypatch):
    def invalid(_ea):
        raise RuntimeError("Invalid effective address")

    monkeypatch.setattr(members, "is_code", invalid)
    assert members.VirtualTable.is_virtual_table(0x1100000000) == 0

def test_virtual_table_population_stops_on_invalid_pointer(monkeypatch):
    vtable = members.VirtualTable.__new__(members.VirtualTable)
    vtable.address = 0x5000
    vtable.vtable_name = "fixture_Test_vtbl"
    vtable.virtual_functions = []

    monkeypatch.setattr(
        members, "read_pointer", lambda _ea: (_ for _ in ()).throw(
            RuntimeError("Invalid effective address")
        )
    )
    vtable.populate_virtual_functions()
    assert vtable.virtual_functions == []
def test_virtual_table_population_rejects_noncanonical_pointer(monkeypatch):
    vtable = members.VirtualTable.__new__(members.VirtualTable)
    vtable.address = 0x5000
    vtable.vtable_name = "fixture_Test_vtbl"
    vtable.virtual_functions = []
    monkeypatch.setattr(members, "read_pointer", lambda _ea: 0xFFFFFFFFFFFFFFFF)
    vtable.populate_virtual_functions()
    assert vtable.virtual_functions == []



def test_resolve_pack_tinfo_heals_ordinal_refs_without_decl_src(monkeypatch):
    """E4 (2026-08-13): a member persisted before decl_src existed renders
    as ``#NN *`` after the type table re-files — packing resolves the
    ordinal to its current name and re-parses instead of serializing the
    stale ref."""
    from types import SimpleNamespace

    healed = []

    def _fake_parse(decl):
        healed.append(decl)
        return SimpleNamespace(dstr=lambda: decl)

    monkeypatch.setattr(members, "parse_user_tinfo", _fake_parse, raising=False)
    monkeypatch.setattr(
        members.ida_typeinf,
        "get_numbered_type_name",
        lambda _til, ordinal: "KeyValuePair" if ordinal == 53 else "",
        raising=False,
    )

    stale = members.Member.__new__(members.Member)
    stale.offset = 0x10
    stale.tinfo = SimpleNamespace(dstr=lambda: "#53 *")
    resolved = stale._resolve_pack_tinfo()

    assert healed == ["KeyValuePair *"]
    assert resolved.dstr() == "KeyValuePair *"


def test_resolve_pack_tinfo_prefers_decl_src(monkeypatch):
    """E4: a fresh decl_src wins over the stored (possibly stale) tinfo."""
    from types import SimpleNamespace

    healed = []

    def _fake_parse(decl):
        healed.append(decl)
        return SimpleNamespace(dstr=lambda: decl)

    monkeypatch.setattr(members, "parse_user_tinfo", _fake_parse, raising=False)

    stale = members.Member.__new__(members.Member)
    stale.offset = 0x10
    stale.tinfo = SimpleNamespace(dstr=lambda: "#53 *")
    stale.decl_src = "KV *"
    resolved = stale._resolve_pack_tinfo()

    assert healed == ["KV *"]
    assert resolved.dstr() == "KV *"


def test_resolve_pack_tinfo_reparses_named_reference(monkeypatch):
    """Recovery-eval gap #5: a scanner-copied tinfo that names an IDB type
    goes stale when the type is re-filed (inline-child members kept binding
    a 48-byte child after it shrank) — packing re-parses the CURRENT
    declaration text and re-binds the fresh size."""
    from types import SimpleNamespace

    parsed = []

    def _fake_parse(decl):
        parsed.append(decl)
        return SimpleNamespace(dstr=lambda: decl, get_size=lambda: 44)

    monkeypatch.setattr(members, "parse_user_tinfo", _fake_parse, raising=False)

    stale = members.Member.__new__(members.Member)
    stale.offset = 0x10
    stale.tinfo = SimpleNamespace(dstr=lambda: "inline_child")
    resolved = stale._resolve_pack_tinfo()

    assert parsed == ["inline_child"]
    assert resolved.dstr() == "inline_child"


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


class _GetUDTMemberFakeTinfo:
    """tinfo double exposing the flags ``Member.type_alias`` introspects."""

    def __init__(self, name="u64", size=8):
        self._name = name
        self._size = size
        self.create_ptr_calls = 0

    def dstr(self):
        return self._name

    def get_size(self):
        return self._size

    def is_floating(self):
        return False

    def is_integral(self):
        return True

    def is_signed(self):
        return False

    def equals_to(self, other):
        return self.dstr() == getattr(other, "dstr", lambda: "")()

    def create_array(self, *_args, **_kwargs):
        return True


def test_get_udt_member_non_array_assigns_type(monkeypatch):
    """Bug 2 (recovery eval): ``Member.get_udt_member`` left ``udt_member.type``
    unassigned on the non-array branch (only the array branch set it), so every
    headless ``create_udt`` committed size-1 types while reporting ok. A real
    UDT member must carry a type equal to the member's pack-resolved tinfo."""
    wrapped = []

    class _RecordingTInfo:
        def __init__(self, src=None):
            # tinfo_t(pack_tinfo) captures the pack-resolved tinfo — proving
            # the non-array branch feeds it a real tinfo instead of leaving
            # the member type unset.
            wrapped.append(src)
            self._name = getattr(src, "dstr", lambda: "")()

        def dstr(self):
            return self._name

    class _RecordingUDTMember:
        def __init__(self):
            self.offset = 0
            self.name = ""

    monkeypatch.setattr(
        members.ida_typeinf, "tinfo_t", _RecordingTInfo, raising=False
    )
    monkeypatch.setattr(
        members.ida_typeinf, "udt_member_t", _RecordingUDTMember, raising=False
    )
    parsed = []

    def _fake_parse(declaration):
        parsed.append(declaration)
        return _GetUDTMemberFakeTinfo(declaration)

    monkeypatch.setattr(members, "parse_user_tinfo", _fake_parse, raising=False)
    member = members.Member(0x10, _GetUDTMemberFakeTinfo(), None, 0)
    member.decl_src = "fixture_World *"
    member.name = "world"

    result = member.get_udt_member()

    # authored decl re-parsed fresh at pack time (the _resolve_pack_tinfo
    # path that feeds get_udt_member its type)
    assert "fixture_World *" in parsed
    # non-array branch MUST have assigned a real tinfo wrapping the pack
    # resolve (the exact bug under test: .type stayed unset)
    assert wrapped, "non-array get_udt_member never built a member type"
    result_type = getattr(result, "type", None)
    assert result_type is not None
    assert result_type.dstr() == "fixture_World *"
    assert result.name == "world"
    # size follows the effective pack size (8 bytes for u64)
    assert result.size == 8


def test_get_udt_member_array_assigns_array_type(monkeypatch):
    """Bug 2: the array branch wraps the element tinfo in an array tinfo and
    sizes the member by array_count × element size."""
    created = []

    class _RecordingTInfo:
        def __init__(self, src=None):
            self._name = getattr(src, "dstr", lambda: "")()

        def dstr(self):
            return self._name

        def create_array(self, array_data):
            created.append(array_data)
            return True

    monkeypatch.setattr(
        members.ida_typeinf, "tinfo_t", _RecordingTInfo, raising=False
    )
    monkeypatch.setattr(
        members.ida_typeinf, "udt_member_t", lambda: SimpleNamespace(), raising=False
    )
    monkeypatch.setattr(
        members, "parse_user_tinfo",
        lambda declaration: _GetUDTMemberFakeTinfo(declaration.split()[0], size=4),
        raising=False,
    )

    member = members.Member(0x10, _GetUDTMemberFakeTinfo(size=4), None, 0)
    member.decl_src = "u32"

    result = member.get_udt_member(array_size=3)

    assert len(created) == 1
    array_data = created[0]
    assert array_data.nelems == 3
    assert result.type is not None
    assert result.size == 4 * 3  # element size × array count
    assert result.offset == 0x10


class _LinkedChildTinfo:
    def __init__(self, name="Child", size=12):
        self._name = name
        self._size = size

    def dstr(self):
        return self._name

    def get_size(self):
        return self._size


def _run_linked_get_udt_member(monkeypatch, fresh):
    """Shared rig: recording ida_typeinf doubles so the linked member's
    get_udt_member runs headless."""
    parsed = []

    def fake_parse(declaration):
        parsed.append(declaration)
        return fresh

    monkeypatch.setattr(members, "parse_user_tinfo", fake_parse, raising=False)

    class _RecordingTInfo:
        def __init__(self, src=None):
            self._name = getattr(src, "dstr", lambda: "")()

        def dstr(self):
            return self._name

    class _RecordingUDTMember:
        def __init__(self):
            self.offset = 0
            self.name = ""

    monkeypatch.setattr(
        members.ida_typeinf, "tinfo_t", _RecordingTInfo, raising=False
    )
    monkeypatch.setattr(
        members.ida_typeinf, "udt_member_t", _RecordingUDTMember, raising=False
    )

    linked = members.LinkedStructureMember(0x10, "Child", 12, "child")
    linked.tinfo = _LinkedChildTinfo("#53 *")  # stale ordinal-shaped handle
    linked.decl_src = "Child"
    linked.comment = "embedded"
    return linked, parsed


def test_get_udt_member_linked_child_reparses_decl_src(monkeypatch):
    """E4 mirror for LinkedStructureMember.get_udt_member: when decl_src is
    set, the child declaration is re-parsed at pack time — the stored
    tinfo may be a stale ``#NN *`` after the child type was re-committed
    under a fresh ordinal."""
    fresh = _LinkedChildTinfo("Child")
    linked, parsed = _run_linked_get_udt_member(monkeypatch, fresh)

    result = linked.get_udt_member()

    # parse_user_tinfo was called with the decl_src, and the FRESH tinfo
    # (not the stale stored handle) feeds the packed member type
    assert parsed == ["Child"]
    assert result.type.dstr() == "Child"
    assert result.name == "child"
    assert result.size == 12
    assert result.offset == 0x10


def test_get_udt_member_linked_child_falls_back_to_stored_tinfo(monkeypatch):
    """A failed decl_src re-parse falls back to the stored tinfo, mirroring
    Member._resolve_pack_tinfo's degraded-til semantics."""
    linked, parsed = _run_linked_get_udt_member(monkeypatch, fresh=None)

    result = linked.get_udt_member()

    assert parsed == ["Child"]
    assert result.type.dstr() == "#53 *"
"""Behavior tests for the flat, self-describing forge_api facade."""

from __future__ import annotations

import inspect
import json
from types import SimpleNamespace

import pytest

import forge.api.members as members_mod
import forge_api


def test_help_catalog_covers_public_exports_and_metadata():
    payload = forge_api.help()
    catalog = payload["functions"]
    assert isinstance(catalog, dict)
    public_names = [name for name in forge_api.__all__ if callable(getattr(forge_api, name, None))]
    assert set(public_names) <= set(catalog)
    required = {"group", "doc", "signature", "params", "returns", "example"}
    for name in public_names:
        entry = catalog[name]
        assert required <= set(entry)
        assert entry["signature"] == str(inspect.signature(getattr(forge_api, name)))
        assert isinstance(entry["params"], list)
        assert entry["returns"]


def test_help_metadata_exposes_error_contract_and_side_effects():
    entry = forge_api.help("plan_structure")["functions"]["plan_structure"]
    assert entry["kind"] == "operation"
    assert entry["error_contract"]["raises"] == ["ForgeApiError"]
    assert "returns" in entry["error_contract"]
    assert entry["side_effects"] == "unknown"

def test_help_returns_detached_metadata():
    payload = forge_api.help("create_structure")
    payload["functions"]["create_structure"]["params"].clear()
    assert forge_api.help("create_structure")["functions"]["create_structure"]["params"]

def test_to_hex_rejects_invalid_ea_values():
    with pytest.raises(forge_api.ForgeApiError, match="ea must be an int"):
        forge_api.to_hex(True)
    with pytest.raises(forge_api.ForgeApiError, match="non-negative"):
        forge_api.to_hex(-1)
    assert forge_api.to_hex(0x401000) == "0x401000"


def test_grouped_api_returns_detached_groups_and_filters_meta():
    payload = forge_api.grouped(group="structures")
    assert set(payload) == {"module", "version", "groups"}
    assert set(payload["groups"]) == {"structures"}
    assert "create_structure" in payload["groups"]["structures"]
    payload["groups"]["structures"]["create_structure"]["params"].clear()
    assert forge_api.help("create_structure")["functions"]["create_structure"]["params"]


def test_get_structure_exposes_detached_provenance_and_abi_metadata():
    forge_api.create_structure("Evidence")
    live = forge_api._resolve_structure("Evidence")
    live.set_provenance(
        kind="cpp_synthesis",
        root_object_ea=0x401000,
        has_multiple_roots=True,
    )
    live.abi_metadata = {"rtti_name": "Evidence", "vtables": [{"slots": []}]}
    payload = forge_api.get_structure("Evidence")
    assert payload["provenance"]["kind"] == "cpp_synthesis"
    assert payload["provenance"]["root_object_ea"] == 0x401000
    assert payload["abi_metadata"]["rtti_name"] == "Evidence"
    payload["abi_metadata"]["vtables"].clear()
    assert forge_api.get_structure("Evidence")["abi_metadata"]["vtables"]


def test_public_transaction_rolls_back_catalog_changes(monkeypatch):
    from forge.api.store import StructureCatalog

    isolated = StructureCatalog()
    monkeypatch.setattr(forge_api, "catalog", isolated)
    monkeypatch.setattr(forge_api, "_structures", isolated)
    with pytest.raises(RuntimeError):
        with forge_api.transaction("rollback"):
            isolated["temporary"] = SimpleNamespace(
                name="temporary",
                members=[],
                main_offset=0,
                created_type_name=None,
                is_auto_named=False,
                pack=1,
                child_relationships=[],
                abi_metadata={},
                provenance=SimpleNamespace(),
            )
            raise RuntimeError("abort")
    assert "temporary" not in isolated
def test_function_info_rejects_malformed_domain_bounds(monkeypatch):
    class Functions:
        @staticmethod
        def get_at(_ea):
            return SimpleNamespace(start_ea=0x1000, end_ea=True)

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(functions=Functions()))
    monkeypatch.setattr(forge_api, "callers_of", lambda *_args: [])
    monkeypatch.setattr(forge_api, "callees_of", lambda *_args: [])
    assert forge_api.function_info(0x1000) is None


def test_function_info_rejects_reversed_domain_bounds(monkeypatch):
    class Functions:
        @staticmethod
        def get_at(_ea):
            return SimpleNamespace(start_ea=0x2000, end_ea=0x1000)

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(functions=Functions()))
    monkeypatch.setattr(forge_api, "callers_of", lambda *_args: [])
    monkeypatch.setattr(forge_api, "callees_of", lambda *_args: [])
    assert forge_api.function_info(0x2000) is None

def test_domain_status_is_headless_safe():
    status = forge_api.domain_status()
    assert status["preferred"] == "ida-domain"
    assert isinstance(status["available"], bool)


def test_domain_adapter_uses_database_open(fake_ida_domain):
    from forge.api import domain

    fake = SimpleNamespace()
    fake_ida_domain.current = fake
    assert domain.current_database() is fake


def test_domain_adapter_records_explicit_fallback():
    from forge.api import domain

    domain.clear_fallback_records()
    domain.sdk_fallback("test.capability", "test reason")
    assert domain.fallback_records()[0].capability == "test.capability"
    assert domain.fallback_records()[0].reason == "test reason"
def test_current_database_translates_open_type_error(monkeypatch):
    from forge.api import domain

    class Database:
        @staticmethod
        def open():
            raise TypeError("unsupported Database.open signature")

    monkeypatch.setattr(domain, "import_module", lambda _name: SimpleNamespace(Database=Database))

    with pytest.raises(domain.DomainUnavailable, match="requires an IDA Domain") as raised:
        domain.current_database()
    assert isinstance(raised.value.__cause__, TypeError)
    assert domain.current_database(required=False) is None

def test_database_open_value_error_is_normalized(monkeypatch):
    from forge.api import domain

    class Database:
        @staticmethod
        def open(*args, **kwargs):
            raise ValueError("invalid database path")

    monkeypatch.setattr(domain, "import_module", lambda _name: SimpleNamespace(Database=Database))

    with pytest.raises(domain.DomainUnavailable, match="could not open database") as raised:
        domain.open_database("bad.exe")
    assert isinstance(raised.value.__cause__, ValueError)

def test_domain_status_reports_preference():
    status = forge_api.domain_status()
    assert status["preferred"] == "ida-domain"
    assert isinstance(status["fallbacks"], list)

def test_domain_is_code_uses_bytes_classifier(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Bytes:
        def is_code_at(self, ea):
            assert ea == 0x401000
            return True

    domain.clear_fallback_records()
    monkeypatch.setattr(_real_hexrays, "_current_domain_database", lambda required=False: SimpleNamespace(bytes=Bytes()), raising=False)
    monkeypatch.setattr(_real_hexrays.ida_ida.idainfo, "procname", "x86", raising=False)
    assert _real_hexrays.is_code(0x401000) is True
    assert domain.fallback_records() == ()


def test_domain_is_code_failure_records_sdk_fallback(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Bytes:
        def is_code_at(self, _ea):
            raise RuntimeError("unsupported")

    domain.clear_fallback_records()
    monkeypatch.setattr(_real_hexrays, "_current_domain_database", lambda required=False: SimpleNamespace(bytes=Bytes()), raising=False)
    monkeypatch.setattr(_real_hexrays.ida_bytes, "get_full_flags", lambda _ea: 1, raising=False)
    monkeypatch.setattr(_real_hexrays.ida_bytes, "is_code", lambda _flags: False, raising=False)
    assert _real_hexrays.is_code(0x401000) is False
    assert any(item.capability == "bytes.is_code_at" for item in domain.fallback_records())


def test_domain_is_code_false_is_handled_without_sdk(monkeypatch, _real_hexrays):
    class Bytes:
        def is_code_at(self, _ea):
            return False

    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(bytes=Bytes()),
        raising=False,
    )
    monkeypatch.setattr(_real_hexrays.ida_ida.idainfo, "procname", "x86", raising=False)
    monkeypatch.setattr(
        _real_hexrays.ida_bytes,
        "is_code",
        lambda _flags: (_ for _ in ()).throw(AssertionError("SDK fallback used")),
        raising=False,
    )
    assert _real_hexrays.is_code(0x401000) is False



def test_domain_failure_records_caller_fallback(monkeypatch):
    from forge.api import domain

    class Xrefs:
        def code_refs_to_ea(self, _ea):
            raise RuntimeError("unsupported")

    class DomainDb:
        xrefs = Xrefs()

    domain.clear_fallback_records()
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "_ida_available", lambda: True)
    monkeypatch.setattr(forge_api, "_sdk_fallback", domain.sdk_fallback)
    with pytest.raises(AttributeError):
        forge_api.callers_of(0x401000)
    assert any(item.capability == "xrefs.callers_of" for item in domain.fallback_records())


def test_domain_is_imported_uses_import_lookup(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Imports:
        def get_import_at(self, ea):
            assert ea == 0x140001010
            return SimpleNamespace(address=ea)

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(imports=Imports(), base_address=0x140000000),
        raising=False,
    )
    assert _real_hexrays.is_imported(0x1010) is True
    assert domain.fallback_records() == ()


def test_domain_is_imported_fallback_records_failure(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Imports:
        def get_import_at(self, _ea):
            raise RuntimeError("unsupported")

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(imports=Imports(), base_address=0x140000000),
        raising=False,
    )
    monkeypatch.setattr(_real_hexrays.ida_segment, "getseg", lambda _ea: None, raising=False)
    monkeypatch.setattr(_real_hexrays.ida_nalt, "get_imagebase", lambda: 0x140000000, raising=False)
    _real_hexrays.cache.imported_ea.clear()
    assert _real_hexrays.is_imported(0x1010) is False
    assert any(item.capability == "imports.get_import_at" for item in domain.fallback_records())


def test_domain_is_imported_uses_segment_name(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Segments:
        def get_at(self, ea):
            assert ea == 0x140001010
            return object()

        def get_name(self, segment):
            assert segment is not None
            return ".plt"

    class Imports:
        def get_import_at(self, _ea):
            return None

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(
            imports=Imports(), segments=Segments(), base_address=0x140000000
        ),
        raising=False,
    )
    assert _real_hexrays.is_imported(0x1010) is True
    assert domain.fallback_records() == ()


def test_domain_is_imported_non_plt_segment_continues_cache(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Segments:
        def get_at(self, _ea):
            return object()

        def get_name(self, _segment):
            return ".text"

    class Imports:
        def get_import_at(self, _ea):
            return None

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(
            imports=Imports(), segments=Segments(), base_address=0x140000000
        ),
        raising=False,
    )
    monkeypatch.setattr(_real_hexrays.ida_nalt, "get_imagebase", lambda: 0x140000000, raising=False)
    _real_hexrays.cache.imported_ea.clear()
    assert _real_hexrays.is_imported(0x1010) is False
    assert domain.fallback_records() == ()


def test_domain_format_string_read_uses_cstring(monkeypatch):
    from forge.api import domain
    import forge.api.hexrays as hexrays_mod

    seen = []

    class Bytes:
        def get_cstring_at(self, ea):
            seen.append(ea)
            return "score=%u"

    class DomainDb:
        bytes = Bytes()
    class Ctype:
        obj = 1
        call = 2
        cast = 3
        str = 5
        ref = 4
    call = SimpleNamespace(
        x=SimpleNamespace(obj_ea=0x401200),
        a=[SimpleNamespace(op=Ctype.obj, obj_ea=0x401100)],
    )
    domain.clear_fallback_records()
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "_resolve_structure", lambda _name: SimpleNamespace())
    monkeypatch.setattr(forge_api, "_printf_call_expressions", lambda _cfunc: [call])
    monkeypatch.setattr(hexrays_mod, "decompile", lambda _ea: SimpleNamespace())
    monkeypatch.setattr(hexrays_mod, "ctype", Ctype(), raising=False)
    result = forge_api.name_members_from_printf("S", 0x401000)
    assert result == {"ok": True, "renamed": []}
    assert seen == [0x401100]


def test_domain_read_pointer_uses_qword(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Bytes:
        def get_qword_at(self, ea):
            assert ea == 0x401000
            return 0x140002000

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(bytes=Bytes(), pointer_size=8),
        raising=False,
    )
    assert _real_hexrays.read_pointer(0x401000) == 0x140002000
    assert domain.fallback_records() == ()


def test_domain_read_pointer_failure_records_fallback(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Bytes:
        def get_qword_at(self, _ea):
            raise RuntimeError("unsupported")

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(bytes=Bytes(), pointer_size=8),
        raising=False,
    )
    monkeypatch.setattr(_real_hexrays.ida_bytes, "get_64bit", lambda _ea: 7, raising=False)
    assert _real_hexrays.read_pointer(0x401000) == 7
    assert any(item.capability == "bytes.read_pointer" for item in domain.fallback_records())


def test_domain_bitness_selects_pointer_reader(monkeypatch, _real_hexrays):
    from forge.api import domain

    seen = []

    class Bytes:
        def get_dword_at(self, ea):
            seen.append(ea)
            return 0x1001

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(
            bytes=Bytes(), bitness=32, architecture="ARM"
        ),
        raising=False,
    )
    assert _real_hexrays.read_pointer(0x401000) == 0x1000
    assert seen == [0x401000]
    assert domain.fallback_records() == ()
 
 
def test_domain_read_pointer_zero_is_handled_without_sdk(monkeypatch, _real_hexrays):
    from forge.api import domain
    class Bytes:
        def get_dword_at(self, _ea):
            return 0

    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(pointer_size=4, architecture="x86", bytes=Bytes()),
        raising=False,
    )
    monkeypatch.setattr(
        _real_hexrays.ida_bytes,
        "get_32bit",
        lambda _ea: (_ for _ in ()).throw(AssertionError("SDK fallback used")),
        raising=False,
    )
    assert _real_hexrays.read_pointer(0x401000) == 0


def test_try_domain_call_records_failure_and_preserves_success(monkeypatch):
    from forge.api import domain

    domain.clear_fallback_records()
    handled, value = domain.try_domain_call(
        lambda: {"ok": True},
        capability="test.call",
        failure_reason="call failed",
    )
    assert handled is True
    assert value == {"ok": True}
    handled, value = domain.try_domain_call(
        lambda: (_ for _ in ()).throw(RuntimeError("unsupported")),
        capability="test.call.failure",
        failure_reason="call failed",
    )
    assert handled is False
    assert value is None
    assert domain.fallback_records()[-1].capability == "test.call.failure"


def test_import_slot_name_uses_direct_domain_import(monkeypatch):
    class Imports:
        def get_import_at(self, ea):
            assert ea == 0x140001008
            return SimpleNamespace(name="printf")

    monkeypatch.setattr(
        forge_api,
        "_domain_database_or_none",
        lambda: SimpleNamespace(imports=Imports()),
    )
    assert forge_api._import_slot_to_name(0x140001008) == "printf"


def test_import_slot_ordinal_uses_domain_name(monkeypatch):
    class Imports:
        def get_import_at(self, _ea):
            return SimpleNamespace(name=None, ordinal=17)

    class Names:
        def get_at(self, ea):
            assert ea == 0x140001008
            return "ordinal_alias"

    monkeypatch.setattr(
        forge_api,
        "_domain_database_or_none",
        lambda: SimpleNamespace(imports=Imports(), names=Names()),
    )
    assert forge_api._import_slot_to_name(0x140001008) == "ordinal_alias"


def test_domain_function_lookup_failure_records_fallback(monkeypatch):
    from forge.api import domain

    class Functions:
        def get_at(self, _ea):
            raise RuntimeError("unsupported")

    domain.clear_fallback_records()
    monkeypatch.setattr(
        forge_api,
        "_domain_database_or_none",
        lambda: SimpleNamespace(functions=Functions()),
    )
    monkeypatch.setattr(forge_api, "_import_slot_target_ea", lambda _ea: None)
    result = forge_api._resolve_import_slot_callees([0x140001000])
    assert result == [0x140001000]
    assert any(
        item.capability == "functions.resolve_import_slots"
        for item in domain.fallback_records()
    )
def test_domain_adapter_opens_clean_binary(fake_ida_domain, tmp_path, monkeypatch):
    from forge.api import domain

    calls = []

    class Database:
        @classmethod
        def open(cls, path, **kwargs):
            calls.append((path, kwargs))
            return SimpleNamespace(path=path, close=lambda: None)

    import ida_domain
    monkeypatch.setattr(ida_domain, "Database", Database)
    result = domain.open_database(tmp_path / "sample.exe", save_on_close=True, options="opts")
    assert result.path == tmp_path / "sample.exe"
    assert calls == [(tmp_path / "sample.exe", {"save_on_close": True, "args": "opts"})]

@pytest.mark.parametrize("options", ["", {}, False])
def test_domain_adapter_forwards_falsey_open_options(
    fake_ida_domain, tmp_path, monkeypatch, options
):
    from forge.api import domain

    calls = []

    class Database:
        @classmethod
        def open(cls, path, **kwargs):
            calls.append((path, kwargs))
            return SimpleNamespace(path=path)

    import ida_domain
    monkeypatch.setattr(ida_domain, "Database", Database)
    domain.open_database(tmp_path / "sample.exe", options=options)

    assert calls == [(tmp_path / "sample.exe", {"save_on_close": False, "args": options})]


def test_domain_adapter_omits_none_open_options(fake_ida_domain, tmp_path, monkeypatch):
    from forge.api import domain

    calls = []

    class Database:
        @classmethod
        def open(cls, path, **kwargs):
            calls.append((path, kwargs))
            return SimpleNamespace(path=path)

    import ida_domain
    monkeypatch.setattr(ida_domain, "Database", Database)
    domain.open_database(tmp_path / "sample.exe")

    assert calls == [(tmp_path / "sample.exe", {"save_on_close": False})]



@pytest.mark.parametrize("save_on_close", [True, False, 1, 0])
def test_domain_adapter_forwards_save_flag(
    fake_ida_domain, tmp_path, monkeypatch, save_on_close
):
    from forge.api import domain

    calls = []

    class Database:
        @classmethod
        def open(cls, path, **kwargs):
            calls.append((path, kwargs))
            return SimpleNamespace(path=path)

    import ida_domain
    monkeypatch.setattr(ida_domain, "Database", Database)
    domain.open_database(tmp_path / "sample.exe", save_on_close=save_on_close)

    assert calls == [
        (tmp_path / "sample.exe", {"save_on_close": save_on_close})
    ]
def test_domain_xref_helpers_resolve_function_starts(monkeypatch, _real_hexrays):
    from forge.api import domain

    class Xrefs:
        def code_refs_to_ea(self, _ea):
            return iter([0x401010])

        def data_refs_to_ea(self, _ea):
            return iter([0x402010])

    class Functions:
        def get_at(self, ea):
            return SimpleNamespace(start_ea=ea - 0x10)

    domain.clear_fallback_records()
    monkeypatch.setattr(
        _real_hexrays,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(xrefs=Xrefs(), functions=Functions()),
        raising=False,
    )
    assert _real_hexrays.get_funcs_calling_address(0x500000) == {0x401000}
    assert _real_hexrays.get_funcs_referencing_address(0x500000) == {0x401000, 0x402000}
    assert domain.fallback_records() == ()


def test_domain_adapter_open_failure_is_domain_error(fake_ida_domain, monkeypatch):
    from forge.api import domain

    class Database:
        @classmethod
        def open(cls, *args, **kwargs):
            raise RuntimeError("no idalib")

    import ida_domain
    monkeypatch.setattr(ida_domain, "Database", Database)
    with pytest.raises(domain.DomainUnavailable, match="could not open database"):
        domain.open_database("missing.exe")


def test_vtable_boundary_uses_domain_data_refs(monkeypatch):
    from forge.api import members

    class Xrefs:
        def data_refs_to_ea(self, ea):
            assert ea == 0x401010
            return iter([0x402000])

    monkeypatch.setattr(
        members,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(xrefs=Xrefs()),
    )
    assert members._vtable_has_data_reference(0x401010) is True


def test_vtable_function_name_uses_domain_names(monkeypatch):
    from forge.api import members

    class Names:
        def get_at(self, ea):
            assert ea == 0x401000
            return "named_function"

    monkeypatch.setattr(
        members,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(names=Names()),
    )
    assert members._function_name(0x401000) == "named_function"




def test_vtable_parser_uses_domain_name(monkeypatch):
    from forge.api import members

    monkeypatch.setattr(
        members,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(
            names=SimpleNamespace(get_at=lambda ea: "vftable_domain")
        ),
    )
    table = object.__new__(members.VirtualTable)
    table.address = 0x401000
    assert table._parse_vtable_name() == ("vftable_domain", True)
def test_domain_decompile_result_maps_contract(monkeypatch):
    from forge.api import domain

    class TypeInfo:
        def dstr(self):
            return "int"

    class Variable:
        def __init__(self, name, is_arg):
            self.name = name
            self.is_arg = is_arg
            self.type_info = TypeInfo()

    class X:
        is_object = True
        obj_ea = 0x402000

    class Call:
        x = X()

    class Function:
        def to_text(self, remove_tags=True):
            assert remove_tags is True
            return ["int f()", "return 0;"]

        local_variables = (Variable("arg", True), Variable("local", False))

        def find_calls(self):
            return [Call()]

    monkeypatch.setattr(domain, "decompile", lambda _db, _ea: Function())
    result = domain.decompile_result(object(), 0x401000)
    assert result == {
        "ea": 0x401000,
        "name": None,
        "pseudocode": "int f()\nreturn 0;",
        "lvars": [
            {"index": 0, "name": "arg", "type": "int", "is_arg": True},
            {"index": 1, "name": "local", "type": "int", "is_arg": False},
        ],
        "calls": [0x402000],
    }



def test_domain_decompile_result_keeps_stable_empty_name():
    from forge.api import domain

    function = SimpleNamespace(
        to_text=lambda remove_tags=True: ["void f()"],
        local_variables=[],
        find_calls=lambda: [],
    )
    original = domain.decompile
    domain.decompile = lambda _db, _ea: function
    try:
        assert domain.decompile_result(object(), 0x401000)["name"] is None
    finally:
        domain.decompile = original

def test_function_info_prefers_domain_function_metadata(monkeypatch):
    class Function:
        start_ea = 0x401000
        end_ea = 0x401120

    class Functions:
        def get_at(self, ea):
            return Function() if ea == 0x401010 else None

        def get_name(self, function):
            assert isinstance(function, Function)
            return "domain_func"

    class DomainDb:
        functions = Functions()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "callers_of", lambda *_args: [])
    monkeypatch.setattr(forge_api, "callees_of", lambda _ea: [0x402000])
    monkeypatch.setattr(forge_api, "signature", lambda _ea: "int domain_func()")
    result = forge_api.function_info(0x401010)
    assert result == {
        "name": "domain_func",
        "start_ea": 0x401000,
        "size": 0x120,
        "prototype": "int domain_func()",
        "callers": [],
        "callees": [0x402000],
        "refs": [],
    }

def test_function_info_normalizes_graph_rows(monkeypatch):
    class Functions:
        def get_at(self, _ea):
            return SimpleNamespace(start_ea=0x401000, end_ea=0x401010)

        def get_name(self, _function):
            return "f"

    monkeypatch.setattr(
        forge_api, "_domain_database_or_none", lambda: SimpleNamespace(functions=Functions())
    )
    monkeypatch.setattr(forge_api, "_resolve_import_slot_callees", lambda values: values)
    monkeypatch.setattr(forge_api, "callers_of", lambda *_args: [3, True, 2, 3, "bad"])
    monkeypatch.setattr(forge_api, "callees_of", lambda _ea: [5, 4, False, 5])
    monkeypatch.setattr(forge_api, "signature", lambda _ea: "void f()")

    result = forge_api.function_info(0x401000)

    assert result["callers"] == [2, 3]
    assert result["callees"] == [4, 5]
    assert result["refs"] == [2, 3]

def test_domain_database_session_closes_handle(monkeypatch):
    from forge.api import domain

    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            return self

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as handle:
        assert isinstance(handle, Handle)
    assert events == ["enter", "exit"]

def test_domain_database_session_translates_cleanup_value_error(monkeypatch):
    from forge.api import domain

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            raise ValueError("invalid cleanup state")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe"):
            pass
    assert isinstance(raised.value.__cause__, ValueError)


@pytest.mark.parametrize("error_type", [ValueError, TypeError, RuntimeError, OSError])
def test_domain_database_session_preserves_body_exception(monkeypatch, error_type):
    from forge.api import domain

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(error_type, match="body failure"):
        with domain.database_session("sample.exe"):
            raise error_type("body failure")

def test_domain_database_session_cleanup_failure_overrides_body_exception(monkeypatch):
    from forge.api import domain

    body_error = ValueError("body failure")
    cleanup_error = RuntimeError("cleanup failure")

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            assert exc is body_error
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value.__cause__ is cleanup_error

def test_domain_database_session_preserves_cleanup_chaining(monkeypatch):
    from forge.api import domain

    body_error = ValueError("body failure")
    cleanup_error = RuntimeError("cleanup failure")
    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value.__cause__ is cleanup_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None
    assert raised.value.__context__ is cleanup_error
def test_domain_database_session_translates_cleanup_type_error(monkeypatch):
    from forge.api import domain

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            raise TypeError("invalid cleanup state")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe"):
            pass
    assert isinstance(raised.value.__cause__, TypeError)


def test_domain_database_session_preserves_enter_keyboard_interrupt(monkeypatch):
    from forge.api import domain

    enter_error = KeyboardInterrupt("enter cancelled")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise enter_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")
            raise AssertionError("exit must not run after enter cancellation")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert raised.value is enter_error
    assert events == ["enter"]
def test_domain_database_session_translates_enter_failure(monkeypatch):
    from forge.api import domain

    enter_error = RuntimeError("enter failure")

    class Handle:
        def __enter__(self):
            raise enter_error

        def __exit__(self, exc_type, exc, tb):
            raise AssertionError("exit must not run after enter failure")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            pass
    assert raised.value.__cause__ is enter_error

def test_domain_database_session_preserves_open_failure_contract(monkeypatch):
    from forge.api import domain

    open_error = OSError("open failed")
    lifecycle = []

    def fail_open(*args, **kwargs):
        lifecycle.append("open")
        raise domain.DomainUnavailable("open unavailable") from open_error

    monkeypatch.setattr(domain, "open_database", fail_open)
    with pytest.raises(domain.DomainUnavailable, match="open unavailable") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("session body must not run")

    assert raised.value.__cause__ is open_error
    assert lifecycle == ["open"]

def test_domain_database_session_preserves_open_keyboard_interrupt(monkeypatch):
    from forge.api import domain

    open_error = KeyboardInterrupt("open cancelled")

    def fail_open(*args, **kwargs):
        raise open_error

    monkeypatch.setattr(domain, "open_database", fail_open)
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert raised.value is open_error

def test_domain_database_session_preserves_keyboard_interrupt(monkeypatch):
    from forge.api import domain

    body_error = KeyboardInterrupt("cancelled")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            return self

        def __exit__(self, exc_type, exc, tb):
            events.append(("exit", exc_type, exc))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert events == ["enter", ("exit", KeyboardInterrupt, body_error)]


def test_domain_database_session_forwards_open_arguments(monkeypatch):
    from forge.api import domain

    calls = []
    exit_args = []
    options = {}

    class Handle:
        def __enter__(self):
            return "active"

        def __exit__(self, exc_type, exc, tb):
            exit_args.append((exc_type, exc, tb))
            return False

    def fake_open(path, *, save_on_close, options):
        calls.append((path, save_on_close, options))
        return Handle()

    monkeypatch.setattr(domain, "open_database", fake_open)
    with domain.database_session(
        "sample.exe", save_on_close=True, options=options
    ) as active:
        assert active == "active"

    assert calls == [("sample.exe", True, options)]
    assert exit_args == [(None, None, None)]

def test_domain_database_session_normalizes_non_context_handle(monkeypatch):
    from forge.api import domain

    handle = object()
    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: handle)
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("session body must not run")

    assert isinstance(raised.value.__cause__, AttributeError)

def test_domain_database_session_normalizes_missing_exit(monkeypatch):
    from forge.api import domain

    class Handle:
        def __enter__(self):
            return self

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe"):
            pass

    assert isinstance(raised.value.__cause__, AttributeError)

def test_domain_database_session_normalizes_non_callable_exit(monkeypatch):
    from forge.api import domain

    class Handle:
        __exit__ = None

        def __enter__(self):
            return self

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe"):
            pass

    assert isinstance(raised.value.__cause__, TypeError)

def test_domain_database_session_normalizes_incompatible_exit_signature(
    monkeypatch,
):
    from forge.api import domain

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self):
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe"):
            pass

    assert isinstance(raised.value.__cause__, TypeError)

def test_domain_database_session_normalizes_keyword_only_exit_signature(
    monkeypatch,
):
    from forge.api import domain

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, *, exc_type, exc, tb):
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe"):
            pass

    assert isinstance(raised.value.__cause__, TypeError)

def test_domain_database_session_delivers_variadic_exit_arguments(monkeypatch):
    from forge.api import domain

    body_error = ValueError("body failure")
    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            seen.append(args)
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_allows_exit_traceback_mutation(monkeypatch):
    from forge.api import domain

    body_error = ValueError("body failure")
    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append(tb)
            assert tb is not None
            tb.tb_next = None
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert len(seen) == 1

def test_domain_database_session_preserves_sys_exception_state(monkeypatch):
    from forge.api import domain

    import sys

    body_error = ValueError("body failure")
    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb, sys.exc_info()))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    exc_type, exc, tb, state = seen[0]
    assert state == (exc_type, exc, tb)

def test_domain_database_session_preserves_empty_success_exception_state(
    monkeypatch,
):
    from forge.api import domain

    import sys

    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append(((exc_type, exc, tb), sys.exc_info()))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        pass

    assert seen == [((None, None, None), (None, None, None))]

def test_domain_database_session_supports_self_returning_handle(monkeypatch):
    from forge.api import domain

    body_error = ValueError("suppressed")
    handle_ref = []
    exits = []

    class Handle:
        def __enter__(self):
            handle_ref.append(self)
            return self

        def __exit__(self, exc_type, exc, tb):
            exits.append((exc_type, exc, tb))
            return self

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as active:
        assert active is handle_ref[0]
        raise body_error

    assert len(exits) == 1
    assert exits[0][1] is body_error

def test_domain_database_session_yields_distinct_active_handle(monkeypatch):
    from forge.api import domain

    raw_handle = object()
    active_handle = object()
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            return active_handle

        def __exit__(self, exc_type, exc, tb):
            events.append(("exit", exc_type, exc, tb))
            return False

    handle = Handle()
    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: handle)
    with domain.database_session("sample.exe") as active:
        assert active is active_handle
        assert active is not raw_handle

    assert events == ["enter", ("exit", None, None, None)]

def test_domain_database_session_delivers_active_body_exception_to_raw_handle(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("active body failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active
            raise body_error

    assert raised.value is body_error
    assert seen[0][1] is body_error
    assert seen[0][0] is ValueError
    assert seen[0][2] is not None

def test_domain_database_session_suppresses_distinct_active_exception(monkeypatch):
    from forge.api import domain

    body_error = ValueError("suppressed active failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as yielded:
        assert yielded is active
        raise body_error

    assert len(seen) == 1
    assert seen[0][1] is body_error

def test_domain_database_session_distinct_cleanup_failure_overrides_body(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("active body failure")
    cleanup_error = RuntimeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active
            raise body_error

    assert raised.value.__cause__ is cleanup_error
    assert seen[0][1] is body_error

def test_domain_database_session_distinct_cleanup_preserves_context(monkeypatch):
    from forge.api import domain

    body_error = ValueError("active body failure")
    cleanup_error = RuntimeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active
            raise body_error

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen[0][1] is body_error

def test_domain_database_session_preserves_distinct_active_keyboard_interrupt(
    monkeypatch,
):
    from forge.api import domain

    cancellation = KeyboardInterrupt("active cancelled")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active
            raise cancellation

    assert raised.value is cancellation
    assert seen[0][0] is KeyboardInterrupt
    assert seen[0][1] is cancellation
    assert seen[0][2] is not None

def test_domain_database_session_distinct_cleanup_failure_overrides_cancellation(
    monkeypatch,
):
    from forge.api import domain

    cancellation = KeyboardInterrupt("active cancelled")
    cleanup_error = RuntimeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active
            raise cancellation

    assert raised.value.__cause__ is cleanup_error
    assert seen[0][0] is KeyboardInterrupt
    assert seen[0][1] is cancellation

def test_domain_database_session_preserves_distinct_cleanup_keyboard_interrupt(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = KeyboardInterrupt("raw cleanup cancelled")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_preserves_distinct_cleanup_system_exit(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = SystemExit(17)
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SystemExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_preserves_distinct_cleanup_generator_exit(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = GeneratorExit()
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(GeneratorExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_suppresses_distinct_active_generator_exit(
    monkeypatch,
):
    from forge.api import domain

    cancellation = GeneratorExit()
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as yielded:
        assert yielded is active
        raise cancellation

    assert seen[0][0] is GeneratorExit
    assert seen[0][1] is cancellation
    assert seen[0][2] is not None

def test_domain_database_session_suppresses_distinct_active_system_exit(
    monkeypatch,
):
    from forge.api import domain

    cancellation = SystemExit(17)
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as yielded:
        assert yielded is active
        raise cancellation

    assert seen[0][0] is SystemExit
    assert seen[0][1] is cancellation
    assert seen[0][2] is not None

def test_domain_database_session_suppresses_distinct_active_keyboard_interrupt(
    monkeypatch,
):
    from forge.api import domain

    cancellation = KeyboardInterrupt("active cancelled")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as yielded:
        assert yielded is active
        raise cancellation

    assert seen[0][0] is KeyboardInterrupt
    assert seen[0][1] is cancellation
    assert seen[0][2] is not None

def test_domain_database_session_suppresses_distinct_active_body_exception(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("active body failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as yielded:
        assert yielded is active
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_suppresses_with_distinct_custom_truthy_result(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("active body failure")
    active = object()
    truthiness = []
    seen = []

    class Truthy:
        def __bool__(self):
            truthiness.append(True)
            return True

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return Truthy()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as yielded:
        assert yielded is active
        raise body_error

    assert truthiness == [True]
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_reraises_with_distinct_custom_falsey_result(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("active body failure")
    active = object()
    truthiness = []
    seen = []

    class Falsey:
        def __bool__(self):
            truthiness.append(True)
            return False

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return Falsey()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active
            raise body_error

    assert raised.value is body_error
    assert truthiness == [True]
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_truthiness_failure_overrides_distinct_body_error(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("active body failure")
    truthiness_error = RuntimeError("truthiness failure")
    active = object()
    seen = []

    class TruthinessFailure:
        def __bool__(self):
            raise truthiness_error

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return TruthinessFailure()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(RuntimeError) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active
            raise body_error

    assert raised.value is truthiness_error
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_ignores_distinct_success_cleanup_truthiness(
    monkeypatch,
):
    from forge.api import domain

    active = object()
    truthiness = []
    seen = []

    class TruthinessFailure:
        def __bool__(self):
            truthiness.append(True)
            raise RuntimeError("truthiness must not run")

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return TruthinessFailure()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe") as yielded:
        assert yielded is active

    assert truthiness == []
    assert seen == [(None, None, None)]

def test_domain_database_session_preserves_distinct_success_cleanup_keyboard_interrupt(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = KeyboardInterrupt("raw cleanup cancelled")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_preserves_distinct_success_cleanup_system_exit(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = SystemExit(17)
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SystemExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_preserves_distinct_success_cleanup_generator_exit(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = GeneratorExit()
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(GeneratorExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_error_normalizes(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = ValueError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_oserror_normalizes(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = OSError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_typeerror_normalizes(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = TypeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_runtimeerror_normalizes(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = RuntimeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_attributeerror_normalizes(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = AttributeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_valueerror_normalizes(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = ValueError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_keyboard_interrupt_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = KeyboardInterrupt("raw cleanup cancelled")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert raised.value.__context__ is None
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_system_exit_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = SystemExit(17)
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SystemExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert raised.value.__context__ is None
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_generator_exit_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = GeneratorExit()
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(GeneratorExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert raised.value.__context__ is None
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_error_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = ValueError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_oserror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = OSError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_typeerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = TypeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_runtimeerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = RuntimeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_attributeerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = AttributeError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_valueerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = ValueError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_keyboard_interrupt_cause(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = KeyboardInterrupt("raw cleanup cancelled")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_system_exit_cause(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = SystemExit("raw cleanup exited")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SystemExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_generator_exit_cause(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = GeneratorExit()
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(GeneratorExit) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is cleanup_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_oserror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = OSError("raw cleanup failure")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_domainunavailable_identity(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = domain.DomainUnavailable("raw cleanup unavailable")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert raised.value is not cleanup_error
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_distinct_success_cleanup_domainunavailable_subclass(
    monkeypatch,
):
    from forge.api import domain

    class SpecificUnavailable(domain.DomainUnavailable):
        pass

    cleanup_error = SpecificUnavailable("specific cleanup unavailable")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="cleanup failed") as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert type(raised.value) is domain.DomainUnavailable
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert isinstance(raised.value.__cause__, SpecificUnavailable)
    assert seen == [(None, None, None)]

def test_domain_database_session_cleanup_domainunavailable_subclass_message_isolated(
    monkeypatch,
):
    from forge.api import domain

    class SpecificUnavailable(domain.DomainUnavailable):
        pass

    cleanup_error = SpecificUnavailable("private cleanup detail")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert str(raised.value) == (
        "ida-domain database session cleanup failed for sample.exe"
    )
    assert "private cleanup detail" not in str(raised.value)
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_cleanup_domainunavailable_subclass_traceback(
    monkeypatch,
):
    from forge.api import domain

    class SpecificUnavailable(domain.DomainUnavailable):
        pass

    cleanup_error = SpecificUnavailable("private cleanup detail")
    active = object()
    seen = []

    class Handle:
        def __enter__(self):
            return active

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe") as yielded:
            assert yielded is active

    assert str(raised.value) == (
        "ida-domain database session cleanup failed for sample.exe"
    )
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__cause__.__traceback__ is not None
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_setup_attributeerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    setup_error = AttributeError("raw enter failure")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value.__cause__ is setup_error
    assert raised.value.__context__ is setup_error
    assert events == ["enter"]

def test_domain_database_session_setup_runtimeerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    setup_error = RuntimeError("raw enter failure")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value.__cause__ is setup_error
    assert raised.value.__context__ is setup_error
    assert events == ["enter"]
    from forge.api import domain


def test_domain_database_session_setup_typeerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    setup_error = TypeError("raw enter failure")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value.__cause__ is setup_error
    assert raised.value.__context__ is setup_error
    assert events == ["enter"]

def test_domain_database_session_setup_valueerror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    setup_error = ValueError("raw enter failure")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value.__cause__ is setup_error
    assert raised.value.__context__ is setup_error
    assert events == ["enter"]

def test_domain_database_session_setup_oserror_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    setup_error = OSError("raw enter failure")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value.__cause__ is setup_error
    assert raised.value.__context__ is setup_error
    assert events == ["enter"]

def test_domain_database_session_setup_domainunavailable_preserves_context(
    monkeypatch,
):
    from forge.api import domain

    setup_error = domain.DomainUnavailable("raw enter unavailable")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable, match="setup failed") as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value is not setup_error
    assert raised.value.__cause__ is setup_error
    assert raised.value.__context__ is setup_error
    assert events == ["enter"]

def test_domain_database_session_setup_keyboard_interrupt_preserves_identity(
    monkeypatch,
):
    from forge.api import domain

    setup_error = KeyboardInterrupt("raw enter cancelled")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value is setup_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events == ["enter"]

def test_domain_database_session_setup_system_exit_preserves_identity(
    monkeypatch,
):
    from forge.api import domain

    setup_error = SystemExit("raw enter exited")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SystemExit) as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value is setup_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events == ["enter"]

def test_domain_database_session_setup_generator_exit_preserves_identity(
    monkeypatch,
):
    from forge.api import domain

    setup_error = GeneratorExit()
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            raise setup_error

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(GeneratorExit) as raised:
        with domain.database_session("sample.exe"):
            raise AssertionError("body must not execute")

    assert raised.value is setup_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events == ["enter"]
    cleanup_error = KeyboardInterrupt("cleanup cancelled")
    events = []

    class Handle:
        def __enter__(self):
            events.append("enter")
            return self

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert raised.value is cleanup_error
    assert events == ["enter", "exit"]

def test_domain_database_session_body_keyboard_interrupt_truthy_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = KeyboardInterrupt("body cancelled")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert events[0][0] is KeyboardInterrupt
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_system_exit_truthy_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = SystemExit("body exited")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert events[0][0] is SystemExit
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_generator_exit_truthy_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = GeneratorExit()
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert events[0][0] is GeneratorExit
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_domainunavailable_truthy_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = domain.DomainUnavailable("body unavailable")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert events[0][0] is domain.DomainUnavailable
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_domainunavailable_subclass_truthy_suppresses(
    monkeypatch,
):
    from forge.api import domain

    class SpecificUnavailable(domain.DomainUnavailable):
        pass

    body_error = SpecificUnavailable("body unavailable")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert events[0][0] is SpecificUnavailable
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_keyboard_interrupt_falsey_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = KeyboardInterrupt("body cancelled")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events[0][0] is KeyboardInterrupt
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_system_exit_falsey_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = SystemExit("body exited")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SystemExit) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events[0][0] is SystemExit
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_generator_exit_falsey_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = GeneratorExit()
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(GeneratorExit) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events[0][0] is GeneratorExit
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_domainunavailable_falsey_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = domain.DomainUnavailable("body unavailable")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events[0][0] is domain.DomainUnavailable
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_body_domainunavailable_subclass_falsey_reraises(
    monkeypatch,
):
    from forge.api import domain

    class SpecificUnavailable(domain.DomainUnavailable):
        pass

    body_error = SpecificUnavailable("body unavailable")
    events = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            events.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SpecificUnavailable) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert events[0][0] is SpecificUnavailable
    assert events[0][1] is body_error
    assert events[0][2] is not None

def test_domain_database_session_success_cleanup_truthiness_isolated(
    monkeypatch,
):
    from forge.api import domain

    truth_error = RuntimeError("truth evaluation failed")
    truth_calls = []
    seen = []

    class FailingTruth:
        def __bool__(self):
            truth_calls.append(True)
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return FailingTruth()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        pass

    assert truth_calls == []
    assert seen == [(None, None, None)]

def test_domain_database_session_success_cleanup_truthy_return_isolated(
    monkeypatch,
):
    from forge.api import domain

    truth_calls = []
    seen = []

    class TruthyReturn:
        def __bool__(self):
            truth_calls.append(True)
            return True

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return TruthyReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        pass

    assert truth_calls == []
    assert seen == [(None, None, None)]

def test_domain_database_session_success_cleanup_domainunavailable_wraps(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = domain.DomainUnavailable("cleanup unavailable")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert raised.value is not cleanup_error
    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_success_cleanup_runtimeerror_wraps(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = RuntimeError("cleanup failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_success_cleanup_oserror_wraps(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = OSError("cleanup failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_success_cleanup_typeerror_wraps(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = TypeError("cleanup failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_success_cleanup_valueerror_wraps(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = ValueError("cleanup failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_success_cleanup_attributeerror_wraps(
    monkeypatch,
):
    from forge.api import domain

    cleanup_error = AttributeError("cleanup failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            pass

    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen == [(None, None, None)]

def test_domain_database_session_body_error_cleanup_runtimeerror_wraps(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    cleanup_error = RuntimeError("cleanup failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_cleanup_domainunavailable_wraps(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    cleanup_error = domain.DomainUnavailable("cleanup unavailable")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            raise cleanup_error

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(domain.DomainUnavailable) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is not cleanup_error
    assert str(raised.value) == "ida-domain database session cleanup failed for sample.exe"
    assert raised.value.__cause__ is cleanup_error
    assert raised.value.__context__ is cleanup_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_truthy_cleanup_suppresses_once(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    truth_calls = []
    seen = []

    class TruthyReturn:
        def __bool__(self):
            truth_calls.append(True)
            return True

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return TruthyReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert truth_calls == [True]
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_falsey_cleanup_evaluates_once(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    truth_calls = []
    seen = []

    class FalseyReturn:
        def __bool__(self):
            truth_calls.append(True)
            return False

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return FalseyReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert truth_calls == [True]
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_nonboolean_cleanup_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class NonBooleanReturn:
        pass

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return NonBooleanReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_integer_cleanup_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return 1

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_zero_cleanup_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return 0

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_true_cleanup_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_false_cleanup_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_none_cleanup_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return None

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_empty_tuple_cleanup_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return ()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_nonempty_tuple_cleanup_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return (False,)

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_one_element_list_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return [False]

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_two_element_list_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return [False, False]

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_len_only_cleanup_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class LenOnlyReturn:
        def __len__(self):
            return 1

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return LenOnlyReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_zero_len_only_cleanup_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class ZeroLenReturn:
        def __len__(self):
            return 0

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return ZeroLenReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_length_two_cleanup_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class LengthTwoReturn:
        def __len__(self):
            return 2

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return LengthTwoReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_boolean_len_cleanup_suppresses(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class BooleanLenReturn:
        def __len__(self):
            return True

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return BooleanLenReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_raising_len_cleanup_propagates(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    len_error = ValueError("length failed")
    seen = []

    class RaisingLenReturn:
        def __len__(self):
            raise len_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return RaisingLenReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is len_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_raising_bool_cleanup_propagates(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    bool_error = ValueError("truth failed")
    seen = []

    class RaisingBoolReturn:
        def __bool__(self):
            raise bool_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return RaisingBoolReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is bool_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_nonboolean_bool_cleanup_typeerror(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class NonBooleanBoolReturn:
        def __bool__(self):
            return 1

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return NonBooleanBoolReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(TypeError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_false_bool_cleanup_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class FalseBoolReturn:
        def __bool__(self):
            return False

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return FalseBoolReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert raised.value.__cause__ is None
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_notimplemented_bool_cleanup_typeerror(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class NotImplementedBoolReturn:
        def __bool__(self):
            return NotImplemented

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return NotImplementedBoolReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(TypeError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_successful_cleanup_does_not_truth_test_result(
    monkeypatch,
):
    from forge.api import domain

    seen = []

    class RaisingBoolReturn:
        def __bool__(self):
            raise AssertionError("successful cleanup must not truth-test result")

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return RaisingBoolReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        pass

    assert seen == [(None, None, None)]

def test_domain_database_session_successful_cleanup_releases_result(
    monkeypatch,
):
    from forge.api import domain

    seen = []

    class CleanupReturn:
        def __del__(self):
            seen.append("released")

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            assert (exc_type, exc, tb) == (None, None, None)
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        pass

    assert seen == ["released"]

def test_domain_database_session_body_error_false_cleanup_releases_result(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class CleanupReturn:
        def __bool__(self):
            return False

        def __del__(self):
            seen.append("released")

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            assert exc_type is ValueError
            assert exc is body_error
            assert tb is not None
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen == ["released"]

def test_domain_database_session_body_error_suppressed_cleanup_releases_result(
    monkeypatch,
):
    import gc
    import weakref

    from forge.api import domain

    body_error = ValueError("body failed")
    returned = []

    class CleanupReturn:
        def __bool__(self):
            return True

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            assert exc_type is ValueError
            assert exc is body_error
            assert tb is not None
            result = CleanupReturn()
            returned.append(weakref.ref(result))
            return result

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert returned[0]() is not None
    del body_error
    gc.collect()
    assert returned[0]() is None

def test_domain_database_session_body_error_truth_error_releases_cleanup_result(
    monkeypatch,
):
    import gc
    import weakref

    from forge.api import domain

    body_error = ValueError("body failed")
    truth_error = ValueError("truth failed")
    returned = []

    class CleanupReturn:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            assert exc is body_error
            result = CleanupReturn()
            returned.append(weakref.ref(result))
            return result

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is body_error
    assert returned[0]() is not None
    del truth_error
    del body_error
    del raised
    gc.collect()
    assert returned[0]() is None

def test_domain_database_session_truth_error_preserves_existing_cause(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    truth_error = ValueError("truth failed")
    cause_error = RuntimeError("original cause")
    truth_error.__cause__ = cause_error

    class CleanupReturn:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__cause__ is cause_error
    assert raised.value.__context__ is body_error

def test_domain_database_session_truth_error_preserves_existing_context(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    truth_error = ValueError("truth failed")
    context_error = RuntimeError("original context")
    truth_error.__context__ = context_error

    class CleanupReturn:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is body_error

def test_domain_database_session_body_error_keyboard_interrupt_truth_cleanup(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    interrupt = KeyboardInterrupt("truth interrupted")
    seen = []

    class CleanupReturn:
        def __bool__(self):
            raise interrupt

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(KeyboardInterrupt) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is interrupt
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_system_exit_truth_cleanup(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    exit_error = SystemExit("truth exited")
    seen = []

    class CleanupReturn:
        def __bool__(self):
            raise exit_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(SystemExit) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is exit_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_generator_exit_truth_cleanup(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    generator_exit = GeneratorExit()
    seen = []

    class CleanupReturn:
        def __bool__(self):
            raise generator_exit

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(GeneratorExit) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is generator_exit
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_body_error_custom_baseexception_truth_cleanup(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class CustomBaseError(BaseException):
        pass

    truth_error = CustomBaseError("truth failed")

    class CleanupReturn:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(CustomBaseError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_custom_baseexception_preserves_cause(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    truth_error = type("CustomBaseError", (BaseException,), {})("truth failed")
    cause_error = RuntimeError("original cause")
    truth_error.__cause__ = cause_error

    class CleanupReturn:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(type(truth_error)) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__cause__ is cause_error
    assert raised.value.__context__ is body_error

def test_domain_database_session_custom_baseexception_replaces_context(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")

    class CustomBaseError(BaseException):
        pass

    truth_error = CustomBaseError("truth failed")
    truth_error.__context__ = RuntimeError("original context")

    class CleanupReturn:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(CustomBaseError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is body_error

def test_domain_database_session_custom_baseexception_preserves_cause_replaces_context(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")

    class CustomBaseError(BaseException):
        pass

    truth_error = CustomBaseError("truth failed")
    cause_error = RuntimeError("original cause")
    truth_error.__cause__ = cause_error
    truth_error.__context__ = RuntimeError("original context")

    class CleanupReturn:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(CustomBaseError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__cause__ is cause_error
    assert raised.value.__context__ is body_error

def test_domain_database_session_truth_error_from_inner_handler_preserves_chain(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    inner_error = RuntimeError("inner failed")
    truth_error = ValueError("truth failed")

    class CleanupReturn:
        def __bool__(self):
            try:
                raise inner_error
            except RuntimeError as caught:
                truth_error.__context__ = caught
                raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is inner_error
    assert inner_error.__context__ is body_error

def test_domain_database_session_truth_error_from_nested_finally_preserves_chain(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    inner_error = RuntimeError("inner failed")
    truth_error = ValueError("truth failed")

    class CleanupReturn:
        def __bool__(self):
            try:
                try:
                    raise inner_error
                finally:
                    raise truth_error
            except ValueError:
                raise

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is inner_error
    assert inner_error.__context__ is body_error

def test_domain_database_session_truth_error_from_nested_except_finally_chain(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    inner_error = RuntimeError("inner failed")
    truth_error = ValueError("truth failed")

    class CleanupReturn:
        def __bool__(self):
            try:
                try:
                    raise inner_error
                except RuntimeError as caught:
                    assert caught is inner_error
                finally:
                    raise truth_error
            except ValueError:
                raise

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is body_error
    assert inner_error.__context__ is body_error

def test_domain_database_session_truth_error_from_plain_raise_uses_body_context(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    truth_error = ValueError("truth failed")

    class CleanupReturn:
        def __bool__(self):
            try:
                raise truth_error
            except ValueError:
                raise

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is body_error

def test_domain_database_session_truth_error_from_nested_with_uses_body_context(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    truth_error = ValueError("truth failed")
    inner_seen = []

    class InnerCM:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            inner_seen.append((exc_type, exc, tb))
            raise truth_error

    class CleanupReturn:
        def __bool__(self):
            with InnerCM():
                return True

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is body_error
    assert inner_seen[0][0] is None
    assert inner_seen[0][1] is None

def test_domain_database_session_truth_error_from_suppressing_nested_with(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    inner_error = RuntimeError("inner failed")
    truth_error = ValueError("truth failed")
    inner_seen = []

    class InnerCM:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            inner_seen.append((exc_type, exc, tb))
            return True

    class CleanupReturn:
        def __bool__(self):
            with InnerCM():
                raise inner_error
            raise truth_error

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return CleanupReturn()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert raised.value.__context__ is body_error
    assert inner_seen[0][0] is RuntimeError
    assert inner_seen[0][1] is inner_error
    assert inner_seen[0][2] is not None

def test_domain_database_session_body_error_empty_list_cleanup_reraises(
    monkeypatch,
):
    from forge.api import domain

    body_error = ValueError("body failed")
    seen = []

    class Handle:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return []

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None

def test_domain_database_session_honors_cleanup_suppression(monkeypatch):
    from forge.api import domain

    body_error = ValueError("suppressed body failure")
    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc))
            return True

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        raise body_error

    assert seen == [(ValueError, body_error)]

@pytest.mark.parametrize("exit_result, suppress", [(None, False), (0, False), ([], False), (False, False), (1, True), ([1], True), (True, True)])
def test_domain_database_session_uses_exit_truthiness(
    monkeypatch, exit_result, suppress
):
    from forge.api import domain

    body_error = ValueError("body failure")
    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc))
            return exit_result

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    if suppress:
        with domain.database_session("sample.exe"):
            raise body_error
    else:
        with pytest.raises(ValueError, match="body failure"):
            with domain.database_session("sample.exe"):
                raise body_error

    assert seen == [(ValueError, body_error)]

def test_domain_database_session_preserves_exit_truth_failure(monkeypatch):
    from forge.api import domain

    truth_error = RuntimeError("cannot evaluate cleanup result")
    body_error = ValueError("body failure")
    seen = []

    class ExitResult:
        def __bool__(self):
            raise truth_error

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc))
            return ExitResult()

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(RuntimeError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is truth_error
    assert seen == [(ValueError, body_error)]

def test_domain_database_session_delivers_exit_arguments(monkeypatch):
    from forge.api import domain

    body_error = ValueError("body failure")
    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with pytest.raises(ValueError) as raised:
        with domain.database_session("sample.exe"):
            raise body_error

    assert raised.value is body_error
    assert seen[0][0] is ValueError
    assert seen[0][1] is body_error
    assert seen[0][2] is not None


def test_domain_database_session_delivers_empty_exit_arguments(monkeypatch):
    from forge.api import domain

    seen = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            seen.append((exc_type, exc, tb))
            return False

    monkeypatch.setattr(domain, "open_database", lambda *args, **kwargs: Handle())
    with domain.database_session("sample.exe"):
        pass

    assert seen == [(None, None, None)]

def test_current_database_optional_outside_ida():
    from forge.api.domain import current_database

    assert current_database(required=False) is None

def test_is_type_prefers_domain_type_lookup(monkeypatch):
    class Types:
        def get_by_name(self, name):
            return object() if name == "Present" else None

    class DomainDb:
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    assert forge_api.is_type("Present") is True
    assert forge_api.is_type("Missing") is False



def test_type_of_uses_domain_type_details(monkeypatch):
    class TInfo:
        def is_udt(self):
            return False

        def is_ptr(self):
            return False

        def is_func(self):
            return True

        def dstr(self):
            return "int f()"

    class Types:
        def get_by_name(self, name):
            return TInfo() if name == "f" else None

        def get_details(self, _tinfo):
            return SimpleNamespace(name="f", declaration="int f()", size=8)

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    assert forge_api.type_of("f") == {
        "name": "f",
        "type": "int f()",
        "size": 8,
        "kind": "function",
        "members": [],
    }


def test_named_types_uses_domain_type_details(monkeypatch):
    class Types:
        def get_all(self):
            return iter([object(), object()])

        def get_details(self, tinfo):
            return SimpleNamespace(name="B" if tinfo is not None else "A")

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    assert forge_api.named_types() == ["B"]

    import ida_typeinf
    from forge.api import domain

    class Types:
        def get_by_name(self, _name):
            raise RuntimeError("unsupported")

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    monkeypatch.setattr(
        ida_typeinf.tinfo_t,
        "get_named_type",
        lambda self, *args, **kwargs: False,
        raising=False,
    )
    domain.clear_fallback_records()
    assert forge_api.is_type("Missing") is False
    assert any(item.capability == "types.is_type" for item in domain.fallback_records())


def test_domain_parse_function_decl_prefers_domain(monkeypatch):
    sentinel = object()
    calls = []

    class Types:
        def parse_one_declaration(self, library, declaration):
            calls.append((library, declaration))
            return sentinel

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    assert forge_api._parse_function_decl("int f(void)") is sentinel
    assert calls == [(None, "int f(void)")]
def test_set_func_proto_prefers_domain_application(monkeypatch):
    calls = []

    class Types:
        def apply_declaration_at(self, ea, declaration):
            calls.append((ea, declaration))
            return True

    class DomainDb:
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "signature", lambda _ea: "int f(int)")
    result = forge_api.set_func_proto(0x401000, "int f(int)")
    assert result == {"ok": True, "ea": 0x401000, "prototype": "int f(int)"}
    assert calls == [(0x401000, "int f(int)")]


def test_set_func_proto_domain_rejection_is_structured_error(monkeypatch):
    class Types:
        def apply_declaration_at(self, _ea, _declaration):
            raise ValueError("bad declaration")

    class DomainDb:
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    result = forge_api.set_func_proto(0x401000, "not valid")
    assert result == {"ok": False, "error": "could not parse declaration 'not valid'"}


def test_set_func_proto_domain_rejection_is_terminal(monkeypatch):
    class Types:
        def apply_declaration_at(self, _ea, _declaration):
            return False

    class DomainDb:
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "_parse_function_decl", lambda _decl: (_ for _ in ()).throw(AssertionError("SDK fallback")))

    result = forge_api.set_func_proto(0x401000, "not valid")
    assert result == {"ok": False, "error": "could not parse declaration 'not valid'"}

def test_rename_local_prefers_domain_wrappers(monkeypatch):
    events = []

    class Variable:
        def __init__(self, name):
            self.name = name

        def set_user_name(self, name):
            events.append(("set", self.name, name))
            self.name = name

    class Function:
        local_variables = (Variable("arg"), Variable("local"))

        def save_local_variable_info(self, variable, *, save_name=False):
            events.append(("save", variable.name, save_name))
            return save_name

    class Pseudocode:
        def decompile(self, _ea):
            return Function()

    class DomainDb:
        pseudocode = Pseudocode()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    assert forge_api.rename_local(0x401000, "arg", "renamed") is True
    assert forge_api.rename_local(0x401000, 1, "local2") is True
    assert events == [("set", "arg", "renamed"), ("save", "renamed", True), ("set", "local", "local2"), ("save", "local2", True)]

def test_set_lvar_types_prefers_domain_local_mutation(monkeypatch):
    events = []

    class Variable:
        def __init__(self, name, is_arg):
            self.name = name
            self.is_arg = is_arg

        def set_type(self, tinfo):
            events.append(("set", self.name, tinfo))
            return True

    class Function:
        local_variables = (Variable("arg", True), Variable("local", False))

        def save_local_variable_info(self, variable, *, save_type=False):
            events.append(("save", variable.name, save_type))
            return save_type

    class Types:
        def parse_one_declaration(self, library, declaration):
            events.append(("parse", library, declaration))
            return declaration

    class Pseudocode:
        def decompile(self, _ea):
            return Function()

    class DomainDb:
        pseudocode = Pseudocode()
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(
        forge_api,
        "_domain_decompile_result",
        lambda _db, _ea: {"pseudocode": "void *arg;"},
    )
    result = forge_api.set_lvar_types(0x401000, {"arg": "World *", "local": "*"})
    assert result == {
        "ok": True,
        "updated": [{"name": "arg", "ok": True}, {"name": "local", "ok": False}],
        "signature": "void *arg;",
    }
    assert events == [
        ("parse", None, "World *"),
        ("set", "arg", "World *"),
        ("save", "arg", True),
    ]

class FakeTinfo:
    """Minimal tinfo double that Member construction + display can use."""

    def __init__(self, name, size=4):
        self._name = name
        self._size = size

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

    def create_ptr(self, *args, **kwargs):
        return True


@pytest.fixture(autouse=True)
def _stub_member_tinfo(monkeypatch):
    """Route parse_user_tinfo -> FakeTinfo so members build without IDA."""

    def _fake_parse(declaration):
        name = (declaration or "u32").split()[0]
        return FakeTinfo(name)

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _fake_parse)


@pytest.fixture(autouse=True)
def _reset_store():
    # clear_structures was removed from the facade (2026-08-13: agents
    # used it to wipe the shared catalog mid-eval, erasing the persisted
    # store the GUI structure-builder reads). Tests reset through the
    # internal dict instead.
    forge_api._structures.clear()
    forge_api._state.current = None
    yield
    forge_api._structures.clear()
    forge_api._state.current = None

def test_resolve_import_slot_callees_prefers_domain_function_lookup(monkeypatch):
    class Function:
        start_ea = 0x402000

    class Functions:
        def get_at(self, ea):
            return Function() if ea == 0x401000 else None

    class DomainDb:
        functions = Functions()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    assert forge_api._resolve_import_slot_callees([0x401000]) == [0x402000]



def test_import_slot_name_prefers_domain_names_and_segments(monkeypatch):
    class Segment:
        pass

    class Names:
        def get_at(self, _ea):
            return "named_target"

    class Segments:
        def get_at(self, _ea):
            return Segment()

        def get_name(self, _segment):
            return ".text"

    class DomainDb:
        names = Names()
        segments = Segments()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    assert forge_api._import_slot_to_name(0x401000) == "named_target"

def test_add_named_sub_heads_prefers_domain_byte_discovery(monkeypatch):
    class Function:
        start_ea = 0x401000

    class Bytes:
        def get_data_size_at(self, ea):
            return 4

        def get_next_head(self, ea, end):
            return None if ea >= 0x401008 else 0x401008

    class Names:
        def get_at(self, ea):
            return "qword_401008" if ea == 0x401008 else None

    class Xrefs:
        def data_refs_to_ea(self, _ea):
            return iter(())

    class Functions:
        def get_at(self, _ea):
            return Function()

    class DomainDb:
        bytes = Bytes()
        names = Names()
        xrefs = Xrefs()
        functions = Functions()

    class Target:
        name = "global_probe"

        def __init__(self):
            self.members = []

        def get_member_by_offset(self, offset):
            return next((m for m in self.members if m["offset"] == offset), None)

    target = Target()
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(
        forge_api,
        "add_member",
        lambda structure, offset, type, name=None: target.members.append(
            {"structure": structure, "offset": offset, "type": type, "name": name}
        ),
    )
    forge_api._add_named_sub_heads(target, 0x401000, 0x10)
    assert target.members == [
        {"structure": "global_probe", "offset": 8, "type": "u32", "name": "qword"}
    ]
def test_help_catalog_lists_every_api_function():
    catalog = forge_api.help()
    functions = catalog["functions"]
    assert set(functions) == set(forge_api.__all__)
    for entry in functions.values():
        assert entry["signature"]
        assert isinstance(entry["params"], list)
        assert entry["returns"]
        assert entry["example"]
        assert entry["group"]

def test_recover_abi_structure_replaces_layout_and_persists_metadata():
    name = "AbiBuilderProbe"
    if name in forge_api.structures():
        forge_api.remove_structure(name)
    result = forge_api.recover_abi_structure(
        name,
        [{"offset": 0, "type": "u64", "name": "vptr"}],
        abi={
            "rtti_name": "fixture::Probe",
            "bases": [{"name": "fixture_Entity", "offset": 0}],
        },
    )
    assert result["name"] == name
    assert result["abi_metadata"]["rtti_name"] == "fixture::Probe"
    assert result["members"][0]["name"] == "vptr"


def test_recover_abi_structure_preserves_sites_and_provenance():
    """ABI rebuild keeps scan evidence and provenance: scanned_variables
    recorded on the prior member merge into the rebuilt ABI member at the
    same offset (reported under preserved_sites), and the cpp_synthesis
    provenance set by synthesize_cpp survives the rebuild untouched."""
    name = "AbiPreserveProbe"
    if name in forge_api.structures():
        forge_api.remove_structure(name)

    first = forge_api.synthesize_cpp(
        name,
        [{"offset": 0, "type": "u64", "name": "vptr"}],
        abi={"rtti_name": "fixture::Probe"},
        roots=[{"object_ea": 0x14001000, "function_ea": 0x140002750}],
        commit=False,
    )
    assert first["ok"] is True
    assert first["provenance"]["kind"] == "cpp_synthesis"

    # Scan evidence on the synthesized member (as deep_scan would record it).
    forge_api._resolve_structure(name).members[0].scanned_variables = {"v0"}

    rebuilt = forge_api.recover_abi_structure(
        name,
        [
            {"offset": 0, "type": "u64", "name": "vptr"},
            {"offset": 8, "type": "u32", "name": "id"},
        ],
        abi={"rtti_name": "fixture::Probe"},
    )

    assert rebuilt["preserved_sites"] == [{"offset": 0, "member": "vptr"}]
    target = forge_api._resolve_structure(name)
    assert target.get_member_by_offset(0).scanned_variables == {"v0"}
    assert target.get_member_by_offset(8).name == "id"
    provenance = target.provenance
    kind = (
        provenance.get("kind")
        if isinstance(provenance, dict)
        else getattr(provenance, "kind", None)
    )
    assert kind == "cpp_synthesis"


def test_help_topic_scoped():
    entry = forge_api.help("deep_scan")["functions"]["deep_scan"]
    assert entry["group"] == "scan"
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.help("does_not_exist")


def test_help_catalog_is_deterministically_ordered_and_topic_scoped():
    first = forge_api.help()
    names = list(first["functions"])
    expected = sorted(
        forge_api.__all__,
        key=lambda name: (first["functions"][name]["group"], name),
    )
    assert names == expected

    topic = forge_api.help("deep_scan")
    assert list(topic["functions"]) == ["deep_scan"]
    assert topic["functions"]["deep_scan"] == first["functions"]["deep_scan"]


def test_requires_ida_guard(monkeypatch):
    monkeypatch.setattr(forge_api, "_ida_available", lambda: False)
    with pytest.raises(forge_api.ForgeApiError, match="requires an IDA Pro session"):
        forge_api.decompile(1)


def test_to_hex_is_pure():
    assert forge_api.to_hex(0x401000) == "0x401000"


def test_intN_aliases_normalize_in_type_declarations():
    """R2.5/R3.2: the intN/uintN shorthand normalizes all the way to the
    IDA-native spellings (``int32`` → ``__int32`` etc.) so member types
    typed ``int32``/``uint64`` parse instead of silently vanishing from
    the committed cdecl."""
    from forge.api.members import normalize_type_declaration

    assert normalize_type_declaration("int8") == "__int8"
    assert normalize_type_declaration("int16") == "__int16"
    assert normalize_type_declaration("int32") == "__int32"
    assert normalize_type_declaration("int64") == "__int64"
    assert normalize_type_declaration("uint8") == "unsigned __int8"
    assert normalize_type_declaration("uint16") == "unsigned __int16"
    assert normalize_type_declaration("uint32") == "unsigned __int32"
    assert normalize_type_declaration("uint64") == "unsigned __int64"
    assert normalize_type_declaration("uint32 *") == "unsigned __int32 *"
    assert normalize_type_declaration("uint64[8]") == "unsigned __int64[8]"
    # R3.2: the alias chain endpoint — _DWORD chains through u32 to the
    # native token in the same pass.
    assert normalize_type_declaration("_DWORD") == "unsigned __int32"
    # unknown tokens are untouched — the parse path still fails loudly
    assert normalize_type_declaration("int33") == "int33"


def test_intN_aliases_add_member_accepts_shorthand(monkeypatch):
    """R2.5: add_member with intN/uintN shorthand succeeds (parse goes
    through the same normalize step as the display path)."""
    forge_api.create_structure("S")
    member = forge_api.add_member("S", 0x10, "int32", name="width")
    assert member["offset"] == 0x10
    assert member["name"] == "width"


def test_create_structure_pack_default_and_override():
    """R3.2 (F1): store structures default to packed (pack=1); a
    create_structure(pack=N) override is honored and exposed."""
    default = forge_api.create_structure("PackDefault")
    assert default["pack"] == 1

    padded = forge_api.create_structure("PackNatural", pack=None)
    assert padded["pack"] is None

    packed2 = forge_api.create_structure("PackTwo", pack=2)
    assert packed2["pack"] == 2
    assert forge_api.get_structure("PackTwo")["pack"] == 2


def test_set_pack_round_trip_and_validation():
    """R3.2 (F1): set_pack mutates the store attribute and persists it;
    non-int/negative values raise ForgeApiError."""
    forge_api.create_structure("PackMutable", pack=2)
    result = forge_api.set_pack("PackMutable", None)
    assert result == {"ok": True, "pack": None}
    assert forge_api.get_structure("PackMutable")["pack"] is None

    result = forge_api.set_pack("PackMutable", 8)
    assert result == {"ok": True, "pack": 8}
    assert forge_api.get_structure("PackMutable")["pack"] == 8

    with pytest.raises(forge_api.ForgeApiError):
        forge_api.set_pack("PackMutable", 0)
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.set_pack("PackMutable", -1)
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.set_pack("PackMutable", "1")
    # rejected values leave the attribute untouched
    assert forge_api.get_structure("PackMutable")["pack"] == 8


def test_duplicate_structure_carries_pack():
    """R3.2 (F1): a duplicated store structure keeps the source pack."""
    forge_api.create_structure("PackSource", pack=None)
    new_name = forge_api.duplicate_structure("PackSource")
    assert forge_api.get_structure(new_name)["pack"] is None
    forge_api.set_pack("PackSource", 4)
    new_name2 = forge_api.duplicate_structure("PackSource")
    assert forge_api.get_structure(new_name2)["pack"] == 4


def test_set_cdecl_wraps_pragma_pack(monkeypatch):
    """R3.2 (F1): every commit path lands in Structure.set_cdecl, which
    prepends ``#pragma pack(push, N)`` when the structure carries a pack
    and the text is not already wrapped (already-wrapped text passes
    through untouched; pack=None is raw)."""
    from forge.api import structure as structure_mod

    captured = []
    monkeypatch.setattr(
        structure_mod.forge_types,
        "create_type",
        lambda name, decl: captured.append((name, decl)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.Structure,
        "_apply_scanned_variable_types",
        lambda self, name, origin: None,
        raising=False,
    )

    body = "struct Packed { char c; unsigned __int64 w; };"

    s = structure_mod.Structure("Packed")
    s.pack = 1
    s.set_cdecl(body)
    assert captured and captured[0][1] == "#pragma pack(push, 1)\n" + body

    # already-wrapped text is never double-wrapped
    already = "#pragma pack(push, 1)\n" + body
    s.set_cdecl(already)
    assert captured[1][1] == already

    # pack=None opts out — raw text reaches create_type
    s.pack = None
    s.set_cdecl(body)
    assert captured[2][1] == body


def test_build_cdecl_skips_void_typed_members(monkeypatch):
    """R3.8: a void-typed member is skipped at pack time with a warning —
    IDA rejects `void` members ("Void type is forbidden here") and the
    failure used to be un-diagnosable."""
    from forge.api import structure as structure_mod
    from forge.api.members import Member, parse_user_tinfo

    class _VoidTinfo:
        def is_void(self):
            return True

        def is_floating(self):
            return False

        def is_int(self):
            return False

        def is_integral(self):
            return False

        def is_ptr(self):
            return False

        def is_array(self):
            return False

        def is_signed(self):
            return False

        def dstr(self):
            return "void"

        def get_size(self):
            return 0

    structure = structure_mod.Structure("V")
    structure.add_member(
        Member(0, _VoidTinfo(), None, 0)
    )
    structure.add_member(
        Member(8, parse_user_tinfo("u32"), None, 0)
    )
    structure.pack = 1

    monkeypatch.setattr(
        structure_mod.ida_typeinf,
        "print_tinfo",
        lambda *a, **k: "struct V { unsigned __int32 b; };",
        raising=False,
    )
    result = structure.build_cdecl()

    assert result is not None
    _, cdecl = result
    assert "void" not in cdecl
    assert "unsigned __int32" in cdecl

    # R3.10: a member with NO tinfo (None) renders as bare `void` through
    # tinfo_t(None) — same "Void type is forbidden here" rejection, and
    # is_void() is not callable on None. Must be skipped like void.
    structure = structure_mod.Structure("W")
    structure.add_member(
        Member(0, None, None, 0)
    )
    structure.add_member(
        Member(8, parse_user_tinfo("u32"), None, 0)
    )
    structure.pack = 1
    result = structure.build_cdecl()
    assert result is not None
    _, cdecl = result
    assert "void" not in cdecl
    assert "unsigned __int32" in cdecl


def test_commit_failure_reason_names_void_members(monkeypatch):
    """R3.8: when the parser rejects a declaration, the reason names the
    bare-void members (IDA's "Void type is forbidden here" names none);
    void * members are NOT flagged."""
    import ida_typeinf

    monkeypatch.setattr(
        ida_typeinf,
        "idc_parse_types",
        lambda cdecl, flags: 2,
        raising=False,
    )
    reason = forge_api._commit_failure_reason(
        "struct S {\n    void field_8;\n    void *fine;\n    void list[4];\n};",
        "S",
    )
    assert "field_8" in reason
    assert "list" in reason
    assert "fine" not in reason
    assert "forbids bare void" in reason


def test_pack_structure_and_headless_share_commit_core(monkeypatch):
    """R3.9: the GUI pack dialog and the headless commit build the SAME
    declaration and land in the SAME set_cdecl — the dialog is the only
    difference, so the two routes cannot diverge."""
    from forge.api import structure as structure_mod
    from forge.api.members import Member, parse_user_tinfo

    calls = []
    monkeypatch.setattr(
        structure_mod.ida_kernwin,
        "ask_text",
        lambda maxsize, text, *a, **k: text,
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, cdecl, origin=0, *, overwrite=None: (
            calls.append((cdecl, origin, overwrite)) or object()
        ),
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.ida_typeinf,
        "print_tinfo",
        lambda *a, **k: "struct P { unsigned __int32 x; };",
        raising=False,
    )

    store = {}
    gui = structure_mod.Structure("P")
    api = structure_mod.Structure("P")
    for structure in (gui, api):
        structure.add_member(Member(0, parse_user_tinfo("u32"), None, 0))

    gui.create_type_if_ready(store, headless=False)
    api.create_type_if_ready(store, headless=True)

    assert len(calls) == 2
    gui_call, api_call = calls
    # the GUI dialog pre-adds the pack wrapper (set_cdecl would add the
    # same line); the headless text reaches set_cdecl unwrapped and the
    # wrapper is added inside. Normalized, the declarations are
    # identical, and the already-wrapped GUI text is never double-wrapped.
    gui_text = gui_call[0].split("\n", 1)[1]
    assert gui_call[0].startswith("#pragma pack(push, 1)")
    assert gui_text == api_call[0]
    assert gui_call[1] == api_call[1]
    assert gui_call[2] is None
    assert api_call[2] is True


def test_commit_declaration_verb(monkeypatch):
    """R3.9: commit_declaration is the API form of the GUI pack dialog —
    exact text through the same set_cdecl chain, with name verification."""
    _commit_stubs(monkeypatch, set_result=object())
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    wrong = forge_api.commit_declaration("S", "struct Other { int x; };")
    assert wrong["ok"] is False
    assert "names 'Other'" in wrong["error"]

    result = forge_api.commit_declaration(
        "S", "struct S { unsigned __int32 x; };", overwrite=True
    )
    assert result["ok"] is True
    assert result["type_name"] == "S"
    assert result["applied_sites"] == []


def test_set_cdecl_pragma_survives_overwrite_gate(monkeypatch):
    """R3.2 (F1): the overwrite gate and the update_named_type branch
    parse the STRIPPED body (parse_decl rejects preprocessor lines),
    while create_type still receives the full wrapped text."""
    from importlib import import_module
    from types import SimpleNamespace

    from forge.api import structure as structure_mod

    parsed_texts = []
    captured = []
    monkeypatch.setattr(
        structure_mod.ida_typeinf,
        "parse_decl",
        lambda out_tif, idati, decl, flags: parsed_texts.append(decl) or "Packed",
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.ida_typeinf,
        "update_named_type",
        lambda idati, name, tinfo: True,
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.forge_types,
        "create_type",
        lambda name, decl: captured.append((name, decl)) or False,
        raising=False,
    )

    class _QMessageBox:
        Yes = 1
        No = 0

    qt_module = import_module("forge.util.qt")
    monkeypatch.setattr(
        qt_module, "QtWidgets", SimpleNamespace(QMessageBox=_QMessageBox)
    )

    body = "struct Packed { int u; unsigned int w; };"
    packed = structure_mod.Structure("Packed")
    packed.pack = 1
    packed.set_cdecl(body, overwrite=True)

    # first attempt (create_type) got the wrapped text, then the overwrite
    # gate AND the update branch parsed the stripped body
    assert captured[0][1] == "#pragma pack(push, 1)\n" + body
    assert parsed_texts == [
        "struct Packed { int u; unsigned int w; };",
        "struct Packed { int u; unsigned int w; };",
    ]


def test_create_structure_validate_pack_raises():
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.create_structure("BadPack", pack=0)
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.create_structure("BadPack2", pack="1")


def test_scan_sites_reports_persisted_and_live_rows(monkeypatch):
    """R3.6: scan_sites answers from the persisted netnode rows; falls
    back to the live member scan objects when nothing is persisted."""
    forge_api.create_structure("Sites")
    forge_api.add_member("Sites", 0, "u32", name="count")

    structure = forge_api._resolve_structure("Sites")
    structure.scan_sites_rows = [
        {
            "func_ea": 0x140001610,
            "var": "v1",
            "ea": 0x140001000,
            "type": None,
            "member_offset": 0,
        }
    ]
    assert forge_api.scan_sites("Sites") == structure.scan_sites_rows

    # no persisted rows yet — derive from the live scan objects
    structure.scan_sites_rows = []
    structure.members[0].scanned_variables = {
        _FakeScanSite(0x1400020F0, "node", 0x140001F10)
    }
    rows = forge_api.scan_sites("Sites")
    assert rows == [
        {
            "func_ea": 0x1400020F0,
            "var": "node",
            "ea": 0x140001F10,
            "type": None,
            "member_offset": 0,
        }
    ]


def test_refresh_scan_sites_recomputes_rows(monkeypatch):
    """R3.6: _refresh_scan_sites copies the live member scan objects into
    the persisted row list (the catalog payload then carries them)."""
    from forge.api.store import _live_scan_site_rows

    forge_api.create_structure("Fresh")
    forge_api.add_member("Fresh", 0, "u32", name="count")
    structure = forge_api._resolve_structure("Fresh")
    structure.members[0].scanned_variables = {
        _FakeScanSite(0x140001610, "v0", 0x140001000)
    }

    forge_api._refresh_scan_sites(structure)

    assert structure.scan_sites_rows == _live_scan_site_rows(structure)
    assert structure.scan_sites_rows[0]["var"] == "v0"


def test_create_type_reports_applied_sites_key(monkeypatch):
    """R3.5: a commit's result carries applied_sites (empty without scan
    records — the visibility that tells the agent to re-scan into the
    structure)."""
    _commit_stubs(monkeypatch, set_result=object())
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    result = forge_api.create_type("S", overwrite=True)

    assert result["ok"] is True
    assert result["applied_sites"] == []


class _FakeScanSite:
    """Hashable stand-in for a scan object (SimpleNamespace is unhashable
    on 3.14 and cannot live in member.scanned_variables sets)."""

    def __init__(self, func_ea, name, ea, tinfo=None):
        self.func_ea = func_ea
        self.name = name
        self.ea = ea
        self.tinfo = tinfo

    def apply_type(self, *args, **kwargs):
        return None


def test_create_type_persists_scan_sites_after_commit(monkeypatch):
    """R3.6: a successful commit re-persists the scan rows (netnode
    payload) so the IDB holds them after the worker drops."""
    _commit_stubs(monkeypatch, set_result=object())
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")
    structure = forge_api._resolve_structure("S")
    structure.members[0].scanned_variables = {
        _FakeScanSite(0x140001000, "a1", 0x140001000)
    }

    result = forge_api.create_type("S", overwrite=True)

    assert result["ok"] is True
    seen = {row["var"] for row in structure.scan_sites_rows}
    assert "a1" in seen


def test_apply_scanned_variables_row_fallback_after_reload(monkeypatch):
    """R3.8: after a catalog reload the live scan objects are gone —
    the commit re-applies from the PERSISTED rows ((func_ea, var) for
    locals, ea for globals), so the GUI's "apply across scanned
    locations" works across sessions."""
    import forge.api.structure as structure_mod

    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")
    structure = forge_api._resolve_structure("S")
    structure.scan_sites_rows = [
        {"func_ea": 0x401000, "var": "v0", "ea": 0x401000, "type": None,
         "member_offset": 0},
        {"func_ea": 0x140000000, "var": "g_world", "ea": 0x140006000,
         "type": None, "member_offset": 8},
    ]
    lvar_calls = []
    ea_calls = []
    monkeypatch.setattr(
        structure_mod,
        "_apply_lvar_pointer_type",
        lambda func_ea, var, name: lvar_calls.append((func_ea, var, name)) or True,
    )
    monkeypatch.setattr(
        structure_mod,
        "_apply_ea_pointer_type",
        lambda ea, tinfo: ea_calls.append((ea, tinfo)) or True,
    )
    monkeypatch.setattr(
        structure_mod.Structure,
        "_load_named_type",
        lambda self, name: object(),
        raising=False,
    )
    import forge.api.hexrays as hexrays_mod

    monkeypatch.setattr(
        hexrays_mod, "is_code", lambda ea: ea != 0x140006000, raising=False
    )
    monkeypatch.setattr(
        structure_mod.ida_typeinf,
        "tinfo_t",
        lambda *a, **k: _FakeTinfoWithCreatePtr(),
        raising=False,
    )

    structure._apply_scanned_variable_types("S", 0)

    assert lvar_calls == [(0x401000, "v0", "S")]
    assert len(ea_calls) == 1
    assert ea_calls[0][0] == 0x140006000
    assert structure.last_apply_sites == structure.scan_sites_rows


class _FakeTinfoWithCreatePtr:
    def create_ptr(self, *a, **k):
        return True


def test_create_type_re_resolves_placeholder_member_sizes(monkeypatch):
    """R2.1 (priority #1): a member added while its type was still the
    1-byte seed placeholder packs with the child's REAL size after the
    child commits — no chain-shift of later members (the eval's
    ``Outer.bag`` 16 → 1 B → grid/dispatch/stacks shift)."""
    import ida_typeinf

    from forge.api import members as members_mod
    from forge.api import structure as structure_mod

    child_committed = False

    def _parse(declaration):
        name = (declaration or "u32").split()[0]
        if name == "Child":
            # 1 B while Child is only a store placeholder; 40 B after the
            # child's own commit (the "real size 40" of the eval scenario).
            return FakeTinfo("Child", size=40 if child_committed else 1)
        return FakeTinfo(name, size={"u64": 8, "u16": 2}.get(name, 4))

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _parse, raising=False)

    forge_api.create_structure("Child")
    forge_api.create_structure("Parent")
    forge_api.add_member("Parent", 0x10, "Child *", name="child")
    forge_api.add_member("Parent", 0x38, "u32", name="count")

    # capture the rows build_cdecl pushes into the udt (print_tinfo is a
    # stub in this environment, so the udt rows are the layout evidence)
    recorded = []
    real_udt_factory = ida_typeinf.udt_type_data_t

    def _recording_udt():
        data = real_udt_factory()
        recorded.append(data)
        return data

    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", _recording_udt, raising=False)
    monkeypatch.setattr(
        ida_typeinf, "print_tinfo", lambda *a, **k: "struct Parent { };", raising=False
    )
    monkeypatch.setattr(
        ida_typeinf.tinfo_t, "get_named_type", lambda self, *a, **k: False, raising=False
    )
    captured_cdecls = []
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, cdecl, origin=0, *, overwrite=None: (
            captured_cdecls.append(cdecl) or object()
        ),
        raising=False,
    )
    assert forge_api.get_member("Parent", 0x10, member_name="child")["size"] == 1

    # commit Child (real size 40), then pack the parent
    child_committed = True
    result = forge_api.create_type("Parent")

    assert result["ok"] is True
    assert len(captured_cdecls) == 1
    rows = recorded[-1]
    # child packs at its REAL 40 bytes (relative to the 0x10 origin)
    assert rows[0].name == "child"
    assert rows[0].offset == 0x0
    assert rows[0].size == 40
    # count lands directly after the child: no padding row, no chain-shift
    assert rows[-1].name == "count"
    assert rows[-1].offset == 0x28
    assert rows[-1].size == 4
    assert not any(getattr(row, "name", "").startswith("gap_") for row in rows)


def test_add_member_rejects_c_keyword_name():
    """R2.6: a member named after a C keyword fails loudly instead of
    silently vanishing from the committed cdecl."""
    forge_api.create_structure("S")
    with pytest.raises(forge_api.ForgeApiError, match="C keyword"):
        forge_api.add_member("S", 0x10, "u32", name="inline")
    with pytest.raises(forge_api.ForgeApiError, match="C keyword"):
        forge_api.add_member("S", 0x10, "u32", name="int")
    # ordinary names still land
    member = forge_api.add_member("S", 0x10, "u32", name="inline_data")
    assert member["name"] == "inline_data"
    assert len(forge_api.get_structure("S")["members"]) == 1


def test_set_member_rejects_c_keyword_name():
    """R2.6: renaming a member to a C keyword fails loudly too."""
    forge_api.create_structure("S")
    forge_api.add_member("S", 0x10, "u32", name="count")
    with pytest.raises(forge_api.ForgeApiError, match="C keyword"):
        forge_api.set_member("S", 0x10, name="union")
    assert forge_api.get_member("S", 0x10)["name"] == "count"


def test_store_create_and_members():
    forge_api.create_structure("S1")
    member = forge_api.add_member("S1", 0x10, "u32", name="count")
    assert member["offset"] == 0x10
    assert member["name"] == "count"
    assert member["type"] == "u32"
    assert member["size"] == 4
    assert member["enabled"] is True

    structure = forge_api.get_structure("S1")
    assert structure["name"] == "S1"
    assert len(structure["members"]) == 1

    # structure=None routes to the selected (current) structure
    assert forge_api.get_structure()["name"] == "S1"

    forge_api.add_member("S1", 0x18, "u64")
    assert len(forge_api.get_structure("S1")["members"]) == 2

    forge_api.remove_members("S1", [0x10])
    assert [m["offset"] for m in forge_api.get_structure("S1")["members"]] == [0x18]

    assert forge_api.remove_structure("S1") is True
    assert forge_api.structures() == []


def test_structure_duplicate_names():
    forge_api.create_structure("X")
    forge_api.create_structure("Y")
    # renaming onto an existing name fails without raising
    assert forge_api.rename_structure("X", "Y") is False
    # renaming to a free name works and drops the old key
    assert forge_api.rename_structure("X", "Z") is True
    assert "Z" in forge_api.structures()
    assert "X" not in forge_api.structures()

    first = forge_api.duplicate_structure("Z")
    second = forge_api.duplicate_structure("Z")
    assert first == "Z Copy"
    assert second == "Z Copy 2"


def test_create_type_guards_missing_members():
    forge_api.create_structure("EmptyStruct")
    result = forge_api.create_type("EmptyStruct")
    assert result["ok"] is False
    assert "error" in result


def _commit_stubs(monkeypatch, *, parses=True, set_result=None):
    from forge.api import structure as structure_mod

    def fake_build_cdecl(self, start=None, end=None):
        return (self.name, f"struct {self.name} {{ int x; }};")

    def fake_set_cdecl(self, cdecl, origin=0, *, overwrite=None):
        if set_result is None:
            return None
        self.created_type_name = self.name
        return set_result

    monkeypatch.setattr(
        structure_mod.Structure, "build_cdecl", fake_build_cdecl, raising=False
    )
    monkeypatch.setattr(
        structure_mod.Structure,
        "_declaration_parses",
        staticmethod(lambda cdecl: parses),
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.Structure, "set_cdecl", fake_set_cdecl, raising=False
    )
    import ida_typeinf

    return ida_typeinf


def test_create_type_overwrite_disabled_reports_existing_type(monkeypatch):
    """R10: overwrite=False + an existing IDB type is a hard abort with the
    distinct error string — not the old generic set_cdecl-None lie."""
    ida_typeinf = _commit_stubs(monkeypatch)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")
    monkeypatch.setattr(
        ida_typeinf.tinfo_t, "get_named_type", lambda self, *a, **k: True, raising=False
    )

    result = forge_api.create_type("S")

    assert result == {"ok": False, "error": "type already exists (overwrite disabled)"}


def test_create_type_overwrite_validates_declaration_before_delete(monkeypatch):
    """R10: overwrite=True with an unparsable declaration must abort before
    the destructive delete (existing type untouched)."""
    ida_typeinf = _commit_stubs(monkeypatch, parses=False)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")
    monkeypatch.setattr(
        ida_typeinf.tinfo_t, "get_named_type", lambda self, *a, **k: True, raising=False
    )

    result = forge_api.create_type("S", overwrite=True)

    assert result == {"ok": False, "error": "declaration could not be parsed for overwrite"}


def test_create_type_overwrite_reports_failed_recreate(monkeypatch):
    """R10: overwrite=True where set_cdecl still fails (delete/recreate
    failure) returns the distinct recreate error, never "already exists";
    since the recovery eval (2026-08-13) it carries the parser reason."""
    _commit_stubs(monkeypatch, parses=True, set_result=None)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    result = forge_api.create_type("S", overwrite=True)

    assert result == {
        "ok": False,
        "error": (
            "failed to recreate type after delete — "
            "type parser accepted the declaration but no type materialized"
        ),
    }


def test_create_type_overwrite_success_returns_type_name(monkeypatch):
    """R10: overwriting an existing type succeeds and reports the commit."""
    _commit_stubs(monkeypatch, parses=True, set_result=object())
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    result = forge_api.create_type("S", overwrite=True)

    assert result["ok"] is True
    assert result["type_name"] == "S"
    assert "int x" in result["declaration"]


def test_create_type_pack_readiness_gate_returns_structured_error(monkeypatch):
    """Gap #9 wiring: create_type refuses to pack when the catalog readiness
    report is not ok — structured unresolved error, set_cdecl never reached."""
    _commit_stubs(monkeypatch, parses=True, set_result=object())
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    monkeypatch.setattr(
        forge_api.catalog,
        "pack_readiness",
        lambda name: SimpleNamespace(
            ok=False,
            to_dict=lambda: {
                "ok": False,
                "structure": name,
                "checked": 1,
                "blocked": [
                    {"member_name": "f", "status": "unresolved_reference"}
                ],
                "unresolved_types": ["Missing"],
                "error": (
                    "cannot pack in 'S': member 'f' @ 0x0 references "
                    "unresolved types: Missing"
                ),
            },
        ),
    )
    from forge.api import structure as structure_mod

    committed = []
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, *a, **k: committed.append(a) or object(),
        raising=False,
    )

    result = forge_api.create_type("S", overwrite=True)

    assert result["ok"] is False
    assert result["code"] == "unresolved_references"
    assert result["unresolved_types"] == ["Missing"]
    assert result["blocked_members"][0]["member_name"] == "f"
    assert "cannot pack in 'S'" in result["error"]
    assert committed == []


def test_commit_declaration_pack_readiness_gate_returns_structured_error(monkeypatch):
    """Gap #9 wiring on the declaration-text commit path: the readiness gate
    runs before set_cdecl and surfaces the structured unresolved error."""
    _commit_stubs(monkeypatch, parses=True, set_result=object())
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    monkeypatch.setattr(
        forge_api.catalog,
        "pack_readiness",
        lambda name: SimpleNamespace(
            ok=False,
            to_dict=lambda: {
                "ok": False,
                "structure": name,
                "checked": 1,
                "blocked": [],
                "unresolved_types": ["Missing"],
                "error": "cannot pack in 'S': unresolved types: Missing",
            },
        ),
    )
    from forge.api import structure as structure_mod

    committed = []
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, *a, **k: committed.append(a) or object(),
        raising=False,
    )

    result = forge_api.commit_declaration("S", "struct S { int f; };")

    assert result["ok"] is False
    assert result["code"] == "unresolved_references"
    assert result["unresolved_types"] == ["Missing"]
    assert committed == []


def test_rename_structure_refreshes_references_on_type_refile(monkeypatch):
    """Gap #10 rename path: renaming a structure whose IDA type is re-filed
    (created_type_name follows the rename) re-points the stored references
    through the payload-rewrite refresh helper."""
    forge_api.create_structure("X")
    structure = forge_api._resolve_structure("X")
    structure.created_type_name = "X"
    monkeypatch.setattr(
        type(structure),
        "rename_created_type",
        lambda self, old, new: setattr(self, "created_type_name", new) or True,
        raising=False,
    )
    calls = []
    monkeypatch.setattr(
        forge_api,
        "_refresh_references_after_rename",
        lambda old, new: calls.append((old, new)) or {"repointed_rows": 0},
        raising=False,
    )

    assert forge_api.rename_structure("X", "Y") is True
    assert calls == [("X", "Y")]


def test_rename_structure_without_created_type_skips_refresh(monkeypatch):
    """Renaming a structure that never committed a type must NOT trigger the
        references refresh (no re-file happened, no rows to re-point)."""
    forge_api.create_structure("X")
    calls = []
    monkeypatch.setattr(
        forge_api,
        "_refresh_references_after_rename",
        lambda old, new: calls.append((old, new)),
        raising=False,
    )

    assert forge_api.rename_structure("X", "Y") is True
    assert calls == []


# ---------------------------------------------------------------------------
# R11: headless finalize / finalize_all / create_child_types
# ---------------------------------------------------------------------------

def _commit_structure_stubs(monkeypatch):
    from forge.api import structure as structure_mod

    def fake_build_cdecl(self, start=None, end=None):
        return (self.name, f"struct {self.name} {{ int x; }};")

    def fake_set_cdecl(self, cdecl, origin=0, *, overwrite=None):
        self.created_type_name = self.name
        return object()

    def fail_pack(*_args, **_kwargs):
        raise AssertionError("pack_structure must not run headless")

    monkeypatch.setattr(
        structure_mod.Structure, "build_cdecl", fake_build_cdecl, raising=False
    )
    monkeypatch.setattr(
        structure_mod.Structure, "set_cdecl", fake_set_cdecl, raising=False
    )
    monkeypatch.setattr(
        structure_mod.Structure, "pack_structure", fail_pack, raising=False
    )
    return structure_mod


def test_finalize_headless_commits_with_type_name(monkeypatch):
    """R11: finalize routes through the headless commit chain and reports
    the created type name — no pack dialogs, no empty ``unresolved``."""
    _commit_structure_stubs(monkeypatch)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    result = forge_api.finalize("S")

    assert result == {
        "ok": True,
        "type_name": "S",
        "skipped": [],
        "applied_sites": [],
    }


def test_finalize_reports_error_when_commit_fails(monkeypatch):
    """R11: a non-child commit failure is a real error string — never the
    old 0-diagnostic ``{"ok": False, "unresolved": []}``."""
    from forge.api import structure as structure_mod

    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")
    monkeypatch.setattr(
        structure_mod.Structure,
        "build_cdecl",
        lambda self, start=None, end=None: (self.name, "struct S { int x; };"),
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, cdecl, origin=0, *, overwrite=None: None,
        raising=False,
    )

    result = forge_api.finalize("S")

    assert result == {
        "ok": False,
        "error": (
            "failed to create type — "
            "type parser accepted the declaration but no type materialized"
        ),
    }
    assert "unresolved" not in result


def test_finalize_reports_unresolved_children(monkeypatch):
    """R11: the child-resolution guard still reports unresolved children by
    name (that failure mode is not an error string)."""
    _commit_structure_stubs(monkeypatch)
    forge_api.create_structure("Parent")
    forge_api.create_structure("Missing")
    parent = forge_api._resolve_structure("Parent")
    parent.add_child_relationship(
        child_structure_name="Missing",
        parent_member_offset=0x10,
        parent_member_name="missing_ptr",
    )

    result = forge_api.finalize("Parent")

    assert result == {"ok": False, "unresolved": ["Missing"]}


def test_create_child_types_preserves_sorted_child_order(monkeypatch):
    class Child:
        def __init__(self, name):
            self.name = name
            self.created_type_name = None

        def create_type_if_ready(self, _structures, *, headless=False):
            self.created_type_name = self.name
            return object()

    class Target:
        child_relationships = [object()]

        def iter_child_structures(self, _structures):
            return iter([Child("Alpha"), Child("Zulu")])

        def get_unresolved_child_names(self, _structures):
            return []

    target = Target()
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(forge_api, "_resolve_structure", lambda *_args: target)
    result = forge_api.create_child_types("Parent")
    assert result == {"ok": True, "created": ["Alpha", "Zulu"], "skipped": []}

def test_finalize_all_runs_headless_subtree(monkeypatch):
    """R11: finalize_all walks subtrees headless (no pack dialogs) and
    reports the committed root."""
    _commit_structure_stubs(monkeypatch)
    forge_api.create_structure("Root")
    forge_api.add_member("Root", 0, "u32")

    results = forge_api.finalize_all()

    assert results == [
        {
            "structure": "Root",
            "ok": True,
            "created": True,
            "created_names": ["Root"],
            "error": None,
        }
    ]


# ---------------------------------------------------------------------------
# I.22 set_func_proto
# ---------------------------------------------------------------------------

def test_set_func_proto_applies_parsed_type(monkeypatch, _real_hexrays):
    """I.22: parses the declaration against the local til and applies via
    set_ti; the result carries the re-decompiled first line."""
    import ida_funcs
    import ida_lines
    import ida_typeinf

    monkeypatch.setattr(ida_lines, "tag_remove", lambda s: s, raising=False)
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: _pseudo_cfunc(["int __cdecl f(World *a1, char *a2)"]),
        raising=False,
    )
    stored = []
    monkeypatch.setattr(
        ida_funcs, "set_ti", lambda ea, t: stored.append((ea, t)), raising=False
    )
    monkeypatch.setattr(
        ida_typeinf,
        "parse_decl",
        lambda t, til, decl, flags: stored.append(decl) or "f",
        raising=False,
    )
    monkeypatch.setattr(ida_typeinf, "PT_TYP", 0, raising=False)
    monkeypatch.setattr(ida_typeinf, "PT_SIL", 1, raising=False)

    result = forge_api.set_func_proto(
        0x401000, "int __cdecl f(World *, char *)"
    )

    assert result["ok"] is True
    assert result["ea"] == 0x401000
    assert result["prototype"] == "int __cdecl f(World *a1, char *a2)"


def test_set_func_proto_reports_parse_failure(monkeypatch):
    import ida_typeinf

    monkeypatch.setattr(
        ida_typeinf, "parse_decl", lambda *a, **k: None, raising=False
    )
    result = forge_api.set_func_proto(0x401000, "not a decl")
    assert result == {"ok": False, "error": "could not parse declaration 'not a decl'"}


# ---------------------------------------------------------------------------
# I.8 root-type hint / I.10 auto-create scan structure
# ---------------------------------------------------------------------------

class _ScanVisitorStub:
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    def process(self):
        pass


def _scan_cfunc(root_name, root_type):
    """Fake cfunc whose first lvar is ``root_name`` of ``root_type``."""
    return SimpleNamespace(
        entry_ea=0x401000,
        argidx=(),
        get_lvars=lambda: [
            SimpleNamespace(
                name=root_name,
                type=lambda: FakeTinfo(root_type),
                location=7,
                defea=0x401010,
            )
        ],
    )


def test_deep_scan_clear_first_converges_on_newest_evidence(monkeypatch, _real_hexrays):
    """E21: clear_first wipes the target's members before the scan, so
    repeated scans replace stale evidence instead of accumulating it."""
    from forge.api.members import Member

    visits = {"n": 0}

    class _Vis:
        def __init__(self, *args, **kwargs):
            self.structure = args[3]  # (cfunc, origin, obj, structure)

        def process(self):
            visits["n"] += 1
            self.structure.add_member(
                Member(0x10 * visits["n"], FakeTinfo("u64"), None, 0)
            )

    monkeypatch.setattr(
        _real_hexrays, "decompile", lambda ea: _scan_cfunc("a1", "__int64"),
        raising=False,
    )
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo("u64"), raising=False)
    from importlib import import_module as _import

    scanner_mod = _import("forge.api.scanner")
    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _Vis, raising=False)
    forge_api.create_structure("S")

    first = forge_api.deep_scan(0x401000, var_name="a1", structure="S")
    assert len(first["members"]) == 1

    merged = forge_api.deep_scan(0x401000, var_name="a1", structure="S")
    assert [m["offset"] for m in merged["members"]] == [0x10, 0x20]

    cleared = forge_api.deep_scan(0x401000, var_name="a1", structure="S", clear_first=True)
    assert [m["offset"] for m in cleared["members"]] == [0x30]


def test_deep_scan_auto_creates_structure_and_auto_retypes_root(monkeypatch, _real_hexrays):
    """I.10/I.8: a bare deep_scan on an empty store auto-creates
    ``Structure`` (then ``Structure Copy``) and an ``__int64`` root is
    retyped to ``void *`` via modify_user_lvar_info before the visitor."""
    import ida_hexrays

    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: _scan_cfunc("a1", "__int64"), raising=False)
    monkeypatch.setattr(ida_hexrays, "lvar_locator_t", lambda loc, defea: SimpleNamespace(location=loc, defea=defea), raising=False)
    monkeypatch.setattr(ida_hexrays, "lvar_saved_info_t", type("S", (), {"__init__": lambda self: setattr(self, "ll", None) or setattr(self, "type", None)}), raising=False)
    monkeypatch.setattr(ida_hexrays, "MLI_TYPE", 0x10, raising=False)
    retyped = []
    monkeypatch.setattr(
        ida_hexrays,
        "modify_user_lvar_info",
        lambda ea, flags, lvi: retyped.append((flags, lvi.type.dstr())) or True,
        raising=False,
    )
    monkeypatch.setattr(_real_hexrays, "mark_cfunc_dirty", lambda ea, close=False: None, raising=False)
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl), raising=False)
    from importlib import import_module as _import
    scanner_mod = _import("forge.api.scanner")
    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _ScanVisitorStub, raising=False)

    first = forge_api.deep_scan(0x401000, var_name="a1")
    second = forge_api.deep_scan(0x401000, var_name="a1")

    assert first["structure"] == "Structure"
    assert second["structure"] == "Structure Copy"
    assert retyped, "root must be retyped"
    assert retyped[0][0] == 0x10
    assert retyped[0][1] == "void *"


def test_deep_scan_root_type_hint_overrides_integral_auto(monkeypatch, _real_hexrays):
    """I.8: an explicit root_type declaration wins over the integral auto type."""
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: _scan_cfunc("a1", "__int64"),
        raising=False,
    )
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl), raising=False)
    scanner_mod = __import__("importlib").import_module("forge.api.scanner")
    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _ScanVisitorStub, raising=False)
    calls = []
    monkeypatch.setattr(
        forge_api,
        "set_lvar_types",
        lambda ea, types, *, scope: calls.append((ea, types, scope))
        or {"ok": True, "updated": [{"name": "a1", "ok": True}]},
    )
    monkeypatch.setattr(_real_hexrays, "mark_cfunc_dirty", lambda ea, close=False: None, raising=False)

    forge_api.deep_scan(0x140001000, var_name="a1", root_type="World *")
    assert calls == [(0x401000, {"a1": "World *"}, "all")]

def test_deep_scan_root_retype_uses_absolute_ea_facade(monkeypatch, _real_hexrays):
    module_calls = []
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: _scan_cfunc("a1", "__int64"), raising=False)
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl), raising=False)
    scanner_mod = __import__("importlib").import_module("forge.api.scanner")
    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _ScanVisitorStub, raising=False)

    def facade_set(ea, types, *, scope):
        module_calls.append((ea, types, scope))
        return {"ok": True, "updated": [{"name": "a1", "ok": True}]}

    monkeypatch.setattr(forge_api, "set_lvar_types", facade_set)
    monkeypatch.setattr(_real_hexrays, "mark_cfunc_dirty", lambda ea, close=False: None, raising=False)
    forge_api.deep_scan(0x140001000, var_name="a1", root_type="World *")
    assert module_calls == [(0x401000, {"a1": "World *"}, "all")]

def test_deep_scan_returns_structured_root_retype_failure(monkeypatch, _real_hexrays):
    """A failed C++ stack-root retype must not escape as InvalidEAError."""
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: _scan_cfunc("a1", "__int64"),
        raising=False,
    )
    restored = []
    monkeypatch.setattr(
        forge_api,
        "set_lvar_types",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("Invalid effective address: 0x1100000000")
        ),
    )
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append(prior),
    )

    result = forge_api.deep_scan(0x1400017A0, var_name="a1", root_type="void *")

    assert result["ok"] is False
    assert "root lvar retype failed" in result["error"]
    assert restored == ["__int64"]

def test_deep_scan_skips_retype_for_pointer_root(monkeypatch, _real_hexrays):
    """I.8: an already-pointer root needs no retype (no visitor churn)."""
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: _scan_cfunc("a1", "World *"), raising=False)
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl), raising=False)
    from importlib import import_module as _import
    scanner_mod = _import("forge.api.scanner")
    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _ScanVisitorStub, raising=False)

    result = forge_api.deep_scan(0x401000, var_name="a1")

    assert result["structure"] == "Structure"
    assert result["members"] == []


def test_deep_scan_subobject_wraps_root_and_reports_base_offset(monkeypatch, _real_hexrays):
    """deep_scan subobject mode must root the shared visitor at a
    SubobjectScanObject (child coordinates) and report the subobject base —
    never leak root_type, never scan the whole parent."""
    from forge.api.scan_subobject import SubobjectScanObject

    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: _scan_cfunc("a1", "World *"),
        raising=False,
    )
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl), raising=False)
    from importlib import import_module as _import
    scanner_mod = _import("forge.api.scanner")

    captured = {}

    class _Vis:
        def __init__(self, *args, **kwargs):
            captured["args"] = args  # (cfunc, origin, obj, structure, ...)

        def process(self):
            pass

    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _Vis, raising=False)

    result = forge_api.deep_scan(
        0x401000, subobject={"base_offset": 0x1B60, "var_name": "a1"}
    )

    assert result["subobject"] == 0x1B60
    assert result["structure"] == "Structure"
    assert result["members"] == []
    root = captured["args"][2]
    assert isinstance(root, SubobjectScanObject)
    assert root.base_offset == 0x1B60
    # The wrapped parent keeps the parent variable identity (a1 : World *).
    assert root.name == "a1"
    assert root.tinfo is None  # tinfo deliberately dropped (child type unknown)


def test_deep_scan_subobject_rejects_root_type(monkeypatch, _real_hexrays):
    """Retyping the parent lvar to the child type would break the
    base-offset addressing — root_type with subobject is refused."""
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: _scan_cfunc("a1", "__int64"), raising=False)
    from importlib import import_module as _import
    scanner_mod = _import("forge.api.scanner")
    monkeypatch.setattr(
        scanner_mod, "NewDeepScanVisitor", type("V", (), {}), raising=False
    )

    result = forge_api.deep_scan(
        0x401000, root_type="Child *", subobject={"base_offset": 0x1B60, "var_name": "a1"}
    )

    assert result["ok"] is False
    assert "root_type is not supported with subobject" in result["error"]
def test_scan_result_marks_success_explicitly():
    target = type("Target", (), {"name": "Recovered", "members": []})()

    assert forge_api._scan_result(target) == {
        "ok": True,
        "structure": "Recovered",
        "members": [],
    }


# ---------------------------------------------------------------------------
# I.18 get_member / B11 collision reporting, I.21 link_child, I.9 to_vtable,
# I.11 skipped members
# ---------------------------------------------------------------------------

def test_get_member_honors_include_disabled(monkeypatch):
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32", name="a")
    forge_api.add_member("S", 0, "u64", name="b", enabled=False)
    forge_api.add_member("S", 8, "u32", name="gone", enabled=False)

    # the first match at offset 0 is the enabled member
    assert forge_api.get_member("S", 0)["name"] == "a"
    assert forge_api.get_member("S", 0, include_disabled=False)["name"] == "a"
    # offset 8's only member is disabled: E20c — hidden by DEFAULT now,
    # visible only with include_disabled=True
    assert forge_api.get_member("S", 8) is None
    assert forge_api.get_member("S", 8, include_disabled=False) is None
    assert forge_api.get_member("S", 8, include_disabled=True)["name"] == "gone"


def test_add_member_reports_collision(monkeypatch):
    forge_api.create_structure("S")
    first = forge_api.add_member("S", 0, "u32", name="a")
    assert first["collision"] is False
    second = forge_api.add_member("S", 2, "u32", name="b")
    assert second["collision"] is True


def test_link_child_creates_relationship_and_placeholder(monkeypatch):
    forge_api.create_structure("Parent")
    forge_api.create_structure("Child")

    linked = forge_api.link_child("Parent", 0x10, "Child")

    assert linked["offset"] == 0x10
    parent = forge_api._resolve_structure("Parent")
    child = forge_api._resolve_structure("Child")
    assert parent.child_relationships[0].child_structure_name == "Child"
    assert child.parent_relationships[0].parent_structure_name == "Parent"
    member = parent.get_member_by_offset(0x10)
    assert member.linked_child_structure_name == "Child"
    assert member.child_relation_kind == "pointer"


def test_link_child_rejects_unknown_child(monkeypatch):
    forge_api.create_structure("Parent")
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.link_child("Parent", 0x10, "Missing")


def test_to_vtable_creates_placeholder_when_no_member(monkeypatch):
    """I.9: an offset with no members converts to a vtable row via a
    placeholder instead of raising."""
    from forge.api import members as members_api

    forge_api.create_structure("S")
    monkeypatch.setattr(
        members_api.VirtualTable,
        "populate_virtual_functions",
        lambda self: None,
        raising=False,
    )
    monkeypatch.setattr(
        members_api.ida_name, "get_name", lambda ea: "vftable_140006358", raising=False
    )

    result = forge_api.to_vtable("S", 0x0, 0x140006358)

    assert result["offset"] == 0
    # the row is a vtable now (its name carries the parsed vtable name)
    from forge.api.members import VirtualTable

    converted = forge_api._resolve_structure("S").get_member_by_offset(0)
    assert isinstance(converted, VirtualTable)
    assert converted.address == 0x140006358


def test_to_vtable_preserves_disabled_member_name(monkeypatch):
    """I.9: converting an existing (disabled, named) member keeps its name."""
    from forge.api import members as members_api

    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32", name="type_id", enabled=False)
    monkeypatch.setattr(
        members_api.VirtualTable,
        "populate_virtual_functions",
        lambda self: None,
        raising=False,
    )
    monkeypatch.setattr(
        members_api.ida_name, "get_name", lambda ea: "vftable_140006358", raising=False
    )

    result = forge_api.to_vtable("S", 0x0, 0x140006358)

    assert result["name"] == "type_id"


def test_create_type_lists_skipped_disabled_members(monkeypatch):
    """I.11: committed types surface collision-disabled members under
    ``skipped``; enabling them clears the list."""
    import ida_typeinf

    from forge.api import structure as structure_mod

    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32", name="curated")
    forge_api.add_member("S", 0, "u64", name="shadowed", enabled=False)

    monkeypatch.setattr(
        structure_mod.Structure,
        "build_cdecl",
        lambda self, start=None, end=None: (self.name, f"struct {self.name} {{ int x; }};"),
        raising=False,
    )
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, cdecl, origin=0, *, overwrite=None: (
            self.__setattr__("created_type_name", self.name) or object()
        ),
        raising=False,
    )
    monkeypatch.setattr(
        ida_typeinf.tinfo_t, "get_named_type", lambda self, *a, **k: False, raising=False
    )
    monkeypatch.setattr(
        structure_mod.ida_typeinf, "parse_decl", lambda *a, **k: "S", raising=False
    )

    result = forge_api.create_type("S")
    assert result["skipped"] == ["shadowed"]

    result = forge_api.create_type("S", overwrite=True)
    assert result["skipped"] == ["shadowed"]

    s = forge_api._resolve_structure("S")
    for member in s.members:
        if not member.enabled:
            member.set_enabled(True)
    s.refresh_collisions()

    result = forge_api.create_type("S", overwrite=True)
    assert result["skipped"] == []


def test_api_returns_only_json_types():
    forge_api.create_structure("JsonSafe")
    forge_api.add_member("JsonSafe", 0x0, "u32", name="a")
    forge_api.add_member("JsonSafe", 0x4, "u64", name="b")
    serialized = json.dumps(forge_api.get_structure("JsonSafe"))
    data = json.loads(serialized)
    assert {m["name"] for m in data["members"]} == {"a", "b"}


def test_set_member_updates_fields_and_validates_offset():
    forge_api.create_structure("S")
    forge_api.add_member("S", 0x10, "u32", name="old")
    updated = forge_api.set_member(
        "S", 0x10, name="size", comment="the size", enabled=False
    )
    assert updated["name"] == "size"
    assert updated["comment"] == "the size"
    assert updated["enabled"] is False
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.set_member("S", 0x20, name="nope")


def test_nudge_members_rejects_overlap_nondestructive():
    forge_api.create_structure("N")
    forge_api.add_member("N", 0x0, "u32")
    forge_api.add_member("N", 0x8, "u32")
    # A move that would collide with a non-moved member is rejected.
    result = forge_api.nudge_members("N", [0x0], 8)
    assert result["ok"] is False
    assert [m["offset"] for m in forge_api.get_structure("N")["members"]] == [0x0, 0x8]
    # A legal move lands and keeps the table non-overlapping.
    result = forge_api.nudge_members("N", [0x0], 4)
    assert result["ok"] is True
    assert [m["offset"] for m in forge_api.get_structure("N")["members"]] == [0x4, 0x8]


# ---------------------------------------------------------------------------
# I.17 is_type / I.12 set_lvar_types + rename_local
# ---------------------------------------------------------------------------

def test_is_type_reports_idb_type_existence(monkeypatch):
    import ida_typeinf

    monkeypatch.setattr(
        ida_typeinf.tinfo_t, "get_named_type", lambda self, *a, **k: False, raising=False
    )
    assert forge_api.is_type("Missing") is False

    # the conftest tinfo double reports every named lookup as present
    monkeypatch.setattr(
        ida_typeinf.tinfo_t, "get_named_type", lambda self, *a, **k: True, raising=False
    )
    assert forge_api.is_type("Anything") is True


@pytest.fixture
def _real_hexrays(monkeypatch):
    """Load the real forge.api.hexrays module (the conftest stub drops it).

    The I.12 facade helpers import decompile/set_lvar_type from
    ``forge.api.hexrays`` at call time; the stub carries none of them, so
    these tests temporarily swap in the real module (test_scanner pattern).
    """
    import sys as _sys
    from importlib import util as _util
    from pathlib import Path

    hexrays_path = (
        Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "hexrays.py"
    )
    spec = _util.spec_from_file_location("forge.api.hexrays", hexrays_path)
    assert spec is not None and spec.loader is not None
    module = _util.module_from_spec(spec)
    saved = _sys.modules.get("forge.api.hexrays")
    _sys.modules["forge.api.hexrays"] = module
    spec.loader.exec_module(module)
    yield module
    if saved is not None:
        _sys.modules["forge.api.hexrays"] = saved
    else:
        _sys.modules.pop("forge.api.hexrays", None)


def _lvar_env(monkeypatch):
    import ida_hexrays
    import ida_lines

    monkeypatch.setattr(ida_lines, "tag_remove", lambda s: s, raising=False)

    class FakeLocator:
        def __init__(self, location, defea):
            self.location = location
            self.defea = defea

    class FakeSavedInfo:
        def __init__(self):
            self.ll = None
            self.type = None

    monkeypatch.setattr(
        ida_hexrays, "lvar_locator_t", lambda location, defea: FakeLocator(location, defea), raising=False
    )
    monkeypatch.setattr(ida_hexrays, "lvar_saved_info_t", FakeSavedInfo, raising=False)
    monkeypatch.setattr(ida_hexrays, "MLI_TYPE", 0x10, raising=False)

    lvars = [
        SimpleNamespace(name="a1", location=7, defea=0x401010, is_arg_var=True),
        SimpleNamespace(name="local", location=8, defea=0x401020, is_arg_var=False),
    ]
    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        get_lvars=lambda: lvars,
        pseudocode=[SimpleNamespace(line="World *a1;")],
    )
    return cfunc, lvars


def test_set_lvar_types_commits_via_modify_user_lvar_info(monkeypatch, _real_hexrays):
    """I.12: one call retypes ``a1`` via modify_user_lvar_info with the
    mandatory MLI_TYPE flag and an lvar_locator_t(location, defea)."""
    import ida_hexrays

    cfunc, _lvars = _lvar_env(monkeypatch)
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)
    seen = {}

    def fake_modify(ea, flags, lvi):
        seen["ea"] = ea
        seen["flags"] = flags
        seen["ll_location"] = lvi.ll.location
        seen["ll_defea"] = lvi.ll.defea
        seen["type"] = lvi.type
        return True

    monkeypatch.setattr(ida_hexrays, "modify_user_lvar_info", fake_modify, raising=False)
    parsed = []
    monkeypatch.setattr(
        members_mod, "parse_user_tinfo", lambda decl: (parsed.append(decl) or FakeTinfo("World *")),
        raising=False,
    )

    result = forge_api.set_lvar_types(0x401000, {"a1": "World *"})

    assert seen["ea"] == 0x401000
    assert seen["flags"] == 0x10  # MLI_TYPE is mandatory
    assert seen["ll_location"] == 7
    assert seen["ll_defea"] == 0x401010
    assert result["updated"] == [{"name": "a1", "ok": True}]
    assert result["signature"] == "World *a1;"


def test_set_lvar_types_star_maps_to_void_pointer(monkeypatch, _real_hexrays):
    """I.12: ``"*"`` shorthand resolves as ``void *``."""
    import ida_hexrays

    cfunc, _lvars = _lvar_env(monkeypatch)
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)
    monkeypatch.setattr(
        ida_hexrays, "modify_user_lvar_info", lambda *a, **k: True, raising=False
    )
    seen = []
    monkeypatch.setattr(
        members_mod, "parse_user_tinfo", lambda decl: (seen.append(decl) or FakeTinfo("void")),
        raising=False,
    )

    forge_api.set_lvar_types(0x401000, {"a1": "*"})

    assert seen == ["void *"]


def test_set_lvar_types_scope_all_retypes_locals(monkeypatch, _real_hexrays):
    """I.12: ``scope="all"`` retypes non-arg locals; ``scope="arg"`` skips
    them (per-entry ok:False)."""
    import ida_hexrays

    cfunc, _lvars = _lvar_env(monkeypatch)
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)
    monkeypatch.setattr(
        ida_hexrays, "modify_user_lvar_info", lambda *a, **k: True, raising=False
    )
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl.split()[0]), raising=False)

    arg_only = forge_api.set_lvar_types(0x401000, {"local": "u8"})
    assert arg_only["updated"] == [{"name": "local", "ok": False}]

    all_scope = forge_api.set_lvar_types(0x401000, {"local": "u8"}, scope="all")
    assert all_scope["updated"] == [{"name": "local", "ok": True}]


def test_rename_local_by_name_and_index(monkeypatch, _real_hexrays):
    """I.12: ``rename_local`` uses the surviving ``rename_lvar`` API, by
    name and by lvar index."""
    import ida_hexrays

    cfunc, _lvars = _lvar_env(monkeypatch)
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)
    calls = []
    monkeypatch.setattr(
        ida_hexrays, "rename_lvar", lambda ea, old, new: calls.append((ea, old, new)) or True,
        raising=False,
    )

    assert forge_api.rename_local(0x401000, "a1", "world") is True
    assert forge_api.rename_local(0x401000, 1, "local2") is True
    assert calls == [
        (0x401000, "a1", "world"),
        (0x401000, "local", "local2"),
    ]


def test_rename_local_rejects_bad_index(monkeypatch, _real_hexrays):
    import ida_hexrays

    cfunc, _lvars = _lvar_env(monkeypatch)
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)
    calls = []
    monkeypatch.setattr(
        ida_hexrays, "rename_lvar", lambda ea, old, new: calls.append(ea) or True,
        raising=False,
    )

    assert forge_api.rename_local(0x401000, 99, "x") is False
    assert calls == []


# ---------------------------------------------------------------------------
# I.16 decompile slicing + signature + force
# ---------------------------------------------------------------------------

def _pseudo_cfunc(lines):
    """Reusable fake cfunc for the decompile facade (real hexrays swapped)."""
    from types import SimpleNamespace as _SN

    lvar = _SN(
        index=0,
        type=lambda: FakeTinfo("u32"),
        name="a1",
        is_arg_var=True,
    )
    return _SN(
        entry_ea=0x401000,
        get_pseudocode=lambda: None,
        get_lvars=lambda: [lvar],
        pseudocode=[_SN(line=line) for line in lines],
        treeitems=[],
    )


def test_decompile_slices_pseudocode_lines(monkeypatch, _real_hexrays):
    """I.16: max_lines / line_range slice pseudocode only; lvars stay whole."""
    import ida_lines

    monkeypatch.setattr(ida_lines, "tag_remove", lambda s: s, raising=False)
    cfunc = _pseudo_cfunc(["l1", "l2", "l3", "l4"])
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)

    full = forge_api.decompile(0x401000)
    assert full["pseudocode"] == "l1\nl2\nl3\nl4"
    assert len(full["lvars"]) == 1

    capped = forge_api.decompile(0x401000, max_lines=2)
    assert capped["pseudocode"] == "l1\nl2"
    assert len(capped["lvars"]) == 1

    ranged = forge_api.decompile(0x401000, line_range=(2, 3))
    assert ranged["pseudocode"] == "l2\nl3"


def test_decompile_force_clears_cached_cfuncs(monkeypatch, _real_hexrays):
    """I.16: force=True calls clear_cached_cfuncs before decompiling."""
    import ida_hexrays
    import ida_lines

    monkeypatch.setattr(ida_lines, "tag_remove", lambda s: s, raising=False)
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: _pseudo_cfunc(["l1"]), raising=False)
    calls = []
    monkeypatch.setattr(
        ida_hexrays, "clear_cached_cfuncs", lambda: calls.append(1), raising=False
    )

    forge_api.decompile(0x401000, force=True)
    assert calls == [1]
    forge_api.decompile(0x401000)
    assert calls == [1]  # not cleared without force


def test_signature_returns_first_line(monkeypatch, _real_hexrays):
    """I.16: signature(ea) is the first pseudocode line; None for a non-
    function address."""
    import ida_lines

    monkeypatch.setattr(ida_lines, "tag_remove", lambda s: s, raising=False)
    monkeypatch.setattr(
        _real_hexrays, "decompile", lambda ea: _pseudo_cfunc(["void *__fastcall f(void *a1)", "body"]), raising=False
    )
    assert forge_api.signature(0x401000) == "void *__fastcall f(void *a1)"

    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: None, raising=False)
    assert forge_api.signature(0x401000) is None


# ---------------------------------------------------------------------------
# I.19 apply_type
# ---------------------------------------------------------------------------

def test_apply_type_redefine_range_order(monkeypatch):
    """I.19/R2.2/R2.3: redefine_range deletes auto names in the span, then
    DELIT_DELNAMES the whole span, applies with TINFO_DEFINITE, waits for
    auto-analysis, and re-applies the base head's name — the sequence that
    survives idalib's re-split race."""
    import ida_auto
    import ida_bytes
    import ida_name
    import ida_typeinf

    events = []
    monkeypatch.setattr(ida_bytes, "get_flags", lambda h: 1, raising=False)
    monkeypatch.setattr(ida_bytes, "is_head", lambda f: True, raising=False)
    monkeypatch.setattr(ida_bytes, "has_user_name", lambda f: False, raising=False)
    monkeypatch.setattr(ida_bytes, "DELIT_DELNAMES", 8, raising=False)
    monkeypatch.setattr(ida_bytes, "get_item_size", lambda ea: 4, raising=False)
    monkeypatch.setattr(
        ida_bytes,
        "del_items",
        lambda ea, flags, end: events.append(("del_items", ea, flags, end)),
        raising=False,
    )
    monkeypatch.setattr(
        ida_name,
        "get_name",
        lambda h: "g_outer_aggregate" if h == 0x401000 else f"qword_{h:x}",
        raising=False,
    )
    monkeypatch.setattr(ida_name, "SN_NOCHECK", 0x10, raising=False)
    monkeypatch.setattr(
        ida_name,
        "del_global_name",
        lambda h: events.append(("del_name", h)),
        raising=False,
    )
    monkeypatch.setattr(
        ida_name,
        "set_name",
        lambda ea, name, flags: events.append(("set_name", ea, name, flags)) or True,
        raising=False,
    )
    monkeypatch.setattr(
        ida_typeinf,
        "apply_tinfo",
        lambda ea, tinfo, flags: events.append(("apply", ea, tinfo.dstr())),
        raising=False,
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)
    monkeypatch.setattr(
        ida_auto, "auto_wait", lambda: events.append(("auto_wait",)), raising=False
    )

    result = forge_api.apply_type(0x401000, "OuterAggregate", redefine_range=True)

    kinds = [event[0] for event in events]
    assert kinds[0] == "del_name"
    # span delete uses DELIT_DELNAMES with the END ea (ea + size = 0x401004)
    assert ("del_items", 0x401000, 8, 0x401004) in events
    assert kinds[-1] == "apply"
    assert "auto_wait" in kinds
    # the base address keeps its own (user) name — restored after the
    # span delete removes it (DELIT_DELNAMES clears names of deleted items)
    assert ("set_name", 0x401000, "g_outer_aggregate", 0x10) in events
    assert result == {"ok": True, "ea": 0x401000, "type": "OuterAggregate"}


def test_apply_type_redefine_range_del_items_end_is_span_end(monkeypatch):
    """R2.4: the del_items 3rd argument is the END offset (ea + size) —
    never a length — so siblings past the span survive (the eval's
    char*[4] at 0x6000 eroded the .data tail through 0x6020+0x20)."""
    import ida_auto
    import ida_bytes
    import ida_name
    import ida_typeinf

    from forge.api import members as members_mod

    monkeypatch.setattr(
        members_mod, "parse_user_tinfo", lambda *a, **k: FakeTinfo("Big", size=0x40),
        raising=False,
    )
    monkeypatch.setattr(ida_bytes, "get_flags", lambda h: 1, raising=False)
    monkeypatch.setattr(ida_bytes, "is_head", lambda f: True, raising=False)
    monkeypatch.setattr(ida_bytes, "has_user_name", lambda f: False, raising=False)
    monkeypatch.setattr(ida_bytes, "DELIT_DELNAMES", 0x08, raising=False)
    monkeypatch.setattr(ida_bytes, "get_item_size", lambda ea: 0x40, raising=False)
    calls = []
    monkeypatch.setattr(
        ida_bytes,
        "del_items",
        lambda ea, flags, end: calls.append((ea, flags, end)),
        raising=False,
    )
    monkeypatch.setattr(ida_name, "get_name", lambda h: "", raising=False)
    monkeypatch.setattr(ida_name, "SN_NOCHECK", 0x10, raising=False)
    monkeypatch.setattr(ida_name, "set_name", lambda *a, **k: True, raising=False)
    monkeypatch.setattr(
        ida_typeinf, "apply_tinfo", lambda *a, **k: None, raising=False
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)
    monkeypatch.setattr(ida_auto, "auto_wait", lambda: None, raising=False)

    result = forge_api.apply_type(0x6000, "char *[4]", redefine_range=True)

    assert result["ok"] is True
    # 3rd argument is END = ea + size (0x40), never "length"
    assert calls == [(0x6000, 0x08, 0x6040)]




def test_apply_type_domain_rejection_is_structured_and_terminal(monkeypatch):
    class Types:
        def parse_one_declaration(self, *_args):
            return object()

        def apply_at(self, *_args):
            return False

    class DomainDb:
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "_require_ida", lambda: None)
    monkeypatch.setattr(
        forge_api,
        "_try_domain_method",
        lambda db, namespace, method, *args, **kwargs: (
            (True, object()) if method == "parse_one_declaration" else (True, False)
        ),
    )
    import forge.api.members as members
    monkeypatch.setattr(members, "parse_user_tinfo", lambda _decl: (_ for _ in ()).throw(AssertionError("SDK fallback")))

    result = forge_api.apply_type(0x401000, "u32")
    assert result == {"ok": False, "error": "could not apply type at 0x401000"}
def test_apply_type_redefine_range_skips_span_delete_for_user_named_head(monkeypatch):
    """R2.2: a user-named SUB-head inside the span blocks the full-span
    delete — the user's name is never swallowed; the type still applies at
    the head and a warning explains the partial coverage."""
    import ida_auto
    import ida_bytes
    import ida_name
    import ida_typeinf

    from forge.api import members as members_mod

    user_head = 0x401008
    monkeypatch.setattr(
        members_mod, "parse_user_tinfo", lambda *a, **k: FakeTinfo("Outer", size=0x20),
        raising=False,
    )
    # has_user_name receives the FLAGS, not the address — discriminate by
    # returning a distinct flag value for the user-named head
    monkeypatch.setattr(
        ida_bytes, "get_flags", lambda h: 2 if h == user_head else 1, raising=False
    )
    monkeypatch.setattr(ida_bytes, "is_head", lambda f: True, raising=False)
    monkeypatch.setattr(ida_bytes, "DELIT_DELNAMES", 8, raising=False)
    monkeypatch.setattr(
        ida_bytes, "has_user_name", lambda f: f == 2, raising=False
    )
    monkeypatch.setattr(ida_bytes, "get_item_size", lambda ea: 0x20, raising=False)
    del_calls = []
    monkeypatch.setattr(
        ida_bytes,
        "del_items",
        lambda ea, flags, end: del_calls.append((ea, flags, end)),
        raising=False,
    )
    monkeypatch.setattr(
        ida_name,
        "get_name",
        lambda h: "user_slot" if h == user_head else f"qword_{h:x}",
        raising=False,
    )
    monkeypatch.setattr(
        ida_name, "del_global_name", lambda h: None, raising=False
    )
    applied = []
    monkeypatch.setattr(
        ida_typeinf,
        "apply_tinfo",
        lambda ea, tinfo, flags: applied.append(ea),
        raising=False,
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)
    monkeypatch.setattr(ida_auto, "auto_wait", lambda: None, raising=False)

    result = forge_api.apply_type(0x401000, "OuterAggregate", redefine_range=True)

    assert result["ok"] is True
    assert del_calls == []  # no span delete — the user name must survive
    assert applied == [0x401000]  # single-item apply only


def test_apply_type_redefine_range_warns_on_resplit_race(monkeypatch):
    """R2.3: when the item re-splits to a smaller item after the apply
    (idalib deferred-analysis race), one retry runs and the result carries
    a warning instead of silently reporting a full-span item."""
    import ida_auto
    import ida_bytes
    import ida_name
    import ida_typeinf

    from forge.api import members as members_mod

    monkeypatch.setattr(
        members_mod, "parse_user_tinfo", lambda *a, **k: FakeTinfo("Outer", size=0x140),
        raising=False,
    )
    monkeypatch.setattr(ida_bytes, "get_flags", lambda h: 1, raising=False)
    monkeypatch.setattr(ida_bytes, "is_head", lambda f: True, raising=False)
    monkeypatch.setattr(ida_bytes, "has_user_name", lambda f: False, raising=False)
    monkeypatch.setattr(ida_bytes, "DELIT_DELNAMES", 8, raising=False)
    monkeypatch.setattr(ida_bytes, "get_item_size", lambda ea: 1, raising=False)
    monkeypatch.setattr(
        ida_bytes, "del_items", lambda *a, **k: None, raising=False
    )
    monkeypatch.setattr(ida_name, "get_name", lambda h: "", raising=False)
    monkeypatch.setattr(ida_name, "SN_NOCHECK", 0x10, raising=False)
    monkeypatch.setattr(ida_name, "set_name", lambda *a, **k: True, raising=False)
    applies = []
    monkeypatch.setattr(
        ida_typeinf,
        "apply_tinfo",
        lambda ea, tinfo, flags: applies.append(ea),
        raising=False,
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)
    monkeypatch.setattr(ida_auto, "auto_wait", lambda: None, raising=False)

    result = forge_api.apply_type(0x1400060B8, "Outer", redefine_range=True)

    assert result["ok"] is True
    assert "re-split" in result["warning"]
    assert len(applies) == 2  # span apply + one retry (early return)


def test_apply_type_parse_failure_reports_error(monkeypatch):
    """I.19: an unparsable declaration that is not a store structure returns
    an error dict instead of raising."""
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: None, raising=False)
    result = forge_api.apply_type(0x401000, "NotParsable */")
    assert result == {"ok": False, "error": "could not parse declaration 'NotParsable */'"}

def test_apply_type_prefers_domain_for_simple_declaration(monkeypatch):
    events = []

    class Tinfo:
        def dstr(self):
            return "int"

    class Types:
        def parse_one_declaration(self, library, declaration):
            events.append(("parse", library, declaration))
            return Tinfo()

        def apply_at(self, tinfo, ea):
            events.append(("apply", tinfo, ea))
            return True

    class DomainDb:
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    result = forge_api.apply_type(0x401000, "int")
    assert result == {"ok": True, "ea": 0x401000, "type": "int"}
def test_apply_type_domain_verifies_read_back_before_trusting(monkeypatch):
    """R2.5 (recovery eval 2026-08-30): ``domain.apply_at`` can report
    success while idalib's deferred analysis drops the item type, so the
    facade must read the tinfo back (``ida_nalt.get_tinfo(tinfo_out, ea)``)
    before trusting it. When the read-back lands the type, apply_type
    returns the VERIFIED domain result and does NOT fall through to the
    SDK apply path."""
    import ida_nalt
    import ida_typeinf

    class Tinfo:
        def dstr(self):
            return "int"

    class Types:
        def parse_one_declaration(self, library, declaration):
            return Tinfo()

        def apply_at(self, tinfo, ea):
            return True

    class DomainDb:
        types = Types()

    sdk_applies = []
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    read_backs = []
    monkeypatch.setattr(
        ida_nalt,
        "get_tinfo",
        lambda tinfo_out, ea: read_backs.append(ea) or True,
        raising=False,
    )
    monkeypatch.setattr(
        ida_typeinf,
        "apply_tinfo",
        lambda ea, tinfo, flags: sdk_applies.append(ea),
        raising=False,
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)

    result = forge_api.apply_type(0x401000, "int")

    # the read-back verified the tinfo actually landed at the EA
    assert read_backs == [0x401000]
    assert result == {"ok": True, "ea": 0x401000, "type": "int"}
    assert sdk_applies == [], "verified domain result must not fall through to the SDK"


def test_apply_type_domain_false_success_falls_through_to_sdk(monkeypatch):
    """R2.5: when domain ``apply_at`` reports success but the read-back
    ``ida_nalt.get_tinfo`` does NOT land the type (idalib dropped it), the
    facade must not trust the false domain success — it falls through to the
    definitive SDK apply path (``ida_typeinf.apply_tinfo``) so the type is
    actually committed."""
    import ida_nalt
    import ida_typeinf

    class Types:
        def parse_one_declaration(self, library, declaration):
            return FakeTinfo("int")

        def apply_at(self, tinfo, ea):
            return True

    class DomainDb:
        types = Types()

    sdk_applies = []
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda tinfo_out, ea: False, raising=False)
    monkeypatch.setattr(
        ida_typeinf,
        "apply_tinfo",
        lambda ea, tinfo, flags: sdk_applies.append(ea),
        raising=False,
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)

    result = forge_api.apply_type(0x401000, "int")

    assert sdk_applies == [0x401000], "unverified domain success must fall through to the SDK"
    assert result == {"ok": True, "ea": 0x401000, "type": "int"}


def test_scan_from_allocation_orchestrates(monkeypatch):
    """I.23/I.26: scan_from_allocation finds the HEAP row, auto-builds the
    structure, scans with recurse_calls, converts the vtable, then commits
    with overwrite=True."""
    calls = []
    rows = [
        {
            "ea": 0x401000,
            "var": "a1",
            "line": "a1 = malloc(0x40)",
            "kind": "HEAP",
            "size_hint": 0x40,
            "callee": None,
        }
    ]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    scanned = {}

    def _fake_deep_scan(ea, *, var_name, structure, recurse_calls, root_type, **k):
        scanned.update(var_name=var_name, structure=structure, recurse_calls=recurse_calls, root_type=root_type)
        return {"structure": structure, "members": [{"name": "m0"}]}

    monkeypatch.setattr(forge_api, "deep_scan", _fake_deep_scan)
    monkeypatch.setattr(
        forge_api,
        "to_vtable",
        lambda *a, **k: calls.append(("to_vtable", a)) or {"offset": 0},
        raising=False,
    )
    monkeypatch.setattr(
        forge_api,
        "create_type",
        lambda *a, **k: calls.append(("create_type", k)) or {"ok": True},
        raising=False,
    )

    result = forge_api.scan_from_allocation(
        0x401000, var_name="a1", name="World", vtable_addr=0x140006358, commit=True
    )

    assert result == {
        "ok": True,
        "allocation": rows[0],
        "structure": "World",
        "members": [{"name": "m0"}],
    }
    assert scanned == {
        "var_name": "a1",
        "structure": "World",
        "recurse_calls": True,
        "root_type": None,
    }
    assert forge_api.get_structure("World") is not None
    # vtable conversion runs before the commit; commit is overwrite=True
    assert calls[0] == ("to_vtable", ("World", 0, 0x140006358))
    assert calls[1] == ("create_type", {"overwrite": True})


def test_scan_from_allocation_helper_row_skips_void_retype(monkeypatch):
    """E.22: a helper-mediated HEAP row (size_hint None + callee) skips the
    void * retype trick — the analyst's root type stays and deep_scan runs
    with root_type=None."""
    rows = [
        {
            "ea": 0x402000,
            "var": "a1",
            "line": "a1 = chain_node_new()",
            "kind": "HEAP",
            "size_hint": None,
            "callee": 0x1400020F0,
        }
    ]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    monkeypatch.setattr(
        forge_api,
        "_allocation_root_prior_type",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("auto-retype must be skipped for helper rows")
        ),
        raising=False,
    )
    scanned = {}
    restored = []
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, *, root_type=None, structure="", **k:
            scanned.update(root_type=root_type) or {"structure": structure, "members": []},
    )
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(
        forge_api, "set_lvar_types", lambda *a, **k: restored.append(1), raising=False
    )

    result = forge_api.scan_from_allocation(
        0x1400014F0, var_name="a1", name="DeepChainNode"
    )

    assert result["ok"] is True
    assert scanned["root_type"] is None
    assert restored == []
    assert result["allocation"]["callee"] == 0x1400020F0


def test_scan_from_allocation_uses_callee_row_without_heap_kind(monkeypatch):
    """E.22: when no row is kind HEAP but a row carries callee, that row
    drives the scan (helper-mediated allocation, kind-agnostic)."""
    rows = [
        {
            "ea": 0x402000,
            "var": "a1",
            "line": "a1 = helper()",
            "kind": "STACK",
            "size_hint": None,
            "callee": 0x1400020F0,
        }
    ]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    scanned = []
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, **k: scanned.append(k.get("root_type")) or {"structure": k["structure"], "members": []},
    )
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)

    result = forge_api.scan_from_allocation(0x1400014F0, var_name="a1")

    assert result["ok"] is True
    assert result["allocation"]["callee"] == 0x1400020F0


def test_scan_from_allocation_teleports_into_helper_body(monkeypatch):
    """R3.2 (F4): helper-mediated rows ALSO deep-scan the callee's
    returned-allocation root; both evidence sets merge by offset —
    higher score wins, ties keep the callee's row."""
    rows = [
        {
            "ea": 0x402000,
            "var": "v0",
            "line": "v0 = sub_1400020F0()",
            "kind": "HEAP",
            "size_hint": None,
            "callee": 0x1400020F0,
        }
    ]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    monkeypatch.setattr(
        forge_api,
        "_helper_allocation_row",
        lambda callee_ea: {
            "ea": 0x402100,
            "var": "node",
            "line": "node = calloc(1, 0x20)",
            "kind": "HEAP",
            "size_hint": 0x20,
            "callee": None,
        },
    )
    calls = []
    caller_members = [
        {"offset": 0, "name": "x", "score": 5},
        {"offset": 8, "name": "caller_only", "score": 3},
    ]
    callee_members = [
        {"offset": 0, "name": "x_init", "score": 5},  # tie -> callee row wins
        {"offset": 8, "name": "caller_only", "score": 2},  # caller higher -> stays
        {"offset": 4, "name": "callee_only", "score": 1},
    ]

    def fake_deep_scan(ea, *, var_name=None, structure="", **k):
        calls.append((ea, var_name))
        if ea == 0x1400014F0:
            return {"structure": structure, "members": caller_members}
        return {"structure": structure, "members": callee_members}

    monkeypatch.setattr(forge_api, "deep_scan", fake_deep_scan)
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)

    result = forge_api.scan_from_allocation(
        0x1400014F0, var_name="v0", name="R3Chain"
    )

    assert result["ok"] is True
    # caller scan first, then the teleported callee scan with the
    # helper's returned var
    assert calls == [(0x1400014F0, "v0"), (0x1400020F0, "node")]
    rows_by_offset = {m["offset"]: m for m in result["members"]}
    assert rows_by_offset[0]["name"] == "x_init"  # tie -> callee wins
    assert rows_by_offset[8]["name"] == "caller_only"  # higher score wins
    assert rows_by_offset[8]["score"] == 3
    assert rows_by_offset[4]["name"] == "callee_only"  # union


def test_scan_from_allocation_teleports_with_folded_size_hint(monkeypatch):
    """R3.2 (F4): a helper row whose calloc size got folded (size_hint
    set — live 9.4 shape) STILL teleports: the gate is the callee, not
    size_hint."""
    rows = [
        {
            "ea": 0x402000,
            "var": "v0",
            "line": "v0 = sub_1400020F0(3, 2);",
            "kind": "HEAP",
            "size_hint": 40,
            "callee": 0x1400020F0,
        }
    ]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    monkeypatch.setattr(
        forge_api,
        "_helper_allocation_row",
        lambda callee_ea: {
            "ea": 0x402100,
            "var": "node",
            "line": "node = calloc(1, 0x28)",
            "kind": "HEAP",
            "size_hint": 40,
            "callee": None,
        },
    )
    calls = []
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, **k: calls.append(ea) or {"structure": k["structure"], "members": []},
    )
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)

    result = forge_api.scan_from_allocation(0x140001F10, var_name="v0", name="R3Chain")

    assert result["ok"] is True
    assert calls == [0x140001F10, 0x1400020F0]


def test_scan_from_allocation_teleport_noop_without_helper_row(monkeypatch):
    """R3.2 (F4): when the helper body proves no allocation, the caller
    scan alone drives the result (current behavior unchanged)."""
    rows = [
        {
            "ea": 0x402000,
            "var": "v0",
            "line": "v0 = sub_1400020F0()",
            "kind": "HEAP",
            "size_hint": None,
            "callee": 0x1400020F0,
        }
    ]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    monkeypatch.setattr(forge_api, "_helper_allocation_row", lambda callee_ea: None)
    calls = []
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, **k: calls.append(ea) or {"structure": k["structure"], "members": []},
    )
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)

    result = forge_api.scan_from_allocation(0x1400014F0, var_name="v0", name="R3Chain")

    assert result["ok"] is True
    assert calls == [0x1400014F0]


def test_scan_from_allocation_reports_missing_heap(monkeypatch):
    """I.23: no heap allocation for the variable -> an error dict, and no
    structure is created."""
    monkeypatch.setattr(
        forge_api,
        "guess_allocation",
        lambda *a, **k: [{"ea": 0x401010, "var": "a1", "kind": "STACK", "size_hint": None, "callee": None}],
    )
    monkeypatch.setattr(forge_api, "deep_scan", lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(forge_api, "create_type", lambda *a, **k: {}, raising=False)

    result = forge_api.scan_from_allocation(0x401000, var_name="a1")

    assert result["ok"] is False
    assert "no heap allocation" in result["error"]
    assert forge_api.structures() == []


def test_scan_from_allocation_retypes_typed_roots_and_restores(monkeypatch):
    """O1: a struct-pointer-typed root (e.g. ``ArrayCell *cells``) scans as
    colliding offset-0 noise; scan_from_allocation transparently retypes to
    void * for the scan and restores the analyst's type afterwards."""
    rows = [{
        "ea": 0x401000, "var": "a1", "line": "a1 = calloc(9u, 0xCu)",
        "kind": "HEAP", "size_hint": 108, "callee": None,
    }]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    monkeypatch.setattr(
        forge_api,
        "_allocation_root_prior_type",
        lambda ea, var: "ArrayCell *",
        raising=False,
    )
    scanned = {}
    restored = []
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, *, var_name, structure, recurse_calls, root_type, **k:
            scanned.update(root_type=root_type) or {"structure": structure, "members": []},
    )
    monkeypatch.setattr(
        forge_api, "set_lvar_types",
        lambda ea, types: restored.append(types), raising=False,
    )
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)

    result = forge_api.scan_from_allocation(0x401000, var_name="a1")

    assert result["ok"] is True
    assert scanned["root_type"] == "void *"
    assert restored == [{"a1": "ArrayCell *"}]


def test_scan_from_allocation_keeps_explicit_root_type(monkeypatch):
    """O1: an explicit root_type wins — no auto-retype, no restore."""
    monkeypatch.setattr(
        forge_api, "guess_allocation", lambda *a, **k: [{
            "ea": 0x401000, "var": "a1", "line": "", "kind": "HEAP",
            "size_hint": None, "callee": None,
        }]
    )
    monkeypatch.setattr(
        forge_api, "_allocation_root_prior_type",
        lambda ea, var: (_ for _ in ()).throw(AssertionError("auto-retype must be skipped")),
        raising=False,
    )
    scanned = {}
    calls = []
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, *, root_type=None, structure="", **k:
            scanned.update(root_type=root_type) or {"structure": structure, "members": []},
    )
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(forge_api, "set_lvar_types", lambda *a, **k: calls.append(1), raising=False)

    forge_api.scan_from_allocation(0x401000, var_name="a1", root_type="char *")

    assert scanned["root_type"] == "char *"
    assert calls == []


def test_scan_from_allocation_auto_names_and_skips_commit(monkeypatch):
    """I.23: unnamed scans get an Allocation auto-name; commit=False leaves
    the type uncommitted."""
    calls = []
    rows = [{"ea": 0x401000, "var": "a1", "kind": "HEAP", "size_hint": None, "callee": None, "line": ""}]
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: rows)
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, **k: {"structure": k["structure"], "members": []},
    )
    monkeypatch.setattr(forge_api, "create_type", lambda *a, **k: calls.append(1) or {}, raising=False)
    monkeypatch.setattr(forge_api, "to_vtable", lambda *a, **k: {}, raising=False)

    result = forge_api.scan_from_allocation(0x401000, var_name="a1")

    assert result["structure"] == "Allocation"
    assert result["ok"] is True
    assert calls == []


def test_import_types_excludes_system_and_template_names(monkeypatch):
    """I.27 (O1 deviation): names in the base til, compiler-generated locals
    (UNWIND_INFO_HDR/C_SCOPE_TABLE), and :: names never import."""
    import ida_typeinf

    names = {
        0: "PointerParent",
        1: "CellMeta",
        2: "UNWIND_INFO_HDR",
        3: "C_SCOPE_TABLE",
        4: "BYTE",
        5: "NS::Member",
    }

    class FakeTinfo:
        def __init__(self, *a, **k):
            self._name = None
        def get_numbered_type(self, til, ordinal):
            return ordinal in names
        def get_named_type(self, til, name):
            return name == "BYTE"
        def is_udt(self):
            return True
        def get_udt_details(self, udt):
            udt.extend(
                [
                    SimpleNamespace(offset=0, name="a", type=SimpleNamespace(dstr=lambda: "u32")),
                    SimpleNamespace(offset=4, name="b", type=SimpleNamespace(dstr=lambda: "u64")),
                ]
            )
            return True

    class FakeBaseTil:
        @staticmethod
        def get_named_type(t, name):
            return name == "BYTE"

    class FakeIdati:
        @staticmethod
        def base(_n):
            return FakeBaseTil()

    monkeypatch.setattr(ida_typeinf, "get_idati", lambda: FakeIdati())
    monkeypatch.setattr(ida_typeinf, "get_ordinal_count", lambda til: len(names))
    monkeypatch.setattr(ida_typeinf, "get_numbered_type_name", lambda til, ord: names.get(ord))
    monkeypatch.setattr(ida_typeinf, "tinfo_t", FakeTinfo)
    added = []
    monkeypatch.setattr(forge_api, "add_member", lambda *a, **k: added.append((a[0], a[1], k.get("name"))))

    forge_api._structures.clear()
    forge_api._state.current = None
    result = forge_api.import_types()

    assert sorted(result["imported"]) == ["CellMeta", "PointerParent"]
    assert forge_api.structures() == ["CellMeta", "PointerParent"]
    assert ("PointerParent", 4, "b") in [(n, off, nm) for n, off, nm in added]


def test_scan_global_adds_named_sub_heads(monkeypatch, _real_hexrays):
    """I.20: named sub-heads inside the global's span become members with
    u8/u16/u32/u64 types derived from their item size."""
    import sys as _sys

    import ida_bytes
    import ida_name

    heads = {
        0x1400A4040: ("qword_1400a4040", 8),
        0x1400A4060: ("dword_1400a4060", 4),
    }

    def _item_size(h):
        if h in heads:
            return heads[h][1]
        if h == 0x1400A4000:
            return 0x140
        return 0

    def _next_head(ea, end):
        candidates = sorted(h for h in heads if ea < h < end)
        return candidates[0] if candidates else -1

    monkeypatch.setattr(ida_bytes, "get_item_size", _item_size, raising=False)
    monkeypatch.setattr(ida_bytes, "next_head", _next_head, raising=False)
    monkeypatch.setattr(
        ida_name, "get_short_name", lambda ea: "obj_1400a4000", raising=False
    )
    monkeypatch.setattr(
        ida_name, "get_name", lambda h: heads.get(h, ("", 0))[0], raising=False
    )
    monkeypatch.setattr(
        _real_hexrays,
        "get_funcs_referencing_address",
        lambda ea: [0x401000],
        raising=False,
    )
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: SimpleNamespace(entry_ea=0x401000),
        raising=False,
    )

    class _FakeVisitor:
        def __init__(self, *args, **kwargs):
            pass

        def process(self):
            pass

    scanner_module = _sys.modules.get("forge.api.scanner")
    monkeypatch.setattr(
        scanner_module, "NewDeepScanVisitor", _FakeVisitor, raising=False
    )
    # GlobalVariableObject needs no on-disk flags; the conftest flag stubs
    # cover is_code etc. — just ensure the real class constructs
    from forge.api.scan_object import GlobalVariableObject as _GVO

    assert _GVO(0x1400A4000).object_ea == 0x1400A4000

    result = forge_api.scan_global(0x1400A4000)

    assert result["ok"] is True
    members = {m["name"]: m for m in result["members"]}
    assert result["structure"] == "global_obj_1400a4000"
    assert members["qword"]["offset"] == 0x40
    assert members["qword"]["type"] == "u64"
    assert members["dword"]["offset"] == 0x60
    assert members["dword"]["type"] == "u32"


def test_scan_global_extends_exclusive_tail_for_boundary_ref(monkeypatch, _real_hexrays):
    """E.25: span is an EXCLUSIVE tail; when the item head at the boundary
    is data-referenced from a scanned function, the tail extends by that
    item's size so the boundary member survives."""
    import sys as _sys

    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_xref

    heads = {0x1400A4060: ("qword_1400a4060", 8)}

    def _item_size(h):
        if h in heads:
            return heads[h][1]
        return 0x80 if h == 0x1400A4000 else 0

    def _next_head(ea, end):
        candidates = sorted(h for h in heads if ea < h < end)
        return candidates[0] if candidates else -1

    monkeypatch.setattr(ida_bytes, "get_item_size", _item_size, raising=False)
    monkeypatch.setattr(ida_bytes, "next_head", _next_head, raising=False)
    monkeypatch.setattr(
        ida_name, "get_short_name", lambda ea: "obj_1400a4000", raising=False
    )
    monkeypatch.setattr(
        ida_name, "get_name", lambda h: heads.get(h, ("", 0))[0], raising=False
    )
    monkeypatch.setattr(
        ida_xref, "get_first_dref_to", lambda ea: 0x401000 if ea == 0x1400A4060 else -1,
        raising=False,
    )
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: SimpleNamespace(start_ea=0x401000) if ea == 0x401000 else None,
        raising=False,
    )
    monkeypatch.setattr(
        _real_hexrays,
        "get_funcs_referencing_address",
        lambda ea: {0x401000},
        raising=False,
    )
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: SimpleNamespace(entry_ea=0x401000),
        raising=False,
    )

    class _FakeVisitor:
        def __init__(self, *args, **kwargs):
            pass

        def process(self):
            pass

    monkeypatch.setattr(
        _sys.modules.get("forge.api.scanner"), "NewDeepScanVisitor", _FakeVisitor, raising=False
    )

    result = forge_api.scan_global(0x1400A4000, span=0x60)

    members = {m["name"]: m for m in result["members"]}
    assert members["qword"]["offset"] == 0x60
    assert members["qword"]["type"] == "u64"


def test_collapse_stride_runs_merges_regular_runs(monkeypatch):
    """E16: a 33-member constant-stride run collapses into one array
    member (is_array + count) at the run base."""
    members = [
        {
            "offset": index * 12,
            "name": f"cell_{index:x}",
            "type": "Cell",
            "size": 12,
            "enabled": True,
            "comment": "",
            "origin": 0,
        }
        for index in range(33)
    ]

    collapsed = forge_api._collapse_stride_runs(members)

    assert len(collapsed) == 1
    first = collapsed[0]
    assert first["offset"] == 0
    assert first["is_array"] is True
    assert first["array"] == 33
    assert first["type"] == "Cell[33]"


def test_collapse_stride_runs_preserves_non_runs(monkeypatch):
    """E16: gaps, mixed types and singletons are preserved untouched."""
    members = [
        {"offset": 0x0, "name": "a", "type": "u32", "size": 4, "enabled": True},
        {"offset": 0x4, "name": "b", "type": "u32", "size": 4, "enabled": True},
        {"offset": 0x10, "name": "c", "type": "u64", "size": 8, "enabled": True},
        {"offset": 0x20, "name": "d", "type": "u32", "size": 4, "enabled": False},
    ]

    collapsed = forge_api._collapse_stride_runs(members)

    # 0x0+0x4 collapse (stride 4); the gap breaks the run; the disabled
    # member is not part of any run but still reported
    assert len(collapsed) == 3
    assert collapsed[0]["array"] == 2
    assert collapsed[0]["type"] == "u32[2]"
    assert collapsed[1]["name"] == "c"
    assert collapsed[2]["name"] == "d"


def test_collapse_stride_runs_detaches_preserved_rows(monkeypatch):
    rows = [
        {"offset": 0, "name": "single", "type": "u32", "size": 4, "enabled": True},
        {"offset": 0x20, "name": "disabled", "type": "u8", "size": 1, "enabled": False},
    ]
    result = forge_api._collapse_stride_runs(rows)
    result[0]["name"] = "mutated"
    result[1]["name"] = "mutated-disabled"
    assert rows[0]["name"] == "single"
    assert rows[1]["name"] == "disabled"


def test_scan_from_allocation_detaches_allocation_row(monkeypatch):
    row = {"ea": 0x401000, "var": "a1", "kind": "HEAP", "size_hint": 8, "callee": None}
    monkeypatch.setattr(forge_api, "guess_allocation", lambda *a, **k: [row])
    monkeypatch.setattr(forge_api, "_allocation_root_prior_type", lambda *a, **k: None)
    monkeypatch.setattr(forge_api, "deep_scan", lambda *a, **k: {"members": []})
    result = forge_api.scan_from_allocation(0x401000, name="Detached")
    result["allocation"]["var"] = "mutated"
    assert row["var"] == "a1"


def test_merge_member_rows_detaches_selected_rows():
    base = [{"offset": 0, "name": "base", "score": 1}]
    extra = [{"offset": 4, "name": "extra", "score": 2}]
    result = forge_api._merge_member_rows(base, extra)
    result[0]["name"] = "mutated-base"
    result[1]["name"] = "mutated-extra"
    assert base == [{"offset": 0, "name": "base", "score": 1}]
    assert extra == [{"offset": 4, "name": "extra", "score": 2}]


def test_scan_global_sub_heads_skip_existing_member(monkeypatch, _real_hexrays):
    """I.20: an offset that already has a member is not overwritten."""
    import sys as _sys

    import ida_bytes
    import ida_name

    monkeypatch.setattr(ida_bytes, "get_item_size", lambda h: 0x80 if h == 0x1400A4000 else 8, raising=False)

    def _next_head(ea, end):
        return 0x1400A4020 if ea < 0x1400A4020 < end else -1

    monkeypatch.setattr(ida_bytes, "next_head", _next_head, raising=False)
    monkeypatch.setattr(
        ida_name, "get_short_name", lambda ea: "obj_1400a4000", raising=False
    )
    monkeypatch.setattr(
        ida_name, "get_name", lambda h: "qword_1400a4020" if h == 0x1400A4020 else "", raising=False
    )
    monkeypatch.setattr(
        _real_hexrays,
        "get_funcs_referencing_address",
        lambda ea: [0x401000],
        raising=False,
    )
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: SimpleNamespace(entry_ea=0x401000),
        raising=False,
    )

    class _FakeVisitor:
        def __init__(self, *args, **kwargs):
            pass

        def process(self):
            pass

    monkeypatch.setattr(
        _sys.modules.get("forge.api.scanner"), "NewDeepScanVisitor", _FakeVisitor, raising=False
    )

    forge_api.create_structure("global_obj_1400a4000")
    forge_api.add_member("global_obj_1400a4000", 0x20, "u32", name="existing")

    result = forge_api.scan_global(0x1400A4000)

    assert [m["name"] for m in result["members"]] == ["existing"]
    assert result["members"][0]["type"] == "u32"


def test_apply_type_store_fallback_creates_placeholder_first(monkeypatch):
    """I.19: a store-structure declaration parses via the lazy placeholder
    (B8) — the placeholder is created before the re-parse."""
    import ida_typeinf

    forge_api.create_structure("GridNode")
    forged = []
    # idc_parse_types returns an ERROR COUNT: 0 == success, nonzero == the
    # parse failed. The stub must mimic the success shape the placeholder
    # gate must proceed on (the old stub returned True, the inverted truth).
    monkeypatch.setattr(
        ida_typeinf,
        "idc_parse_types",
        lambda decl, flags: forged.append(decl) or 0,
        raising=False,
    )
    monkeypatch.setattr(forge_api, "is_type", lambda name: False, raising=False)
    monkeypatch.setattr(
        ida_typeinf, "apply_tinfo", lambda *a, **k: None, raising=False
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)
    calls = {"n": 0}

    def first_fails_then_parses(decl):
        calls["n"] += 1
        return None if calls["n"] == 1 else FakeTinfo("GridNode *")

    monkeypatch.setattr(members_mod, "parse_user_tinfo", first_fails_then_parses, raising=False)

    result = forge_api.apply_type(0x401000, "GridNode *")

    assert calls["n"] == 2
    assert len(forged) == 1
    assert "GridNode" in forged[0]
    assert result["ok"] is True
    assert result["type"] == "GridNode *"


def _xref_stubs(monkeypatch, *, crefs=(), drefs=()):
    """Route ida_xref walkers; each sequence is walked until -1."""
    import ida_funcs
    import ida_xref

    def _walk(first, nxt):
        calls = {"n": 0}

        def get_first(ea):
            calls["n"] = 0
            return first[calls["n"]] if calls["n"] < len(first) else -1

        def get_next(ea, src):
            calls["n"] += 1
            return first[calls["n"]] if calls["n"] < len(first) else -1

        return get_first, get_next

    if crefs:
        cf, cn = _walk(crefs, None)
        monkeypatch.setattr(ida_xref, "get_first_cref_to", cf, raising=False)
        monkeypatch.setattr(ida_xref, "get_next_cref_to", cn, raising=False)
    if drefs:
        df, dn = _walk(drefs, None)
        monkeypatch.setattr(ida_xref, "get_first_dref_to", df, raising=False)
        monkeypatch.setattr(ida_xref, "get_next_dref_to", dn, raising=False)
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: SimpleNamespace(start_ea=ea & ~0xF, end_ea=(ea & ~0xF) + 0x20),
        raising=False,
    )


def test_callers_of_walks_code_xrefs_to_function_starts(monkeypatch):
    """I.13: cref sources are resolved to their containing function starts
    and deduplicated (two refs from one function collapse to one EA)."""
    _xref_stubs(monkeypatch, crefs=(0x401120, 0x401000, 0x401020, 0x401021))

    assert forge_api.callers_of(0x400000) == [0x401000, 0x401020, 0x401120]


def test_callers_of_data_kind_uses_dref_walkers(monkeypatch):
    """I.13: kind='data' walks drefs only (vtable/RTTI discovery)."""
    _xref_stubs(monkeypatch, drefs=(0x140006358, 0x140006360))

    result = forge_api.callers_of(0x140006358, "data")

    assert result == [0x140006350, 0x140006360]


def test_callees_of_reuses_decompile_calls(monkeypatch, _real_hexrays):
    """I.13: callees come from the decompiler's call-expression scan."""
    import ida_lines

    monkeypatch.setattr(ida_lines, "tag_remove", lambda s: s, raising=False)
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: _pseudo_cfunc(["void f() { g(); h(); }"]),
        raising=False,
    )
    assert forge_api.callees_of(0x400000) == []


def test_callees_of_resolves_iat_slots_to_functions(monkeypatch, _real_hexrays):
    """E.23: a callee EA that is an IAT slot (not a function) resolves to
    the pointer stored at the slot when it lands in a function."""
    import ida_funcs

    monkeypatch.setattr(forge_api, "decompile", lambda ea: {"calls": [0x180001000]})
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: (
            None
            if ea == 0x180001000
            else SimpleNamespace(start_ea=0x140002000, end_ea=0x140002040)
        ),
        raising=False,
    )
    monkeypatch.setattr(forge_api, "_import_slot_to_name", lambda ea: "printf", raising=False)
    monkeypatch.setattr(_real_hexrays, "read_pointer", lambda ea: 0x140002000, raising=False)

    assert forge_api.callees_of(0x401000) == [0x140002000]


def test_callees_of_keeps_unresolvable_slot_ea(monkeypatch):
    """E.23: a callee EA that cannot be resolved stays as-is (no silent
    dropping — the raw slot is honest when nothing better is provable)."""
    import ida_funcs

    monkeypatch.setattr(forge_api, "decompile", lambda ea: {"calls": [0x180001000]})
    monkeypatch.setattr(ida_funcs, "get_func", lambda ea: None, raising=False)
    monkeypatch.setattr(forge_api, "_import_slot_to_name", lambda ea: None, raising=False)

    assert forge_api.callees_of(0x401000) == [0x180001000]


def test_import_slot_target_uses_domain_qword(monkeypatch):
    from forge.api import domain

    class Bytes:
        def get_qword_at(self, ea):
            assert ea == 0x180001000
            return 0x140002000

    class DomainDb:
        bytes = Bytes()
        database = SimpleNamespace(pointer_size=8)
        functions = SimpleNamespace(get_at=lambda ea: SimpleNamespace(start_ea=ea))

    domain.clear_fallback_records()
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "_import_slot_to_name", lambda _ea: "printf")
    assert forge_api._import_slot_target_ea(0x180001000) == 0x140002000
    assert domain.fallback_records() == ()


def test_import_slot_target_domain_failure_records_fallback(monkeypatch):
    from forge.api import domain

    class Bytes:
        def get_qword_at(self, _ea):
            raise RuntimeError("unsupported")

    class DomainDb:
        bytes = Bytes()
        database = SimpleNamespace(pointer_size=8)
        functions = SimpleNamespace(get_at=lambda ea: SimpleNamespace(start_ea=ea))

    domain.clear_fallback_records()
    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "_import_slot_to_name", lambda _ea: "printf")
    monkeypatch.setattr(forge_api, "_sdk_fallback", domain.sdk_fallback)
    assert forge_api._import_slot_target_ea(0x180001000) == 0
    assert any(item.capability == "bytes.import_slot_pointer" for item in domain.fallback_records())


def test_function_info_aggregates_recon(monkeypatch, _real_hexrays):
    """I.13: function_info aggregates the xref walk + prototype + calls."""
    import ida_funcs
    import ida_lines

    _xref_stubs(monkeypatch, crefs=(0x401120,), drefs=(0x140006358,))
    monkeypatch.setattr(ida_lines, "tag_remove", lambda s: s, raising=False)
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: _pseudo_cfunc(["int __cdecl f(World *a1)"]),
        raising=False,
    )
    table = {
        0x400010: (0x400000, 0x400120),
        0x401120: (0x401120, 0x401140),
        0x140006358: (0x140006350, 0x140006378),
        # E.23: the IAT-slot pass re-queries already-resolved EAs, so the
        # function-start addresses must answer too.
        0x140006350: (0x140006350, 0x140006378),
        0x401000: (0x401000, 0x401000),
    }
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: (
            SimpleNamespace(start_ea=table[ea][0], end_ea=table[ea][1])
            if ea in table
            else None
        ),
        raising=False,
    )

    info = forge_api.function_info(0x400010)

    assert info["name"] == "sub_400010"
    assert info["start_ea"] == 0x400000
    assert info["size"] == 0x120
    assert "World" in info["prototype"]
    assert info["callers"] == [0x401120]
    assert info["callees"] == []
    assert info["refs"] == [0x401120, 0x140006350]


def test_function_info_returns_none_outside_function(monkeypatch):
    import ida_funcs

    monkeypatch.setattr(ida_funcs, "get_func", lambda ea: None, raising=False)
    assert forge_api.function_info(0x400000) is None


def test_imports_walks_entries_and_filters(monkeypatch):
    """I.15: walks idautils.Entries with per-version tuple shapes; pattern
    case-folds on the name."""
    import sys

    import ida_segment

    fake_entries = [
        (1, 0x180001000, "CreateWindowExA"),
        (2, 0x180001008, ""),
        (9, 0x180001200, "malloc"),
    ]
    monkeypatch.setitem(
        sys.modules,
        "idautils",
        SimpleNamespace(Entries=lambda: iter(fake_entries)),
    )
    monkeypatch.setattr(
        ida_segment,
        "getseg",
        lambda ea: SimpleNamespace() if ea == 0x180001008 else None,
        raising=False,
    )
    monkeypatch.setattr(ida_segment, "get_segm_name", lambda seg: ".idata", raising=False)

    rows = forge_api.imports()
    assert rows[0] == {"module": "", "ea": 0x180001000, "name": "CreateWindowExA"}
    # an entry with an empty name resolves through ida_name.get_name ("" here)
    assert rows[1] == {"module": ".idata", "ea": 0x180001008, "name": ""}
    filtered = forge_api.imports("window")
    assert [row["name"] for row in filtered] == ["CreateWindowExA"]
    assert forge_api.imports("nomatch_xyz") == []


def test_imports_handles_ida_7_tuple_shapes(monkeypatch):
    import sys

    monkeypatch.setitem(
        sys.modules,
        "idautils",
        SimpleNamespace(Entries=lambda: iter([(0, 5, 0x180001000, "old_shape")])),
    )
    rows = forge_api.imports()
    assert rows == [{"module": "", "ea": 0x180001000, "name": "old_shape"}]


def _vtable_stubs(monkeypatch, pointers):
    """Fake read_pointer/is_code/is_imported so VirtualTable reads ``pointers``
    (code pointers until the first non-code), with a real-looking name."""
    from forge.api import members as members_api

    monkeypatch.setattr(
        members_api, "read_pointer", lambda ea: pointers.pop(0) if pointers else 0, raising=False
    )
    monkeypatch.setattr(members_api, "is_code", lambda ea: ea != 0, raising=False)
    monkeypatch.setattr(members_api, "is_imported", lambda ea: False, raising=False)
    monkeypatch.setattr(
        members_api.ida_name, "get_name", lambda ea: "vftable_140006358", raising=False
    )
    return members_api


def test_vtable_entries_reads_slots(monkeypatch):
    """I.14: vtable_entries maps the read pointer slots to slot dicts."""
    members_api = _vtable_stubs(monkeypatch, [0x140001000, 0x140001010, 0])

    slots = forge_api.vtable_entries(0x140006358)

    assert slots == [
        {"offset": 0, "ea": 0x140001000, "slot": 0},
        {"offset": members_api.types.width, "ea": 0x140001010, "slot": 1},
    ]


def test_vtable_entries_reports_non_vtable(monkeypatch):
    """I.14: an address that is not a vtable returns an error dict, not a
    raise — and since E2 (2026-08-13) an unnamed pointer table no longer
    asserts either: it yields an empty slot list."""
    from forge.api import members as members_api

    monkeypatch.setattr(members_api, "read_pointer", lambda ea: 0, raising=False)
    monkeypatch.setattr(
        members_api.ida_name, "get_name", lambda ea: "", raising=False
    )

    # E2: unnamed table → vtbl_<addr> fallback, zero slots, no assert.
    # E20e: zero slots now says "not a code-pointer array" (was []).
    result = forge_api.vtable_entries(0x140006358)
    assert result == {"ok": False, "error": "not a code-pointer array"}

    # A genuinely broken read still surfaces as an error dict.
    def _broken_read(ea):
        raise OSError("unmapped")

    monkeypatch.setattr(members_api, "read_pointer", _broken_read, raising=False)

    result = forge_api.vtable_entries(0x140006358)
    assert result["ok"] is False
    assert "error" in result


def test_vtable_name_resolves_display_name(monkeypatch):
    """I.14: vtable_name returns the parsed name + niceness flag."""
    _vtable_stubs(monkeypatch, [0x140001000, 0])

    result = forge_api.vtable_name(0x140006358)

    assert result["name"] == "vftable_140006358"
    assert result["is_nice"] is True


# ---------------------------------------------------------------------------
# E-series regression tests (eval review 2026-08-13)
# ---------------------------------------------------------------------------

def test_create_structure_seeds_own_placeholder_before_members(monkeypatch):
    """E3: a member whose type references the structure's own name must
    not be silently dropped — the lazy placeholder is seeded before the
    member loop parses."""
    ensure_calls = []
    monkeypatch.setattr(forge_api, "is_type", lambda name: False, raising=False)
    monkeypatch.setattr(
        forge_api,
        "_ensure_placeholder_type",
        lambda name: (ensure_calls.append(name) or True),
        raising=False,
    )

    result = forge_api.create_structure(
        "KV",
        members=[
            {"offset": 0, "type": "char *", "name": "key"},
            {"offset": 8, "type": "char *", "name": "value"},
            {"offset": 0x10, "type": "KV *", "name": "next"},
        ],
    )

    assert ensure_calls == ["KV"]
    assert result["name"] == "KV"
    # members that parse survive the loop (parse is stubbed to FakeTinfo)
    assert {m["name"] for m in result["members"]} == {"key", "value", "next"}


def test_e3_no_placeholder_seeded_without_members(monkeypatch):
    ensure_calls = []
    monkeypatch.setattr(
        forge_api,
        "_ensure_placeholder_type",
        lambda name: (ensure_calls.append(name) or True)[1],
        raising=False,
    )
    forge_api.create_structure("Empty")
    assert ensure_calls == []


def test_e5_imports_walks_iat_and_filters_module_and_name(monkeypatch):
    """E5: imports() reads the real import table (module + name filters),
    not the bogus Entries() namespace."""
    import ida_nalt

    monkeypatch.setattr(ida_nalt, "get_import_module_qty", lambda: 2)
    monkeypatch.setattr(
        ida_nalt,
        "get_import_module_name",
        lambda idx: ("KERNEL32.dll" if idx == 0 else "VCRUNTIME140.dll"),
    )

    def fake_enum(idx, cb):
        if idx == 0:
            cb(0x140001000, "CreateFileW", 1)
            cb(0x140001008, "printf", 2)
        else:
            cb(0x140001010, "malloc", 1)
        return True

    monkeypatch.setattr(ida_nalt, "enum_import_names", fake_enum)

    rows = forge_api.imports("printf")
    assert rows == [{"module": "KERNEL32.dll", "ea": 0x140001008, "name": "printf"}]

    all_rows = forge_api.imports()
    assert [r["name"] for r in all_rows] == ["CreateFileW", "printf", "malloc"]
    assert {r["module"] for r in all_rows} == {
        "KERNEL32.dll",
        "VCRUNTIME140.dll",
    }


def test_e8_link_child_materializes_child_pointer_type(monkeypatch):
    """E8: linking a member at an offset materializes the ``Child *``
    member type instead of leaving the ``u32`` placeholder."""
    from forge.api import members as members_mod

    parsed = []

    def _fake_parse(declaration):
        parsed.append(declaration)
        name = (declaration or "u32").split()[0]
        return FakeTinfo(name)

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _fake_parse, raising=False)

    forge_api.create_structure("PointerParent")
    forge_api.create_structure("Kid")
    linked = forge_api.link_child("PointerParent", 0x10, "Kid")

    assert linked["offset"] == 0x10
    assert parsed[0] == "u32"  # placeholder creation
    assert parsed[1] == "Kid *"  # E8 materialization
    member = forge_api.get_member("PointerParent", 0x10)
    assert member is not None
    assert member["type"] == "Kid"


def test_e10_create_type_overwrites_own_placeholder(monkeypatch):
    """E10: create_type(overwrite=False) treats the plugin's lazy
    placeholder as absent — the default scan→commit flow survives
    self-referencing structs."""
    _commit_structure_stubs(monkeypatch)
    overwrite_seen = []

    from forge.api import structure as structure_mod

    real_set_cdecl = structure_mod.Structure.set_cdecl
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, cdecl, origin=0, *, overwrite=None: (
            overwrite_seen.append(overwrite)
            or real_set_cdecl(self, cdecl, origin, overwrite=overwrite)
        ),
        raising=False,
    )
    monkeypatch.setattr(
        forge_api, "_is_forge_placeholder_type", lambda name: True, raising=False
    )

    forge_api.create_structure("KV")
    forge_api.add_member("KV", 0, "u32", name="key")

    result = forge_api.create_type("KV")  # overwrite=False by default

    assert result["ok"] is True
    assert overwrite_seen == [True]


def _sized_parse(declaration):
    """Autouse fixture override: distinct type names by width so
    same-offset members don't merge (Member.__eq__ keys on offset+type)."""
    name = (declaration or "u32").split()[0]
    size = {"u64": 8, "u16": 2}.get(name, 4)
    return FakeTinfo(name, size=size)


def test_e11_get_member_disambiguates_collision_by_name(monkeypatch):
    from forge.api import members as members_mod

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _sized_parse, raising=False)
    forge_api.create_structure("Coll")
    forge_api.add_member("Coll", 0x10, "u32", name="scanned")
    forge_api.add_member("Coll", 0x10, "u64", name="hand")

    assert forge_api.get_member("Coll", 0x10, member_name="hand")["name"] == "hand"
    assert (
        forge_api.get_member("Coll", 0x10, member_name="scanned")["name"]
        == "scanned"
    )
    assert forge_api.get_member("Coll", 0x10)["name"] in {"scanned", "hand"}


def test_e11_set_member_targets_collision_by_name(monkeypatch):
    from forge.api import members as members_mod

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _sized_parse, raising=False)
    forge_api.create_structure("Coll")
    forge_api.add_member("Coll", 0x10, "u32", name="scanned")
    forge_api.add_member("Coll", 0x10, "u64", name="hand")

    result = forge_api.set_member(
        "Coll", 0x10, member_name="hand", name="key", comment="E11"
    )

    assert result["name"] == "key"
    assert result["comment"] == "E11"
    assert forge_api.get_member("Coll", 0x10, member_name="scanned")["name"] == "scanned"


def test_e11_set_member_unknown_name_raises(monkeypatch):
    from forge.api import members as members_mod

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _sized_parse, raising=False)
    forge_api.create_structure("Coll")
    forge_api.add_member("Coll", 0x10, "u32", name="scanned")

    with pytest.raises(forge_api.ForgeApiError):
        forge_api.set_member("Coll", 0x10, member_name="nope", name="x")
def test_e24_get_member_disambiguates_by_type(monkeypatch):
    """E24: same offset + same name but different types — member_type
    selects the right member (the (offset, name, type) triple match)."""
    from forge.api import members as members_mod

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _sized_parse, raising=False)
    forge_api.create_structure("Triple")
    forge_api.add_member("Triple", 0x10, "u32", name="slot")
    forge_api.add_member("Triple", 0x10, "u64", name="slot")

    assert forge_api.get_member("Triple", 0x10, member_type="u32")["size"] == 4
    assert forge_api.get_member("Triple", 0x10, member_type="u64")["size"] == 8
    # name+type together still resolve
    picked = forge_api.get_member(
        "Triple", 0x10, member_name="slot", member_type="u32"
    )
    assert picked["type"] == "u32"
    assert forge_api.get_member("Triple", 0x10, member_type="f64") is None


def test_e24_set_member_targets_collision_by_type(monkeypatch):
    """E24: set_member with member_type edits the right twin."""
    from forge.api import members as members_mod

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _sized_parse, raising=False)
    forge_api.create_structure("Triple")
    forge_api.add_member("Triple", 0x10, "u32", name="slot")
    forge_api.add_member("Triple", 0x10, "u64", name="slot")

    result = forge_api.set_member(
        "Triple", 0x10, member_type="u64", name="payload"
    )

    assert result["type"] == "u64"
    assert result["name"] == "payload"
    assert forge_api.get_member("Triple", 0x10, member_type="u32")["name"] == "slot"
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.set_member("Triple", 0x10, member_type="f64", name="nope")


def test_e6_inverse_if_picks_nearest_if_with_else(monkeypatch):
    """E6: inverse_if locates the cit_if nearest to insn_ea (treeitems
    path) instead of returning False on the first miss."""
    import ida_hexrays

    from forge.api import hexrays as hexrays_mod
    from forge.features.swap_if import helper as swap_helper
    from forge.features.swap_if import storage as swap_storage

    monkeypatch.setattr(ida_hexrays, "cit_if", 42, raising=False)

    def fake_decompile(ea):
        return SimpleNamespace(
            treeitems=[
                SimpleNamespace(
                    to_specific_type=lambda: SimpleNamespace(
                        op=42,
                        cif=SimpleNamespace(ielse=True, ea=0x4000),
                    )
                ),
                SimpleNamespace(
                    to_specific_type=lambda: SimpleNamespace(
                        op=42,
                        cif=SimpleNamespace(ielse=True, ea=0x4020),
                    )
                ),
            ],
            body=None,
        )

    monkeypatch.setattr(hexrays_mod, "decompile", fake_decompile, raising=False)
    inverted = []
    monkeypatch.setattr(
        swap_helper, "inverse_if", lambda cif: inverted.append(cif), raising=False
    )
    monkeypatch.setattr(
        swap_storage, "set_inverted", lambda *args: None, raising=False
    )

    assert forge_api.inverse_if(0x140001000, 0x4010) is True
    assert len(inverted) == 1
    assert inverted[0].ea == 0x4000


def test_e6_inverse_if_skips_else_less_ifs(monkeypatch):
    import ida_hexrays

    from forge.api import hexrays as hexrays_mod

    monkeypatch.setattr(ida_hexrays, "cit_if", 42, raising=False)

    def fake_decompile(ea):
        return SimpleNamespace(
            treeitems=[
                SimpleNamespace(
                    to_specific_type=lambda: SimpleNamespace(
                        op=42, cif=SimpleNamespace(ielse=None, ea=0x4000)
                    )
                )
            ],
            body=None,
        )

    monkeypatch.setattr(hexrays_mod, "decompile", fake_decompile, raising=False)

    assert forge_api.inverse_if(0x140001000, 0x4010) is False


def test_remove_type_verb_does_not_exist():
    """R3.1: the delete verb is gone — agents update committed types via
    create_type(overwrite=True), they never delete them."""
    assert not hasattr(forge_api, "remove_type")
    assert "remove_type" not in forge_api.__all__


def test_remove_structure_refuses_committed_structure(monkeypatch):
    """R3.1: a store structure committed to the IDB cannot be removed —
    deleting it would orphan applied items; update in place instead."""
    monkeypatch.setattr(forge_api, "_resolve_structure", lambda name, required=True: SimpleNamespace(
        name="Committed", created_type_name="Committed"
    ))

    with pytest.raises(forge_api.ForgeApiError, match="committed to the IDB"):
        forge_api.remove_structure("Committed")


def test_remove_structure_allows_uncommitted(monkeypatch):
    """R3.1: uncommitted store work is a scratch area and may be removed."""
    structures = {"Wip": SimpleNamespace(name="Wip", created_type_name=None)}
    monkeypatch.setattr(forge_api, "_structures", structures)
    monkeypatch.setattr(
        forge_api, "_resolve_structure",
        lambda name, required=True: structures.get(name),
        raising=False,
    )
    monkeypatch.setattr(forge_api, "_state", SimpleNamespace(current="Wip"))

    assert forge_api.remove_structure("Wip") is True
    assert structures == {}


def test_undo_type_snapshot_and_restore(monkeypatch):
    """E17: a commit snapshots the prior declaration; undo_type restores it
    via Structure.set_cdecl(overwrite=True) and consumes the snapshot."""
    from forge.api import structure as structure_mod

    snap = {}
    monkeypatch.setattr(forge_api, "_UNDO_STORE", lambda: snap)
    monkeypatch.setattr(
        forge_api,
        "_named_type_declaration",
        lambda name: f"struct {name} {{ int v; }};",
        raising=False,
    )
    _commit_structure_stubs(monkeypatch)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32", name="x")

    forge_api.create_type("S", overwrite=True)
    assert "S" in snap
    assert snap["S"]["before"] == "struct S { int v; };"

    restored_calls = []
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, cdecl, origin=0, *, overwrite=None: (
            restored_calls.append((cdecl, overwrite)) or object()
        ),
        raising=False,
    )

    result = forge_api.undo_type("S")

    assert result == {"ok": True, "restored_declaration": "struct S { int v; };"}
    assert restored_calls == [("struct S { int v; };", True)]
    assert snap == {}  # snapshot consumed


def test_undo_type_refuses_to_delete_type_created_by_commit(monkeypatch):
    """R3.1: a commit that CREATED the type (no prior declaration) cannot be
    undone by deletion — the type may already be applied. Update instead."""
    snap = {"S": {"before": None, "after": "struct S { int x; };"}}
    monkeypatch.setattr(forge_api, "_UNDO_STORE", lambda: snap)

    result = forge_api.undo_type("S")

    assert result == {
        "ok": False,
        "error": (
            "no prior declaration for 'S' — the type was created by the "
            "commit. Update it instead: edit the store structure "
            "(remove_members/add_member/set_member) and re-commit with "
            "create_type(..., overwrite=True)."
        ),
    }
    assert snap == {}  # snapshot consumed either way


def test_undo_type_missing_snapshot_errors(monkeypatch):
    monkeypatch.setattr(forge_api, "_UNDO_STORE", dict)



def test_named_type_declaration_uses_domain_existence_preflight(monkeypatch):
    class Types:
        def get_by_name(self, name):
            return object() if name == "Present" else None

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    assert forge_api._named_type_declaration("Missing") is None


def test_named_type_declaration_does_not_use_domain_export_as_serializer(monkeypatch):
    calls = []

    class Types:
        def get_by_name(self, _name):
            return object()

        def export_type(self, *_args):
            calls.append("export")
            raise AssertionError("export_type is not a serializer")

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    forge_api._named_type_declaration("Present")
    assert calls == []
    result = forge_api.undo_type("S")

    assert result["ok"] is False
    assert "no undo snapshot" in result["error"]


def test_create_typedef_commits_typedef_line(monkeypatch):
    """E29: create_typedef parses the declaration and commits
    ``typedef <decl> <name>;`` through the pure IDB-write path."""
    import forge.api.types as forge_types_mod

    created = []
    monkeypatch.setattr(
        forge_types_mod,
        "create_type",
        lambda name, decl: (created.append((name, decl)) or True),
        raising=False,
    )

    result = forge_api.create_typedef(
        "DispatchFn", "int (__cdecl *)(void *, unsigned int)"
    )

    assert result == {"ok": True, "type": "DispatchFn"}
    assert created == [
        (
            "DispatchFn",
            "typedef int (__cdecl *)(void *, unsigned int) DispatchFn;",
        )
    ]


def test_create_typedef_parse_failure_is_loud(monkeypatch):
    """E29: an unparseable typedef body fails loudly (no silent drop)."""
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: None, raising=False)

    result = forge_api.create_typedef("X", "not a type")

    assert result["ok"] is False
    assert "could not parse typedef declaration" in result["error"]

def test_create_typedef_prefers_domain_registration(monkeypatch):
    calls = []

    class Types:
        def parse_one_declaration(self, library, declaration, name):
            calls.append((library, declaration, name))
            return object()

    class DomainDb:
        types = Types()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    result = forge_api.create_typedef("Word", "unsigned int")
    assert result == {"ok": True, "type": "Word"}
    assert calls == [(None, "unsigned int", "Word")]


def test_create_typedef_falls_back_to_hexrays_create_typedef(monkeypatch):
    """E29: when the pure write path fails, the templated-types typedef
    mechanism (ida_hexrays.create_typedef) materializes the type."""
    import ida_hexrays

    import forge.api.types as forge_types_mod

    monkeypatch.setattr(
        forge_types_mod, "create_type", lambda *a, **k: False, raising=False
    )
    calls = []
    monkeypatch.setattr(
        ida_hexrays,
        "create_typedef",
        lambda name: (calls.append(name) or True),
        raising=False,
    )
    monkeypatch.setattr(forge_api, "is_type", lambda name: True, raising=False)

    result = forge_api.create_typedef(
        "DispatchFn", "int (__cdecl *)(void *, unsigned int)"
    )

    assert result == {"ok": True, "type": "DispatchFn"}
    assert calls == ["DispatchFn"]


def test_typedef_declarator_name_transform_pairs():
    """R3.2 (F3): the transform inserts the typedef name right after the
    pointer star; non-function-pointer declarations are untouched (None)."""
    assert (
        forge_api._typedef_declarator_name(
            "int (__cdecl *)(void *, unsigned int)", "DispatchFn"
        )
        == "int (__cdecl *DispatchFn)(void *, unsigned int)"
    )
    assert (
        forge_api._typedef_declarator_name(
            "int (*)(unsigned int)", "Callback"
        )
        == "int (*Callback)(unsigned int)"
    )
    assert forge_api._typedef_declarator_name("unsigned int", "Word") is None
    assert forge_api._typedef_declarator_name("void *", "Opaque") is None


def test_create_typedef_ladder_tries_declarator_name_before_hexrays(monkeypatch):
    """R3.2 (F3): the write ladder is (1) ``typedef <decl> <name>;``, (2)
    the declarator-name form when the first is rejected, (3) the
    hexrays fallback — each lower rung only when the one above fails."""
    import ida_hexrays

    import forge.api.types as forge_types_mod

    attempts = []
    monkeypatch.setattr(
        forge_types_mod,
        "create_type",
        lambda name, decl: (
            attempts.append((name, decl))
            or (len(attempts) == 3)
        ),
        raising=False,
    )
    hexrays_calls = []
    monkeypatch.setattr(
        ida_hexrays,
        "create_typedef",
        lambda name: (hexrays_calls.append(name) or True),
        raising=False,
    )
    monkeypatch.setattr(forge_api, "is_type", lambda name: True, raising=False)

    result = forge_api.create_typedef(
        "DispatchFn", "int (__cdecl *)(void *, unsigned int)"
    )

    assert result == {"ok": True, "type": "DispatchFn"}
    assert attempts == [
        (
            "DispatchFn",
            "typedef int (__cdecl *)(void *, unsigned int) DispatchFn;",
        ),
        (
            "DispatchFn",
            "typedef int (__cdecl *DispatchFn)(void *, unsigned int);",
        ),
    ]
    assert hexrays_calls == ["DispatchFn"]


def test_create_typedef_scalar_skips_declarator_rung(monkeypatch):
    """R3.2 (F3): scalar/enum typedefs have no pointer declarator — the
    ladder still reaches the hexrays fallback, not a bogus rung."""
    import ida_hexrays

    import forge.api.types as forge_types_mod

    attempts = []
    monkeypatch.setattr(
        forge_types_mod,
        "create_type",
        lambda name, decl: (attempts.append((name, decl)) or False),
        raising=False,
    )
    hexrays_calls = []
    monkeypatch.setattr(
        ida_hexrays,
        "create_typedef",
        lambda name: (hexrays_calls.append(name) or True),
        raising=False,
    )
    monkeypatch.setattr(forge_api, "is_type", lambda name: True, raising=False)

    result = forge_api.create_typedef("Word", "unsigned int")

    assert result == {"ok": True, "type": "Word"}
    assert attempts == [("Word", "typedef unsigned int Word;")]
    assert hexrays_calls == ["Word"]


def test_create_typedef_rejects_keyword_name(monkeypatch):
    """R3.2 (F3): a reserved-word typedef name fails loudly before any
    write (same rule as members)."""
    import forge.api.types as forge_types_mod

    calls = []
    monkeypatch.setattr(
        forge_types_mod,
        "create_type",
        lambda name, decl: calls.append(name) or False,
        raising=False,
    )

    with pytest.raises(forge_api.ForgeApiError):
        forge_api.create_typedef("int", "unsigned int")

    assert calls == []


def test_rename_member_uses_rename_udm_til_persistent(monkeypatch):
    """R3.2 (F2): the live path mutates the named-type tinfo in place —
    rename_udm itself is the til write (no commit verb touched); gaps are
    renamable (the F2 case) and bit offsets are accepted."""
    from types import SimpleNamespace

    import ida_typeinf

    class _FakeTinfo:
        def __init__(self, members=None):
            self._members = members or [
                SimpleNamespace(offset=0, name="first"),
                SimpleNamespace(offset=8, name="wide"),  # bit offsets (9.4)
                SimpleNamespace(offset=72, name="tail"),
            ]
            self.renamed = []

        def get_named_type(self, _idati, name):
            return name == "Outer"

        def get_udt_details(self, udt):
            udt[:] = self._members
            return True

        def rename_udm(self, index, new_name, etf_flags=0):
            self.renamed.append((index, new_name))
            self._members[index].name = new_name
            return 0  # TERR_OK

    updates = []
    seen = []
    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeTinfo, raising=False)
    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", list, raising=False)
    monkeypatch.setattr(
        ida_typeinf,
        "update_named_type",
        lambda idati, name, tinfo: updates.append(name) or True,
        raising=False,
    )
    real_rename = _FakeTinfo.rename_udm

    def _spy(self, index, new_name, etf_flags=0):
        seen.append((index, new_name))
        return real_rename(self, index, new_name, etf_flags)

    monkeypatch.setattr(_FakeTinfo, "rename_udm", _spy)

    result = forge_api.rename_member("Outer", 1, "renamed_wide")

    assert result == {
        "ok": True,
        "type": "Outer",
        "offset": 1,
        "from": "wide",
        "to": "renamed_wide",
    }
    # rename_udm carried the rename at the right index — no commit verb
    assert seen == [(1, "renamed_wide")]
    assert updates == []


def test_rename_member_gap_entry_offsets_supported(monkeypatch):
    """R3.2 (F2): padding/gap entries are NOT skipped — renaming them is
    the F2 use case (bit offsets accepted)."""
    from types import SimpleNamespace

    import ida_typeinf

    class _FakeTinfo:
        def __init__(self):
            self._members = [
                SimpleNamespace(offset=0, name="gap_0"),
                SimpleNamespace(offset=0x220, name="gap_1"),  # 0x44 * 8
            ]
            self.renamed = []

        def get_named_type(self, _idati, name):
            return True

        def get_udt_details(self, udt):
            udt[:] = self._members
            return True

        def rename_udm(self, index, new_name, etf_flags=0):
            self.renamed.append((index, new_name))
            self._members[index].name = new_name
            return 0

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeTinfo, raising=False)
    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", list, raising=False)

    result = forge_api.rename_member("Outer", 0x44, "pad_end")

    assert result == {
        "ok": True,
        "type": "Outer",
        "offset": 0x44,
        "from": "gap_1",
        "to": "pad_end",
    }
    assert _FakeTinfo().renamed == []


def test_rename_member_legacy_rebuild_path(monkeypatch):
    """R3.2 (F2): without rename_udm (older builds), the udt copy is
    rebuilt via create_udt and committed through update_named_type."""
    from types import SimpleNamespace

    import ida_typeinf

    class _FakeTinfo:
        def __init__(self):
            self._members = [
                SimpleNamespace(offset=0, name="first"),
                SimpleNamespace(offset=8, name="wide"),
            ]
            self.rebuild_flags = None

        def get_named_type(self, _idati, name):
            return name == "Outer"

        def get_udt_details(self, udt):
            udt[:] = self._members
            return True

        def create_udt(self, udt, flags):
            self._members = list(udt)
            self.rebuild_flags = flags
            return True

    updates = []
    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeTinfo, raising=False)
    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", list, raising=False)
    monkeypatch.setattr(
        ida_typeinf,
        "update_named_type",
        lambda idati, name, tinfo: updates.append((name, tinfo)) or True,
        raising=False,
    )

    result = forge_api.rename_member("Outer", 1, "renamed_wide")

    assert result == {
        "ok": True,
        "type": "Outer",
        "offset": 1,
        "from": "wide",
        "to": "renamed_wide",
    }
    # the rebuilt udt (committed via update_named_type) carries the name
    assert len(updates) == 1
    assert updates[0][0] == "Outer"
    assert updates[0][1]._members[1].name == "renamed_wide"
    assert updates[0][1]._members[0].name == "first"
    assert updates[0][1].rebuild_flags == 0


def test_rename_member_error_dicts(monkeypatch):
    """R3.2 (F2): missing type and missing-offset are distinct error
    dicts; keyword new names raise ForgeApiError before any lookup."""
    from types import SimpleNamespace

    import ida_typeinf

    class _FakeTinfo:
        def __init__(self):
            self._members = [
                SimpleNamespace(offset=0, name="first"),
                SimpleNamespace(offset=64, name="second"),
            ]

        def get_named_type(self, _idati, name):
            return name == "Outer"

        def get_udt_details(self, udt):
            udt[:] = self._members
            return True

        def create_udt(self, udt, flags):
            self._members = list(udt)
            return True

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FakeTinfo, raising=False)
    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", list, raising=False)

    assert forge_api.rename_member("Missing", 0, "x") == {
        "ok": False,
        "error": "no type Missing",
    }
    assert forge_api.rename_member("Outer", 0x10, "x") == {
        "ok": False,
        "error": "no member at offset 0x10",
    }
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.rename_member("Outer", 0, "int")




def test_rename_member_domain_same_name_avoids_sdk(monkeypatch):
    class Member:
        offset = 8
        name = "field"

    class Types:
        def get_by_name(self, _name):
            return object()

        def get_udt_members(self, _tinfo):
            return [Member()]

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    assert forge_api.rename_member("Outer", 8, "field") == {
        "ok": True,
        "type": "Outer",
        "offset": 8,
        "from": "field",
        "to": "field",
    }
def test_add_member_accepts_inline_union_type():
    """E28: add_member with an inline union type lands a real member."""
    forge_api.create_structure("Variant")
    member = forge_api.add_member(
        "Variant",
        0,
        "union { unsigned __int32 as_u32; int as_i32; float as_f32; void *as_ptr; }",
        name="as",
    )
    assert member["name"] == "as"
    assert member["offset"] == 0


def test_placeholder_detection_uses_domain_members(monkeypatch):
    class TInfo:
        def is_udt(self):
            return True

    class Member:
        name = "_placeholder"

    class Types:
        def get_by_name(self, _name):
            return TInfo()

        def get_udt_members(self, _tinfo):
            return iter([Member()])

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: SimpleNamespace(types=Types()))
    assert forge_api._is_forge_placeholder_type("Node") is True
    """E28: add_member with an inline union type lands a real member."""
    forge_api.create_structure("Variant")
    member = forge_api.add_member(
        "Variant",
        0,
        "union { unsigned __int32 as_u32; int as_i32; float as_f32; void *as_ptr; }",
        name="as",
    )
    assert member["name"] == "as"
    assert member["offset"] == 0


# ---------------------------------------------------------------------------
# Round-2 review regressions (2026-08-13)
# ---------------------------------------------------------------------------

def test_name_members_from_printf_uses_format_labels(monkeypatch, _real_hexrays):
    """E14: the format literal's labels name synthesized members at the
    matching memptr arg offsets; hand-named members and non-member args
    are never touched."""
    import ida_bytes

    import forge.api.hexrays as hx  # real module under the fixture

    forge_api.create_structure("Player")
    forge_api.add_member("Player", 0x00, "u64")  # u64_0
    forge_api.add_member("Player", 0x08, "u64")  # u64_8
    forge_api.set_member("Player", 0x08, name="reserved")  # user name
    forge_api.add_member("Player", 0x10, "u64")  # u64_10
    forge_api.add_member("Player", 0x18, "u64")  # u64_18

    monkeypatch.setattr(
        forge_api,
        "imports",
        lambda *a, **k: [{"ea": 0x180001000, "name": "printf"}],
        raising=False,
    )
    monkeypatch.setattr(
        ida_bytes,
        "get_strlit_contents",
        lambda *a, **k: b"score=%u flags=%p name=%s label=%s",
        raising=False,
    )

    def _memptr(offset):
        return SimpleNamespace(
            op=hx.ctype.memptr,
            x=SimpleNamespace(op=hx.ctype.var, v=SimpleNamespace(name="p")),
            m=offset,
        )

    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        get_lvars=lambda: [
            SimpleNamespace(name="p", type=lambda: FakeTinfo("u64 *")),
        ],
        argidx=(),
        treeitems=[
            SimpleNamespace(
                to_specific_type=lambda: SimpleNamespace(
                    op=hx.ctype.call,
                    x=SimpleNamespace(obj_ea=0x180001000),
                    a=[
                        SimpleNamespace(op=hx.ctype.obj, obj_ea=0x40101100),
                        _memptr(0x00),
                        _memptr(0x08),
                        _memptr(0x10),
                        _memptr(0x18),
                        _memptr(0x20),  # no store member at 0x20
                    ],
                )
            )
        ],
    )
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)

    result = forge_api.name_members_from_printf("Player", 0x401000)

    assert result == {"ok": True, "renamed": ["score", "name", "label"]}
    assert forge_api.get_member("Player", 0x00)["name"] == "score"
    assert forge_api.get_member("Player", 0x08)["name"] == "reserved"
    assert forge_api.get_member("Player", 0x10)["name"] == "name"
    assert forge_api.get_member("Player", 0x18)["name"] == "label"
    # the 0x20 member never existed — no phantom naming


def test_name_members_from_printf_recognizes_local_wrappers(monkeypatch, _real_hexrays):
    """E14: a local function named like a log wrapper (fixture log_msg)
    carries the printf argument shape too."""
    import ida_bytes
    import ida_funcs

    import forge.api.hexrays as hx

    forge_api.create_structure("Player")
    forge_api.add_member("Player", 0x00, "u64")

    monkeypatch.setattr(forge_api, "imports", lambda *a, **k: [], raising=False)
    monkeypatch.setattr(
        ida_funcs, "get_func_name", lambda ea: "log_msg", raising=False
    )
    monkeypatch.setattr(
        ida_bytes,
        "get_strlit_contents",
        lambda *a, **k: b"id=%p count=%u",
        raising=False,
    )
    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        get_lvars=lambda: [
            SimpleNamespace(name="p", type=lambda: FakeTinfo("u64 *"))
        ],
        argidx=(),
        treeitems=[
            SimpleNamespace(
                to_specific_type=lambda: SimpleNamespace(
                    op=hx.ctype.call,
                    x=SimpleNamespace(obj_ea=0x140001F0),
                    a=[
                        SimpleNamespace(op=hx.ctype.obj, obj_ea=0x40101100),
                        SimpleNamespace(
                            op=hx.ctype.memptr,
                            x=SimpleNamespace(
                                op=hx.ctype.var, v=SimpleNamespace(name="p")
                            ),
                            m=0x00,
                        ),
                        SimpleNamespace(
                            op=hx.ctype.memptr,
                            x=SimpleNamespace(
                                op=hx.ctype.var, v=SimpleNamespace(name="p")
                            ),
                            m=0xFF,
                        ),
                    ],
                )
            )
        ],
    )
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)

    result = forge_api.name_members_from_printf("Player", 0x401000)

    assert result["ok"] is True
    assert result["renamed"] == ["id"]
    assert forge_api.get_member("Player", 0x00)["name"] == "id"

def test_printf_callee_name_prefers_domain_function_metadata(monkeypatch):
    class Function:
        pass

    class Functions:
        def get_at(self, _ea):
            return Function()

        def get_name(self, _function):
            return "log_msg"

    class DomainDb:
        functions = Functions()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    monkeypatch.setattr(forge_api, "imports", lambda: [])
    monkeypatch.setattr(
        forge_api,
        "_iter_ctree_calls",
        lambda _cfunc: [SimpleNamespace(x=SimpleNamespace(obj_ea=0x401000))],
    )
    assert len(forge_api._printf_call_expressions(SimpleNamespace())) == 1


def test_name_members_from_printf_no_printf_call(monkeypatch, _real_hexrays):
    """E14: no printf-family call in the function → a loud error."""
    cfunc = SimpleNamespace(entry_ea=0x401000, treeitems=[], get_lvars=list, argidx=())
    monkeypatch.setattr(
        forge_api,
        "imports",
        lambda *a, **k: [{"ea": 0x180001000, "name": "malloc"}],
        raising=False,
    )
    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: cfunc, raising=False)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    result = forge_api.name_members_from_printf("S", 0x401000)

    assert result["ok"] is False
    assert "printf" in result["error"]


def test_recover_pipeline_scans_commits_and_retypes(monkeypatch, _real_hexrays):
    """F.8/E.13: recover() builds the structure, deep-scans with recursion
    + clear_first, commits the type, retypes the root and re-applies."""
    calls = []
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda ea, **k: (
            calls.append(("deep_scan", k)) or {
                "structure": k["structure"],
                "members": [{"name": "next"}, {"name": "tag"}],
            }
        ),
    )
    monkeypatch.setattr(
        forge_api,
        "create_type",
        lambda *a, **k: calls.append(("create_type", k)) or {"ok": True},
        raising=False,
    )
    monkeypatch.setattr(
        forge_api,
        "set_lvar_types",
        lambda *a, **k: calls.append(("set_lvar_types", a[1])),
        raising=False,
    )
    monkeypatch.setattr(
        forge_api,
        "reapply",
        lambda *a, **k: calls.append(("reapply", a)) or {"applied": 2, "skipped": []},
        raising=False,
    )

    result = forge_api.recover(0x1400020F0, var_name="v1", name="DeepChainNodeR")

    assert result == {
        "ok": True,
        "structure": "DeepChainNodeR",
        "type": "DeepChainNodeR",
        "members": 2,
    }
    scan_kwargs = calls[0][1]
    assert scan_kwargs["structure"] == "DeepChainNodeR"
    assert scan_kwargs["var_name"] == "v1"
    assert scan_kwargs["recurse_calls"] is True
    assert scan_kwargs["clear_first"] is True
    assert calls[1] == ("create_type", {"overwrite": True})
    assert calls[2] == ("set_lvar_types", {"v1": "DeepChainNodeR *"})
    assert calls[3] == ("reapply", ("DeepChainNodeR",))


def test_recover_reports_commit_failure(monkeypatch):
    monkeypatch.setattr(
        forge_api,
        "deep_scan",
        lambda *a, **k: {"structure": "S", "members": []},
    )
    monkeypatch.setattr(
        forge_api,
        "create_type",
        lambda *a, **k: {"ok": False, "error": "boom"},
        raising=False,
    )

    result = forge_api.recover(0x401000, name="S")

    assert result["ok"] is False
    assert result["error"] == "boom"


def test_reapply_applies_pointer_type_to_scan_evidence(monkeypatch):
    """E.19: reapply re-runs the apply-globally step over the recorded
    scan variables; failing objects are reported, not fatal."""
    import ida_typeinf

    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32", name="x")
    structure = forge_api._resolve_structure("S")
    applied = []

    class _PtrTinfo:
        def __init__(self, *a, **k):
            pass

        def get_named_type(self, til, name):
            return True

        def create_ptr(self, other):
            return True

        def dstr(self):
            return "S *"

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _PtrTinfo, raising=False)

    class _Good:
        name = "v1"

        def apply_type(self, tinfo):
            applied.append(tinfo.dstr())

    class _Bad:
        name = "v2"

        def apply_type(self, tinfo):
            raise RuntimeError("boom")

    member = structure.members[0]
    member.scanned_variables = {_Good(), _Bad()}

    result = forge_api.reapply("S")

    assert result["applied"] == 1
    assert result["skipped"] == ["v2"]
    assert applied == ["S *"]


def test_nudge_members_reports_moved_map():
    forge_api.create_structure("M")
    forge_api.add_member("M", 0x0, "u32")
    forge_api.add_member("M", 0x8, "u32")

    result = forge_api.nudge_members("M", [0x0], 4)

    assert result["ok"] is True
    assert result["moved"] == {"0x0": "0x4"}


def test_push_all_surfaces_real_commit_error(monkeypatch):
    """E20a: push_all failures carry the create_type error for
    known structures (not the generic string)."""
    forge_api.create_structure("Good")
    forge_api.add_member("Good", 0, "u32")
    forge_api.create_structure("Bad")
    forge_api.add_member("Bad", 0, "u32")

    monkeypatch.setattr(forge_api, "push_type", lambda name: False)
    monkeypatch.setattr(
        forge_api,
        "create_type",
        lambda *a, **k: {"ok": False, "error": "boom"},
        raising=False,
    )

    result = forge_api.push_all()

    assert set(result["pushed"]) == set()
    assert result["failed"] == {"Good": "boom", "Bad": "boom"}


def test_decompile_many_returns_heads(monkeypatch):
    """F.2: decompile_many rows carry ea/ok/first-pseudocode-line."""
    monkeypatch.setattr(
        forge_api,
        "signature",
        lambda ea: f"int f_{ea:x}(void)" if ea == 0x401000 else None,
        raising=False,
    )

    rows = forge_api.decompile_many([0x401000, 0x402000])

    assert rows == [
        {"ea": 0x401000, "ok": True, "head": "int f_401000(void)"},
        {"ea": 0x402000, "ok": False, "head": None},
    ]


def test_scan_returned_rows_with_callers(monkeypatch, _real_hexrays):
    """F.3: pointer-typed returns yield recon rows; caller assignments
    resolve to the receiving lvar name."""
    import sys as _sys

    # the guess-allocation module (imported by scan_returned at call
    # time) needs a visitor base; the conftest stub only carries
    # FunctionTouchVisitor — mirror what test_guess_allocation installs.
    visitor_module = _sys.modules["forge.api.visitor"]
    if not hasattr(visitor_module, "RecursiveUpwardsObjectVisitor"):
        visitor_module.RecursiveUpwardsObjectVisitor = type(
            "RecursiveUpwardsObjectVisitor",
            (),
            {
                "__init__": lambda self, *a, **k: None,
                "parent_expr": lambda self: None,
                "get_line": lambda self: "",
                "_cfunc": None,
            },
        )

    import forge.api.hexrays as hx

    make_chain = SimpleNamespace(
        entry_ea=0x1400020F0,
        treeitems=[
            SimpleNamespace(
                to_specific_type=lambda: SimpleNamespace(
                    op=hx.ctype.cit_return,
                    x=SimpleNamespace(
                        ea=0x140002120,
                        type=SimpleNamespace(
                            is_ptr=lambda: True, dstr=lambda: "DeepChainNode *"
                        ),
                        v=SimpleNamespace(name="v1"),
                    ),
                )
            )
        ],
    )
    caller = SimpleNamespace(
        entry_ea=0x140001000,
        treeitems=[
            SimpleNamespace(
                to_specific_type=lambda: SimpleNamespace(
                    op=hx.ctype.call,
                    x=SimpleNamespace(obj_ea=0x1400020F0),
                    a=[],
                )
            )
        ],
        body=SimpleNamespace(
            find_parent_of=lambda call: SimpleNamespace(
                op=hx.ctype.asg, x=SimpleNamespace(v=SimpleNamespace(name="node"))
            )
        ),
    )

    def _decompile(ea):
        if ea == 0x1400020F0:
            return make_chain
        if ea == 0x140001000:
            return caller
        return None

    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: _decompile(ea))
    monkeypatch.setattr(
        _real_hexrays,
        "get_funcs_calling_address",
        lambda ea: {0x140001000},
    )

    rows = forge_api.scan_returned(0x1400020F0)

    assert rows == [
        {
            "return_ea": 0x140002120,
            "type": "DeepChainNode *",
            "var": "v1",
            "allocation": None,
            "callers": [{"func_ea": 0x140001000, "lvar_name": "node"}],
        }
    ]


def test_export_import_store_roundtrip(tmp_path):
    """F.5: export/import round-trips the store model through JSON."""
    forge_api.create_structure("World")
    forge_api.add_member("World", 0x10, "u64", name="magic", comment="c")
    forge_api.add_member("World", 0x18, "u32", name="count")

    exported = forge_api.export_store(str(tmp_path / "store.json"))

    assert exported["ok"] is True
    assert exported["structures"] == 1

    forge_api.remove_structure("World")
    assert forge_api.structures() == []

    imported = forge_api.import_store(str(tmp_path / "store.json"))

    assert imported == {"ok": True, "imported": ["World"], "skipped": []}
    world = forge_api.get_structure("World")
    assert {m["name"]: m["offset"] for m in world["members"]} == {
        "magic": 0x10,
        "count": 0x18,
    }


def test_import_store_skips_existing_unless_merge(tmp_path):
    """F.5: merge=False skips names already in the store; merge=True
    replaces them."""
    forge_api.create_structure("World")
    forge_api.add_member("World", 0, "u32", name="x")
    forge_api.export_store(str(tmp_path / "store.json"))
    forge_api.remove_structure("World")
    forge_api.create_structure("World")
    forge_api.add_member("World", 0x20, "u32", name="y")

    skipped = forge_api.import_store(str(tmp_path / "store.json"))
    assert skipped == {"ok": True, "imported": [], "skipped": ["World"]}

    merged = forge_api.import_store(str(tmp_path / "store.json"), merge=True)
    assert merged == {"ok": True, "imported": ["World"], "skipped": []}


def test_split_flags_splits_byte_aligned_fields(monkeypatch):
    """E.18: a u64 flag member splits into byte-aligned named fields."""
    from forge.api import members as members_mod

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _sized_parse, raising=False)
    forge_api.create_structure("Flags")
    forge_api.add_member("Flags", 0x10, "u64", name="flags")

    result = forge_api.split_flags(
        "Flags", 0x10, [("visible", 8), ("mode", 8), ("opts", 32), ("reserved", 16)]
    )

    assert result["ok"] is True
    assert result["bit_spec_ok"] is True
    offsets = [(m["offset"], m["name"], m["type"]) for m in result["members"]]
    assert offsets == [
        (0x10, "visible", "u8"),
        (0x11, "mode", "u8"),
        (0x12, "opts", "u32"),
        (0x16, "reserved", "u16"),
    ]
    assert len(forge_api.get_structure("Flags")["members"]) == 4


def test_split_flags_rejects_bit_fields():
    """E18: non-byte-aligned widths fail loudly (bit-fields unsupported)."""
    forge_api.create_structure("Flags")
    forge_api.add_member("Flags", 0x10, "u64", name="flags")

    result = forge_api.split_flags("Flags", 0x10, [("a", 4), ("b", 4)])

    assert result["ok"] is False
    assert "bit-fields not byte-aligned" in result["error"]


def test_backfill_lumina_applies_metadata(monkeypatch):
    """F.7: calc+apply per function; missing API is a loud error."""
    import ida_hexrays

    applied = []
    monkeypatch.setattr(
        ida_hexrays,
        "calc_func_metadata",
        lambda ea: (applied.append(("calc", ea)) or ea),
        raising=False,
    )
    monkeypatch.setattr(
        ida_hexrays,
        "apply_metadata",
        lambda ea: applied.append(("apply", ea)),
        raising=False,
    )

    result = forge_api.backfill_lumina([0x401000, 0x402000])

    assert result == {"applied": 2, "errors": []}
    assert applied == [("calc", 0x401000), ("apply", 0x401000), ("calc", 0x402000), ("apply", 0x402000)]

    monkeypatch.setattr(ida_hexrays, "calc_func_metadata", None, raising=False)
    missing = forge_api.backfill_lumina([0x401000])
    assert missing == {
        "ok": False,
        "error": "lumina metadata API not available on this build",
    }


def test_if_inverter_and_transform_contract(monkeypatch):
    """F.6: the ctree_transform DSL — IfInverter wraps one inversion;
    StatementTransform is a contract base."""
    import ida_hexrays

    from forge.api.ctree_transform import (
        CtreeStatementVisitor,
        IfInverter,
        StatementTransform,
    )
    from forge.features.swap_if import helper as swap_helper

    monkeypatch.setattr(ida_hexrays, "cit_if", 42, raising=False)
    monkeypatch.setattr(ida_hexrays, "ctree_visitor_t", type("V", (), {
        "__init__": lambda self, *a, **k: None,
        "apply_to": lambda self, *a, **k: None,
    }), raising=False)
    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        treeitems=[
            SimpleNamespace(
                to_specific_type=lambda: SimpleNamespace(
                    op=42, cif=SimpleNamespace(ielse=True, ea=0x4000)
                )
            )
        ],
        body=None,
    )
    inverted = []
    monkeypatch.setattr(
        swap_helper, "inverse_if", lambda cif: inverted.append(cif), raising=False
    )

    transform = IfInverter(cfunc, 0x4000)
    assert transform.transform() is True
    assert inverted[0].ea == 0x4000

    with pytest.raises(NotImplementedError):
        StatementTransform(None).transform()

    # the window visitor records statements and dispatches
    seen = []

    class _Spy(CtreeStatementVisitor):
        def handle_statement(self, insn):
            seen.append(getattr(insn, "ea", None))

    visitor = _Spy(-1)
    visitor.visit_insn(SimpleNamespace(ea=0x4010))
    assert visitor.window == [SimpleNamespace(ea=0x4010)]
    assert seen == [0x4010]


def test_iter_returned_exprs_reads_creturn_expr(monkeypatch, _real_hexrays):
    """Live 9.4 finding (2026-08-15): return statements carry the value
    under creturn.expr, via a PROPERTY to_specific_type."""
    from forge.api import hexrays as hexrays_mod

    # property-style wrapper: to_specific_type is NOT callable
    return_value = SimpleNamespace(op=65, v=SimpleNamespace(idx=5))
    item = SimpleNamespace(
        to_specific_type=SimpleNamespace(
            op=80, creturn=SimpleNamespace(expr=return_value)
        )
    )
    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        treeitems=[item],
        body=SimpleNamespace(apply_to=lambda *a, **k: None),
    )

    found = list(hexrays_mod.iter_returned_exprs(cfunc, ret_op=80))

    assert found == [return_value]


def test_guess_allocation_callee_statement_wrapper_property(monkeypatch, _real_hexrays):
    """Live 9.4 finding: treeitem statements arrive through a
    property-style to_specific_type that must not be called — the alias
    chain still resolves `return v` where v = w; w = calloc(...)."""
    import ida_funcs

    from forge.api.scan_object import ObjectType
    from forge.features.guess_allocation import guess_allocation as guess_mod

    cfunc = SimpleNamespace(
        entry_ea=0x401000,
        body=SimpleNamespace(find_parent_of=lambda expr: None),
    )
    obj = SimpleNamespace(id=ObjectType.local_variable, ea=0x5000, name="node")

    visitor = guess_mod.GuessAllocationVisitor(cfunc, obj)
    monkeypatch.setattr(
        guess_mod,
        "ctype",
        SimpleNamespace(asg=1, ref=2, ret=3, call=5, var=4),
    )
    monkeypatch.setattr(
        visitor,
        "parent_expr",
        lambda: SimpleNamespace(op=1, y=SimpleNamespace(op=5, x=SimpleNamespace(obj_ea=0x402000))),
    )
    monkeypatch.setattr(visitor, "get_line", lambda: "node = chain_node_new(...)")
    v = SimpleNamespace(idx=7)
    w = SimpleNamespace(idx=9)
    monkeypatch.setattr(
        guess_mod.MemoryAllocationObject,
        "create",
        lambda _cfunc, _expr: (
            SimpleNamespace(ea=0x401200, size=40)
            if getattr(getattr(_expr, "x", None), "obj_ea", None) == 0x6000
            else None
        ),
    )
    monkeypatch.setattr(
        ida_funcs, "get_func", lambda ea: SimpleNamespace(start_ea=0x402000), raising=False
    )
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: SimpleNamespace(
            treeitems=[
                # property-style shape: the specific object directly (patched ops:
                # ret=3, asg=1, var=4, call=5)
                SimpleNamespace(
                    to_specific_type=SimpleNamespace(
                        op=3, creturn=SimpleNamespace(expr=SimpleNamespace(op=4, v=v))
                    )
                ),
                SimpleNamespace(
                    to_specific_type=SimpleNamespace(
                        op=1,
                        x=SimpleNamespace(op=4, v=v),
                        y=SimpleNamespace(op=4, v=w),
                    )
                ),
                SimpleNamespace(
                    to_specific_type=SimpleNamespace(
                        op=1,
                        x=SimpleNamespace(op=4, v=w),
                        y=SimpleNamespace(op=5, x=SimpleNamespace(obj_ea=0x6000)),
                    )
                ),
            ]
        ),
    )

    visitor._manipulate(SimpleNamespace(), obj)

    assert visitor._data == [
        [0x401200, "node", "node = chain_node_new(...)", "HEAP", 40, 0x402000]
    ]


def test_rename_ea_renames_function_or_global(monkeypatch):
    """Round-2 request #1: the naming-core verb — ida_name.set_name with
    SN_NOCHECK semantics, loud failure."""
    import ida_name

    calls = []
    monkeypatch.setattr(
        ida_name,
        "set_name",
        lambda ea, name, flags: calls.append((ea, name, flags)) or True,
        raising=False,
    )
    monkeypatch.setattr(ida_name, "SN_NOCHECK", 0x10, raising=False)

    result = forge_api.rename_ea(0x140001000, "run_struct_sections")

    assert result == {"ok": True, "ea": 0x140001000, "name": "run_struct_sections"}
    assert calls == [(0x140001000, "run_struct_sections", 0x10)]


def test_rename_ea_fails_loudly(monkeypatch):
    import ida_name

    monkeypatch.setattr(ida_name, "set_name", lambda *args: False, raising=False)
    monkeypatch.setattr(ida_name, "SN_NOCHECK", 0x10, raising=False)

    result = forge_api.rename_ea(0x140001000, "dup_name")

    assert result["ok"] is False
    assert "dup_name" in result["error"]

def test_rename_ea_prefers_domain_names(monkeypatch):
    calls = []

    class Names:
        def set_name(self, ea, name, flags):
            calls.append((ea, name, flags))
            return True

    class DomainDb:
        names = Names()

    monkeypatch.setattr(forge_api, "_domain_database_or_none", lambda: DomainDb())
    result = forge_api.rename_ea(0x140001000, "domain_name")
    assert result == {"ok": True, "ea": 0x140001000, "name": "domain_name"}
    assert calls == [(0x140001000, "domain_name", 1)]


def test_templated_args_with_suffixes_synthesize_names():
    assert forge_api._templated_args_with_suffixes(["u32"]) == ["u32", "u32"]
    assert forge_api._templated_args_with_suffixes(["char *", "u32"]) == [
        "char *",
        "char__",
        "u32",
        "u32",
    ]
    assert forge_api._templated_args_with_suffixes([]) == []


def test_templated_decl_expands_args_for_multi_token_keys(monkeypatch):
    """Round-2 §3.5: std::vector<T> needs (type, suffix) pairs; the facade
    accepts plain type args and synthesizes the suffix."""
    from forge.features.templated_types.templated_types import TemplatedTypes

    seen = []

    class _FakeTemplate(TemplatedTypes):
        def get_decl_str(self, key, args):
            seen.append((key, args))
            return ("std_vector_u32", "struct std_vector_u32 { u32 *_Myfirst; };")

    monkeypatch.setattr(forge_api, "_templated_instance", lambda: _FakeTemplate())

    result = forge_api.templated_decl("std::vector<T>", ["u32"])

    assert result == {
        "name": "std_vector_u32",
        "cdecl": "struct std_vector_u32 { u32 *_Myfirst; };",
    }
    assert seen == [("std::vector<T>", ["u32", "u32"])]


def test_nudge_members_unknown_offsets_are_loud(monkeypatch):
    forge_api.create_structure("DemoNode")
    forge_api.add_member("DemoNode", 0x0, "u32", name="tag")

    result = forge_api.nudge_members("DemoNode", [0x18], -0x20)

    assert result["ok"] is False
    assert "0x18" in result["error"]


def _commit_fails(monkeypatch):
    from forge.api import structure as structure_mod

    _commit_structure_stubs(monkeypatch)
    monkeypatch.setattr(
        structure_mod.Structure,
        "set_cdecl",
        lambda self, cdecl, origin=0, *, overwrite=None: None,
        raising=False,
    )


def test_create_type_reports_keyword_tag_plainly(monkeypatch):
    """Recovery-eval gap #1: `struct inline` is silently rejected by the
    IDB parser; the facade must say the name is a C keyword, not the
    generic 'failed to recreate'."""
    _commit_fails(monkeypatch)
    forge_api.create_structure("inline")

    result = forge_api.create_type("inline", overwrite=True)

    assert result["ok"] is False
    assert "C keyword" in result["error"]


def test_create_type_reports_parser_rejection(monkeypatch):
    """Recovery-eval gap #1: a declaration the IDB parser rejects surfaces
    the parser error count."""
    import ida_typeinf

    _commit_fails(monkeypatch)
    monkeypatch.setattr(ida_typeinf, "idc_parse_types", lambda *a, **k: 4, raising=False)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32", name="x")

    result = forge_api.create_type("S", overwrite=True)

    assert result["ok"] is False
    assert "rejected" in result["error"]
    assert "4" in result["error"]
def test_type_of_ea_dispatches_nalt_get_tinfo_with_correct_arg_order(monkeypatch):
    """Bug 4 (recovery eval): ``type_of(<EA>)`` on IDA 9.4 called the
    nonexistent module-level ``ida_typeinf.get_tinfo(ea, tinfo)`` (and a
    swapped-arg ``ida_bytes.get_tinfo`` fallback), returning None for every
    address. It must call ``ida_nalt.get_tinfo(tinfo, ea)`` and map the
    result into the scalar dict — no IDA runtime required."""
    import ida_bytes
    import ida_nalt
    import ida_typeinf

    call_args = []

    def _nalt_get_tinfo(tinfo, ea):
        call_args.append(("nalt", tinfo, ea))
        tinfo._name = "const char *"
        tinfo._size = 8
        return True

    monkeypatch.setattr(
        ida_nalt, "get_tinfo", _nalt_get_tinfo, raising=False
    )
    monkeypatch.setattr(
        ida_bytes,
        "get_tinfo",
        lambda tinfo, ea: call_args.append(("bytes", tinfo, ea)) or False,
        raising=False,
    )
    landed = []

    class _FakeEA:
        def __init__(self):
            self._name = ""
            self._size = 0

        def dstr(self):
            return self._name

        def get_size(self):
            return self._size

    monkeypatch.setattr(
        ida_typeinf,
        "tinfo_t",
        lambda: landed.append(_FakeEA()) or landed[-1],
        raising=False,
    )

    result = forge_api.type_of(0x140007E28)

    # ida_nalt is preferred and receives (tinfo_out, ea) — never (ea, tinfo);
    # landed[0] is the exact tinfo instance passed into get_tinfo
    assert call_args == [("nalt", landed[0], 0x140007E28)]
    assert result == {
        "name": 0x140007E28,
        "type": "const char *",
        "size": 8,
        "kind": "scalar",
        "members": [],
    }


def test_type_of_ea_falls_back_to_bytes_and_none_when_unavailable(monkeypatch):
    """Bug 4: without ``ida_nalt.get_tinfo`` the facade falls back to
    ``ida_bytes.get_tinfo``; when neither lands, ``type_of(EA)`` returns
    None instead of raising."""
    import ida_bytes
    import ida_nalt
    import ida_typeinf

    monkeypatch.delattr(ida_nalt, "get_tinfo", raising=False)
    calls = []

    def _bytes_get_tinfo(tinfo, ea):
        calls.append((tinfo, ea))
        return False  # no tinfo landed

    monkeypatch.setattr(ida_bytes, "get_tinfo", _bytes_get_tinfo, raising=False)
    monkeypatch.setattr(ida_typeinf, "tinfo_t", lambda: object(), raising=False)

    assert forge_api.type_of(0x140007E28) is None
    assert len(calls) == 1
    assert calls[0][1] == 0x140007E28

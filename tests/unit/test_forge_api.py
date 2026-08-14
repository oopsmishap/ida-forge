"""Behavior tests for the flat, self-describing forge_api facade."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import forge.api.members as members_mod
import forge_api


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


def test_help_topic_scoped():
    entry = forge_api.help("deep_scan")["functions"]["deep_scan"]
    assert entry["group"] == "scan"
    with pytest.raises(forge_api.ForgeApiError):
        forge_api.help("does_not_exist")


def test_requires_ida_guard(monkeypatch):
    monkeypatch.setattr(forge_api, "_ida_available", lambda: False)
    with pytest.raises(forge_api.ForgeApiError, match="requires an IDA Pro session"):
        forge_api.decompile(1)


def test_to_hex_is_pure():
    assert forge_api.to_hex(0x401000) == "0x401000"


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
    failure) returns the distinct recreate error, never "already exists"."""
    _commit_stubs(monkeypatch, parses=True, set_result=None)
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    result = forge_api.create_type("S", overwrite=True)

    assert result == {"ok": False, "error": "failed to recreate type after delete (see IDA log)"}


def test_create_type_overwrite_success_returns_type_name(monkeypatch):
    """R10: overwriting an existing type succeeds and reports the commit."""
    _commit_stubs(monkeypatch, parses=True, set_result=object())
    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32")

    result = forge_api.create_type("S", overwrite=True)

    assert result["ok"] is True
    assert result["type_name"] == "S"
    assert "int x" in result["declaration"]


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

    assert result == {"ok": True, "type_name": "S", "skipped": []}


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
        "error": "failed to create type (see IDA log for reason)",
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
    """I.8: an explicit root_type declaration wins over the auto void *."""
    import ida_hexrays

    monkeypatch.setattr(_real_hexrays, "decompile", lambda ea: _scan_cfunc("a1", "__int64"), raising=False)
    monkeypatch.setattr(ida_hexrays, "lvar_locator_t", lambda loc, defea: SimpleNamespace(location=loc, defea=defea), raising=False)
    monkeypatch.setattr(ida_hexrays, "lvar_saved_info_t", type("S", (), {"__init__": lambda self: setattr(self, "ll", None) or setattr(self, "type", None)}), raising=False)
    monkeypatch.setattr(ida_hexrays, "MLI_TYPE", 0x10, raising=False)
    retyped = []
    monkeypatch.setattr(ida_hexrays, "modify_user_lvar_info", lambda ea, flags, lvi: retyped.append(lvi.type.dstr()) or True, raising=False)
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl), raising=False)
    from importlib import import_module as _import
    scanner_mod = _import("forge.api.scanner")
    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _ScanVisitorStub, raising=False)

    forge_api.deep_scan(0x401000, var_name="a1", root_type="World *")

    assert retyped == ["World *"]


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
    # offset 8's only member is disabled: hidden when excluded, visible when
    # include_disabled=True
    assert forge_api.get_member("S", 8)["name"] == "gone"
    assert forge_api.get_member("S", 8, include_disabled=False) is None


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
    """I.19: redefine_range clears auto names in the span, then del_items,
    then apply_tinfo — in that order — and reports the applied type."""
    import ida_bytes
    import ida_name
    import ida_typeinf

    events = []
    monkeypatch.setattr(ida_bytes, "get_flags", lambda h: 1, raising=False)
    monkeypatch.setattr(ida_bytes, "is_head", lambda f: True, raising=False)
    monkeypatch.setattr(ida_bytes, "has_user_name", lambda f: False, raising=False)
    monkeypatch.setattr(ida_bytes, "DELIT_SIMPLE", 1, raising=False)
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
    monkeypatch.setattr(
        ida_name,
        "del_global_name",
        lambda h: events.append(("del_name", h)),
        raising=False,
    )
    monkeypatch.setattr(
        ida_typeinf,
        "apply_tinfo",
        lambda ea, tinfo, flags: events.append(("apply", ea, tinfo.dstr())),
        raising=False,
    )
    monkeypatch.setattr(ida_typeinf, "TINFO_DEFINITE", 0x100, raising=False)

    result = forge_api.apply_type(0x401000, "OuterAggregate", redefine_range=True)

    kinds = [event[0] for event in events]
    assert kinds[0] == "del_name"
    assert kinds[-2:] == ["del_items", "apply"]
    # the base address itself keeps its (user) name
    assert 0x401000 not in [event[1] for event in events if event[0] == "del_name"]
    assert result == {"ok": True, "ea": 0x401000, "type": "OuterAggregate"}


def test_apply_type_parse_failure_reports_error(monkeypatch):
    """I.19: an unparsable declaration that is not a store structure returns
    an error dict instead of raising."""
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: None, raising=False)
    result = forge_api.apply_type(0x401000, "NotParsable */")
    assert result == {"ok": False, "error": "could not parse declaration 'NotParsable */'"}
    monkeypatch.setattr(members_mod, "parse_user_tinfo", lambda decl: FakeTinfo(decl.split()[0]), raising=False)


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

    members = {m["name"]: m for m in result["members"]}
    assert result["structure"] == "global_obj_1400a4000"
    assert members["qword"]["offset"] == 0x40
    assert members["qword"]["type"] == "u64"
    assert members["dword"]["offset"] == 0x60
    assert members["dword"]["type"] == "u32"


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
    monkeypatch.setattr(
        ida_typeinf,
        "idc_parse_types",
        lambda decl, flags: forged.append(decl) or True,
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
    }
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: SimpleNamespace(start_ea=table[ea][0], end_ea=table[ea][1]),
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
    result = forge_api.vtable_entries(0x140006358)
    assert result == []

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


# ---------------------------------------------------------------------------
# Round-2 review regressions (2026-08-13)
# ---------------------------------------------------------------------------

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

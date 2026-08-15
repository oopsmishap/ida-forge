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


def test_intN_aliases_normalize_in_type_declarations():
    """R2.5: the intN/uintN shorthand normalizes to the __intN spellings so
    member types typed ``int32``/``uint64`` parse instead of silently
    vanishing from the committed cdecl."""
    from forge.api.members import normalize_type_declaration

    assert normalize_type_declaration("int8") == "i8"
    assert normalize_type_declaration("int16") == "i16"
    assert normalize_type_declaration("int32") == "i32"
    assert normalize_type_declaration("int64") == "i64"
    assert normalize_type_declaration("uint8") == "u8"
    assert normalize_type_declaration("uint16") == "u16"
    assert normalize_type_declaration("uint32") == "u32"
    assert normalize_type_declaration("uint64") == "u64"
    assert normalize_type_declaration("uint32 *") == "u32 *"
    assert normalize_type_declaration("uint64[8]") == "u64[8]"
    # unknown tokens are untouched — the parse path still fails loudly
    assert normalize_type_declaration("int33") == "int33"


def test_intN_aliases_add_member_accepts_shorthand(monkeypatch):
    """R2.5: add_member with intN/uintN shorthand succeeds (parse goes
    through the same normalize step as the display path)."""
    forge_api.create_structure("S")
    member = forge_api.add_member("S", 0x10, "int32", name="width")
    assert member["offset"] == 0x10
    assert member["name"] == "width"


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

    # Gap #3 (recovery eval 2026-08-13): the stub scan produces no
    # evidence, so the root retype is undone — a failed scan must not
    # leave the lvar re-typed.
    assert retyped == ["World *", "__int64"]


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


def test_add_member_accepts_inline_union_type(monkeypatch):
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
    import sys as _sys

    import ida_funcs

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

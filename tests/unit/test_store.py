"""StructureCatalog (I.28): shared store, persistence, form coupling."""

from __future__ import annotations

import sys
from importlib import import_module
from types import SimpleNamespace
from typing import ClassVar

import pytest

import forge_api

# form module import (via StructureBuilderForm) needs these two names the
# conftest hexrays stub does not carry; the form test file patches the same
# two before importing.
hexrays_api = import_module("forge.api.hexrays")
hexrays_api.get_funcs_referencing_address = lambda *_args, **_kwargs: []
hexrays_api.is_legal_type = lambda *_args, **_kwargs: True
scanner_api = import_module("forge.api.scanner")
scanner_api.NewShallowScanVisitor = type("NewShallowScanVisitor", (), {})


class _FakeStorage:
    """Dict-backed stand-in for forge.api.storage.Storage."""

    _data: ClassVar[dict[str, dict]] = {}

    def __init__(self, name: str):
        self.name = name
        self._local = _FakeStorage._data.setdefault(name, {})

    def __getitem__(self, key):
        return self._local[key]

    def __setitem__(self, key, value):
        self._local[key] = value

    def get(self, key, default=None):
        return self._local.get(key, default)

    def keys(self):
        return list(self._local)

    def items(self):
        return list(self._local.items())

    def kill(self):
        self._local.clear()


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    from forge.api import store as store_module

    monkeypatch.setattr(store_module, "Storage", _FakeStorage)
    monkeypatch.setattr(
        sys.modules["forge.api.storage"], "Storage", _FakeStorage, raising=False
    )
    _FakeStorage._data.clear()
    forge_api._structures.clear()
    forge_api._state.current = None
    from forge.api.store import catalog
    catalog._loaded = False
    catalog._load_failed = False
    catalog._recovery = {"load_failures": 0, "corrupt_entries": 0, "write_failures": 0}
    catalog._last_error = None

    catalog.events.clear()
    yield
    catalog.events.clear()
    forge_api._structures.clear()
    forge_api._state.current = None
    _FakeStorage._data.clear()


class FakeTinfo:
    def __init__(self, name: str):
        self._name = name

    def dstr(self):
        return self._name

    def get_size(self):
        return 4

    def is_floating(self):
        return False

    def is_integral(self):
        return True

    def is_signed(self):
        return False

    def equals_to(self, other):
        return self.dstr() == getattr(other, "dstr", lambda: "")()


@pytest.fixture(autouse=True)
def _stub_member_tinfo(monkeypatch):
    """Route parse_user_tinfo -> FakeTinfo so Member construction works
    under the conftest ida_typeinf dummy (test_forge_api pattern)."""
    import forge.api.members as members_mod

    monkeypatch.setattr(
        members_mod,
        "parse_user_tinfo",
        lambda declaration: FakeTinfo((declaration or "u32").split()[0]),
    )


def test_catalog_persistence_preserves_member_decl_src():
    """Bug 3 (recovery eval): ``_serialize`` dropped ``decl_src``, so a
    persist/reload cycle degraded authored struct-typed members to rendered
    placeholders (``fixture_World *`` -> ``unsigned __int64``), silently
    changing committed sizes. The authored declaration must survive the
    catalog round trip and be re-asserted on the reloaded member."""
    from forge.api.store import StructureCatalog

    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "fixture_World *", name="world")

    structure = StructureCatalog()["S"]
    payload = StructureCatalog()._serialize(structure)
    member_payload = payload["members"][0]
    assert member_payload["decl_src"] == "fixture_World *"

    restored = StructureCatalog()._deserialize(payload)
    member = restored.get_member_by_offset(0)
    assert member.decl_src == "fixture_World *"
    # re-parse went through the authored declaration, not a u64 fallback
    assert member.tinfo.dstr() != "u64"
    assert member.tinfo.dstr().startswith("fixture_World")


def test_catalog_persistence_pack_round_trip():
    """R3.2 (F1): the pack attribute survives a catalog serialize/reload;
    catalogs persisted before R3.2 (no "pack" key) default to packed."""
    from forge.api.store import StructureCatalog

    forge_api.create_structure("PackedS", pack=2)
    forge_api.set_pack("PackedS", None)
    forge_api.create_structure("DefaultedS")

    fresh = StructureCatalog()

    assert fresh["PackedS"].pack is None
    assert fresh["DefaultedS"].pack == 1

    # legacy payload without a "pack" key restores as packed
    legacy = StructureCatalog()
    legacy_structure = legacy._deserialize(
        {"name": "Legacy", "main_offset": 0, "members": []}
    )
    assert legacy_structure.pack == 1


def test_catalog_persistence_scan_sites_round_trip():
    """R3.6: scan-evidence rows ride the catalog's netnode payload —
    plain rows survive serialize/reload (no live scan objects needed on
    reload) and last_applied rides along."""
    from forge.api.members import Member, parse_user_tinfo
    from forge.api.store import StructureCatalog, _live_scan_site_rows
    from forge.api.structure import Structure

    class _Site:
        __hash__ = object.__hash__

        def __init__(self, func_ea, name, ea):
            self.func_ea = func_ea
            self.name = name
            self.ea = ea
            self.tinfo = None

    structure = Structure("S")
    member = Member(0, parse_user_tinfo("u32"), None, 0)
    member.scanned_variables = {
        _Site(0x140001610, "v1", 0x140001000)
    }
    structure.add_member(member)
    structure.last_apply_sites = [
        {"func_ea": 0x140001610, "var": "v1", "ea": 0x140000000, "type": "S *"}
    ]
    structure.scan_sites_rows = _live_scan_site_rows(structure)

    payload = StructureCatalog()._serialize(structure)
    assert payload["scan_sites"] == [
        {
            "func_ea": 0x140001610,
            "var": "v1",
            "ea": 0x140001000,
            "type": None,
            "member_offset": 0,
        }
    ]
    assert payload["last_applied"] == [
        {"func_ea": 0x140001610, "var": "v1", "ea": 0x140000000, "type": "S *"}
    ]

    restored = StructureCatalog()._deserialize(payload)
    assert restored.scan_sites_rows == payload["scan_sites"]
    assert restored.last_apply_sites == payload["last_applied"]


def test_catalog_persistence_vtable_member_round_trip(monkeypatch):
    """I.28: vtable members survive the round trip as VirtualTables."""
    import ida_name

    from forge.api.members import VirtualTable
    from forge.api.store import StructureCatalog
    from forge.api.structure import Structure

    monkeypatch.setattr(
        ida_name, "get_name", lambda ea: "vftable_140006358", raising=False
    )

    structure = Structure("V")
    structure.add_member(VirtualTable(0, 0x140006358, None, 0))
    from forge.api.store import catalog

    catalog["V"] = structure

    fresh = StructureCatalog()
    loaded = fresh["V"]
    member = loaded.get_member_by_offset(0)
    assert isinstance(member, VirtualTable)
    assert member.address == 0x140006358


def test_catalog_load_falls_back_to_u64_for_bad_member_type(monkeypatch):
    """I.28: an unparsable persisted member type degrades to u64 with a
    warning instead of dropping the member."""
    import forge.api.members as members_mod
    from forge.api.store import StructureCatalog

    payload = {
        "structures": [
            {
                "name": "S",
                "main_offset": 0,
                "created_type_name": None,
                "is_auto_named": False,
                "provenance": {},
                "members": [
                    {
                        "offset": 0,
                        "name": "bad",
                        "type": "NoSuchThing *",
                        "size": 8,
                        "comment": "",
                        "enabled": True,
                        "is_array": False,
                        "origin": 0,
                        "kind": "member",
                    }
                ],
                "child_relationships": [],
            }
        ],
        "current": "S",
    }
    _FakeStorage._data["Structures"] = {"data": payload}

    monkeypatch.setattr(
        members_mod,
        "parse_user_tinfo",
        lambda declaration: FakeTinfo("u64") if declaration == "u64" else None,
    )

    fresh = StructureCatalog()
    loaded = fresh["S"]
    member = loaded.get_member_by_offset(0)
    assert member is not None
    assert member.tinfo.dstr() == "u64"


def test_store_has_no_default_wipe_verb():
    """2026-08-30: clear_structures was REMOVED from the facade.

    Eval agents used it per-script to wipe the shared store, erasing the
    persisted catalog the GUI structure-builder reads (data-loss trap).
    Nothing — not the catalog, not __all__, not help() — may offer a
    wholesale wipe through the facade.
    """
    assert "clear_structures" not in forge_api.__all__
    assert "clear_structures" not in forge_api.help()["functions"]


def test_form_shares_catalog_with_forge_api(monkeypatch):
    """I.28: headless mutations are visible to the form's structure dict and
    form deletions update the headless store."""
    from forge.api.store import catalog
    from forge.features.structure_builder.form import StructureBuilderForm

    form = StructureBuilderForm()
    try:
        assert form.structures is catalog

        forge_api.create_structure("Shared")
        add = forge_api.add_member("Shared", 0, "u32", name="count")
        assert "ok" not in add and "error" not in add
        assert "Shared" in form.structures
        assert form.structures["Shared"].get_member_by_offset(0).name == "count"

        structure = forge_api._resolve_structure("Shared")
        form.ui = SimpleNamespace()
        monkeypatch.setattr(form, "reload_structure_list", lambda: None, raising=False)
        monkeypatch.setattr(form, "update_action_states", lambda: None, raising=False)
        monkeypatch.setattr(form, "_current_tree_structure", lambda: structure, raising=False)

        form.remove_structure()

        assert "Shared" not in forge_api.structures()
    finally:
        del form

# -- provenance-safe member merge (gap #8) ------------------------------------


class _MergeSite:
    """Minimal scan-evidence site for merge tests."""

    __hash__ = object.__hash__

    def __init__(self, func_ea, name, ea):
        self.func_ea = func_ea
        self.name = name
        self.ea = ea
        self.tinfo = None


def test_merge_member_preserves_authored_identity_and_merges_evidence():
    """Gap #8: merging scan evidence into a same-offset authored member must
    keep the authored name/decl_src/type/comment and must drop the loser
    from structure.members, then persist."""
    from forge.api.members import Member, parse_user_tinfo
    from forge.api.store import StructureCatalog, catalog

    forge_api.create_structure("M")
    forge_api.add_member("M", 0, "u32", name="count", comment="keep me")

    scan_member = Member(0, parse_user_tinfo("u64"), None, 0)
    scan_member.scanned_variables = {_MergeSite(0x140001000, "v0", 0x140002000)}

    result = catalog.merge_member("M", scan_member)

    assert result["ok"] is True
    merged = result["merged"]
    assert merged is catalog["M"].get_member_by_offset(0)
    assert merged.name == "count"
    assert merged.decl_src == "u32"
    assert merged.comment == "keep me"
    assert merged.tinfo.dstr() == "u32"
    # scan evidence merged in
    assert any(
        getattr(site, "ea", None) == 0x140002000
        for site in merged.scanned_variables
    )
    # loser removed
    assert len(catalog["M"].members) == 1
    # persisted: a fresh catalog sees the merged state
    fresh = StructureCatalog()
    restored = fresh["M"].get_member_by_offset(0)
    assert restored.name == "count"
    assert restored.decl_src == "u32"


def test_merge_member_adds_when_no_member_at_offset():
    from forge.api.members import Member, parse_user_tinfo
    from forge.api.store import catalog

    forge_api.create_structure("A")
    scan_member = Member(0x10, parse_user_tinfo("u32"), None, 0)

    result = catalog.merge_member("A", scan_member)

    assert result["ok"] is True
    assert result["dropped"] is None
    assert result["merged"] is catalog["A"].get_member_by_offset(0x10)
    assert len(catalog["A"].members) == 1


def test_merge_member_unknown_structure_reports_error():
    from forge.api.members import Member, parse_user_tinfo
    from forge.api.store import catalog

    scan_member = Member(0, parse_user_tinfo("u32"), None, 0)
    result = catalog.merge_member("NoSuch", scan_member)
    assert result["ok"] is False
    assert "NoSuch" in result["error"]


def test_provenance_rebuilds_from_persisted_catalog(monkeypatch):
    """Reconstruction end-to-end: after a reopen, the reference catalog
    rebuilds structure-member rows from the persisted catalog's authored
    declarations."""
    from forge.api import provenance
    from forge.api.provenance import TypeReferenceCatalog
    from forge.api.store import StructureCatalog

    monkeypatch.setattr(provenance, "Storage", _FakeStorage)

    forge_api.create_structure("World")
    forge_api.add_member("World", 0, "u32", name="hp")
    forge_api.add_member("World", 8, "Guild *", name="guild")

    fresh = StructureCatalog()
    refs = TypeReferenceCatalog()
    summary = refs.rebuild(fresh.values())

    # u32 is a builtin scalar (no row); the Guild * declaration records one
    assert summary["recorded"] == 1
    rows = refs.references_from_structure("World")
    assert [row.type_name for row in rows] == ["Guild"]
    assert rows[0].offset == 8
    assert rows[0].member_name == "guild"
    # and the rebuilt rows persist
    assert TypeReferenceCatalog().all() == refs.all()


def test_catalog_persistence_root_vtable_ea_round_trip():
    """Hierarchy provenance: ``root_vtable_ea`` (and the aggregate
    ``root_argument_index``) survive a catalog serialize/reload so the
    identity-keyed dedup keeps working after a reopen; payloads persisted
    before the field existed restore as ``None``."""
    from forge.api.store import StructureCatalog

    forge_api.create_structure("HierarchyRoot")
    structure = StructureCatalog()["HierarchyRoot"]
    structure.set_provenance(
        kind="automatic_hierarchy", root_vtable_ea=0x140009000
    )

    payload = StructureCatalog()._serialize(structure)
    assert payload["provenance"]["root_vtable_ea"] == 0x140009000

    restored = StructureCatalog()._deserialize(payload)
    assert restored.provenance.kind == "automatic_hierarchy"
    assert restored.provenance.root_vtable_ea == 0x140009000

    # aggregate identity fields ride the same payload
    aggregate = StructureCatalog()._deserialize(
        dict(payload, provenance=dict(payload["provenance"], root_vtable_ea=None))
    )
    aggregate.set_provenance(
        kind="automatic_aggregate", root_function_ea=0x401000, root_argument_index=2
    )
    aggregate_payload = StructureCatalog()._serialize(aggregate)
    assert aggregate_payload["provenance"]["root_argument_index"] == 2
    assert (
        StructureCatalog()._deserialize(aggregate_payload).provenance.root_argument_index
        == 2
    )

    # legacy payload without the new keys restores with None defaults
    legacy = StructureCatalog()._deserialize(
        {"name": "LegacyProv", "main_offset": 0, "members": []}
    )
    assert legacy.provenance.root_vtable_ea is None
    assert legacy.provenance.root_argument_index is None


# -- C1/C2/C3/F4/F5 + linked-row persistence (2026-09 review) -----------------


def test_catalog_persistence_member_flags_round_trip():
    """C2: enabled/comment/is_array must survive the catalog round trip —
    the serializer used to drop them, so a disabled member resurrected as
    enabled and a comment erased on reload. Defaults stay omitted from the
    payload, but every load honors the keys."""
    from forge.api.store import StructureCatalog, catalog

    forge_api.create_structure("Flags")
    forge_api.add_member("Flags", 0, "u32", name="hp", comment="keep me")
    member = catalog["Flags"].get_member_by_offset(0)
    member.enabled = False
    member.is_array = True

    payload = StructureCatalog()._serialize(catalog["Flags"])
    entry = next(
        raw for raw in payload["members"] if raw.get("name") == "hp"
    )
    assert entry["enabled"] is False
    assert entry["comment"] == "keep me"
    assert entry["is_array"] is True

    restored = StructureCatalog()._deserialize(payload)
    restored_member = restored.get_member_by_offset(0)
    assert restored_member.enabled is False
    assert restored_member.comment == "keep me"
    assert restored_member.is_array is True

    # lean payload: defaults are omitted, load honors absence as default
    forge_api.create_structure("Defaults")
    forge_api.add_member("Defaults", 0, "u32")
    default_entry = StructureCatalog()._serialize(catalog["Defaults"])["members"][0]
    assert "enabled" not in default_entry
    assert "comment" not in default_entry
    assert "is_array" not in default_entry


def test_catalog_persistence_linked_member_round_trip():
    """Linked-row persistence (2026-09 contract): a LinkedStructureMember
    serializes as a plain portable row (no live tinfo — T1.1) and reloads
    as a linked placeholder with tinfo None, name fallback, and the
    child/relation fields intact."""
    from forge.api.members import LinkedStructureMember
    from forge.api.store import StructureCatalog
    from forge.api.structure import Structure

    structure = Structure("Parent")
    linked = LinkedStructureMember(
        0x10,
        "Child",
        24,
        "child_field",
        relation_kind="pointer",
    )
    linked.enabled = False
    linked.comment = "linked note"
    structure.add_member(linked)
    structure.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x10,
        parent_member_name="child_field",
        relation_kind="pointer",
    )

    payload = StructureCatalog()._serialize(structure)
    entry = payload["members"][0]
    assert entry["kind"] == "linked"
    assert entry["offset"] == 0x10
    assert entry["name"] == "child_field"
    assert entry["child_structure_name"] == "Child"
    assert entry["conservative_extent"] == 24
    assert entry["child_relation_kind"] == "pointer"
    assert entry["enabled"] is False
    assert entry["comment"] == "linked note"
    assert "type" not in entry and "decl_src" not in entry

    restored = StructureCatalog()._deserialize(payload)
    member = restored.get_member_by_offset(0x10)
    assert isinstance(member, LinkedStructureMember)
    assert member.child_structure_name == "Child"
    assert member.conservative_extent == 24
    assert member.child_relation_kind == "pointer"
    assert member.name == "child_field"
    assert member.tinfo is None
    assert member.enabled is False
    assert member.comment == "linked note"

    # name fallback for a legacy row without one (field_<offset> convention)
    legacy = StructureCatalog()._deserialize(
        {
            "name": "Parent",
            "main_offset": 0,
            "members": [
                {
                    "kind": "linked",
                    "offset": 4,
                    "child_structure_name": "Child",
                    "conservative_extent": 8,
                    "child_relation_kind": "embedded",
                }
            ],
        }
    )
    assert legacy.get_member_by_offset(4).name == "field_4"


def test_merge_member_keeps_survivor_identity_among_equal_typed_members():
    """C1: with a third member sharing (offset, type) with the survivor,
    the value-equality ``list.remove`` used to delete the SURVIVOR itself.
    Identity ops must keep the survivor in place."""
    from forge.api.members import Member, parse_user_tinfo
    from forge.api.store import StructureCatalog, catalog

    forge_api.create_structure("Eq")
    forge_api.add_member("Eq", 0, "u32", name="hp", comment="authored")
    survivor = catalog["Eq"].get_member_by_offset(0)
    catalog["Eq"].add_member(Member(0, parse_user_tinfo("u32"), None, 0))

    incoming = Member(0, parse_user_tinfo("u32"), None, 0)
    result = catalog.merge_member("Eq", incoming)

    assert result["ok"] is True
    assert result["merged"] is survivor
    assert result["dropped"] is incoming
    members = catalog["Eq"].members
    assert any(member is survivor for member in members)
    assert not any(member is incoming for member in members)
    assert survivor.name == "hp"
    assert survivor.decl_src == "u32"
    # sorted (offset, type) order is preserved for refresh_collisions
    offsets = [member.offset for member in members]
    assert offsets == sorted(offsets)
    # persisted: a fresh catalog still resolves the authored survivor
    fresh = StructureCatalog()
    restored = fresh["Eq"].get_member_by_offset(0)
    assert restored.name == "hp"
    assert restored.decl_src == "u32"


def test_catalog_load_counts_corrupt_entries_and_degrades_health():
    """Mixed good+corrupt load: the good structure loads, the corrupt one
    is counted (corrupt_entries, degraded health,
    last_error.operation == 'corrupt_entry') — never silently dropped."""
    from forge.api.store import StructureCatalog

    good = {
        "name": "Good",
        "main_offset": 0,
        "created_type_name": None,
        "is_auto_named": False,
        "provenance": {},
        "members": [],
        "child_relationships": [],
    }
    _FakeStorage._data["Structures"] = {
        "data": {
            "structures": [good, {"main_offset": 0, "members": []}],
            "current": "Good",
        }
    }

    fresh = StructureCatalog()
    assert "Good" in fresh
    status = fresh.recovery_status()
    assert status["corrupt_entries"] >= 1
    assert status["health"] == "degraded"
    assert status["last_error"]["operation"] == "corrupt_entry"


def test_failed_load_does_not_wipe_persisted_catalog(monkeypatch):
    """F4: when the persisted payload is corrupt, a failed load must be
    counted and the NEXT mutation must not write the empty in-memory guess
    through — the saved catalog survives."""
    from forge.api import store as store_module
    from forge.api.store import StructureCatalog
    from forge.api.structure import Structure

    class _FailingStorage(_FakeStorage):
        """Simulates Storage.get swallowing a corrupt read into None."""

        def __getitem__(self, key):
            if key == "data":
                raise ValueError("simulated corrupt blob")
            return super().__getitem__(key)

    saved = {
        "structures": [
            {
                "name": "Keep",
                "main_offset": 0,
                "created_type_name": None,
                "is_auto_named": False,
                "provenance": {},
                "members": [],
                "child_relationships": [],
            }
        ],
        "current": "Keep",
    }
    _FakeStorage._data["Structures"] = {"data": saved}

    monkeypatch.setattr(store_module, "Storage", _FailingStorage)
    catalog = StructureCatalog()

    # the load attempt fails: the saved structures cannot enter memory
    # (loudly degraded), the failure is counted
    assert len(catalog) == 0
    status = catalog.recovery_status()
    assert status["load_failures"] >= 1
    assert status["health"] == "degraded"
    assert status["last_error"]["operation"] == "load"

    # the mutation must NOT persist an empty catalog over the saved one
    catalog["New"] = Structure("New")
    persisted = _FakeStorage._data["Structures"]["data"]
    assert persisted == saved
    # in-memory mutation still happened (the session stays usable)
    assert "New" in catalog


def test_transaction_rollback_restores_persisted_state():
    """C3: a mid-transaction write-through must not survive an abort —
    rollback re-snapshots the netnode with the restored state."""
    from forge.api.store import StructureCatalog, catalog

    forge_api.create_structure("Keep")
    with pytest.raises(RuntimeError, match="abort"):
        with catalog.transaction("rollback test"):
            forge_api.create_structure("Aborted")
            raise RuntimeError("abort")

    assert "Aborted" not in catalog  # memory restored
    fresh = StructureCatalog()
    assert "Keep" in fresh
    assert "Aborted" not in fresh  # netnode restored too


def test_transaction_rollback_failure_preserves_original_error(monkeypatch):
    """F5: when the rollback itself fails, the ORIGINAL exception must
    surface (never the restore error) and the mutated in-memory state is
    kept rather than half-restored."""
    from forge.api.store import catalog

    forge_api.create_structure("Keep2")
    with pytest.raises(RuntimeError, match="original"):
        with catalog.transaction("restore failure test"):
            forge_api.create_structure("Bad")

            def _broken_restore(_payload):
                raise ValueError("restore blew up")

            monkeypatch.setattr(catalog, "_deserialize_payload", _broken_restore)
            raise RuntimeError("original")

    # restore failed -> the mutated in-memory state is kept, loudly
    assert "Bad" in catalog


def test_transaction_suppresses_per_item_and_fires_once():
    """In-transaction batching: _mark_dirty side effects (snapshot + notify)
    are suppressed inside transaction(); the outermost commit (and the
    rollback path) fires exactly one notify."""
    from forge.api.store import catalog

    notifies = []
    catalog.events.append(lambda: notifies.append("n"))
    try:
        with catalog.transaction("batch test"):
            forge_api.create_structure("B1")
            forge_api.create_structure("B2")
            forge_api.create_structure("B3")
        assert len(notifies) == 1
        assert "B1" in catalog and "B3" in catalog

        notifies.clear()
        with pytest.raises(RuntimeError, match="abort"):
            with catalog.transaction("batch abort test"):
                forge_api.create_structure("B4")
                raise RuntimeError("abort")
        assert len(notifies) == 1  # one notify from the rollback path
        assert "B4" not in catalog
    finally:
        catalog.events.clear()

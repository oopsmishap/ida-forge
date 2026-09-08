"""Ordinal refresh gate (recovery-eval gap #10 wiring).

Focused regression: after a fresh type write (create_type / push_type),
every recorded consumer re-applies its stored declaration. Scenario: a
function prototype referencing ``fixture_World`` survives a re-file (fresh
ordinal) — the re-applied prototype stays named ``fixture_World *`` and
never degrades to an ordinal reference (``#N``).
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

import forge_api
from forge.api.provenance import PROTOTYPE, references


@pytest.fixture(autouse=True)
def _fresh_references():
    references.clear()
    yield
    references.clear()


class _FakeStructure:
    """Minimal store structure for the create_type / push_type paths."""

    def __init__(self, name):
        self.name = name
        self.members = []
        self.main_offset = 0
        self.created_type_name = name
        self.provenance = {}
        self.last_apply_sites = []

    def build_cdecl(self):
        return (None, f"struct {self.name} {{ int x; }};")

    def set_cdecl(self, declaration, main_offset, *, overwrite=True):
        assert overwrite is True
        return SimpleNamespace(name=self.name)


DECL = "int __cdecl f(fixture_World *)"


@pytest.fixture
def _world_env(monkeypatch):
    """Seed the store + stub the IDA boundary; capture prototype re-applies."""
    structure = _FakeStructure("fixture_World")
    forge_api._structures["fixture_World"] = structure
    forge_api._state.current = "fixture_World"

    monkeypatch.setattr(forge_api, "_refresh_scan_sites", lambda t: None)
    monkeypatch.setattr(forge_api, "_mark_dirty", lambda: None)
    monkeypatch.setattr(forge_api, "_snapshot_type_before_commit", lambda *a, **k: None)

    reapplied = []

    real_set_func_proto = forge_api.set_func_proto

    def _spy_set_func_proto(ea, declaration):
        reapplied.append((ea, declaration))
        return {"ok": True, "ea": ea, "prototype": declaration}

    monkeypatch.setattr(forge_api, "set_func_proto", _spy_set_func_proto)
    monkeypatch.setattr(forge_api, "signature", lambda ea: DECL, raising=False)
    return SimpleNamespace(structure=structure, reapplied=reapplied,
                           real_set_func_proto=real_set_func_proto)


def test_set_func_proto_records_prototype_row(_world_env, monkeypatch):
    """Precondition of the scenario: applying the prototype records a
    PROTOTYPE row for fixture_World with the full declaration as detail."""
    import ida_typeinf

    monkeypatch.setattr(ida_typeinf, "PT_TYP", 0, raising=False)
    monkeypatch.setattr(ida_typeinf, "PT_SIL", 1, raising=False)
    monkeypatch.setattr(ida_typeinf, "parse_decl",
                        lambda t, til, decl, flags: "f", raising=False)

    result = _world_env.real_set_func_proto(0x1400014F0, DECL)

    assert result["ok"] is True
    rows = references.dependents_of("fixture_World")
    assert [r.kind for r in rows] == [PROTOTYPE]
    assert rows[0].func_ea == 0x1400014F0
    assert rows[0].detail == DECL


def test_create_type_fresh_write_reapplies_prototype_named_not_ordinal(_world_env):
    """Re-file fixture_World via create_type(overwrite=True): the recorded
    prototype is re-applied verbatim — stays ``fixture_World *``, no #N."""
    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)

    result = forge_api.create_type("fixture_World", overwrite=True)

    assert result["ok"] is True
    assert result["type_name"] == "fixture_World"
    assert _world_env.reapplied == [(0x1400014F0, DECL)]
    text = _world_env.reapplied[0][1]
    assert "fixture_World *" in text
    assert not re.search(r"#\d+", text), "prototype must never show ordinal #N"


def test_create_type_failure_does_not_trigger_refresh(_world_env, monkeypatch):
    """The gate only fires on SUCCESSFUL type writes."""
    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)
    monkeypatch.setattr(_world_env.structure, "set_cdecl",
                        lambda *a, **k: None)  # write fails
    result = forge_api.create_type("fixture_World", overwrite=True)
    assert result["ok"] is False
    assert _world_env.reapplied == []


def test_push_type_fresh_write_reapplies_prototype_exactly_once(_world_env, monkeypatch):
    """push_type path: fresh write triggers the gate once (guard-engaged
    create_type defers; the end-of-call refresh does the single pass)."""
    import ida_typeinf

    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)
    # 1st snapshot: IDB rows differ from store -> forces the fresh write;
    # 2nd snapshot (baseline): in-sync rows.
    state = {"n": 0}

    def _snap(name):
        state["n"] += 1
        return (None, [(0, "x", "i32")]) if state["n"] == 1 else (None, [])

    monkeypatch.setattr(forge_api, "_idb_udt_snapshot", _snap)
    monkeypatch.setattr(ida_typeinf, "get_type_ordinal",
                        lambda til, name: 0x2A, raising=False)

    class _Mirror(dict):
        pass

    mirror = _Mirror()
    monkeypatch.setattr(forge_api, "_mirror_store", lambda: mirror)

    ok = forge_api.push_type("fixture_World")

    assert ok is True
    assert mirror["fixture_World"]["ordinal"] == 0x2A
    assert _world_env.reapplied == [(0x1400014F0, DECL)]  # exactly once
    text = _world_env.reapplied[0][1]
    assert "fixture_World *" in text
    assert not re.search(r"#\d+", text)


def test_push_type_in_sync_no_write_no_refresh(_world_env, monkeypatch):
    """Delta-sync no-op (store == IDB) must NOT fire the gate."""
    import ida_typeinf

    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)
    monkeypatch.setattr(forge_api, "_idb_udt_snapshot", lambda name: (None, []))
    monkeypatch.setattr(ida_typeinf, "get_type_ordinal",
                        lambda til, name: 7, raising=False)
    monkeypatch.setattr(forge_api, "_mirror_store", dict)

    assert forge_api.push_type("fixture_World") is True
    assert _world_env.reapplied == []


def test_refresh_references_after_rename_repoints_and_refreshes(_world_env):
    """_refresh_references_after_rename: rows re-pointed old->new (detail
    rewritten too), then the gate re-applies with the NEW name."""
    references.record_prototype(0x1400014F0, "fixture_World_Old",
                                detail="int f(fixture_World_Old *)")
    forge_api._structures["fixture_World"] = _FakeStructure("fixture_World")

    report = forge_api._refresh_references_after_rename(
        "fixture_World_Old", "fixture_World")

    assert report["repointed_rows"] == 1
    rows = references.dependents_of("fixture_World")
    # payload rewrite also rewrites detail old->new, then the gate re-applies it
    assert len(rows) == 1 and rows[0].detail == "int f(fixture_World *)"
    assert references.dependents_of("fixture_World_Old") == []
    assert _world_env.reapplied == [(0x1400014F0, "int f(fixture_World *)")]


def test_cascade_stays_one_level_deep(_world_env, monkeypatch):
    """Recursion guard preserved: inside a running refresh, nested
    push_type->create_type->refresh must reentrant-skip."""
    calls = []

    def fake_push_type(owner):
        calls.append(owner)
        # a nested fresh write here would attempt a nested refresh; the
        # helper must report the reentrant skip instead of recursing
        nested = forge_api._refresh_type_references(owner)
        assert nested == {"skipped": "reentrant"}
        return True

    monkeypatch.setattr(forge_api, "push_type", fake_push_type)

    references.record_structure_member(
        "fixture_Outer", 0x10, "w", "fixture_World", detail="fixture_World *")
    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)
    # owners are only re-committed if present in the store
    forge_api._structures["fixture_Outer"] = _FakeStructure("fixture_Outer")

    report = forge_api._refresh_type_references("fixture_World")

    assert report["structures"] == ["fixture_Outer"]
    assert calls == ["fixture_Outer"]
    assert report["prototypes"] == 1

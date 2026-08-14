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


def test_catalog_persistence_round_trip():
    """I.28: create + add_member persists a portable description; a fresh
    catalog instance reloads names, members and provenance."""
    from forge.api.store import StructureCatalog

    forge_api.create_structure("S")
    forge_api.add_member("S", 0, "u32", name="count")
    forge_api.add_member("S", 4, "u64", name="next")
    forge_api.set_current("S")

    fresh = StructureCatalog()

    assert "S" in fresh
    assert fresh.current == "S"
    loaded = fresh["S"]
    assert loaded.name == "S"
    by_name = {m.name: m.offset for m in loaded.members}
    assert by_name == {"count": 0, "next": 4}
    assert loaded.provenance.kind == "manual"


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
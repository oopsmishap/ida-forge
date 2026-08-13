"""Type-library mirror (I.27): import_types / push_type / push_all / refresh_types."""

from __future__ import annotations

from types import SimpleNamespace
from typing import ClassVar

import pytest

import forge_api

_BASE_TIL = object()


class _DeclT:
    """Stand-in for an IDB udt member's tinfo handle."""

    def __init__(self, decl: str):
        self._decl = decl

    def dstr(self):
        return self._decl


class _UdtMember:
    def __init__(self, offset: int, name: str, decl: str):
        self.offset = offset
        self.name = name
        self.type = _DeclT(decl)


class FakeUdt:
    def __init__(self, name: str, rows: list, *, in_base: bool = False):
        self.name = name
        self.rows = rows
        self.in_base = in_base


_UDTS: dict[str, FakeUdt] = {}


class _RegistryTInfo:
    """ida_typeinf.tinfo_t stand-in backed by the ``_UDTS`` registry."""

    def __init__(self, *args, **kwargs):
        self.name = None

    def get_named_type(self, til, name):
        if til is _BASE_TIL:
            udt = _UDTS.get(name)
            return bool(udt and udt.in_base)
        udt = _UDTS.get(name)
        if udt is None:
            return False
        self.name = name
        return True

    def get_numbered_type(self, til, ordinal):
        names = list(_UDTS)
        if 0 <= ordinal < len(names):
            self.name = names[ordinal]
            return True
        return False

    def is_udt(self):
        return self.name in _UDTS

    def get_udt_details(self, udt):
        if self.name not in _UDTS:
            return False
        udt[:] = [_UdtMember(o, n, d) for o, n, d in _UDTS[self.name].rows]
        return True

    def create_udt(self, *args, **kwargs):
        return True

    def dstr(self):
        return self.name or ""


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
    import forge.api.members as members_mod

    monkeypatch.setattr(
        members_mod,
        "parse_user_tinfo",
        lambda declaration: FakeTinfo((declaration or "u32").split()[0]),
    )


@pytest.fixture(autouse=True)
def _fresh_catalog(monkeypatch):
    import sys

    from forge.api import store as store_module

    class _FakeStorage:
        data: ClassVar[dict] = {}

        def __init__(self, name: str):
            self._local = _FakeStorage.data.setdefault(name, {})

        def __getitem__(self, key):
            return self._local[key]

        def __setitem__(self, key, value):
            self._local[key] = value

        def get(self, key, default=None):
            return self._local.get(key, default)

        def items(self):
            return list(self._local.items())

    monkeypatch.setattr(store_module, "Storage", _FakeStorage)
    monkeypatch.setattr(
        sys.modules["forge.api.storage"], "Storage", _FakeStorage, raising=False
    )
    _FakeStorage.data.clear()

    from forge.api.store import catalog

    catalog.events.clear()
    catalog.clear()
    yield
    catalog.events.clear()
    catalog.clear()


@pytest.fixture()
def _registry(monkeypatch):
    import ida_typeinf

    _UDTS.clear()
    monkeypatch.setattr(ida_typeinf, "tinfo_t", _RegistryTInfo)
    monkeypatch.setattr(
        ida_typeinf,
        "get_idati",
        lambda: SimpleNamespace(base=lambda n: _BASE_TIL),
    )
    monkeypatch.setattr(
        ida_typeinf, "get_ordinal_count", lambda idati: len(_UDTS)
    )
    monkeypatch.setattr(
        ida_typeinf,
        "get_numbered_type_name",
        lambda idati, ordinal: list(_UDTS)[ordinal]
        if 0 <= ordinal < len(_UDTS)
        else "",
    )
    monkeypatch.setattr(
        ida_typeinf, "get_type_ordinal", lambda idati, name: list(_UDTS).index(name)
    )
    yield _UDTS
    _UDTS.clear()


def test_import_types_imports_local_udts(_registry):
    """I.27: local UDTs land in the catalog as imported structures with
    ordered members; the return value splits imported/skipped."""
    _registry["World"] = FakeUdt("World", [(0, "x", "u32"), (8, "y", "u64")])
    _registry["Player"] = FakeUdt("Player", [(0, "a", "u32")])

    result = forge_api.import_types("world")

    assert result == {"imported": ["World"], "skipped": []}
    from forge.api.store import catalog

    assert catalog["World"].provenance.kind == "imported"
    offsets = [m["offset"] for m in forge_api.get_structure("World")["members"]]
    assert offsets == [0, 8]


def test_import_types_skips_existing_and_base_and_temp(_registry):
    """I.27: already-present names are skipped; base-til and '::' names are
    never imported at all."""
    forge_api.create_structure("World")
    forge_api.add_member("World", 0, "u32", name="keep")
    _registry["World"] = FakeUdt("World", [(0, "o", "u32")])
    _registry["ns::Thing"] = FakeUdt("ns::Thing", [(0, "z", "u32")])
    _registry["BaseT"] = FakeUdt("BaseT", [(0, "b", "u32")], in_base=True)

    result = forge_api.import_types()

    assert "World" in result["skipped"]
    assert "ns::Thing" not in result["imported"] and "ns::Thing" not in result["skipped"]
    assert "BaseT" not in result["imported"] and "BaseT" not in result["skipped"]
    kept = forge_api.get_structure("World")
    assert [m["name"] for m in kept["members"]] == ["keep"]


def test_push_type_noop_when_in_sync(_registry, monkeypatch):
    """I.27: a structure matching the IDB type is a no-op (no type rewrite),
    and the mirror baseline is still recorded."""
    forge_api.create_structure("World")
    forge_api.add_member("World", 0, "u32", name="x")
    forge_api.add_member("World", 8, "u64", name="y")
    _registry["World"] = FakeUdt("World", [(0, "x", "u32"), (8, "y", "u64")])

    calls = []
    real_create = forge_api.create_type

    def _spy(name, *, overwrite=False):
        calls.append((name, overwrite))
        return real_create(name, overwrite=overwrite)

    monkeypatch.setattr(forge_api, "create_type", _spy)

    assert forge_api.push_type("World") is True
    assert calls == []


def test_push_type_rewrites_when_idb_differs(_registry, monkeypatch):
    """I.27: a store/IDB member mismatch triggers create_type(overwrite=True)
    before recording the baseline."""
    from forge.api import members as members_mod
    from forge.api import structure as structure_mod

    member = members_mod.Member(0, FakeTinfo("u32"), None, 0)
    member.name = "x"
    structure = structure_mod.Structure("World")
    structure.add_member(member)
    from forge.api.store import catalog

    catalog["World"] = structure
    _registry["World"] = FakeUdt("World", [(0, "x", "u16")])

    def fake_build_cdecl(self, start=None, end=None):
        return (self.name, f"typedef struct {self.name} {{ u16 x; }} {self.name};")

    def fake_set_cdecl(self, cdecl, origin=0, *, overwrite=None):
        self.created_type_name = self.name
        return self.name

    calls = []
    real_create = forge_api.create_type

    def _spy(name, *, overwrite=False):
        calls.append((name, overwrite))
        return real_create(name, overwrite=overwrite)

    monkeypatch.setattr(forge_api, "create_type", _spy)
    monkeypatch.setattr(
        structure_mod.Structure, "build_cdecl", fake_build_cdecl, raising=False
    )
    monkeypatch.setattr(
        structure_mod.Structure, "set_cdecl", fake_set_cdecl, raising=False
    )

    assert forge_api.push_type("World") is True
    assert calls == [("World", True)]


def test_push_type_unknown_structure():
    """I.27: unknown names return False without touching the IDB."""
    assert forge_api.push_type("NoSuchStruct") is False


def test_push_all_reports_failures(_registry, monkeypatch):
    """I.27: push_all pushes every catalog structure and isolates per-name
    failures."""
    forge_api.create_structure("Good")
    forge_api.add_member("Good", 0, "u32")
    forge_api.create_structure("Bad")
    forge_api.add_member("Bad", 0, "u32")
    _registry["Good"] = FakeUdt("Good", [(0, "x", "u32")])
    _registry["Bad"] = FakeUdt("Bad", [(0, "x", "u32")])

    def _flaky(name, *, overwrite=False):
        if name == "Bad":
            return {"ok": False, "error": "boom"}
        return {"ok": True, "created": True}

    monkeypatch.setattr(forge_api, "create_type", _flaky)

    result = forge_api.push_all()

    assert result["pushed"] == ["Good"]
    assert set(result["failed"]) == {"Bad"}


def test_refresh_types_updates_members_keeping_names(_registry):
    """I.27: refresh_types re-imports changed IDB member types in place,
    preserving store names, and marks the entry unchanged on the next pass."""
    forge_api.create_structure("World")
    forge_api.add_member("World", 0, "u32", name="count")
    forge_api.add_member("World", 8, "u64", name="next")
    _registry["World"] = FakeUdt("World", [(0, "count", "u32"), (8, "next", "u64")])
    assert forge_api.push_type("World") is True  # seeds the TypeMirror baseline

    # IDB layout changes behind our back
    _registry["World"] = FakeUdt("World", [(0, "z", "u64")])

    result = forge_api.refresh_types()

    assert result["updated"] == ["World"]
    member = forge_api.get_member("World", 0)
    assert member["name"] == "count"
    assert member["type"] == "u64"
    assert forge_api.get_structure("World")["members"][1]["name"] == "next"

    result = forge_api.refresh_types()

    assert result == {"updated": [], "unchanged": ["World"]}


def test_push_then_refresh_is_noop(_registry):
    """I.27 delta: the TypeMirror baseline is the IDB-side digest, so a push
    followed immediately by refresh_types() reports the entry unchanged —
    store/IDB row-tuple shapes must never produce hash churn."""
    forge_api.create_structure("World")
    forge_api.add_member("World", 0, "u32", name="x")
    _registry["World"] = FakeUdt("World", [(0, "x", "u32")])

    assert forge_api.push_type("World") is True

    result = forge_api.refresh_types()

    assert result == {"updated": [], "unchanged": ["World"]}
"""TypeReferenceCatalog: applied type dependency/reference primitives
(recovery-eval gap #10, 2026-08-30)."""

from __future__ import annotations

from typing import ClassVar

import pytest

from forge.api import provenance
from forge.api.provenance import (
    GLOBAL_EA,
    LVAR,
    PROTOTYPE,
    STRUCTURE_MEMBER,
    TypeReference,
    TypeReferenceCatalog,
)


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
    monkeypatch.setattr(provenance, "Storage", _FakeStorage)
    _FakeStorage._data.clear()
    yield
    _FakeStorage._data.clear()


class _FakeMember:
    def __init__(self, offset, name, decl_src=None, child=None, relation="pointer"):
        self.offset = offset
        self.name = name
        self.decl_src = decl_src
        self.linked_child_structure_name = child
        self.child_relation_kind = relation


class _FakeStructure:
    def __init__(self, name, members):
        self.name = name
        self.members = members


# -- recording and queries ----------------------------------------------------


def test_record_rows_across_all_kinds_and_query_dependents():
    catalog = TypeReferenceCatalog()
    catalog.record_structure_member("Player", 0x08, "world", "World", detail="World *")
    catalog.record_structure_member("World", 0x10, "quest", "Quest", detail="Quest *")
    catalog.record_global_ea(0x140007E28, "const char *")
    catalog.record_lvar(0x140001040, "this", "Player")
    catalog.record_prototype(0x140002750, "World")

    dependents = catalog.dependents_of("World")
    assert {(row.kind, row.func_ea) for row in dependents} == {
        (STRUCTURE_MEMBER, None),
        (PROTOTYPE, 0x140002750),
    }
    assert {row.kind for row in catalog.dependents_of("Player")} == {LVAR}
    assert {row.kind for row in catalog.dependents_of("Quest")} == {STRUCTURE_MEMBER}
    assert {row.kind for row in catalog.dependents_of("const char *")} == {GLOBAL_EA}


def test_record_is_idempotent_by_identity():
    catalog = TypeReferenceCatalog()
    first = catalog.record_global_ea(0x140007E28, "const char *")
    second = catalog.record_global_ea(0x140007E28, "const char *")
    assert first is second
    assert len(catalog) == 1


def test_owners_of_and_references_from_structure():
    catalog = TypeReferenceCatalog()
    catalog.record_structure_member("World", 0x10, "quest", "Quest")
    catalog.record_structure_member("World", 0x18, "guild", "Guild")
    catalog.record_structure_member("Guild", 0, "lead", "Player")
    catalog.record_lvar(0x140001040, "this", "Quest")

    assert catalog.owners_of("Quest") == {"World"}
    assert catalog.owners_of("Guild") == {"World"}
    assert {row.member_name for row in catalog.references_from_structure("World")} == {
        "quest",
        "guild",
    }


def test_record_declaration_expands_references():
    catalog = TypeReferenceCatalog()
    rows = catalog.record_declaration("World", 0x40, "route", "PatrolRoute *")
    assert [row.type_name for row in rows] == ["PatrolRoute"]
    assert rows[0].kind == STRUCTURE_MEMBER
    assert rows[0].detail == "PatrolRoute *"
    # scalar declarations record nothing
    assert catalog.record_declaration("World", 0x48, "dt", "float") == []


def test_type_reference_validation():
    with pytest.raises(ValueError):
        TypeReference("nonsense", "Quest")
    with pytest.raises(ValueError):
        TypeReference(STRUCTURE_MEMBER, "")
    with pytest.raises(ValueError):
        TypeReference.from_dict({"kind": "bogus", "type_name": "Quest"})


# -- persistence --------------------------------------------------------------


def test_write_through_persistence_and_lazy_reload():
    catalog = TypeReferenceCatalog()
    catalog.record_structure_member("World", 0x10, "quest", "Quest")
    catalog.record_lvar(0x140001040, "this", "Player")

    fresh = TypeReferenceCatalog()
    assert len(fresh) == 2
    kinds = {row.kind for row in fresh.all()}
    assert kinds == {STRUCTURE_MEMBER, LVAR}


def test_payload_round_trip_preserves_rows():
    catalog = TypeReferenceCatalog()
    catalog.record_structure_member("World", 0x10, "quest", "Quest", detail="Quest *")
    catalog.record_global_ea(0x140007E28, "const char *")
    payload = catalog.to_payload()
    assert payload["version"] == 1

    fresh = TypeReferenceCatalog()
    assert fresh.load_payload(payload) == 2
    assert fresh.all() == catalog.all()


def test_load_payload_skips_corrupt_rows_and_counts_them():
    catalog = TypeReferenceCatalog()
    loaded = catalog.load_payload(
        {
            "references": [
                {"kind": STRUCTURE_MEMBER, "type_name": "Quest", "owner": "World"},
                {"kind": "bogus", "type_name": "X"},
                "not-a-mapping",
                {"kind": GLOBAL_EA},
            ]
        }
    )
    assert loaded == 1
    assert [row.type_name for row in catalog.all()] == ["Quest"]
    status = catalog.recovery_status()
    assert status["corrupt_entries"] == 2
    assert status["health"] == "degraded"


def test_clear_owner_keeps_other_owners_and_applied_rows():
    catalog = TypeReferenceCatalog()
    catalog.record_structure_member("World", 0x10, "quest", "Quest")
    catalog.record_structure_member("Guild", 0, "lead", "Player")
    catalog.record_global_ea(0x140007E28, "const char *")

    assert catalog.clear_owner("World") == 1
    remaining = {(row.kind, row.owner) for row in catalog.all()}
    assert remaining == {(STRUCTURE_MEMBER, "Guild"), (GLOBAL_EA, None)}


def test_clear_drops_everything():
    catalog = TypeReferenceCatalog()
    catalog.record_global_ea(0x140007E28, "const char *")
    catalog.record_lvar(1, "v0", "Player")
    catalog.clear()
    assert len(catalog) == 0
    # and the empty state persisted
    assert len(TypeReferenceCatalog()) == 0


# -- reconstruction ------------------------------------------------------------


def test_rebuild_from_structures_and_keeps_applied_rows():
    catalog = TypeReferenceCatalog()
    catalog.record_global_ea(0x140007E28, "const char *")
    catalog.record_structure_member("World", 0x99, "stale", "Stale")

    world = _FakeStructure(
        "World",
        [
            _FakeMember(0x10, "quest", "Quest *"),
            _FakeMember(0x18, "route", "PatrolRoute *"),
        ],
    )
    guild = _FakeStructure(
        "Guild", [_FakeMember(0, "lead", None, child="Player")]
    )

    summary = catalog.rebuild([world, guild])

    assert summary["kept_applied"] == 1  # the global EA row survived
    rows = catalog.references_from_structure("World")
    assert {row.type_name for row in rows} == {"Quest", "PatrolRoute"}
    assert {row.type_name for row in catalog.references_from_structure("Guild")} == {"Player"}
    assert catalog.dependents_of("Stale") == []
    # rebuild persists
    fresh = TypeReferenceCatalog()
    assert fresh.all() == catalog.all()


def test_rebuild_replaces_previous_rows_for_same_owner():
    catalog = TypeReferenceCatalog()
    world = _FakeStructure("World", [_FakeMember(0x10, "quest", "Quest *")])
    catalog.rebuild([world])
    assert {row.type_name for row in catalog.references_from_structure("World")} == {"Quest"}

    world_v2 = _FakeStructure("World", [_FakeMember(0x10, "guild", "Guild *")])
    catalog.rebuild([world_v2])
    assert {row.type_name for row in catalog.references_from_structure("World")} == {"Guild"}


def test_rebuild_without_keep_applied_drops_runtime_rows():
    catalog = TypeReferenceCatalog()
    catalog.record_global_ea(0x140007E28, "const char *")
    world = _FakeStructure("World", [_FakeMember(0x10, "quest", "Quest *")])

    summary = catalog.rebuild([world], keep_applied=False)

    assert summary["kept_applied"] == 0
    assert {row.kind for row in catalog.all()} == {STRUCTURE_MEMBER}


def test_rebuild_ignores_unnamed_structures():
    catalog = TypeReferenceCatalog()
    summary = catalog.rebuild([_FakeStructure("", [])])
    assert summary["recorded"] == 0


# -- dependency ordering -------------------------------------------------------


def test_dependencies_of_scoped_to_commit_set():
    catalog = TypeReferenceCatalog()
    world = _FakeStructure(
        "World",
        [
            _FakeMember(0x10, "quest", "Quest *"),
            _FakeMember(0x18, "count", "u32"),
        ],
    )
    catalog.rebuild([world])
    assert catalog.dependencies_of("World") == {"Quest"}
    assert catalog.dependencies_of("World", scope={"Player"}) == set()


def test_resolve_commit_order_puts_referenced_types_first():
    catalog = TypeReferenceCatalog()
    catalog.rebuild(
        [
            _FakeStructure("World", [_FakeMember(0x10, "quest", "Quest *")]),
            _FakeStructure("Quest", [_FakeMember(0, "next", "Quest *")]),
        ]
    )

    ordered, deferred = catalog.resolve_commit_order(["World", "Quest"])

    assert deferred == []
    assert ordered.index("Quest") < ordered.index("World")
    assert sorted(ordered) == ["Quest", "World"]


def test_resolve_commit_order_breaks_cycles_deterministically():
    catalog = TypeReferenceCatalog()
    catalog.rebuild(
        [
            _FakeStructure("A", [_FakeMember(0, "b", "B *")]),
            _FakeStructure("B", [_FakeMember(0, "a", "A *")]),
        ]
    )

    ordered, deferred = catalog.resolve_commit_order(["A", "B"])

    # every requested name still commits, cycles reported for the caller
    assert sorted(ordered) == ["A", "B"]
    assert set(deferred) == {"A", "B"}


def test_resolve_commit_order_self_reference_never_defers():
    catalog = TypeReferenceCatalog()
    catalog.rebuild(
        [_FakeStructure("Node", [_FakeMember(0, "next", "Node *")])]
    )

    ordered, deferred = catalog.resolve_commit_order(["Node"])

    assert ordered == ["Node"]
    assert deferred == []


# -- robustness: storage degradation -------------------------------------------


class _BrokenStorage:
    """Storage stand-in whose reads and writes always fail."""

    def __init__(self, name: str):
        self.name = name

    def __getitem__(self, key):
        raise RuntimeError("netnode unavailable")

    def __setitem__(self, key, value):
        raise RuntimeError("netnode unavailable")

    def get(self, key, default=None):
        raise RuntimeError("netnode unavailable")


def test_storage_failure_degrades_to_warning_never_raises(monkeypatch):
    """Persistence failures degrade to a warning + recovery counters (the
    structure catalog's policy): facade operations must never break."""
    monkeypatch.setattr(provenance, "Storage", _BrokenStorage)

    catalog = TypeReferenceCatalog()
    # lazy load failure is swallowed
    catalog.record_global_ea(0x140007E28, "const char *")

    status = catalog.recovery_status()
    assert status["health"] == "degraded"
    assert status["load_failures"] >= 1
    assert status["write_failures"] >= 1
    assert status["last_error"]["operation"] in {"load", "write", "corrupt_entry"}


def test_rebuild_reports_corrupt_member_rows_without_dying():
    catalog = TypeReferenceCatalog()
    # a member whose declaration explodes must not kill the whole rebuild
    class _BoomMember:
        offset = 0
        name = "boom"

        @property
        def decl_src(self):
            raise RuntimeError("degenerate member")

    ok = _FakeStructure("Fine", [_FakeMember(0, "lead", "Player *")])
    boom = _FakeStructure("Boom", [_BoomMember()])

    summary = catalog.rebuild([ok, boom])

    # the healthy structure is fully recorded despite the degenerate one
    assert {row.type_name for row in catalog.references_from_structure("Fine")} == {"Player"}
    assert summary["total"] == len(catalog)

"""Facade remediation regressions (2026-09-03 workstream).

Covers the facade gaps owned by this workstream:

1. deep_scan / shallow_scan scan-root restore error paths (pre-retype
   object identity, structured errors, both verbs).
2. recover_abi_structure true in-place rebuild (no-delete guard on
   committed structures, evidence/child-link/provenance preservation).
3. Subobject-mode suppression of the automatic integral->void * retype.
5. create_type ordinal refresh change-gated like push_type (manual
   applied-site changes survive an unchanged re-commit).
"""

from __future__ import annotations

import sys
from importlib import import_module
from importlib import util as _util
from pathlib import Path
from types import SimpleNamespace

import pytest

import forge_api
from forge.api.provenance import references

members_mod = import_module("forge.api.members")

DECL = "int __cdecl f(fixture_World *)"


@pytest.fixture(autouse=True)
def _fresh_references():
    references.clear()
    yield
    references.clear()


def _cleanup_store(*names):
    for name in names:
        if name in forge_api.structures():
            # simulated committed state must not trip the no-delete guard
            structure = forge_api._resolve_structure(name, required=False)
            if structure is not None:
                structure.created_type_name = None
            forge_api.remove_structure(name)
class _T:
    """Minimal tinfo double for retype helpers AND member construction."""

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
    """Route parse_user_tinfo -> _T so members build without IDA."""

    def _fake_parse(declaration):
        name = (declaration or "u32").split()[0]
        return _T(name)

    monkeypatch.setattr(members_mod, "parse_user_tinfo", _fake_parse)


@pytest.fixture(autouse=True)
def _reset_store():
    """Start every test with an empty store (no clear_structures verb)."""
    forge_api._structures.clear()
    forge_api._state.current = None
    yield
    forge_api._structures.clear()
    forge_api._state.current = None
# --------------------------------------------------------------------------- #
# real hexrays module fixture (mirrors test_forge_api._real_hexrays)
# --------------------------------------------------------------------------- #


@pytest.fixture
def _real_hexrays(monkeypatch):
    hexrays_path = (
        Path(__file__).resolve().parents[2] / "src" / "forge" / "api" / "hexrays.py"
    )
    spec = _util.spec_from_file_location("forge.api.hexrays", hexrays_path)
    assert spec is not None and spec.loader is not None
    module = _util.module_from_spec(spec)
    saved = sys.modules.get("forge.api.hexrays")
    sys.modules["forge.api.hexrays"] = module
    spec.loader.exec_module(module)
    yield module
    if saved is not None:
        sys.modules["forge.api.hexrays"] = saved
    else:
        sys.modules.pop("forge.api.hexrays", None)



def _scan_cfunc(root_name, root_type):
    """Fake cfunc whose first lvar is ``root_name`` of ``root_type``."""
    return SimpleNamespace(
        entry_ea=0x401000,
        argidx=(),
        get_lvars=lambda: [
            SimpleNamespace(
                name=root_name,
                type=lambda: _T(root_type),
                location=7,
                defea=0x401010,
            )
        ],
    )


class _VisitorStub:
    def __init__(self, *args, **kwargs):
        self.args = args

    def process(self):
        pass


def _stub_scanner(monkeypatch, verb):
    scanner_mod = import_module("forge.api.scanner")
    monkeypatch.setattr(
        scanner_mod,
        f"New{'Deep' if verb == 'deep' else 'Shallow'}ScanVisitor",
        _VisitorStub,
        raising=False,
    )
    return scanner_mod


def _scan_env(
    monkeypatch, _real_hexrays, *, set_lvar_types_result=None, set_lvar_types_exc=None
):
    """Common stubs: decompile returns a FRESH cfunc each call (so the
    post-retype re-resolution runs against a new object), and set_lvar_types
    is a spy with configurable outcome."""
    decompiled = []
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: decompiled.append(_scan_cfunc("a1", "__int64")) or decompiled[-1],
        raising=False,
    )
    monkeypatch.setattr(
        _real_hexrays, "mark_cfunc_dirty", lambda ea, close=False: None, raising=False
    )
    monkeypatch.setattr(
        members_mod, "parse_user_tinfo", lambda decl: _T(decl), raising=False
    )
    retype_calls = []

    def _set_lvar_types(ea, types, *, scope):
        retype_calls.append((ea, dict(types), scope))
        if set_lvar_types_exc is not None:
            raise set_lvar_types_exc
        return set_lvar_types_result or {
            "ok": True,
            "updated": [{"name": "a1", "ok": True}],
        }

    monkeypatch.setattr(forge_api, "set_lvar_types", _set_lvar_types)
    return SimpleNamespace(decompiled=decompiled, retype_calls=retype_calls)


# --------------------------------------------------------------------------- #
# 1. scan-root restore error paths
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("verb", ["deep", "shallow"])
def test_scan_restore_on_re_resolution_failure_uses_pre_retype_object(
    monkeypatch, _real_hexrays, verb
):
    """When the retype succeeds but the root cannot be re-resolved on the
    refreshed cfunc, the verbs must restore the PRE-retype lvar (the original
    cfunc/object pair — the IDB user-lvar entry is keyed by entry_ea/location/
    defea, which the pre-retype object still carries) and return a structured
    error instead of raising TypeError (the old ``_restore_root_type(cfunc,
    prior)`` arity bug)."""
    env = _scan_env(monkeypatch, _real_hexrays)
    _stub_scanner(monkeypatch, verb)

    real_resolve = forge_api._resolve_scan_root
    resolved = []
    calls = {"n": 0}

    def _resolve(cfunc, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            obj = real_resolve(cfunc, **kw)
            resolved.append(obj)
            return obj
        return None  # re-resolution after the retype fails

    monkeypatch.setattr(forge_api, "_resolve_scan_root", _resolve)
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append((cfunc, obj, prior)),
    )

    scan = forge_api.deep_scan if verb == "deep" else forge_api.shallow_scan
    result = scan(0x401000, var_name="a1", root_type="void *")

    assert result["ok"] is False
    assert result["error"] == "could not resolve a scan root after retype"
    assert len(restored) == 1
    restored_cfunc, restored_obj, prior = restored[0]
    # PRE-retype objects: the first decompile result and the first root.
    assert restored_cfunc is env.decompiled[0]
    assert restored_obj is resolved[0]
    assert prior == "__int64"


@pytest.mark.parametrize("verb", ["deep", "shallow"])
def test_scan_retype_exception_restores_and_reports(monkeypatch, _real_hexrays, verb):
    """A raising retype must restore the prior lvar and return a structured
    error on BOTH verbs (shallow_scan used to let the exception escape)."""
    env = _scan_env(
        monkeypatch,
        _real_hexrays,
        set_lvar_types_exc=RuntimeError("Invalid effective address"),
    )
    _stub_scanner(monkeypatch, verb)
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append((cfunc, obj, prior)),
    )

    scan = forge_api.deep_scan if verb == "deep" else forge_api.shallow_scan
    result = scan(0x401000, var_name="a1", root_type="void *")

    assert result["ok"] is False
    assert "root lvar retype failed" in result["error"]
    assert len(restored) == 1
    assert restored[0][0] is env.decompiled[0]
    assert restored[0][2] == "__int64"


@pytest.mark.parametrize("verb", ["deep", "shallow"])
def test_scan_explicit_retype_noop_reports_structured_error(
    monkeypatch, _real_hexrays, verb
):
    """An explicitly requested root_type whose application lands ok:False
    must be a structured error, never a silent un-retyped scan."""
    _scan_env(
        monkeypatch,
        _real_hexrays,
        set_lvar_types_result={"ok": False, "updated": []},
    )
    _stub_scanner(monkeypatch, verb)

    scan = forge_api.deep_scan if verb == "deep" else forge_api.shallow_scan
    result = scan(0x401000, var_name="a1", root_type="World *")

    assert result["ok"] is False
    assert "root lvar retype" in result["error"]


@pytest.mark.parametrize("verb", ["deep", "shallow"])
def test_scan_auto_retype_noop_degrades_to_unretyped_scan(
    monkeypatch, _real_hexrays, verb
):
    """The automatic integral->void * retype is best-effort sugar: when it
    does not land, the scan proceeds on the un-retyped root (documented
    policy — no structured error, no restore of a type that never moved)."""
    _scan_env(
        monkeypatch,
        _real_hexrays,
        set_lvar_types_result={"ok": False, "updated": []},
    )
    from forge.api.members import Member

    scanner_mod = _stub_scanner(monkeypatch, verb)

    class _EvidenceVisitor:
        def __init__(self, *args, **kwargs):
            self.structure = args[3]  # (cfunc, origin, obj, structure)

        def process(self):
            self.structure.add_member(Member(0x10, _T("u64"), None, 0))

    monkeypatch.setattr(
        scanner_mod,
        f"New{'Deep' if verb == 'deep' else 'Shallow'}ScanVisitor",
        _EvidenceVisitor,
        raising=False,
    )
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append(prior),
    )

    scan = forge_api.deep_scan if verb == "deep" else forge_api.shallow_scan
    result = scan(0x401000, var_name="a1")

    assert result["ok"] is True
    assert result["structure"]
    assert restored == []  # nothing was ever retyped, so nothing to undo
    assert [m["offset"] for m in result["members"]] == [0x10]


# --------------------------------------------------------------------------- #
# 3. subobject mode suppresses the automatic void * retype
# --------------------------------------------------------------------------- #


def test_deep_scan_subobject_suppresses_integral_auto_retype(
    monkeypatch, _real_hexrays
):
    """Policy: subobject mode never retypes the parent lvar. An __int64
    parent root must NOT be auto-retyped to void * — retyping the parent
    would break the subobject base-offset addressing."""
    env = _scan_env(monkeypatch, _real_hexrays)
    scanner_mod = _stub_scanner(monkeypatch, "deep")

    captured = {}

    class _Vis:
        def __init__(self, *args, **kwargs):
            captured["root"] = args[2]

        def process(self):
            pass

    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _Vis, raising=False)

    result = forge_api.deep_scan(
        0x401000, subobject={"base_offset": 0x1B60, "var_name": "a1"}
    )

    assert result["ok"] is True
    assert result["subobject"] == 0x1B60
    assert env.retype_calls == [], "subobject mode must not retype the parent lvar"
    from forge.api.scan_subobject import SubobjectScanObject

    assert isinstance(captured["root"], SubobjectScanObject)


# --------------------------------------------------------------------------- #
# 3b. subobject parent_type: temporary parent-root retype + restoration
# --------------------------------------------------------------------------- #


def test_deep_scan_subobject_parent_type_temporarily_retypes_parent_root(
    monkeypatch, _real_hexrays
):
    """An integral/untyped parent root produces no matchable subobject
    expressions (live verification: 0 members). With ``parent_type`` the
    parent root must be temporarily retyped to ``parent_type *`` — never
    the child type — before the visitor runs."""
    env = _scan_env(monkeypatch, _real_hexrays)
    scanner_mod = _stub_scanner(monkeypatch, "deep")

    captured = {}

    class _Vis:
        def __init__(self, *args, **kwargs):
            captured["root"] = args[2]

        def process(self):
            pass

    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _Vis, raising=False)
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append((cfunc, obj, prior)),
    )

    result = forge_api.deep_scan(
        0x401000,
        subobject={
            "base_offset": 0x1B60,
            "var_name": "a1",
            "parent_type": "fixture_World",
        },
    )

    assert result["ok"] is True
    assert result["subobject"] == 0x1B60
    assert env.retype_calls == [
        (0x401000, {"a1": "fixture_World *"}, "all")
    ], "parent_type must retype the PARENT root to parent_type *, never the child type"
    from forge.api.scan_subobject import SubobjectScanObject

    assert isinstance(captured["root"], SubobjectScanObject)
    # Temporary retype: the original lvar type is restored after the scan.
    assert [prior for _, _, prior in restored] == ["__int64"]


def test_deep_scan_subobject_parent_type_restores_on_visitor_exception(
    monkeypatch, _real_hexrays
):
    """The temporary parent retype must be undone even when the scan blows
    up mid-visitor — no failure path leaves the parent re-typed."""
    env = _scan_env(monkeypatch, _real_hexrays)
    scanner_mod = _stub_scanner(monkeypatch, "deep")

    class _Boom:
        def __init__(self, *args, **kwargs):
            pass

        def process(self):
            raise RuntimeError("visitor exploded")

    monkeypatch.setattr(scanner_mod, "NewDeepScanVisitor", _Boom, raising=False)
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append(prior),
    )

    with pytest.raises(RuntimeError, match="visitor exploded"):
        forge_api.deep_scan(
            0x401000,
            subobject={
                "base_offset": 0x1B60,
                "var_name": "a1",
                "parent_type": "fixture_World",
            },
        )

    assert env.retype_calls == [(0x401000, {"a1": "fixture_World *"}, "all")]
    assert restored == ["__int64"]


def test_deep_scan_subobject_parent_type_skips_retype_when_already_typed(
    monkeypatch, _real_hexrays
):
    """A parent root already carrying ``parent_type *`` must not be retyped
    (and therefore needs no restore)."""
    env = _scan_env(monkeypatch, _real_hexrays)
    monkeypatch.setattr(
        _real_hexrays,
        "decompile",
        lambda ea: _scan_cfunc("a1", "fixture_World *"),
        raising=False,
    )
    scanner_mod = _stub_scanner(monkeypatch, "deep")
    monkeypatch.setattr(
        scanner_mod, "NewDeepScanVisitor", _VisitorStub, raising=False
    )
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append(prior),
    )

    result = forge_api.deep_scan(
        0x401000,
        subobject={
            "base_offset": 0x1B60,
            "var_name": "a1",
            "parent_type": "fixture_World",
        },
    )

    assert result["ok"] is True
    assert env.retype_calls == [], "already-typed parent root must not be retyped"
    assert restored == []


def test_deep_scan_subobject_parent_type_retype_failure_is_structured_error(
    monkeypatch, _real_hexrays
    ):
    """Without the parent retype the scan can only land zero members, so a
    failed parent_type retype is a structured error, never a silent
    un-retyped scan — and the parent is never mutated."""
    _scan_env(
        monkeypatch,
        _real_hexrays,
        set_lvar_types_result={"ok": False, "updated": []},
    )
    _stub_scanner(monkeypatch, "deep")
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append(prior),
    )

    result = forge_api.deep_scan(
        0x401000,
        subobject={
            "base_offset": 0x1B60,
            "var_name": "a1",
            "parent_type": "fixture_World",
        },
    )

    assert result["ok"] is False
    assert "root lvar retype to 'fixture_World *' failed" in result["error"]
    assert restored == []  # nothing ever moved, so nothing to undo


def test_deep_scan_subobject_parent_type_visitor_output_lands_child_members(
    monkeypatch, _real_hexrays
):
    """End-to-end at the facade: retyped parent + SubobjectScanObject root
    lets real visitor output record CHILD members while the parent lvar is
    restored afterwards."""
    env = _scan_env(monkeypatch, _real_hexrays)
    from forge.api.members import Member

    scanner_mod = _stub_scanner(monkeypatch, "deep")

    class _EvidenceVisitor:
        def __init__(self, *args, **kwargs):
            self.structure = args[3]  # (cfunc, origin, obj, structure)

        def process(self):
            self.structure.add_member(Member(0x08, _T("u64"), None, 0))

    monkeypatch.setattr(
        scanner_mod, "NewDeepScanVisitor", _EvidenceVisitor, raising=False
    )
    restored = []
    monkeypatch.setattr(
        forge_api,
        "_restore_root_type",
        lambda cfunc, obj, prior: restored.append(prior),
    )

    result = forge_api.deep_scan(
        0x401000,
        subobject={
            "base_offset": 0x1B60,
            "var_name": "a1",
            "parent_type": "fixture_World",
        },
    )

    assert result["ok"] is True
    assert [m["offset"] for m in result["members"]] == [0x08]
    assert env.retype_calls == [(0x401000, {"a1": "fixture_World *"}, "all")]
    assert restored == ["__int64"]


# --------------------------------------------------------------------------- #
# 2. recover_abi_structure: true in-place rebuild (no-delete guard)
# --------------------------------------------------------------------------- #


def test_recover_abi_structure_committed_target_rebuilds_in_place():
    """A committed structure (created_type_name set) must rebuild WITHOUT
    tripping remove_structure's no-delete guard: same object identity,
    committed-type state, evidence, child link and provenance preserved."""
    name, child_name = "FacRemCommitted", "FacRemChild"
    _cleanup_store(name, child_name)
    try:
        forge_api.create_structure(name, [{"offset": 0, "type": "u64", "name": "vptr"}])
        forge_api.create_structure(child_name)
        forge_api.link_child(name, 0, child_name)
        target = forge_api._resolve_structure(name)
        target.created_type_name = name  # simulate committed-to-IDB state
        target.members[0].scanned_variables = {"v0"}
        from forge.api.structure import StructureProvenance

        target.provenance = StructureProvenance(kind="cpp_synthesis")

        result = forge_api.recover_abi_structure(
            name,
            [
                {"offset": 0, "type": "u64", "name": "vptr"},
                {"offset": 8, "type": "u32", "name": "id"},
            ],
            abi={"rtti_name": "fixture::Probe"},
        )

        assert result["ok"] is True
        # In-place: same object, committed state never destroyed.
        assert forge_api._structures[name] is target
        assert target.created_type_name == name
        # Layout replaced.
        assert target.get_member_by_offset(8).name == "id"
        # Evidence merged into the rebuilt member at the same offset.
        assert result["preserved_sites"] == [{"offset": 0, "member": "vptr"}]
        assert target.get_member_by_offset(0).scanned_variables == {"v0"}
        # Child link preserved in both directions (name synced to the row).
        rel = next(
            rel
            for rel in target.child_relationships
            if rel.child_structure_name == child_name
        )
        assert rel.parent_member_offset == 0
        assert rel.parent_member_name == "vptr"
        child = forge_api._resolve_structure(child_name)
        assert any(
            r.parent_structure_name == name and r.parent_member_offset == 0
            for r in child.parent_relationships
        )
        # Provenance restored, not reset by the rebuild.
        assert target.provenance.kind == "cpp_synthesis"
        # Persisted scan-site rows recomputed for the new layout.
        assert target.scan_sites_rows is not None
        assert result["abi_metadata"]["rtti_name"] == "fixture::Probe"
    finally:
        _cleanup_store(name, child_name)


def test_recover_abi_structure_prunes_child_link_of_vanished_offset():
    """A child link whose parent member offset does not survive the rebuild
    is dropped together with its reciprocal on the child (the old recreate
    path dropped it with the object; the in-place path must prune it)."""
    name, child_name = "FacRemStale", "FacRemStaleChild"
    _cleanup_store(name, child_name)
    try:
        forge_api.create_structure(name, [{"offset": 0, "type": "u64", "name": "vptr"}])
        forge_api.create_structure(child_name)
        forge_api.link_child(name, 0, child_name)

        result = forge_api.recover_abi_structure(
            name, [{"offset": 8, "type": "u32", "name": "id"}]
        )

        assert result["ok"] is True
        assert result["preserved_sites"] == []
        target = forge_api._resolve_structure(name)
        assert target.child_relationships == []
        child = forge_api._resolve_structure(child_name)
        assert child.parent_relationships == []
    finally:
        _cleanup_store(name, child_name)


def test_recover_abi_structure_fresh_target_still_creates():
    """No prior structure: the create path is unchanged."""
    name = "FacRemFresh"
    _cleanup_store(name)
    try:
        result = forge_api.recover_abi_structure(
            name, [{"offset": 0, "type": "u64", "name": "vptr"}]
        )
        assert result["ok"] is True
        assert result["name"] == name
        assert result["members"][0]["name"] == "vptr"
        assert result["preserved_sites"] == []
    finally:
        _cleanup_store(name)


# --------------------------------------------------------------------------- #
# 5. create_type ordinal refresh change-gated like push_type
# --------------------------------------------------------------------------- #


class _FakeStructure:
    """Minimal store structure for the create_type commit path."""

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


@pytest.fixture
def _commit_env(monkeypatch):
    structure = _FakeStructure("fixture_World")
    forge_api._structures["fixture_World"] = structure
    forge_api._state.current = "fixture_World"
    monkeypatch.setattr(forge_api, "_refresh_scan_sites", lambda t: None)
    monkeypatch.setattr(forge_api, "_mark_dirty", lambda: None)
    monkeypatch.setattr(forge_api, "_snapshot_type_before_commit", lambda *a, **k: None)
    reapplied = []

    def _spy_set_func_proto(ea, declaration):
        reapplied.append((ea, declaration))
        return {"ok": True, "ea": ea, "prototype": declaration}

    monkeypatch.setattr(forge_api, "set_func_proto", _spy_set_func_proto)
    monkeypatch.setattr(forge_api, "signature", lambda ea: DECL, raising=False)
    yield SimpleNamespace(reapplied=reapplied)
    del forge_api._structures["fixture_World"]
    forge_api._state.current = None


def test_create_type_unchanged_commit_skips_refresh(_commit_env, monkeypatch):
    """An unchanged re-commit (IDB rows identical before/after) must NOT fire
    the reference refresh: re-applying recorded sites would clobber manual
    applied-site changes made between commits."""
    rows = [(0, "x", "i32")]
    monkeypatch.setattr(forge_api, "_idb_udt_snapshot", lambda name: (None, rows))
    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)

    result = forge_api.create_type("fixture_World", overwrite=True)

    assert result["ok"] is True
    assert result["references"] == {"skipped": "unchanged"}
    assert _commit_env.reapplied == []


def test_create_type_changed_commit_refreshes_exactly_once(_commit_env, monkeypatch):
    """A commit that CHANGED the IDB type still fires the gate once."""
    state = {"n": 0}

    def _snap(name):
        state["n"] += 1
        return (None, []) if state["n"] == 1 else (None, [(0, "x", "i32")])

    monkeypatch.setattr(forge_api, "_idb_udt_snapshot", _snap)
    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)

    result = forge_api.create_type("fixture_World", overwrite=True)

    assert result["ok"] is True
    assert "skipped" not in result["references"]
    assert _commit_env.reapplied == [(0x1400014F0, DECL)]


def test_create_type_first_commit_refreshes(_commit_env, monkeypatch):
    """No prior UDT rows (fresh commit) = a change: the gate fires."""
    monkeypatch.setattr(forge_api, "_idb_udt_snapshot", lambda name: (None, []))
    references.record_prototype(0x1400014F0, "fixture_World", detail=DECL)

    result = forge_api.create_type("fixture_World", overwrite=True)

    assert result["ok"] is True
    assert _commit_env.reapplied == [(0x1400014F0, DECL)]


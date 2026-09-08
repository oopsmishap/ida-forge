from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from types import SimpleNamespace

from forge.api import structure as structure_module
from forge.api.structure import Structure


class FakeMember:
    def __init__(
        self,
        offset: int,
        size: int,
        *,
        enabled: bool = True,
        score: int = 0,
        origin: int = 0,
        type_name: str | None = None,
        scanned_variables=None,
    ):
        self.offset = offset
        self.size = size
        self.enabled = enabled
        self.score = score
        self.origin = origin
        self.type_name = type_name or f"member_{offset:x}"
        self.scanned_variables = set(scanned_variables or [])

    def set_enabled(self, enabled: bool):
        self.enabled = enabled

    def effective_size(self) -> int:
        # Pack-time size — identical to `size` in these unit doubles
        # (real Members resolve the FRESH tinfo at pack; see R2.1).
        return self.size

    def has_collision(self, other) -> bool:
        return self.offset + self.size > other.offset

    def __lt__(self, other):
        return (self.offset, self.type_name) < (other.offset, other.type_name)

    __hash__ = None  # mutable fake; __eq__ compares and merges
    def __eq__(self, other):
        return (self.offset, self.type_name) == (other.offset, other.type_name)


class FakeVirtualTable(FakeMember):
    def __init__(self, offset: int, vtable_name: str, *, nice: bool = True):
        super().__init__(offset, 8, type_name=vtable_name)
        self.vtable_name = vtable_name
        self.has_nice_vtable_name = nice


def test_add_member_orders_members_and_detects_collisions():
    structure = Structure("Example")
    structure.add_member(FakeMember(8, 4))
    structure.add_member(FakeMember(0, 8))
    structure.add_member(FakeMember(4, 8))

    assert [member.offset for member in structure.members] == [0, 4, 8]
    assert structure.collisions == [True, True, True]


def test_calculate_array_size_skips_disabled_members():
    structure = Structure("Example")
    structure.add_member(FakeMember(0, 4))
    structure.add_member(FakeMember(4, 4, enabled=False))
    structure.add_member(FakeMember(16, 4))

    assert structure.get_next_enabled(0) == 2
    assert structure.calculate_array_size(0) == 4


def test_remove_members_updates_main_offset():
    structure = Structure("Example")
    structure.add_member(FakeMember(0, 4))
    structure.add_member(FakeMember(4, 4))
    structure.add_member(FakeMember(8, 4))
    structure.set_main_offset(4)

    structure.remove_members(1)

    assert [member.offset for member in structure.members] == [0, 8]
    assert structure.main_offset == 0


def test_auto_resolve_disables_lower_scoring_colliding_member():
    structure = Structure("Example")
    low_score = FakeMember(0, 8, score=1)
    high_score = FakeMember(4, 8, score=10)
    structure.add_member(low_score)
    structure.add_member(high_score)

    structure.auto_resolve()

    assert low_score.enabled is False
    assert high_score.enabled is True
    assert structure.collisions == [False, False]


def test_get_name_uses_single_nice_vtable(monkeypatch):
    monkeypatch.setattr(structure_module, "VirtualTable", FakeVirtualTable)
    structure = Structure("FallbackName")
    structure.add_member(FakeVirtualTable(0, "MyClass_vtbl"))

    assert structure.get_name() == "MyClass"


@dataclass(frozen=True)
class FakeScanObject:
    func_ea: int
    ea: int
    id: int
    name: str


def test_get_unique_scanned_variables_deduplicates_by_identity_fields():
    structure = Structure("Example")
    scan_a = FakeScanObject(func_ea=1, ea=2, id=3, name="x")
    scan_b = FakeScanObject(func_ea=1, ea=2, id=3, name="x")
    scan_c = FakeScanObject(func_ea=1, ea=2, id=4, name="x")
    structure.add_member(FakeMember(0, 4, origin=0, scanned_variables={scan_a, scan_b}))
    structure.add_member(FakeMember(4, 4, origin=0, scanned_variables={scan_c}))

    unique = structure.get_unique_scanned_variables(0)

    assert len(unique) == 2



def test_clear_members_resets_state():
    structure = Structure("Example")
    structure.add_member(FakeMember(0, 4))
    structure.add_member(FakeMember(4, 4))
    structure.set_main_offset(4)

    structure.clear_members()

    assert structure.members == []
    assert structure.collisions == []
    assert structure.main_offset == 0



def test_enable_disable_and_remove_ignore_out_of_range_indices():
    structure = Structure("Example")
    first = FakeMember(0, 4)
    second = FakeMember(8, 4)
    structure.add_member(first)
    structure.add_member(second)

    structure.disable_members([99, -1])
    assert first.enabled is True and second.enabled is True

    structure.enable_members([99])
    assert first.enabled is True and second.enabled is True

    structure.remove_members([99, -1])
    assert [member.offset for member in structure.members] == [0, 8]



def test_get_name_with_multiple_nice_vtables_falls_back_to_structure_name(monkeypatch):
    monkeypatch.setattr(structure_module, "VirtualTable", FakeVirtualTable)
    warnings = []
    monkeypatch.setattr(structure_module, "log_warning", lambda message, *args, **kwargs: warnings.append(message))
    structure = Structure("FallbackName")
    structure.add_member(FakeVirtualTable(0, "A_vtbl"))
    structure.add_member(FakeVirtualTable(8, "B_vtbl"))

    assert structure.get_name() == "FallbackName"
    assert warnings



def test_pack_structure_on_empty_structure_returns_none_and_warns(monkeypatch):
    warnings = []
    monkeypatch.setattr(structure_module, "log_warning", lambda message, *args, **kwargs: warnings.append(message))
    structure = Structure("Example")

    assert structure.pack_structure() is None
    assert warnings == ["Structure is empty"]



def test_get_provenance_summary_reports_scan_context():
    structure = Structure("Example")
    structure.set_provenance(
        kind="confirmed_root",
        root_object_name="player",
        source_member_offset=0x30,
        has_multiple_roots=True,
    )

    assert (
        structure.get_provenance_summary()
        == "confirmed root | player | member @ 0x30 | multiple roots"
    )


def test_relationship_helpers_update_parent_child_links_and_members():
    parent = Structure("Parent")
    child = Structure("Child")
    member = FakeMember(0x30, 8, type_name="Child *")
    parent.add_member(member)
    member.linked_child_structure_name = "Child"
    member.child_relation_kind = "pointer"

    relationship = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="inventory_ptr",
    )
    duplicate = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="inventory_ptr",
    )
    child.add_parent_relationship(relationship)
    child.add_parent_relationship(relationship)

    assert duplicate is relationship
    assert parent.get_linked_child_names() == ["Child"]
    assert len(parent.child_relationships) == 1
    assert len(child.parent_relationships) == 1

    parent.rename_relationship_references("Child", "Inventory")
    child.rename_relationship_references("Child", "Inventory")

    assert parent.child_relationships[0].child_structure_name == "Inventory"
    assert child.parent_relationships[0].child_structure_name == "Inventory"
    assert member.linked_child_structure_name == "Inventory"

    parent.remove_relationships_with("Inventory")
    child.remove_relationships_with("Parent")

    assert parent.child_relationships == []
    assert child.parent_relationships == []
    assert member.linked_child_structure_name is None
    assert member.child_relation_kind is None

def test_rename_created_type_updates_type_name_when_canonical(monkeypatch):
    structure = Structure("Parent")
    structure.created_type_name = "Parent"
    rename_calls = []

    class FakeTinfo:
        def get_named_type(self, _idati, name):
            return name == "Parent"

        def rename_type(self, new_name, ntf_flags=0):
            rename_calls.append((new_name, ntf_flags))
            return 0

    monkeypatch.setattr(structure_module.ida_typeinf, "tinfo_t", lambda: FakeTinfo())
    monkeypatch.setattr(structure_module.ida_typeinf, "get_idati", lambda: object())

    assert structure.rename_created_type("Parent", "Inventory") is True
    assert structure.created_type_name == "Inventory"
    assert rename_calls == [("Inventory", 0)]



def test_get_unresolved_child_names_only_returns_missing_or_untyped_children():
    parent = Structure("Parent")
    unresolved_child = Structure("Child")
    resolved_child = Structure("Resolved")
    resolved_child.created_type_name = "Resolved_t"

    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x10,
        parent_member_name="child_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Resolved",
        parent_member_offset=0x18,
        parent_member_name="resolved_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Missing",
        parent_member_offset=0x20,
        parent_member_name="missing_ptr",
    )

    assert parent.get_unresolved_child_names(
        {"Child": unresolved_child, "Resolved": resolved_child}
    ) == ["Child", "Missing"]

def test_create_type_if_ready_headless_commits_via_set_cdecl(monkeypatch):
    """R11: ``headless=True`` commits through build_cdecl -> set_cdecl with
    ``overwrite=True`` and never touches ``pack_structure`` (whose Qt
    dialogs return None in idalib workers and turned ``finalize`` into a
    0-diagnostic failure)."""
    recorded = {}

    def fail(*_args, **_kwargs):
        raise AssertionError("pack_structure must not run headless")

    def fake_build_cdecl(self, start=None, end=None):
        return (self.name, f"struct {self.name} {{ int x; }};")

    def fake_set_cdecl(self, cdecl, origin=0, *, overwrite=None):
        recorded["cdecl"] = cdecl
        recorded["origin"] = origin
        recorded["overwrite"] = overwrite
        return object()

    monkeypatch.setattr(Structure, "pack_structure", fail)
    monkeypatch.setattr(Structure, "build_cdecl", fake_build_cdecl)
    monkeypatch.setattr(Structure, "set_cdecl", fake_set_cdecl)

    structure = Structure("X")
    structure.add_member(FakeMember(0, 4))

    result = structure.create_type_if_ready({}, headless=True)

    assert result is not None
    assert recorded["overwrite"] is True
    assert "struct X" in recorded["cdecl"]


def test_create_type_if_ready_blocks_unresolved_children_and_skips_pack_structure(monkeypatch):
    warnings = []
    pack_calls = []
    monkeypatch.setattr(
        structure_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    def fake_pack_structure(self, start=None, end=None):
        pack_calls.append((self.name, start, end))
        return "packed"

    monkeypatch.setattr(Structure, "pack_structure", fake_pack_structure)

    parent = Structure("Parent")
    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x10,
        parent_member_name="child_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Resolved",
        parent_member_offset=0x18,
        parent_member_name="resolved_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Missing",
        parent_member_offset=0x20,
        parent_member_name="missing_ptr",
    )

    child = Structure("Child")
    resolved = Structure("Resolved")
    resolved.created_type_name = "Resolved_t"

    structures_by_name = {"Child": child, "Resolved": resolved}

    assert parent.can_create_type(structures_by_name) is False
    assert parent.create_type_if_ready(structures_by_name, start=1, end=2) is None
    assert pack_calls == []
    assert warnings == [
        "Cannot create type for Parent: unresolved child structures: Child, Missing",
    ]


def test_iter_child_structures_resolves_children_in_offset_order():
    parent = Structure("Parent")
    parent.add_child_relationship(
        child_structure_name="Beta",
        parent_member_offset=0x30,
        parent_member_name="beta_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Gamma",
        parent_member_offset=0x10,
        parent_member_name="gamma_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Alpha",
        parent_member_offset=0x10,
        parent_member_name="alpha_ptr",
    )

    structures_by_name = {
        "Alpha": Structure("Alpha"),
        "Beta": Structure("Beta"),
        "Gamma": Structure("Gamma"),
    }

    assert [child.name for child in parent.iter_child_structures(structures_by_name)] == [
        "Alpha",
        "Gamma",
        "Beta",
    ]


def test_rename_relationship_references_rewrites_member_decl_src(monkeypatch):
    """E4 (eval review 2026-08-13): member type strings that name the
    renamed structure follow it, and the member tinfo is re-parsed — a
    stale ``KV *`` declaration would otherwise rebuild as ``#NN *``."""
    from types import SimpleNamespace

    refreshed = []
    monkeypatch.setattr(
        structure_module,
        "parse_user_tinfo",
        lambda decl: (refreshed.append(decl) or object()),
    )

    parent = Structure("KV")
    self_ref = SimpleNamespace(decl_src="KV *")
    unrelated = SimpleNamespace(decl_src="Kid *")
    parent.members = [self_ref, unrelated]

    parent.rename_relationship_references("KV", "KeyValuePair")

    assert self_ref.decl_src == "KeyValuePair *"
    assert self_ref.tinfo is not None
    assert unrelated.decl_src == "Kid *"
    assert refreshed == ["KeyValuePair *"]


def test_create_subtree_types_postorder_creates_children_before_parent(monkeypatch):
    warnings = []
    pack_calls = []
    monkeypatch.setattr(
        structure_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    def fake_pack_structure(self, start=None, end=None):
        pack_calls.append(self.name)
        self.created_type_name = f"{self.name}_t"
        return self.name

    monkeypatch.setattr(Structure, "pack_structure", fake_pack_structure)

    parent = Structure("Parent")
    parent.add_child_relationship(
        child_structure_name="Beta",
        parent_member_offset=0x30,
        parent_member_name="beta_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Alpha",
        parent_member_offset=0x10,
        parent_member_name="alpha_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="Gamma",
        parent_member_offset=0x10,
        parent_member_name="gamma_ptr",
    )

    structures_by_name = {
        "Parent": parent,
        "Alpha": Structure("Alpha"),
        "Beta": Structure("Beta"),
        "Gamma": Structure("Gamma"),
    }

    ok, created_names, error = parent.create_subtree_types_postorder(
        structures_by_name
    )
    assert ok is True
    assert created_names == ["Alpha", "Gamma", "Beta", "Parent"]
    assert error is None
    assert pack_calls == ["Alpha", "Gamma", "Beta", "Parent"]
    assert warnings == []


def test_create_subtree_types_postorder_warns_on_missing_child(monkeypatch):
    warnings = []
    pack_calls = []
    monkeypatch.setattr(
        structure_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    def fake_pack_structure(self, start=None, end=None):
        pack_calls.append(self.name)
        self.created_type_name = f"{self.name}_t"
        return self.name

    monkeypatch.setattr(Structure, "pack_structure", fake_pack_structure)

    parent = Structure("Parent")
    parent.add_child_relationship(
        child_structure_name="Missing",
        parent_member_offset=0x10,
        parent_member_name="missing_ptr",
    )

    ok, created_names, error = parent.create_subtree_types_postorder(
        {"Parent": parent}
    )
    assert ok is False
    assert created_names == []
    assert error == "unresolved children: Missing"
    assert pack_calls == []
    assert warnings == [
        "Cannot create type for Parent: unresolved child structures: Missing",
    ]


def test_create_subtree_types_postorder_detects_cycles(monkeypatch):
    warnings = []
    pack_calls = []
    monkeypatch.setattr(
        structure_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    def fake_pack_structure(self, start=None, end=None):
        pack_calls.append(self.name)
        self.created_type_name = f"{self.name}_t"
        return self.name

    monkeypatch.setattr(Structure, "pack_structure", fake_pack_structure)

    parent = Structure("A")
    child = Structure("B")
    parent.add_child_relationship(
        child_structure_name="B",
        parent_member_offset=0x10,
        parent_member_name="b_ptr",
    )
    child.add_child_relationship(
        child_structure_name="A",
        parent_member_offset=0x18,
        parent_member_name="a_ptr",
    )

    structures_by_name = {"A": parent, "B": child}

    ok, created_names, error = parent.create_subtree_types_postorder(
        structures_by_name
    )
    assert ok is False
    assert created_names == []
    assert error == "cycle: A -> B -> A"
    assert pack_calls == []
    assert any(
        warning == "Cycle detected while creating type subtree: A -> B -> A"
        for warning in warnings
    )
    assert any(
        warning == "Cannot create subtree for A: child subtree B could not be finalized"
        for warning in warnings
    )

# ---------------------------------------------------------------------------
# Type-preservation guard: overwrite flow validates before deleting
# ---------------------------------------------------------------------------

def _overwrite_setup(monkeypatch, structure_module):
    """Reusable setup: existing type, user confirms overwrite.

    ``create_type`` fails on the first call (the type exists) and succeeds on
    the second (after the delete) — mirroring the real flow. The fake
    ``tinfo_t.get_named_type`` tracks whether the (fake) IDB type exists, so
    the ordinal-delete step visibly removes it and the recreate restores it.
    """
    recorded = {"deleted": [], "created": []}
    state = {"exists": True}

    def create_type(name, decl):
        recorded["created"].append((name, decl))
        if len(recorded["created"]) >= 2:
            state["exists"] = True
            return True
        return False

    monkeypatch.setattr(
        structure_module.idaapi, "get_type_ordinal",
        lambda *_a, **_k: 50, raising=False,
    )
    monkeypatch.setattr(
        structure_module.idaapi, "del_numbered_type",
        lambda *_a, **_k: recorded["deleted"].append(_a) or (state.__setitem__("exists", False) or True),
        raising=False,
    )
    monkeypatch.setattr(
        structure_module.ida_typeinf.tinfo_t,
        "get_named_type",
        lambda self, *a, **k: state["exists"],
        raising=False,
    )
    monkeypatch.setattr(structure_module.forge_types, "create_type", create_type, raising=False)

    class _QMessageBox:
        Yes = 1
        No = 0

        @staticmethod
        def question(*_a, **_k):
            return _QMessageBox.Yes

    # set_cdecl imports QtWidgets lazily inside the overwrite branch; patch the
    # source module attribute so that local import resolves to our fake.
    qt_module = import_module("forge.util.qt")
    monkeypatch.setattr(
        qt_module, "QtWidgets", SimpleNamespace(QMessageBox=_QMessageBox)
    )
    return recorded


def test_set_cdecl_overwrite_keeps_existing_type_when_declaration_invalid(monkeypatch):
    structure_module = import_module("forge.api.structure")
    recorded = _overwrite_setup(monkeypatch, structure_module)

    # parse_decl(out_tif, til, decl, pt_flags) -> name | None
    monkeypatch.setattr(
        structure_module.ida_typeinf, "parse_decl", lambda *_a, **_k: None, raising=False,
    )

    structure = structure_module.Structure("test")
    structure.created_type_name = "test"

    result = structure.set_cdecl("struct test { int x; };")

    assert result is None
    assert recorded["deleted"] == [], "the existing type must NOT be deleted"
    assert len(recorded["created"]) == 1, (
        "only the initial existence probe may run; no recreate after a failed parse"
    )


def test_set_cdecl_overwrite_deletes_and_recreates_when_declaration_valid(monkeypatch):
    structure_module = import_module("forge.api.structure")
    recorded = _overwrite_setup(monkeypatch, structure_module)

    monkeypatch.setattr(
        structure_module.ida_typeinf, "parse_decl", lambda *_a, **_k: "test", raising=False,
    )

    structure = structure_module.Structure("test")
    structure.created_type_name = "test"

    structure.set_cdecl("struct test { int x; };")

    assert len(recorded["deleted"]) == 1
    assert len(recorded["created"]) == 2  # failed probe + recreate after delete


def test_set_cdecl_overwrite_prefers_ordinal_delete_over_name_delete(monkeypatch):
    """Regression (R10): when the in-place update path fails, the fallback
    path must delete by ordinal (``get_type_ordinal`` ->
    ``del_numbered_type``), not ``del_named_type`` which is a silent no-op
    on IDA 9.4. The two delete calls land in order before the recreate, and
    the name-delete fallback only runs when the ordinal delete left the
    type resolvable. ``update_named_type`` is patched to return False
    explicitly so the test exercises the delete+recreate fallback path even
    on stubs that do carry ``update_named_type``."""
    structure_module = import_module("forge.api.structure")
    calls = []

    def create_type(name, decl):
        calls.append("create_type")
        return calls.count("create_type") == 2  # probe fails, recreate succeeds

    state = {"exists": True}
    monkeypatch.setattr(
        structure_module.ida_typeinf,
        "update_named_type",
        lambda *_a, **_k: False,  # in-place update fails -> fallback path
        raising=False,
    )
    monkeypatch.setattr(
        structure_module.idaapi,
        "get_type_ordinal",
        lambda *_a, **_k: calls.append("get_type_ordinal") or 50,
        raising=False,
    )
    monkeypatch.setattr(
        structure_module.idaapi,
        "del_numbered_type",
        lambda *_a, **_k: calls.append("del_numbered_type") or state.__setitem__("exists", False) or True,
        raising=False,
    )
    monkeypatch.setattr(
        structure_module.ida_typeinf.tinfo_t,
        "get_named_type",
        lambda self, *a, **k: calls.append("get_named_type") or state["exists"],
        raising=False,
    )
    name_deletes = []
    monkeypatch.setattr(
        structure_module.ida_typeinf,
        "del_named_type",
        lambda *_a, **_k: name_deletes.append(_a),
        raising=False,
    )
    monkeypatch.setattr(
        structure_module.ida_typeinf, "parse_decl", lambda *_a, **_k: "test", raising=False,
    )
    monkeypatch.setattr(structure_module.forge_types, "create_type", create_type, raising=False)

    qt_module = import_module("forge.util.qt")
    monkeypatch.setattr(
        qt_module,
        "QtWidgets",
        SimpleNamespace(QMessageBox=type("M", (), {"Yes": 1, "No": 0, "question": lambda *a, **k: 1})),
    )

    structure = structure_module.Structure("test")
    structure.created_type_name = "test"
    structure.set_cdecl("struct test { int x; };")

    assert calls[0] == "create_type"  # existence probe first
    assert calls[1] == "get_type_ordinal"
    assert calls[2] == "del_numbered_type"
    assert "del_numbered_type" not in calls[3:]
    assert name_deletes == [], "ordinal delete succeeded; name-delete must not run"


def test_set_cdecl_overwrite_reports_failed_delete_instead_of_silently_keeping(monkeypatch):
    """Regression (R10): when the in-place update path fails and the type
    STILL resolves after both fallback-path delete attempts (ordinal
    delete, then name delete), the overwrite must fail loudly (log + None)
    — never report a bogus "recreated" state over a stale type.
    ``update_named_type`` is patched to return False explicitly so the test
    exercises the delete+recreate fallback path even on stubs that do
    carry ``update_named_type``."""
    structure_module = import_module("forge.api.structure")
    logged = []
    monkeypatch.setattr(
        structure_module, "log_error",
        lambda message, *args, **kwargs: logged.append(message),
    )
    monkeypatch.setattr(
        structure_module.ida_typeinf,
        "update_named_type",
        lambda *_a, **_k: False,  # in-place update fails -> fallback path
        raising=False,
    )

    def create_type(name, decl):
        # The probe must fail (type exists) to enter the overwrite branch;
        # the recreate after a real delete never runs in this test because
        # the delete itself fails.
        return False

    state = {"exists": True}
    monkeypatch.setattr(
        structure_module.idaapi, "get_type_ordinal",
        lambda *_a, **_k: 50, raising=False,
    )
    monkeypatch.setattr(
        structure_module.idaapi, "del_numbered_type",
        lambda *_a, **_k: None, raising=False,  # ordinal delete does nothing
    )
    monkeypatch.setattr(
        structure_module.ida_typeinf.tinfo_t,
        "get_named_type",
        lambda self, *a, **k: state["exists"],
        raising=False,
    )
    monkeypatch.setattr(
        structure_module.ida_typeinf,
        "del_named_type",
        lambda *_a, **_k: None, raising=False,  # name-delete fallback also fails
    )
    monkeypatch.setattr(
        structure_module.ida_typeinf, "parse_decl", lambda *_a, **_k: "test", raising=False,
    )
    monkeypatch.setattr(structure_module.forge_types, "create_type", create_type, raising=False)

    qt_module = import_module("forge.util.qt")
    monkeypatch.setattr(
        qt_module,
        "QtWidgets",
        SimpleNamespace(QMessageBox=type("M", (), {"Yes": 1, "No": 0, "question": lambda *a, **k: 1})),
    )

    structure = structure_module.Structure("test")
    structure.created_type_name = "test"
    result = structure.set_cdecl("struct test { int x; };")

    assert result is None
    assert any("delete existing type" in message for message in logged)


def test_declaration_parses_rejects_bad_declarations(monkeypatch):
    structure_module = import_module("forge.api.structure")

    monkeypatch.setattr(
        structure_module.ida_typeinf, "parse_decl", lambda *_a, **_k: None, raising=False,
    )

    assert structure_module.Structure._declaration_parses("struct test {") is False
    assert structure_module.Structure._declaration_parses("") is False


def test_declaration_parses_accepts_clean_declaration(monkeypatch):
    structure_module = import_module("forge.api.structure")

    monkeypatch.setattr(
        structure_module.ida_typeinf, "parse_decl", lambda *_a, **_k: "test", raising=False,
    )

    assert structure_module.Structure._declaration_parses("struct test { int x; };") is True


# ---------------------------------------------------------------------------


def test_declaration_parses_prefers_domain(monkeypatch):
    structure_module = import_module("forge.api.structure")
    calls = []

    class Types:
        def parse_one_declaration(self, library, declaration):
            calls.append((library, declaration))
            return object()

    monkeypatch.setattr(
        structure_module,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(types=Types()),
    )
    assert structure_module.Structure._declaration_parses("struct X { int x; };") is True
    assert calls == [(None, "struct X { int x; };")]


def test_load_named_type_prefers_domain(monkeypatch):
    structure_module = import_module("forge.api.structure")
    domain_tinfo = object()

    class Types:
        def get_by_name(self, name):
            return domain_tinfo if name == "X" else None

    monkeypatch.setattr(
        structure_module,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(types=Types()),
    )
    assert structure_module.Structure._load_named_type("X") is domain_tinfo
    assert structure_module.Structure._load_named_type("Missing") is None


def test_try_domain_method_distinguishes_none_from_fallback(monkeypatch):
    from forge.api import domain as domain_module

    domain_module.clear_fallback_records()

    class Types:
        def get_value(self):
            return None

    handled, value = domain_module.try_domain_method(
        SimpleNamespace(types=Types()),
        "types",
        "get_value",
        capability="test.none",
        unavailable_reason="unavailable",
        failure_reason="failed",
    )
    assert handled is True
    assert value is None
    assert domain_module.fallback_records() == ()

    handled, value = domain_module.try_domain_method(
        None,
        "types",
        "get_value",
        capability="test.missing",
        unavailable_reason="unavailable",
        failure_reason="failed",
    )
    assert handled is False
    assert value is None
    assert domain_module.fallback_records()[-1].capability == "test.missing"
# Tier 4: auto_resolve dry-run + undo snapshot
# ---------------------------------------------------------------------------


def test_auto_resolve_preview_reports_without_mutating():
    structure = Structure("S")
    high = FakeMember(0, 8, score=5)
    low = FakeMember(4, 8, score=3)
    structure.add_member(high)
    structure.add_member(low)

    disabled = structure.auto_resolve_preview()

    assert disabled == [low]
    assert high.enabled is True and low.enabled is True  # preview is read-only

    resolved = structure.auto_resolve()
    assert resolved == [low]
    assert high.enabled is True and low.enabled is False


def test_auto_resolve_preview_disables_lower_scored_earlier_member():
    structure = Structure("S")
    low_early = FakeMember(0, 8, score=2)
    high_late = FakeMember(4, 8, score=9)
    structure.add_member(low_early)
    structure.add_member(high_late)

    disabled = structure.auto_resolve_preview()

    assert disabled == [low_early]  # the earlier, lower-scored half is dropped

    structure.auto_resolve()
    assert low_early.enabled is False and high_late.enabled is True


def test_set_cdecl_wraps_type_write_in_undo_snapshot(monkeypatch):
    from types import SimpleNamespace

    structure = Structure("Example")
    events = []
    monkeypatch.setattr(
        structure_module,
        "ida_undo",
        SimpleNamespace(
            begin_undo_action=lambda name: events.append(("begin", name)),
            end_undo_action=lambda: events.append(("end",)),
        ),
    )
    monkeypatch.setattr(
        structure_module.forge_types, "create_type",
        lambda name, decl: True, raising=False,
    )

    structure.set_cdecl("struct Example { int x; };")

    assert [e[0] for e in events] == ["begin", "end"]
    assert events[0][1] == "forge: set type Example"


def test_set_cdecl_undo_is_absent_without_ida_undo(monkeypatch):
    structure = Structure("Example")
    monkeypatch.setattr(structure_module, "ida_undo", None)
    monkeypatch.setattr(
        structure_module.forge_types, "create_type",
        lambda name, decl: True, raising=False,
    )

    result = structure.set_cdecl("struct Example { int x; };")

    assert result is not None  # no undo bookkeeping required off-IDA

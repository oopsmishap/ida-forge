from __future__ import annotations

from dataclasses import dataclass

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

    def has_collision(self, other) -> bool:
        return self.offset + self.size > other.offset

    def __lt__(self, other):
        return (self.offset, self.type_name) < (other.offset, other.type_name)

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

    assert parent.create_subtree_types_postorder(structures_by_name) is True
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

    assert parent.create_subtree_types_postorder({"Parent": parent}) is False
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

    assert parent.create_subtree_types_postorder(structures_by_name) is False
    assert pack_calls == []
    assert any(
        warning == "Cycle detected while creating type subtree: A -> B -> A"
        for warning in warnings
    )
    assert any(
        warning == "Cannot create subtree for A: child subtree B could not be finalized"
        for warning in warnings
    )
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

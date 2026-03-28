from __future__ import annotations

from dataclasses import dataclass

from forge.api.structure import Structure


@dataclass(frozen=True)
class FakeScanObject:
    func_ea: int
    ea: int
    id: int
    name: str


class FakeMember:
    def __init__(self, offset: int, size: int, *, enabled: bool = True, origin: int = 0, scanned_variables=None, type_name: str | None = None):
        self.offset = offset
        self.size = size
        self.enabled = enabled
        self.origin = origin
        self.type_name = type_name or f"member_{offset:x}"
        self.scanned_variables = set(scanned_variables or [])

    def set_enabled(self, enabled: bool):
        self.enabled = enabled

    def __lt__(self, other):
        return (self.offset, self.type_name) < (other.offset, other.type_name)

    def __eq__(self, other):
        return (self.offset, self.type_name) == (other.offset, other.type_name)


def test_get_stats_reports_enabled_members_collisions_and_unique_scans():
    structure = Structure("Example")
    shared_a = FakeScanObject(1, 2, 3, "x")
    shared_b = FakeScanObject(1, 2, 3, "x")
    unique = FakeScanObject(1, 3, 4, "y")

    structure.add_member(FakeMember(0, 8, origin=0, scanned_variables={shared_a}))
    structure.add_member(FakeMember(4, 8, origin=0, scanned_variables={shared_b}))
    structure.add_member(FakeMember(16, 4, enabled=False, origin=0, scanned_variables={unique}))
    structure.set_main_offset(0)

    stats = structure.get_stats()

    assert stats.total_members == 3
    assert stats.enabled_members == 2
    assert stats.collision_count == 2
    assert stats.scanned_variable_count == 2
    assert stats.origin_offset == 0


def test_iter_packable_members_starts_at_main_offset_and_skips_disabled():
    structure = Structure("Example")
    structure.add_member(FakeMember(0, 4, enabled=True))
    structure.add_member(FakeMember(4, 4, enabled=False))
    structure.add_member(FakeMember(8, 4, enabled=True))
    structure.set_main_offset(4)

    packable = list(structure.iter_packable_members())

    assert [(index, member.offset) for index, member in packable] == [(2, 8)]

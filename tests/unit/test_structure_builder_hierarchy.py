from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace

from forge.api.members import LinkedStructureMember, VirtualTable
from forge.api.structure import Structure

# structure_builder's package __init__ pulls actions -> scanner; the conftest
# hexrays stub does not carry the two names the import chain touches
# (test_structure_builder_actions pattern).
hexrays_api = import_module("forge.api.hexrays")
scanner_api = import_module("forge.api.scanner")
hexrays_api.get_funcs_referencing_address = lambda *_args, **_kwargs: []
hexrays_api.is_legal_type = lambda *_args, **_kwargs: True
scanner_api.NewShallowScanVisitor = type("NewShallowScanVisitor", (), {})

from forge.features.structure_builder.hierarchy import (
    HierarchyFrame,
    StructureHierarchySession,
)


class _FakeMember:
    """Plain data member fake with the offsets/sizes the engine reads."""

    def __init__(
        self,
        offset: int,
        size: int = 4,
        name: str = "m",
        *,
        is_array: bool = False,
        is_call_argument_evidence: bool = False,
        scanned_variables=None,
    ):
        self.offset = offset
        self.size = size
        self.name = name
        self.origin = 0
        self.enabled = True
        self.comment = ""
        self.is_array = is_array
        self.is_call_argument_evidence = is_call_argument_evidence
        self.scanned_variables = set(scanned_variables or ())
        self.linked_child_structure_name = None
        self.child_relation_kind = None

    @property
    def type_name(self):
        return self.name

    def __lt__(self, other):
        other_name = getattr(other, "type_name", None) or getattr(other, "name", "")
        return (self.offset, self.type_name) < (other.offset, other_name)


def _fake_vtable(offset: int, address: int, *, name: str = "Child_vtbl", nice: bool = True):
    vtable = VirtualTable.__new__(VirtualTable)
    vtable.offset = offset
    vtable.address = address
    vtable.origin = 0
    vtable.enabled = True
    vtable.comment = ""
    vtable.is_array = False
    vtable.name = "_vftable"
    vtable.vtable_name = name
    vtable.has_nice_vtable_name = nice
    vtable.virtual_functions = []
    vtable.scanned_variables = set()
    vtable.linked_child_structure_name = None
    vtable.child_relation_kind = None
    return vtable


def _frame(
    frame_id: int,
    *,
    parent_frame_id: int | None = None,
    function_ea: int = 0x401000,
    argument_index: int = -1,
    call_site_ea: int = 0x402000,
    base_offset: int = 0,
    depth: int = 1,
):
    return SimpleNamespace(
        frame_id=frame_id,
        parent_frame_id=parent_frame_id,
        function_ea=function_ea,
        argument_index=argument_index,
        call_site_ea=call_site_ea,
        base_offset=base_offset,
        depth=depth,
    )


def _session(*structures: Structure) -> StructureHierarchySession:
    root = structures[0]
    by_name = {structure.name: structure for structure in structures}
    return StructureHierarchySession(root, by_name)


def test_vtable_candidate_commits_automatic_hierarchy_with_root_vtable_ea():
    root = Structure("Root")
    session = _session(root)
    frame = _frame(1, base_offset=0x10, depth=1)
    vtable = _fake_vtable(0x10, 0x140009000)
    member = _FakeMember(0x18, 4, "tail")

    session.add_scan([frame], [(vtable, 1), (member, 1)])
    classification = session.classify()

    assert len(classification.candidates) == 1
    candidate = classification.candidates[0]
    assert candidate.base_offset == 0x10
    assert candidate.identity_key == ("vtable", 0x140009000, -1)
    assert candidate.vtable_ea == 0x140009000

    result = session.commit()

    assert [structure.name for structure in result.structures] == ["Root", "Child"]
    child = session.structures_by_name["Child"]
    assert child.provenance.kind == "automatic_hierarchy"
    assert child.provenance.root_vtable_ea == 0x140009000

    linked = root.get_member_by_offset(0x10)
    assert isinstance(linked, LinkedStructureMember)
    assert linked.child_structure_name == "Child"
    assert linked.type_name == "Child"
    assert linked.conservative_extent == 12
    assert root.child_relationships[0].child_structure_name == "Child"
    assert root.child_relationships[0].relation_kind == "embedded"

    # child members are rebased relative to the candidate's base offset
    assert isinstance(child.get_member_by_offset(0), VirtualTable)
    rebased = child.get_member_by_offset(8)
    assert rebased is not None and rebased.offset == 8

    assert root.conservative_extent == 0x1C


def test_aggregate_identity_commits_automatic_aggregate():
    root = Structure("Root")
    session = _session(root)
    frame = _frame(1, function_ea=0x401000, argument_index=0, base_offset=0x10)
    head = _FakeMember(0x10, 4, "head")
    tail = _FakeMember(0x18, 4, "tail")

    session.add_scan([frame], [(head, 1), (tail, 1)])
    classification = session.classify()

    assert len(classification.candidates) == 1
    assert classification.candidates[0].identity_key == ("aggregate", 0x401000, 0)

    result = session.commit()

    child = session.structures_by_name["struct_10"]
    assert child in result.structures
    assert child.provenance.kind == "automatic_aggregate"
    assert child.provenance.root_function_ea == 0x401000
    assert child.provenance.root_argument_index == 0
    assert child.provenance.root_vtable_ea is None

    linked = root.get_member_by_offset(0x10)
    assert isinstance(linked, LinkedStructureMember)
    assert linked.child_structure_name == "struct_10"
    # identity key survives on the committed structure for later scans
    assert session._structure_identity_key(child) == ("aggregate", 0x401000, 0)


def test_duplicate_identity_commits_a_single_child_structure():
    root = Structure("Root")
    session = _session(root)
    # the same vtable observed at two base offsets: two candidates, one identity
    frame_low = _frame(1, base_offset=0x10)
    frame_high = _frame(2, base_offset=0x20)
    vtable_low = _fake_vtable(0x10, 0x140009000)
    vtable_high = _fake_vtable(0x20, 0x140009000)

    session.add_scan([frame_low, frame_high], [(vtable_low, 1), (vtable_high, 2)])
    classification = session.classify()

    assert len(classification.candidates) == 2
    assert {candidate.identity_key for candidate in classification.candidates} == {
        ("vtable", 0x140009000, -1)
    }

    plan = session.plan()
    assert len(plan.identities) == 1

    result = session.commit()

    child_names = [
        structure.name
        for structure in result.structures
        if structure is not root
    ]
    assert child_names == ["Child"]
    linked_offsets = sorted(
        member.offset
        for member in root.members
        if isinstance(member, LinkedStructureMember)
    )
    assert linked_offsets == [0x10, 0x20]
    assert len(root.child_relationships) == 2
    child = session.structures_by_name["Child"]
    assert len(child.parent_relationships) == 2


def test_flat_and_nonpositive_base_observations_stay_root():
    root = Structure("Root")
    session = _session(root)
    flat_frame = _frame(1, base_offset=0)
    negative_frame = _frame(2, base_offset=-8)
    unidentifiable_frame = _frame(3, base_offset=0x10)  # no vtable, argument_index -1
    flat_member = _FakeMember(4, 4, "flat")
    negative_member = _FakeMember(-4, 4, "neg")
    plain_member = _FakeMember(0x10, 4, "plain")

    session.add_scan(
        [flat_frame, negative_frame, unidentifiable_frame],
        [
            (flat_member, 1),
            (negative_member, 2),
            (plain_member, 3),
        ],
    )
    classification = session.classify()

    assert classification.candidates == ()
    assert len(classification.root_observations) == 3

    result = session.commit()

    assert result.structures == (root,)
    assert [member.offset for member in root.members] == [-4, 4, 0x10]
    assert root.child_relationships == []


def test_add_scan_source_base_rebases_observed_members():
    root = Structure("Root")
    session = _session(root)
    frame = _frame(1, base_offset=0)
    member = _FakeMember(0x28, 4, "observed")

    session.add_scan([frame], [(member, 1)], source_base=0x20)
    assert session.has_observations

    session.commit()

    rebased = root.get_member_by_offset(8)
    assert rebased is not None
    assert rebased.offset == 8
    assert rebased.origin == 0
    # the caller's member object is copied, never mutated
    assert member.offset == 0x28


def test_finish_scan_routes_sink_observations_through_live_frames():
    root = Structure("Root")
    session = _session(root)
    live_frame = _frame(7, base_offset=0x10)
    stale_frame = _frame(9, base_offset=0x10)
    visitor = SimpleNamespace(call_frames=[live_frame], frame_aliases={})

    session.member_sink(_FakeMember(0x18, 4, "live"), live_frame)
    session.member_sink(_FakeMember(0x18, 4, "stale"), stale_frame)
    session.finish_scan(visitor)

    # only the live frame's observation was consumed; the stale one stays
    # pending for a later scan whose visitor contains its frame
    assert [
        frame.frame_id for _, frame in session._pending_observations
    ] == [9]
    assert [frame.frame_id for frame in session.frames] == [0]
    assert session.frames[0] == HierarchyFrame(
        frame_id=0,
        parent_frame_id=None,
        function_ea=0x401000,
        argument_index=-1,
        call_site_ea=0x402000,
        base_offset=0x10,
        depth=1,
    )
    assert session.has_observations


def test_finish_scan_applies_frame_aliases():
    root = Structure("Root")
    session = _session(root)
    canonical_frame = _frame(1, base_offset=0)
    alias_frame = _frame(2, base_offset=0)
    visitor = SimpleNamespace(call_frames=[canonical_frame, alias_frame], frame_aliases={2: 1})

    session.member_sink(_FakeMember(4, 4, "shared"), canonical_frame)
    session.finish_scan(visitor)

    # the alias frame inherited the canonical frame's observations
    assert [len(observations) for observations in session._frame_observations.values()] == [1, 1]

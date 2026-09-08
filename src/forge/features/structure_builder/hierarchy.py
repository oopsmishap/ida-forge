"""Hierarchy reconstruction engine (ported from daax's fork snapshot).

Pure-Python classification/planning/commit over the already-scanned members
and recursive call frames: no SDK calls. The engine groups call frames by
their base offset, classifies each base group by a vtable identity (the
qualifying vtable observed at the base offset) or an aggregate identity
(the (function_ea, argument_index) pair of the qualifying call frame),
plans placements of child structures inside their parents, and commits the
result as unique structures with ``automatic_hierarchy`` /
``automatic_aggregate`` provenance.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

import forge.api.types as forge_types
from forge.api.members import AbstractMember, LinkedStructureMember, VirtualTable
from forge.api.structure import Structure
from forge.util.cxx_to_c_name import sanitize_c_identifier

if TYPE_CHECKING:
    from forge.api.visitor import RecursiveCallFrame

IdentityKey = tuple[str, int, int]


@dataclass(frozen=True)
class HierarchyFrame:
    frame_id: int
    parent_frame_id: int | None
    function_ea: int
    argument_index: int
    call_site_ea: int
    base_offset: int
    depth: int


@dataclass(frozen=True)
class HierarchyObservation:
    member: AbstractMember
    frame_id: int


@dataclass
class HierarchyCandidate:
    candidate_id: int
    base_offset: int
    identity_key: IdentityKey
    vtable_ea: int | None
    identity_frame_id: int
    frame_ids: tuple[int, ...]
    branch_root_frame_ids: tuple[int, ...]
    observations: tuple[HierarchyObservation, ...]
    parent_candidate_id: int | None = None


@dataclass(frozen=True)
class HierarchyClassification:
    candidates: tuple[HierarchyCandidate, ...]
    root_observations: tuple[HierarchyObservation, ...]


@dataclass
class HierarchyPlacement:
    candidate_id: int
    parent_candidate_id: int | None
    base_offset: int
    relative_offset: int
    identity_key: IdentityKey
    vtable_ea: int | None
    extent: int
    depth: int
    observations: tuple[HierarchyObservation, ...]
    parent_scanned_variables: tuple[object, ...] = ()
    accepted: bool = True
    existing_child_name: str | None = None


@dataclass(frozen=True)
class HierarchyIdentityPlan:
    identity_key: IdentityKey
    vtable_ea: int | None
    extent: int
    placement_ids: tuple[int, ...]
    observations: tuple[HierarchyObservation, ...]


@dataclass(frozen=True)
class HierarchyPlan:
    placements: tuple[HierarchyPlacement, ...]
    identities: tuple[HierarchyIdentityPlan, ...]
    flat_observations: Mapping[int | None, tuple[HierarchyObservation, ...]]


@dataclass(frozen=True)
class HierarchyCommitResult:
    plan: HierarchyPlan
    structures: tuple[Structure, ...]


class StructureHierarchySession:
    def __init__(
        self,
        root_structure: Structure,
        structures_by_name: MutableMapping[str, Structure] | None = None,
        make_unique_name: Callable[[str], str] | None = None,
    ):
        self.root_structure = root_structure
        self.structures_by_name = (
            structures_by_name
            if structures_by_name is not None
            else {root_structure.name: root_structure}
        )
        self._make_unique_name_callback = make_unique_name
        self._frames: dict[int, HierarchyFrame] = {}
        self._frame_observations: dict[int, list[AbstractMember]] = {}
        self._pending_observations: list[tuple[AbstractMember, RecursiveCallFrame]] = []
        self._next_frame_id = 0

    def member_sink(self, member: AbstractMember, frame: RecursiveCallFrame) -> None:
        self._pending_observations.append((member, frame))

    def finish_scan(self, visitor, *, source_base: int = 0) -> None:
        frame_object_ids = {id(frame) for frame in visitor.call_frames}
        observations = [
            (member, frame)
            for member, frame in self._pending_observations
            if id(frame) in frame_object_ids
        ]
        self._pending_observations = [
            (member, frame)
            for member, frame in self._pending_observations
            if id(frame) not in frame_object_ids
        ]
        self.add_scan(
            visitor.call_frames,
            observations,
            visitor.frame_aliases,
            source_base=source_base,
        )

    def add_scan(
        self,
        frames: Sequence[RecursiveCallFrame],
        observations: Iterable[tuple[AbstractMember, RecursiveCallFrame | int]],
        aliases: Mapping[int, int] | None = None,
        *,
        source_base: int = 0,
    ) -> None:
        local_frames = {frame.frame_id: frame for frame in frames}
        local_to_session: dict[int, int] = {}
        for local_frame_id in sorted(local_frames):
            local_to_session[local_frame_id] = self._next_frame_id
            self._next_frame_id += 1

        for local_frame_id in sorted(local_frames):
            frame = local_frames[local_frame_id]
            parent_frame_id = (
                None
                if frame.parent_frame_id is None
                else local_to_session[frame.parent_frame_id]
            )
            session_frame_id = local_to_session[local_frame_id]
            self._frames[session_frame_id] = HierarchyFrame(
                frame_id=session_frame_id,
                parent_frame_id=parent_frame_id,
                function_ea=frame.function_ea,
                argument_index=frame.argument_index,
                call_site_ea=frame.call_site_ea,
                base_offset=frame.base_offset,
                depth=frame.depth,
            )
            self._frame_observations[session_frame_id] = []

        for member, frame in observations:
            local_frame_id = frame if isinstance(frame, int) else frame.frame_id
            session_frame_id = local_to_session.get(local_frame_id)
            if session_frame_id is not None:
                normalized_member = member
                if source_base:
                    normalized_member = copy.copy(member)
                    normalized_member.offset = member.offset - source_base
                    normalized_member.origin = 0
                    if hasattr(member, "scanned_variables"):
                        normalized_member.scanned_variables = set(
                            member.scanned_variables
                        )
                self._frame_observations[session_frame_id].append(
                    normalized_member
                )

        for alias_local_id, canonical_local_id in (aliases or {}).items():
            alias_frame_id = local_to_session.get(alias_local_id)
            canonical_frame_id = local_to_session.get(canonical_local_id)
            if alias_frame_id is None or canonical_frame_id is None:
                continue
            self._frame_observations[alias_frame_id].extend(
                self._frame_observations[canonical_frame_id]
            )

    @property
    def has_observations(self) -> bool:
        return any(self._frame_observations.values())

    @property
    def frames(self) -> tuple[HierarchyFrame, ...]:
        return tuple(self._frames[frame_id] for frame_id in sorted(self._frames))

    def _same_base_branch_root(self, frame_id: int, base_offset: int) -> int:
        frame = self._frames[frame_id]
        while frame.parent_frame_id is not None:
            parent = self._frames[frame.parent_frame_id]
            if parent.base_offset != base_offset:
                break
            frame = parent
        return frame.frame_id

    def _observations_for_frames(
        self, frame_ids: Iterable[int]
    ) -> tuple[HierarchyObservation, ...]:
        return tuple(
            HierarchyObservation(member, frame_id)
            for frame_id in sorted(frame_ids)
            for member in self._frame_observations.get(frame_id, ())
        )

    @staticmethod
    def _qualifying_vtable(
        observations: Iterable[HierarchyObservation], base_offset: int
    ) -> VirtualTable | None:
        for observation in observations:
            member = observation.member
            if isinstance(member, VirtualTable) and member.offset == base_offset:
                return member
        return None

    @classmethod
    def _qualifying_aggregate(
        cls,
        observations: Iterable[HierarchyObservation],
        base_offset: int,
    ) -> bool:
        members = [
            observation.member
            for observation in observations
            if not isinstance(observation.member, VirtualTable)
            and not bool(
                getattr(
                    observation.member,
                    "is_call_argument_evidence",
                    False,
                )
            )
            and observation.member.offset >= base_offset
        ]
        offsets = {int(member.offset) for member in members}
        if len(offsets) >= 2 and max(offsets) > base_offset:
            return True
        return any(
            int(member.offset) == base_offset
            and bool(getattr(member, "is_array", False))
            and cls._member_size(member) > cls._default_width()
            for member in members
        )

    def classify(self) -> HierarchyClassification:
        root_observations: list[HierarchyObservation] = []
        candidates: list[HierarchyCandidate] = []
        frames_by_base: dict[int, list[int]] = {}
        for frame_id, frame in self._frames.items():
            frames_by_base.setdefault(frame.base_offset, []).append(frame_id)

        for base_offset in sorted(frames_by_base):
            frame_ids = sorted(frames_by_base[base_offset])
            group_observations = self._observations_for_frames(frame_ids)
            if base_offset <= 0:
                root_observations.extend(group_observations)
                continue

            branches: dict[int, list[int]] = {}
            for frame_id in frame_ids:
                branch_root = self._same_base_branch_root(frame_id, base_offset)
                branches.setdefault(branch_root, []).append(frame_id)

            branch_records: list[
                tuple[
                    int,
                    tuple[int, ...],
                    int,
                    int | None,
                    IdentityKey | None,
                    tuple[HierarchyObservation, ...],
                ]
            ] = []
            for branch_root, branch_frame_ids in sorted(branches.items()):
                branch_frame_ids.sort(
                    key=lambda frame_id: (
                        self._frames[frame_id].depth,
                        frame_id,
                    )
                )
                branch_observations = self._observations_for_frames(
                    branch_frame_ids
                )
                identity_frame_id = -1
                identity_vtable = None
                for frame_id in branch_frame_ids:
                    frame_observations = self._observations_for_frames(
                        (frame_id,)
                    )
                    identity_vtable = self._qualifying_vtable(
                        frame_observations, base_offset
                    )
                    if identity_vtable is not None:
                        identity_frame_id = frame_id
                        break

                aggregate_identity = None
                if identity_vtable is None:
                    for frame_id in branch_frame_ids:
                        frame = self._frames[frame_id]
                        if frame.argument_index < 0:
                            continue
                        frame_observations = self._observations_for_frames(
                            (frame_id,)
                        )
                        if not self._qualifying_aggregate(
                            frame_observations, base_offset
                        ):
                            continue
                        aggregate_identity = (
                            "aggregate",
                            frame.function_ea,
                            frame.argument_index,
                        )
                        identity_frame_id = frame_id
                        break
                branch_records.append(
                    (
                        branch_root,
                        tuple(branch_frame_ids),
                        identity_frame_id,
                        (
                            identity_vtable.address
                            if identity_vtable is not None
                            else None
                        ),
                        aggregate_identity,
                        branch_observations,
                    )
                )

            vtable_records = [
                record for record in branch_records if record[3] is not None
            ]
            vtable_eas = {record[3] for record in vtable_records}
            if len(vtable_eas) > 1:
                root_observations.extend(group_observations)
                continue

            candidate_records = []
            identity_key = None
            vtable_ea = None
            identity_frame_id = -1
            if vtable_records:
                vtable_ea = next(iter(vtable_eas))
                identity_key = ("vtable", int(vtable_ea), -1)
                candidate_records = [
                    record
                    for record in branch_records
                    if record[3] == vtable_ea
                ]
                identity_frame_id = min(
                    record[2]
                    for record in vtable_records
                    if record[3] == vtable_ea
                )
            else:
                aggregate_records = [
                    record
                    for record in branch_records
                    if record[4] is not None
                ]
                if aggregate_records:
                    identity_record = min(
                        aggregate_records,
                        key=lambda record: (
                            -len(
                                {
                                    observation.member.offset
                                    for observation
                                    in self._observations_for_frames(
                                        (record[2],)
                                    )
                                }
                            ),
                            record[4],
                        ),
                    )
                    identity_key = identity_record[4]
                    candidate_records = [
                        record
                        for record in aggregate_records
                        if record[4] == identity_key
                    ]
                    identity_frame_id = identity_record[2]

            if identity_key is None:
                root_observations.extend(group_observations)
                continue

            candidate_record_ids = {
                record[0] for record in candidate_records
            }
            root_observations.extend(
                observation
                for record in branch_records
                if record[0] not in candidate_record_ids
                for observation in record[5]
            )
            candidate_id = len(candidates)
            candidates.append(
                HierarchyCandidate(
                    candidate_id=candidate_id,
                    base_offset=base_offset,
                    identity_key=identity_key,
                    vtable_ea=vtable_ea,
                    identity_frame_id=identity_frame_id,
                    frame_ids=tuple(
                        sorted(
                            frame_id
                            for record in candidate_records
                            for frame_id in record[1]
                        )
                    ),
                    branch_root_frame_ids=tuple(
                        record[0] for record in candidate_records
                    ),
                    observations=tuple(
                        observation
                        for record in candidate_records
                        for observation in record[5]
                    ),
                )
            )

        frame_candidate_ids = {
            frame_id: candidate.candidate_id
            for candidate in candidates
            for frame_id in candidate.frame_ids
        }
        for candidate in candidates:
            parent_candidate_ids: set[int] = set()
            for branch_root_frame_id in candidate.branch_root_frame_ids:
                frame = self._frames[branch_root_frame_id]
                parent_frame_id = frame.parent_frame_id
                while parent_frame_id is not None:
                    parent_candidate_id = frame_candidate_ids.get(
                        parent_frame_id
                    )
                    if parent_candidate_id is not None:
                        parent_candidate_ids.add(parent_candidate_id)
                        break
                    parent_frame_id = self._frames[
                        parent_frame_id
                    ].parent_frame_id
            if len(parent_candidate_ids) == 1:
                candidate.parent_candidate_id = next(
                    iter(parent_candidate_ids)
                )

        return HierarchyClassification(
            candidates=tuple(candidates),
            root_observations=tuple(root_observations),
        )

    @staticmethod
    def _default_width() -> int:
        return max(1, int(getattr(forge_types.types, "width", 8)))

    @classmethod
    def _member_size(cls, member: AbstractMember) -> int:
        try:
            size = int(member.size)
        except Exception:  # noqa: BLE001 — duck-typed/test members; any failure degrades to width
            size = cls._default_width()
        return max(1, size)

    @classmethod
    def _member_range(cls, member: AbstractMember) -> tuple[int, int]:
        start = int(member.offset)
        return start, start + cls._member_size(member)

    @staticmethod
    def _ranges_overlap(
        left_start: int,
        left_end: int,
        right_start: int,
        right_end: int,
    ) -> bool:
        return left_start < right_end and right_start < left_end

    @staticmethod
    def _rebased_scanned_variables(scanned_variables) -> set:
        rebased_variables = set()
        for scanned_variable in scanned_variables:
            if hasattr(scanned_variable, "_applicable"):
                rebased_variable = copy.copy(scanned_variable)
                rebased_variable._applicable = True
            else:
                rebased_variable = scanned_variable
            rebased_variables.add(rebased_variable)
        return rebased_variables

    @staticmethod
    def clone_rebased_member(member: AbstractMember, base_offset: int):
        cloned_member = copy.copy(member)
        cloned_member.offset = member.offset - base_offset
        cloned_member.origin = 0
        if hasattr(member, "scanned_variables"):
            cloned_member.scanned_variables = (
                StructureHierarchySession._rebased_scanned_variables(
                    member.scanned_variables
                )
            )
        return cloned_member

    @staticmethod
    def _candidate_depth(
        candidate: HierarchyCandidate,
        candidates_by_id: Mapping[int, HierarchyCandidate],
    ) -> int:
        depth = 1
        parent_candidate_id = candidate.parent_candidate_id
        seen = {candidate.candidate_id}
        while parent_candidate_id is not None and parent_candidate_id not in seen:
            seen.add(parent_candidate_id)
            depth += 1
            parent_candidate_id = candidates_by_id[
                parent_candidate_id
            ].parent_candidate_id
        return depth

    def _frame_is_ancestor_of_candidate(
        self,
        frame_id: int,
        candidate: HierarchyCandidate,
    ) -> bool:
        for branch_root_frame_id in candidate.branch_root_frame_ids:
            current_frame_id: int | None = branch_root_frame_id
            while current_frame_id is not None:
                if current_frame_id == frame_id:
                    return True
                current_frame_id = self._frames[current_frame_id].parent_frame_id
        return False

    @staticmethod
    def _structure_extent(structure: Structure) -> int:
        return max(
            (
                int(member.offset)
                + StructureHierarchySession._member_size(member)
                for member in structure.members
            ),
            default=StructureHierarchySession._default_width(),
        )

    @staticmethod
    def _structure_identity_key(structure: Structure) -> IdentityKey | None:
        provenance = structure.provenance
        if provenance.root_vtable_ea is not None:
            return ("vtable", int(provenance.root_vtable_ea), -1)
        if (
            provenance.kind == "automatic_aggregate"
            and provenance.root_function_ea is not None
            and provenance.root_argument_index is not None
        ):
            return (
                "aggregate",
                int(provenance.root_function_ea),
                int(provenance.root_argument_index),
            )
        return None

    def _structures_by_identity(self) -> dict[IdentityKey, Structure]:
        structures_by_identity: dict[IdentityKey, Structure] = {}
        for structure in self.structures_by_name.values():
            identity_key = self._structure_identity_key(structure)
            if identity_key is not None:
                structures_by_identity[identity_key] = structure
        return structures_by_identity

    def _fixed_relationship_conflict(
        self,
        placement: HierarchyPlacement,
        parent_structure: Structure,
        structures_by_identity: Mapping[IdentityKey, Structure],
    ) -> tuple[bool, str | None]:
        placement_start = placement.relative_offset
        placement_end = placement_start + placement.extent
        for relationship in parent_structure.child_relationships:
            member = parent_structure.get_member_by_offset(
                relationship.parent_member_offset
            )
            if member is None:
                continue
            fixed_start = relationship.parent_member_offset
            fixed_end = fixed_start + self._member_size(member)
            if not self._ranges_overlap(
                placement_start,
                placement_end,
                fixed_start,
                fixed_end,
            ):
                continue
            existing_child = self.structures_by_name.get(
                relationship.child_structure_name
            )
            existing_identity_key = (
                self._structure_identity_key(existing_child)
                if existing_child is not None
                else None
            )
            if (
                fixed_start == placement_start
                and existing_identity_key == placement.identity_key
            ):
                return False, existing_child.name
            return True, None
        return False, None

    def _identity_enlargement_conflicts(
        self,
        identity_key: IdentityKey,
        proposed_extent: int,
        structures_by_identity: Mapping[IdentityKey, Structure],
    ) -> bool:
        child_structure = structures_by_identity.get(identity_key)
        if child_structure is None:
            return False
        current_extent = self._structure_extent(child_structure)
        if proposed_extent <= current_extent:
            return False

        for parent_structure in self.structures_by_name.values():
            child_relationships = [
                relationship
                for relationship in parent_structure.child_relationships
                if relationship.child_structure_name == child_structure.name
            ]
            for child_relationship in child_relationships:
                enlarged_start = child_relationship.parent_member_offset
                enlarged_end = enlarged_start + proposed_extent
                for other_relationship in parent_structure.child_relationships:
                    if other_relationship is child_relationship:
                        continue
                    other_member = parent_structure.get_member_by_offset(
                        other_relationship.parent_member_offset
                    )
                    if other_member is None:
                        continue
                    other_start = other_relationship.parent_member_offset
                    other_end = other_start + self._member_size(other_member)
                    if self._ranges_overlap(
                        enlarged_start,
                        enlarged_end,
                        other_start,
                        other_end,
                    ):
                        return True
        return False

    def plan(self) -> HierarchyPlan:
        classification = self.classify()
        root_vtable_eas = {
            observation.member.address
            for observation in classification.root_observations
            if isinstance(observation.member, VirtualTable)
            and observation.member.offset == 0
        }
        inferred_root_vtable_ea = (
            next(iter(root_vtable_eas)) if len(root_vtable_eas) == 1 else None
        )
        root_vtable_ea = (
            getattr(self.root_structure.provenance, "root_vtable_ea", None)
            or inferred_root_vtable_ea
        )
        root_identity_key = (
            ("vtable", int(root_vtable_ea), -1)
            if root_vtable_ea is not None
            else None
        )
        candidates_by_id = {
            candidate.candidate_id: candidate
            for candidate in classification.candidates
        }
        placements: dict[int, HierarchyPlacement] = {}
        direct_flat_observations: dict[int, list[HierarchyObservation]] = {}
        call_argument_observations: dict[
            int, list[HierarchyObservation]
        ] = {}
        for candidate in classification.candidates:
            parent_base_offset = (
                candidates_by_id[candidate.parent_candidate_id].base_offset
                if candidate.parent_candidate_id is not None
                else 0
            )
            local_observations: list[HierarchyObservation] = []
            for observation in candidate.observations:
                if observation.member.offset < candidate.base_offset:
                    direct_flat_observations.setdefault(
                        candidate.candidate_id, []
                    ).append(observation)
                elif bool(
                    getattr(
                        observation.member,
                        "is_call_argument_evidence",
                        False,
                    )
                ):
                    call_argument_observations.setdefault(
                        candidate.candidate_id, []
                    ).append(observation)
                else:
                    local_observations.append(observation)
            local_extent = max(
                (
                    self._member_range(observation.member)[1]
                    - candidate.base_offset
                    for observation in local_observations
                ),
                default=self._default_width(),
            )
            parent_candidate = (
                candidates_by_id.get(candidate.parent_candidate_id)
                if candidate.parent_candidate_id is not None
                else None
            )
            parent_identity_key = (
                parent_candidate.identity_key
                if parent_candidate is not None
                else root_identity_key
            )
            placements[candidate.candidate_id] = HierarchyPlacement(
                candidate_id=candidate.candidate_id,
                parent_candidate_id=candidate.parent_candidate_id,
                base_offset=candidate.base_offset,
                relative_offset=candidate.base_offset - parent_base_offset,
                identity_key=candidate.identity_key,
                vtable_ea=candidate.vtable_ea,
                extent=max(self._default_width(), local_extent),
                depth=self._candidate_depth(candidate, candidates_by_id),
                observations=tuple(local_observations),
                parent_scanned_variables=tuple(
                    {
                        scanned_variable
                        for observation in call_argument_observations.get(
                            candidate.candidate_id, ()
                        )
                        for scanned_variable in getattr(
                            observation.member, "scanned_variables", ()
                        )
                    }
                ),
                accepted=parent_identity_key != candidate.identity_key,
            )

        max_passes = max(1, len(placements) * 2 + 1)
        for _ in range(max_passes):
            changed = False
            identity_extents: dict[IdentityKey, int] = {}
            for placement in placements.values():
                if placement.accepted:
                    identity_extents[placement.identity_key] = max(
                        identity_extents.get(placement.identity_key, 0),
                        placement.extent,
                    )
            for placement in placements.values():
                if not placement.accepted:
                    continue
                shared_extent = identity_extents[placement.identity_key]
                if shared_extent > placement.extent:
                    placement.extent = shared_extent
                    changed = True
            for placement in sorted(
                placements.values(), key=lambda item: (-item.depth, item.candidate_id)
            ):
                if not placement.accepted or placement.parent_candidate_id is None:
                    continue
                parent = placements[placement.parent_candidate_id]
                if not parent.accepted:
                    continue
                required_parent_extent = placement.relative_offset + placement.extent
                if required_parent_extent > parent.extent:
                    parent.extent = required_parent_extent
                    changed = True
            if not changed:
                break

        sibling_groups: dict[int | None, list[HierarchyPlacement]] = {}
        for placement in placements.values():
            if placement.accepted:
                sibling_groups.setdefault(placement.parent_candidate_id, []).append(
                    placement
                )
        for siblings in sibling_groups.values():
            overlapping_ids: set[int] = set()
            overlap_pairs: list[
                tuple[HierarchyPlacement, HierarchyPlacement]
            ] = []
            ordered_siblings = sorted(
                siblings, key=lambda item: (item.relative_offset, item.candidate_id)
            )
            for index, left in enumerate(ordered_siblings):
                left_end = left.relative_offset + left.extent
                for right in ordered_siblings[index + 1 :]:
                    if right.relative_offset >= left_end:
                        break
                    right_end = right.relative_offset + right.extent
                    if self._ranges_overlap(
                        left.relative_offset,
                        left_end,
                        right.relative_offset,
                        right_end,
                    ):
                        overlap_pairs.append((left, right))
                        overlapping_ids.update(
                            (left.candidate_id, right.candidate_id)
                        )
            for candidate_id in overlapping_ids:
                placements[candidate_id].accepted = False

            ambiguous_vtable_ids = {
                placement.candidate_id
                for left, right in overlap_pairs
                if left.vtable_ea is not None and right.vtable_ea is not None
                for placement in (left, right)
            }
            for placement in siblings:
                if placement.vtable_ea is not None or placement.accepted:
                    continue
                neighbors = {
                    right.candidate_id
                    for left, right in overlap_pairs
                    if left.candidate_id == placement.candidate_id
                } | {
                    left.candidate_id
                    for left, right in overlap_pairs
                    if right.candidate_id == placement.candidate_id
                }
                if neighbors and neighbors <= ambiguous_vtable_ids:
                    placement.accepted = True
        structures_by_identity = self._structures_by_identity()
        for placement in sorted(
            placements.values(), key=lambda item: (-item.depth, item.candidate_id)
        ):
            if not placement.accepted:
                continue
            if placement.parent_candidate_id is None:
                parent_structure = self.root_structure
            else:
                parent_placement = placements[placement.parent_candidate_id]
                parent_structure = structures_by_identity.get(
                    parent_placement.identity_key
                )
                if parent_structure is None:
                    continue
            conflict, existing_child_name = self._fixed_relationship_conflict(
                placement, parent_structure, structures_by_identity
            )
            if conflict:
                placement.accepted = False
            else:
                placement.existing_child_name = existing_child_name

        proposed_identity_extents: dict[IdentityKey, int] = {}
        for placement in placements.values():
            if placement.accepted:
                proposed_identity_extents[placement.identity_key] = max(
                    proposed_identity_extents.get(placement.identity_key, 0),
                    placement.extent,
                )
        rejected_identities = {
            identity_key
            for identity_key, proposed_extent in proposed_identity_extents.items()
            if self._identity_enlargement_conflicts(
                identity_key, proposed_extent, structures_by_identity
            )
        }
        for placement in placements.values():
            if placement.identity_key in rejected_identities:
                placement.accepted = False

        for placement in sorted(
            placements.values(), key=lambda item: (item.depth, item.candidate_id)
        ):
            if placement.parent_candidate_id is None:
                continue
            if not placements[placement.parent_candidate_id].accepted:
                placement.accepted = False

        flat_observations: dict[int | None, list[HierarchyObservation]] = {
            None: []
        }
        for placement in placements.values():
            if placement.accepted:
                continue
            owner_candidate_id = placement.parent_candidate_id
            while (
                owner_candidate_id is not None
                and not placements[owner_candidate_id].accepted
            ):
                owner_candidate_id = placements[owner_candidate_id].parent_candidate_id
            flat_observations.setdefault(owner_candidate_id, []).extend(
                placement.observations
            )
            flat_observations.setdefault(owner_candidate_id, []).extend(
                direct_flat_observations.get(placement.candidate_id, ())
            )
            flat_observations.setdefault(owner_candidate_id, []).extend(
                call_argument_observations.get(placement.candidate_id, ())
            )

        for placement in placements.values():
            if placement.accepted:
                flat_observations.setdefault(placement.candidate_id, []).extend(
                    direct_flat_observations.get(placement.candidate_id, ())
                )

        for observation in classification.root_observations:
            observation_start, observation_end = self._member_range(
                observation.member
            )
            containing = [
                placement
                for placement in placements.values()
                if placement.accepted
                and placement.base_offset <= observation_start
                and observation_end <= placement.base_offset + placement.extent
                and self._frame_is_ancestor_of_candidate(
                    observation.frame_id,
                    candidates_by_id[placement.candidate_id],
                )
            ]
            if not containing:
                flat_observations[None].append(observation)
                continue
            deepest_depth = max(placement.depth for placement in containing)
            deepest = [
                placement
                for placement in containing
                if placement.depth == deepest_depth
            ]
            if len(deepest) != 1:
                flat_observations[None].append(observation)
                continue
            target = deepest[0]
            if bool(
                getattr(
                    observation.member,
                    "is_call_argument_evidence",
                    False,
                )
            ):
                target.parent_scanned_variables = tuple(
                    set(target.parent_scanned_variables).union(
                        getattr(
                            observation.member,
                            "scanned_variables",
                            (),
                        )
                    )
                )
                continue
            target.observations = (*target.observations, observation)

        identity_plans: list[HierarchyIdentityPlan] = []

        for identity_key in sorted(
            {
                placement.identity_key
                for placement in placements.values()
                if placement.accepted
            }
        ):
            identity_placements = sorted(
                (
                    placement
                    for placement in placements.values()
                    if placement.accepted
                    and placement.identity_key == identity_key
                ),
                key=lambda item: item.candidate_id,
            )
            identity_plans.append(
                HierarchyIdentityPlan(
                    identity_key=identity_key,
                    vtable_ea=identity_placements[0].vtable_ea,
                    extent=max(
                        placement.extent for placement in identity_placements
                    ),
                    placement_ids=tuple(
                        placement.candidate_id
                        for placement in identity_placements
                    ),
                    observations=tuple(
                        observation
                        for placement in identity_placements
                        for observation in placement.observations
                    ),
                )
            )

        return HierarchyPlan(
            placements=tuple(
                placements[candidate_id] for candidate_id in sorted(placements)
            ),
            identities=tuple(identity_plans),
            flat_observations={
                owner_candidate_id: tuple(observations)
                for owner_candidate_id, observations in flat_observations.items()
            },
        )

    def _next_auto_structure_name(self) -> str:
        index = 1
        while True:
            candidate = f"auto_struct_{index:03d}"
            if candidate not in self.structures_by_name:
                return candidate
            index += 1

    def _make_unique_structure_name(self, base_name: str) -> str:
        if base_name not in self.structures_by_name:
            return base_name
        if self._make_unique_name_callback is not None:
            callback_candidate = self._make_unique_name_callback(base_name)
            if callback_candidate not in self.structures_by_name:
                return callback_candidate
        copy_index = 1
        while True:
            suffix = " Copy" if copy_index == 1 else f" Copy {copy_index}"
            candidate = f"{base_name}{suffix}"
            if candidate not in self.structures_by_name:
                return candidate
            copy_index += 1

    def _identity_structure_name(
        self,
        identity: HierarchyIdentityPlan,
        placements_by_id: Mapping[int, HierarchyPlacement],
    ) -> tuple[str, bool]:
        for observation in identity.observations:
            member = observation.member
            if (
                identity.vtable_ea is not None
                and isinstance(member, VirtualTable)
                and member.address == identity.vtable_ea
                and member.has_nice_vtable_name
            ):
                vtable_name = member.vtable_name
                marker_index = vtable_name.find("_vtbl")
                base_name = (
                    vtable_name[:marker_index]
                    if marker_index >= 0
                    else vtable_name
                )
                return self._make_unique_structure_name(base_name), False
        if identity.identity_key[0] == "aggregate":
            relative_offset = min(
                placements_by_id[placement_id].relative_offset
                for placement_id in identity.placement_ids
            )
            return (
                self._make_unique_structure_name(
                    f"struct_{relative_offset:x}"
                ),
                True,
            )
        return self._next_auto_structure_name(), True

    def _create_identity_structures(
        self,
        plan: HierarchyPlan,
        placements_by_id: Mapping[int, HierarchyPlacement],
    ) -> dict[IdentityKey, Structure]:
        existing_by_identity = self._structures_by_identity()
        identity_structures: dict[IdentityKey, Structure] = {}
        for identity in plan.identities:
            structure = existing_by_identity.get(identity.identity_key)
            if structure is None:
                structure_name, is_auto_named = self._identity_structure_name(
                    identity, placements_by_id
                )
                structure = Structure(structure_name)
                structure.is_auto_named = is_auto_named
                if identity.identity_key[0] == "vtable":
                    structure.set_provenance(
                        kind="automatic_hierarchy",
                        root_vtable_ea=identity.vtable_ea,
                    )
                else:
                    structure.set_provenance(
                        kind="automatic_aggregate",
                        root_function_ea=identity.identity_key[1],
                        root_argument_index=identity.identity_key[2],
                    )
                self.structures_by_name[structure.name] = structure
            structure.conservative_extent = max(
                structure.conservative_extent, identity.extent
            )
            identity_structures[identity.identity_key] = structure
        return identity_structures

    def _linked_member_name(
        self,
        parent_structure: Structure,
        child_structure: Structure,
        relative_offset: int,
    ) -> str:
        base_name = sanitize_c_identifier(child_structure.name).lower()
        used_names = {member.name for member in parent_structure.members}
        if base_name not in used_names:
            return base_name
        return f"{base_name}_{relative_offset:x}"

    def _remove_flat_span(
        self,
        parent_structure: Structure,
        start: int,
        extent: int,
    ) -> None:
        end = start + extent
        parent_structure.members = [
            member
            for member in parent_structure.members
            if not self._ranges_overlap(
                member.offset,
                member.offset + self._member_size(member),
                start,
                end,
            )
        ]
        parent_structure.refresh_collisions()

    def commit(self) -> HierarchyCommitResult:
        plan = self.plan()
        root_vtable_eas = {
            observation.member.address
            for observation in plan.flat_observations.get(None, ())
            if isinstance(observation.member, VirtualTable)
            and observation.member.offset == 0
        }
        if (
            self.root_structure.provenance.root_vtable_ea is None
            and len(root_vtable_eas) == 1
        ):
            self.root_structure.provenance.root_vtable_ea = next(
                iter(root_vtable_eas)
            )
        placements_by_id = {
            placement.candidate_id: placement for placement in plan.placements
        }
        identity_structures = self._create_identity_structures(
            plan, placements_by_id
        )

        for observation in plan.flat_observations.get(None, ()):
            self.root_structure.add_member(observation.member)

        for identity in plan.identities:
            child_structure = identity_structures[identity.identity_key]
            for placement_id in identity.placement_ids:
                placement = placements_by_id[placement_id]
                for observation in placement.observations:
                    child_structure.add_member(
                        self.clone_rebased_member(
                            observation.member, placement.base_offset
                        )
                    )

        for owner_candidate_id, observations in plan.flat_observations.items():
            if owner_candidate_id is None:
                continue
            owner_placement = placements_by_id[owner_candidate_id]
            if not owner_placement.accepted:
                continue
            owner_structure = identity_structures[
                owner_placement.identity_key
            ]
            for observation in observations:
                owner_structure.add_member(
                    self.clone_rebased_member(
                        observation.member, owner_placement.base_offset
                    )
                )

        for placement in sorted(
            (
                placement
                for placement in plan.placements
                if placement.accepted
            ),
            key=lambda item: (-item.depth, item.candidate_id),
        ):
            child_structure = identity_structures[placement.identity_key]
            if placement.parent_candidate_id is None:
                parent_structure = self.root_structure
            else:
                parent_placement = placements_by_id[
                    placement.parent_candidate_id
                ]
                parent_structure = identity_structures[
                    parent_placement.identity_key
                ]

            existing_relationship = next(
                (
                    relationship
                    for relationship in parent_structure.child_relationships
                    if relationship.parent_member_offset
                    == placement.relative_offset
                    and relationship.child_structure_name == child_structure.name
                ),
                None,
            )
            existing_member = parent_structure.get_member_by_offset(
                placement.relative_offset
            )
            if existing_relationship is None:
                self._remove_flat_span(
                    parent_structure,
                    placement.relative_offset,
                    placement.extent,
                )
                scanned_variables = self._rebased_scanned_variables(
                    placement.parent_scanned_variables
                )
                linked_member = LinkedStructureMember(
                    placement.relative_offset,
                    child_structure.name,
                    placement.extent,
                    self._linked_member_name(
                        parent_structure,
                        child_structure,
                        placement.relative_offset,
                    ),
                    relation_kind="embedded",
                    scanned_variables=scanned_variables,
                )
                parent_structure.add_member(linked_member)
                existing_member = linked_member
                existing_relationship = parent_structure.add_child_relationship(
                    child_structure_name=child_structure.name,
                    parent_member_offset=placement.relative_offset,
                    parent_member_name=linked_member.name,
                    relation_kind="embedded",
                )
            elif isinstance(existing_member, LinkedStructureMember):
                existing_member.conservative_extent = max(
                    existing_member.conservative_extent,
                    placement.extent,
                )

            child_structure.add_parent_relationship(existing_relationship)
            if existing_member is not None:
                existing_member.linked_child_structure_name = child_structure.name
                existing_member.child_relation_kind = "embedded"

        self.root_structure.conservative_extent = max(
            self.root_structure.conservative_extent,
            self._structure_extent(self.root_structure)
            - self.root_structure.main_offset,
        )

        committed_structures = [self.root_structure]
        committed_structures.extend(
            identity_structures[identity_key]
            for identity_key in sorted(identity_structures)
        )
        unique_structures = tuple(
            {
                structure.name: structure
                for structure in committed_structures
            }.values()
        )
        return HierarchyCommitResult(plan=plan, structures=unique_structures)

from __future__ import annotations

import bisect
import itertools
import re
from dataclasses import dataclass, replace
from typing import Iterator, Mapping, Sequence

import ida_kernwin
import ida_typeinf

from forge.util.qt import QtWidgets

import forge.api.types as forge_types
from forge.api.hexrays import create_udt_padding_member
from forge.api.members import AbstractMember, VirtualTable
from forge.util.logging import log_debug, log_error, log_warning


@dataclass(frozen=True)
class StructureStats:
    total_members: int
    enabled_members: int
    collision_count: int
    scanned_variable_count: int
    origin_offset: int


@dataclass
class StructureProvenance:
    kind: str = "manual"
    root_object_name: str | None = None
    root_object_ea: int | None = None
    root_function_ea: int | None = None
    source_member_offset: int | None = None
    has_multiple_roots: bool = False


@dataclass
class StructureRelationship:
    parent_structure_name: str
    child_structure_name: str
    parent_member_offset: int
    parent_member_name: str
    relation_kind: str = "pointer"


class Structure:
    def __init__(self, name: str):
        self.name = name
        self.main_offset = 0
        self.members: list[AbstractMember] = []
        self.collisions: list[bool] = []
        self.is_auto_named: bool = False
        self.created_type_name: str | None = None
        self.provenance: StructureProvenance = StructureProvenance()
        self.parent_relationships: list[StructureRelationship] = []
        self.child_relationships: list[StructureRelationship] = []

    def add_member(self, member: AbstractMember) -> None:
        """Insert a member while keeping the structure ordered by offset/type."""
        if not hasattr(member, "linked_child_structure_name"):
            member.linked_child_structure_name = None
        if not hasattr(member, "child_relation_kind"):
            member.child_relation_kind = None
        if member in self.members:
            return
        bisect.insort(self.members, member)
        self.refresh_collisions()

    def set_provenance(
        self,
        *,
        kind: str,
        root_object_name: str | None = None,
        root_object_ea: int | None = None,
        root_function_ea: int | None = None,
        source_member_offset: int | None = None,
        has_multiple_roots: bool = False,
    ) -> None:
        self.provenance = StructureProvenance(
            kind=kind,
            root_object_name=root_object_name,
            root_object_ea=root_object_ea,
            root_function_ea=root_function_ea,
            source_member_offset=source_member_offset,
            has_multiple_roots=has_multiple_roots,
        )

    def clone_provenance(self) -> StructureProvenance:
        return replace(self.provenance)

    def get_member_by_offset(self, offset: int) -> AbstractMember | None:
        return next((member for member in self.members if member.offset == offset), None)

    def add_child_relationship(
        self,
        *,
        child_structure_name: str,
        parent_member_offset: int,
        parent_member_name: str,
        relation_kind: str = "pointer",
    ) -> StructureRelationship:
        relationship = StructureRelationship(
            parent_structure_name=self.name,
            child_structure_name=child_structure_name,
            parent_member_offset=parent_member_offset,
            parent_member_name=parent_member_name,
            relation_kind=relation_kind,
        )
        existing = next(
            (
                rel
                for rel in self.child_relationships
                if rel.child_structure_name == child_structure_name
                and rel.parent_member_offset == parent_member_offset
            ),
            None,
        )
        if existing is None:
            self.child_relationships.append(relationship)
            return relationship
        return existing

    def add_parent_relationship(self, relationship: StructureRelationship) -> None:
        if any(
            rel.parent_structure_name == relationship.parent_structure_name
            and rel.parent_member_offset == relationship.parent_member_offset
            and rel.child_structure_name == relationship.child_structure_name
            for rel in self.parent_relationships
        ):
            return
        self.parent_relationships.append(relationship)

    def remove_relationships_with(self, structure_name: str) -> None:
        self.child_relationships = [
            rel for rel in self.child_relationships if rel.child_structure_name != structure_name
        ]
        self.parent_relationships = [
            rel for rel in self.parent_relationships if rel.parent_structure_name != structure_name
        ]
        for member in self.members:
            if getattr(member, "linked_child_structure_name", None) == structure_name:
                member.linked_child_structure_name = None
                member.child_relation_kind = None

    def rename_relationship_references(self, old_name: str, new_name: str) -> None:
        for relationship in self.child_relationships:
            if relationship.parent_structure_name == old_name:
                relationship.parent_structure_name = new_name
            if relationship.child_structure_name == old_name:
                relationship.child_structure_name = new_name
        for relationship in self.parent_relationships:
            if relationship.parent_structure_name == old_name:
                relationship.parent_structure_name = new_name
            if relationship.child_structure_name == old_name:
                relationship.child_structure_name = new_name
        for member in self.members:
            if getattr(member, "linked_child_structure_name", None) == old_name:
                member.linked_child_structure_name = new_name


    def rename_created_type(self, old_name: str, new_name: str) -> bool:
        if self.created_type_name != old_name or old_name == new_name:
            return True

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_named_type(ida_typeinf.get_idati(), old_name):
            log_warning(
                f"Created type {old_name} is missing; leaving the type name unchanged.",
                True,
            )
            return True

        rename_result = tinfo.rename_type(new_name)
        if rename_result != 0:
            log_warning(
                f"Failed to rename created type {old_name} to {new_name}: {rename_result}",
                True,
            )
            return False

        self.created_type_name = new_name
        return True

    def get_linked_child_names(self) -> list[str]:
        return sorted({rel.child_structure_name for rel in self.child_relationships})

    def has_linked_children(self) -> bool:
        return bool(self.child_relationships)

    def get_provenance_summary(self) -> str:
        parts = [self.provenance.kind.replace("_", " ")]
        if self.provenance.root_object_name:
            parts.append(self.provenance.root_object_name)
        if self.provenance.source_member_offset is not None:
            parts.append(f"member @ 0x{self.provenance.source_member_offset:X}")
        if self.provenance.has_multiple_roots:
            parts.append("multiple roots")
        return " | ".join(parts)

    def get_unresolved_child_names(
        self,
        structures_by_name: Mapping[str, "Structure"],
    ) -> list[str]:
        return sorted(
            {
                relationship.child_structure_name
                for relationship in self.child_relationships
                if (
                    child := structures_by_name.get(
                        relationship.child_structure_name
                    )
                )
                is None
                or child.created_type_name is None
            }
        )

    def _iter_child_relationships(self) -> Iterator[StructureRelationship]:
        yield from sorted(
            self.child_relationships,
            key=lambda relationship: (
                relationship.parent_member_offset,
                relationship.parent_member_name,
                relationship.child_structure_name,
            ),
        )

    def iter_child_structures(
        self,
        structures_by_name: Mapping[str, "Structure"],
    ) -> Iterator["Structure"]:
        seen_child_names: set[str] = set()
        for relationship in self._iter_child_relationships():
            child = structures_by_name.get(relationship.child_structure_name)
            if child is None or child.name in seen_child_names:
                continue
            seen_child_names.add(child.name)
            yield child

    def can_create_type(
        self,
        structures_by_name: Mapping[str, "Structure"],
    ) -> bool:
        return not self.get_unresolved_child_names(structures_by_name)

    def create_type_if_ready(
        self,
        structures_by_name: Mapping[str, "Structure"],
        *,
        start: int | None = None,
        end: int | None = None,
    ) -> ida_typeinf.tinfo_t | None:
        unresolved_child_names = self.get_unresolved_child_names(structures_by_name)
        if unresolved_child_names:
            child_names = ", ".join(unresolved_child_names)
            log_warning(
                f"Cannot create type for {self.name}: unresolved child structures: {child_names}",
                True,
            )
            return None
        return self.pack_structure(start=start, end=end)

    def create_subtree_types_postorder(
        self,
        structures_by_name: Mapping[str, "Structure"],
        *,
        visited: set[str] | None = None,
    ) -> bool:
        completed = visited if visited is not None else set()
        stack: list[str] = []

        def _walk(structure: "Structure") -> bool:
            if structure.name in completed:
                return True
            if structure.name in stack:
                cycle_start = stack.index(structure.name)
                cycle_path = " -> ".join(stack[cycle_start:] + [structure.name])
                log_warning(
                    f"Cycle detected while creating type subtree: {cycle_path}",
                    True,
                )
                return False

            stack.append(structure.name)
            try:
                for child_structure in structure.iter_child_structures(structures_by_name):
                    if not _walk(child_structure):
                        log_warning(
                            f"Cannot create subtree for {structure.name}: child subtree {child_structure.name} could not be finalized",
                            True,
                        )
                        return False

                if structure.create_type_if_ready(structures_by_name) is None:
                    return False

                completed.add(structure.name)
                return True
            finally:
                stack.pop()

        return _walk(self)

    def has_collision(self, index: int) -> bool:
        return 0 <= index < len(self.collisions) and self.collisions[index]

    def refresh_collisions(self) -> None:
        self.collisions = [False] * len(self.members)
        current_index = next(
            (index for index, member in enumerate(self.members) if member.enabled),
            None,
        )
        if current_index is None:
            return

        for next_index in range(current_index + 1, len(self.members)):
            next_member = self.members[next_index]
            if not next_member.enabled:
                continue

            current_member = self.members[current_index]
            if current_member.offset + current_member.size > next_member.offset:
                self.collisions[current_index] = True
                self.collisions[next_index] = True

                current_end = current_member.offset + current_member.size
                next_end = next_member.offset + next_member.size
                if current_end < next_end:
                    current_index = next_index
            else:
                current_index = next_index

    def get_next_enabled(self, index: int) -> int:
        for candidate in range(index + 1, len(self.members)):
            if self.members[candidate].enabled:
                return candidate
        return -1

    def calculate_array_size(self, index: int) -> int:
        next_enabled = self.get_next_enabled(index)
        if next_enabled == -1:
            return 0

        member = self.members[index]
        if member.size <= 0:
            return 0

        span = self.members[next_enabled].offset - member.offset
        if span <= member.size:
            return 0
        return span // member.size

    def clear_members(self) -> None:
        self.members.clear()
        self.collisions.clear()
        self.main_offset = 0

    def set_main_offset(self, offset: int) -> None:
        self.main_offset = offset

    def get_main_offset_index(self) -> int:
        for index, member in enumerate(self.members):
            if member.offset >= self.main_offset:
                return index
        return 0

    def get_name(self) -> str:
        virtual_tables = [
            member
            for member in self.members
            if isinstance(member, VirtualTable) and member.has_nice_vtable_name
        ]

        if len(virtual_tables) == 1:
            return virtual_tables[0].vtable_name.replace("_vtbl", "")

        if len(virtual_tables) > 1:
            log_warning(
                "Multiple candidates for structure name: "
                f"{[vt.vtable_name for vt in virtual_tables]}. Setting to {self.name}."
            )
        return self.name

    def get_unique_scanned_variables(self, origin: int = 0) -> list:
        scan_objects = itertools.chain.from_iterable(
            member.scanned_variables
            for member in self.members
            if member.origin == origin
        )
        unique_scan_objects = {}
        for scan_object in scan_objects:
            key = (
                getattr(scan_object, "func_ea", None),
                getattr(scan_object, "ea", None),
                getattr(scan_object, "id", None),
                scan_object.name,
            )
            unique_scan_objects[key] = scan_object
        return list(unique_scan_objects.values())

    def get_stats(self) -> StructureStats:
        self.refresh_collisions()
        return StructureStats(
            total_members=len(self.members),
            enabled_members=sum(1 for member in self.members if member.enabled),
            collision_count=sum(1 for has_collision in self.collisions if has_collision),
            scanned_variable_count=len(
                self.get_unique_scanned_variables(self.main_offset)
            ),
            origin_offset=self.main_offset,
        )

    def disable_members(self, indices: int | Sequence[int]) -> None:
        if isinstance(indices, int):
            indices = [indices]
        for index in indices:
            if 0 <= index < len(self.members):
                self.members[index].set_enabled(False)
        self.refresh_collisions()

    def enable_members(self, indices: int | Sequence[int]) -> None:
        if isinstance(indices, int):
            indices = [indices]
        for index in indices:
            if 0 <= index < len(self.members):
                self.members[index].set_enabled(True)
        self.refresh_collisions()

    def remove_members(self, indices: int | Sequence[int]) -> None:
        if isinstance(indices, int):
            indices = [indices]
        for index in sorted(set(indices), reverse=True):
            if 0 <= index < len(self.members):
                removed_member = self.members[index]
                del self.members[index]
                if removed_member.offset == self.main_offset:
                    self.main_offset = self.members[0].offset if self.members else 0
        self.refresh_collisions()

    def auto_resolve(self) -> None:
        current_member = None
        for member in self.members:
            if not member.enabled:
                continue

            if current_member is None:
                current_member = member
                continue

            if current_member.has_collision(member):
                if member.score <= current_member.score:
                    member.set_enabled(False)
                    continue
                current_member.set_enabled(False)

            current_member = member

        self.refresh_collisions()

    def iter_packable_members(
        self, start: int | None = None
    ) -> Iterator[tuple[int, AbstractMember]]:
        start_index = self.get_main_offset_index() if start is None else start
        origin = (
            self.members[start_index].offset if start_index < len(self.members) else 0
        )
        for index in range(start_index, len(self.members)):
            member = self.members[index]
            if member.enabled and member.offset >= origin:
                yield index, member

    def pack_structure(self, start: int | None = None, end: int | None = None):
        if not self.members:
            log_warning("Structure is empty", True)
            return None

        self.refresh_collisions()
        struct_name = self.get_name()
        if not struct_name:
            struct_name = ida_kernwin.ask_str("", ida_kernwin.HIST_TYPE, "Struct name:")
            if not struct_name:
                return None

        start_index = self.get_main_offset_index() if start is None else start
        origin = (
            self.members[start_index].offset if start_index < len(self.members) else 0
        )
        packable_members = list(self.iter_packable_members(start_index))
        if end is not None:
            packable_members = [
                (index, member)
                for index, member in packable_members
                if index <= end
            ]
        if not packable_members:
            log_warning("No enabled members are available to create a type.", True)
            return None

        log_debug(f"Packing structure {struct_name}")

        final_tinfo = ida_typeinf.tinfo_t()
        udt_data = ida_typeinf.udt_type_data_t()
        current_offset = origin

        for index, member in packable_members:
            gap_size = member.offset - current_offset
            if gap_size > 0:
                udt_data.push_back(
                    create_udt_padding_member(current_offset - origin, gap_size)
                )

            if member.is_array:
                array_size = self.calculate_array_size(index)
                if array_size > 1:
                    udt_data.push_back(member.get_udt_member(array_size, offset=origin))
                    current_offset = member.offset + member.size * array_size
                    continue

            udt_data.push_back(member.get_udt_member(offset=origin))
            current_offset = member.offset + member.size

        final_tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT)
        cdecl = ida_typeinf.print_tinfo(
            None,
            4,
            5,
            ida_typeinf.PRTYPE_MULTI
            | ida_typeinf.PRTYPE_TYPE
            | ida_typeinf.PRTYPE_SEMI,
            final_tinfo,
            struct_name,
            None,
        )
        if not cdecl:
            raise RuntimeError("Failed to generate C declaration")

        edited_cdecl = ida_kernwin.ask_text(
            0x10000,
            f"#pragma pack(push, 1)\n{cdecl}",
            "The following new type will be created",
        )
        if not edited_cdecl:
            log_warning("No type definition was provided", True)
            return None
        return self.set_cdecl(edited_cdecl, origin)

    @staticmethod
    def _extract_type_name(cdecl: str) -> str | None:
        match = re.search(r"\b(struct|union|enum)\s+([A-Za-z_]\w*)", cdecl)
        if match:
            return match.group(2)
        return None

    @staticmethod
    def _load_named_type(name: str) -> ida_typeinf.tinfo_t | None:
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_named_type(ida_typeinf.get_idati(), name):
            return tinfo
        return None

    def _apply_scanned_variable_types(
        self, structure_name: str, origin: int
    ) -> ida_typeinf.tinfo_t | None:
        tinfo = self._load_named_type(structure_name)
        if tinfo is None:
            log_error(f"Created type {structure_name}, but failed to load it back.")
            return None

        ptr_tinfo = ida_typeinf.tinfo_t()
        ptr_tinfo.create_ptr(tinfo)
        for scan_object in self.get_unique_scanned_variables(origin):
            scan_object.apply_type(ptr_tinfo)
        return tinfo

    def set_cdecl(self, cdecl: str, origin: int = 0):
        structure_name = self._extract_type_name(cdecl)
        if not structure_name:
            log_warning("Failed to determine type name from the declaration.", True)
            return None

        if forge_types.create_type(structure_name, cdecl):
            self.created_type_name = structure_name
            log_debug(f"Created type {structure_name}")
            return self._apply_scanned_variable_types(structure_name, origin)

        reply = QtWidgets.QMessageBox.question(
            None,
            "Overwrite existing type?",
            f"Type {structure_name} already exists. Overwrite?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if reply != QtWidgets.QMessageBox.Yes:
            log_error(
                f"Structure {structure_name} probably already exists. Please check manually.",
                True,
            )
            return None

        ida_typeinf.del_named_type(ida_typeinf.get_idati(), structure_name)
        if not forge_types.create_type(structure_name, cdecl):
            log_error(f"Failed to recreate type {structure_name}", True)
            return None

        self.created_type_name = structure_name
        log_debug(f"Created type {structure_name}")
        return self._apply_scanned_variable_types(structure_name, origin)

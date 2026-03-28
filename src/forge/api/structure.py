from __future__ import annotations

import bisect
import itertools
import re
from dataclasses import dataclass
from typing import Iterator, Sequence

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


class Structure:
    def __init__(self, name: str):
        self.name = name
        self.main_offset = 0
        self.members: list[AbstractMember] = []
        self.collisions: list[bool] = []

    def add_member(self, member: AbstractMember) -> None:
        """Insert a member while keeping the structure ordered by offset/type."""
        if member in self.members:
            return
        bisect.insort(self.members, member)
        self.refresh_collisions()

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

        log_debug(f"Created type {structure_name}")
        return self._apply_scanned_variable_types(structure_name, origin)

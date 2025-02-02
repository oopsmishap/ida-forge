import bisect
import itertools

import ida_typeinf
import idaapi
import idc
from PyQt5 import QtWidgets

from forge.api.hexrays import create_udt_padding_member
from forge.api.members import VirtualTable, AbstractMember
from forge.util.logging import *

import forge.api.types as forge_types


class Structure:
    def __init__(self, name: str):
        self.name = name
        self.main_offset = 0
        self.members: AbstractMember = []
        self.collisions = []

    @staticmethod
    def create():
        pass

    def add_member(self, member: AbstractMember) -> None:
        """
        Add a member to the structure
        :param member: Member to add
        :return: None
        """
        if member in self.members:
            return
        bisect.insort(self.members, member)

    def has_collision(self, index: int) -> bool:
        """
        Check if member at `index` has a collision with another member

        :param index: Index of member to check
        :return: True if member at `index` has a collision, False otherwise
        """
        return self.collisions[index]

    def refresh_collisions(self) -> None:
        """
        Check for collisions between member items and update `self.collisions` list.

        :return: None
        """
        # Initialize self.collisions list with False values
        self.collisions = [False] * len(self.members)

        # Find the first enabled item to start comparison
        current_index = next(
            (i for i, item in enumerate(self.members) if item.enabled), None
        )

        # If at least two enabled members are present, compare them for collisions
        if current_index is not None:
            for next_index in range(current_index + 1, len(self.members)):
                if self.members[next_index].enabled:
                    # Check for overlap between current_index and next_index
                    if (
                        self.members[current_index].offset
                        + self.members[current_index].size
                        > self.members[next_index].offset
                    ):
                        self.collisions[current_index] = True
                        self.collisions[next_index] = True

                        # If current item overlaps more than next item, update current_index to point to next_index
                        current_item_end = (
                            self.members[current_index].offset
                            + self.members[current_index].size
                        )
                        next_item_end = (
                            self.members[next_index].offset
                            + self.members[next_index].size
                        )

                        if current_item_end < next_item_end:
                            current_index = next_index
                    else:
                        current_index = next_index

    def get_next_enabled(self, index: int) -> int:
        """
        Get the index of the next enabled item after `index`

        :param index: Index of item to start search from
        :return: Index of next enabled item, -1 if no enabled item is found
        """
        for i in range(index + 1, len(self.members)):
            if self.members[i].enabled:
                return i
        return -1

    def calculate_array_size(self, idx) -> int:
        """
        Calculate the size of the array at `idx`

        :param idx: Index of array item
        :return: Size of array at `idx`
        """
        next_enabled = self.get_next_enabled(idx)
        if next_enabled == -1:
            return 0
        return (
            self.members[next_enabled].offset
            - self.members[idx].offset // self.members[idx].size
        )

    def get_name(self):
        """
        Returns the name of the structure. If there is a single VirtualTable in the `members` attribute with a nice
        vtable name, then the vtable name with the "_vtbl" suffix removed is returned. Otherwise, the original
        name of the structure is returned.

        :return: A string containing the name of the structure.
        :rtype: str
        """
        virtual_tables = [
            field
            for field in self.members
            if isinstance(field, VirtualTable) and field.has_nice_vtable_name
        ]

        if len(virtual_tables) == 1:
            return virtual_tables[0].vtable_name.replace("_vtbl", "")

        elif len(virtual_tables) > 1:
            log_warning(
                f"Multiple candidates for structure name: "
                f"{[vt.vtable_name for vt in virtual_tables]}. Setting to {self.name}."
            )

        return self.name

    # def get_unique_scanned_variables(self, origin=0):
    #     scan_objects = itertools.chain.from_iterable(
    #         [list(member.scanned_variables) for member in self.members if member.origin == origin])
    #     return list(dict(((item.function_name, item.name), item) for item in scan_objects).values())

    def get_unique_scanned_variables(self, origin=0):
        """Return a list of unique scanned variables, optionally filtered by origin."""
        scan_objects = itertools.chain.from_iterable(
            [
                list(member.scanned_variables)
                for member in self.members
                if member.origin == origin
            ]
        )
        return list(
            dict(((obj.function_name, obj.name), obj) for obj in scan_objects).values()
        )

    def disable_members(self, indices):
        if isinstance(indices, int):
            indices = [indices]
        for index in indices:
            self.members[index].enabled = False
        self.refresh_collisions()

    def enable_members(self, indices):
        if isinstance(indices, int):
            indices = [indices]
        for index in indices:
            self.members[index].enabled = True
        self.refresh_collisions()

    def remove_members(self, indices):
        if isinstance(indices, int):
            indices = [indices]
        for index in sorted(indices, reverse=True):
            del self.members[index]
        self.refresh_collisions()

    def auto_resolve(self):
        """
        Automatically resolve member collisions by disabling lower-scoring members.

        This method will iterate through each enabled member of the struct, comparing it to the current highest-scoring
        member.
        If a member has a collision with the current member, the member with the lower score will be disabled.
        If a member has a higher score than the current highest-scoring member, the current highest-scoring member will
        be disabled.

        :return: None
        """
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
                elif member.score > current_member.score:
                    current_member.set_enabled(False)

            current_member = member

        self.refresh_collisions()

    def pack_structure(self, start=0, end=None):
        """
        Pack the structure by removing all disabled members and reordering the remaining members
        :return: None
        """
        self.refresh_collisions()

        struct_name = self.get_name()
        if not struct_name:
            struct_name = ida_kernwin.ask_str("", ida_kernwin.HIST_TYPE, "Struct name:")
            if not struct_name:
                return

        log_debug(f"Packing structure {struct_name}")

        final_tinfo = ida_typeinf.tinfo_t()
        udt_data = ida_typeinf.udt_type_data_t()
        origin = self.members[start].offset if start else 0
        offset = origin

        for idx, member in enumerate(self.members):
            if member.enabled is False:
                continue
            gap_size = member.offset - offset
            if gap_size:
                udt_data.push_back(create_udt_padding_member(offset - origin, gap_size))
            if member.is_array:
                array_size = self.calculate_array_size(
                    bisect.bisect_left(self.members, member)
                )
                if array_size:
                    udt_data.push_back(member.get_udt_member(array_size, offset=origin))
                    offset = member.offset + member.size * array_size
                    continue
            udt_data.push_back(member.get_udt_member(offset=origin))
            offset = member.offset + member.size

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
            raise Exception("Failed to generate C declaration")

        cdecl = ida_kernwin.ask_text(
            0x10000,
            "#pragma pack(push, 1)\n" + cdecl,
            "The following new type will be created",
        )
        if not cdecl:
            log_warning("No type definition was provided", True)

        return self.set_cdecl(cdecl, origin)

    def set_cdecl(self, cdecl, origin=0):
        """
        Sets the cdecl for the given structure and applies it to the scanned variables.
        
        :param cdecl: The cdecl to set.
        :param origin: The origin for the scanned variables.
        :return: The created tinfo if successful, None otherwise.
        """
        result = idaapi.idc_parse_decl(idaapi.get_idati(), cdecl, idaapi.PT_TYP)
        if result is None:
            log_warning("Failed to parse type definition", True)
            return
        
        structure_name = result[0]

        if forge_types.create_type(structure_name, cdecl):
            log_debug(f"Created type {structure_name}")
            tinfo = idaapi.create_typedef(structure_name)
            ptr_tinfo = idaapi.tinfo_t()
            ptr_tinfo.create_ptr(tinfo)
            for var in self.get_unique_scanned_variables(origin):
                var.apply_type(ptr_tinfo)
            return tinfo
        else:
            reply = QtWidgets.QMessageBox.question(
                None,
                "Overwrite existing type?",
                f"Type {structure_name} already exists. Overwrite?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            )
            if reply == QtWidgets.QMessageBox.Yes:
                ida_typeinf.del_named_type(idaapi.get_idati(), structure_name)
                if forge_types.create_type(structure_name, cdecl):
                    log_debug(f"Created type {structure_name}")
                    tinfo = idaapi.create_typedef(structure_name)
                    ptr_tinfo = idaapi.tinfo_t()
                    ptr_tinfo.create_ptr(tinfo)
                    for var in self.get_unique_scanned_variables(origin):
                        var.apply_type(ptr_tinfo)
                    return tinfo
            log_error(
                f"Structure {structure_name} probably already exists. Please check manually.",
                True,
            )

import re
from collections import defaultdict

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import idaapi
import ida_name
import ida_segment
import ida_typeinf
import ida_xref
import idaapi
import idc

from forge.api.hexrays import get_ptr, is_code, is_imported, decompile
from forge.api.scan_object import VariableObject
from forge.api.scanner import NewDeepScanVisitor
from forge.api.types import types
from forge.api.visitor import FunctionTouchVisitor
from forge.util.cxx_to_c_name import demangled_name_to_c_str
from forge.util.logging import *

import forge.api.types as forge_types

class AbstractMember:
    def __init__(self, offset: int, scanned_variable, origin: int, tinfo=None):
        self.offset: int = offset
        self.origin: int = origin
        self.enabled: bool = True
        self.comment: str = ""
        self.is_array: bool = False
        self._score: int = 0
        self.scanned_variables = {scanned_variable} if scanned_variable else set()
        self.tinfo: ida_typeinf.tinfo_t = tinfo

    def type_equals_to(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        return self.tinfo.equals_to(tinfo)

    def switch_array_flag(self):
        self.is_array ^= True

    def activate(self):
        pass

    def set_enabled(self, enabled):
        self.enabled = enabled
        self.is_array = False

    def has_collision(self, other):
        if self.offset <= other.offset:
            return self.offset + self.size > other.offset
        return (other.offset + other.size) >= self.offset

    def is_simple_type(self):
        return re.match(r"((i|u|f)(8|16|32|64|128))", self.tinfo.dstr())

    @property
    def score(self):
        """
        Returns the score for the current Type object based on its size and alignment.

        :return: The score of the type.
        """
        # TODO: reimplement the score calculation into something better
        if self._score != 0:
            return self._score
        else:
            # Calculate the score based on the size and alignment of the type
            score = 0
            if self.alignment == 0:
                if self.size in (8, 4, 2, 1):
                    score += 8 // self.size
            elif self.alignment == 4:
                if self.size in (4, 2, 1):
                    score += 8 // self.size
            elif self.alignment in (2, 6):
                if self.size in (2, 1):
                    score += 8 // self.size
            elif self.alignment in (1, 3, 5, 7):
                if self.size == 1:
                    score += 8 // self.size

            # Add the number of scanned variables to the score
            score += len(self.scanned_variables)

            # Ajdust the score based on the type
            if self.is_simple_type():
                score -= 1
            elif self.tinfo.is_funcptr():
                score += 1000 + len(self.tinfo.dstr())
            elif "struct " in self.tinfo.dstr():
                score -= 10
            else:
                score += 1

            # Ensure the score is not negative
            score = max(0, score)

            self._score = score
            return self._score

    @property
    def alignment(self):
        return self.offset % types.width

    @property
    def type_name(self):
        return self.tinfo.dstr()

    @property
    def size(self):
        size = self.tinfo.get_size()
        return size if size != ida_typeinf.BADSIZE else 1

    @property
    def type_alias(self):
        if self.tinfo is None:
            return "field"

        aliases = []

        # future proofing I guess??
        if self.tinfo.is_floating():
            aliases = ["f8", "f16", "f32", "f64", "f128", "f256", "f512", "f1024"]
        elif self.tinfo.is_integral():
            if self.tinfo.is_signed():
                aliases = ["i8", "i16", "i32", "i64", "i128"]
            else:
                aliases = ["u8", "u16", "u32", "u64", "u128"]
        else:
            return "field"

        n = self._log_base_2_lookup(self.size)
        try:
            return aliases[n]
        except IndexError:
            return "field"

    def _log_base_2_lookup(self, v):
        """
        Find the log base 2 of an N-bit integer in O(lg(N)) operations with multiply and lookup
        http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
        :param v: No of bits (t width)
        :return: log base 2 of n
        """
        # fmt: off
        multiply_de_bruijn_bit_position_2 = [ 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
                                             31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9]
        # fmt: on

        n = ((v * 0x077CB531) & 0xFFFFFFFF) >> 27
        return multiply_de_bruijn_bit_position_2[n]

    def __repr__(self):
        return f"{self.type_name}:{hex(self.offset)}[{hex(self.size)}]"

    def __eq__(self, other):
        if self.offset == other.offset and self.type_name == other.type_name:
            self.scanned_variables |= other.scanned_variables
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.offset < other.offset or (
            self.offset == other.offset and self.type_name < other.type_name
        )

    def __le__(self, other):
        return self.offset <= other.offset

    def __gt__(self, other):
        return self.offset > other.offset or (
            self.offset == other.offset and self.type_name > other.type_name
        )

    def __ge__(self, other):
        return self.offset >= other.offset


class Member(AbstractMember):
    def __init__(
        self, offset: int, tinfo: ida_typeinf.tinfo_t, scanned_variable, origin: int = 0
    ):
        super().__init__(offset, scanned_variable, origin, tinfo)
        self.name = f"{self.type_alias}_{self.offset:x}"

    def get_udt_member(self, array_size: int = 0, offset: int = 0):
        udt_member = ida_typeinf.udt_member_t()

        udt_member.name = (
            f"{self.type_alias}_{self.offset - offset:x}"
            if self._is_name_aliased()
            else self.name
        )
        udt_member.type = self.tinfo
        if array_size:
            udt_member.type.create_array(array_size)
        udt_member.offset = self.offset - offset
        udt_member.cmt = self.comment
        udt_member.size = self.size
        return udt_member

    def activate(self):
        new_type_decl = ida_kernwin.ask_str(self.type_name, 0x100, "Enter type:")
        if new_type_decl is None:
            return

        result = ida_typeinf.parse_decl(new_type_decl, 0)
        if result is None:
            return

        _, tp, fld = result
        tinfo = ida_typeinf.tinfo_t()
        tinfo.deserialize(ida_typeinf.cvar.idati, tp, fld, None)
        self.tinfo = tinfo
        self.is_array = False

    def _is_name_aliased(self):
        return re.match(r"((i|u|f)(8|16|32|64|128|256|512|1024))|(field)_", self.name)


class VoidMember(Member):
    def __init__(
        self, offset: int, scanned_variable, origin: int = 0, char: bool = False
    ):
        tinfo = types["i8"].type if char else types["u8"].type
        # tinfo = const.CHAR_TINFO if char else const.BYTE_TINFO
        super().__init__(offset, tinfo, scanned_variable, origin)
        self.is_array = True

    def type_equals_to(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        return True

    def switch_array_flag(self):
        pass

    def set_enabled(self, enabled) -> None:
        self.enabled = enabled


class VirtualFunction:
    def __init__(self, address: int, offset: int, table_name: str = ""):
        self.address = address
        self.offset = offset
        self.vtable_name = table_name
        self.visited = False

    def get_ptr_tinfo(self):
        ptr_tinfo = ida_typeinf.tinfo_t()
        ptr_tinfo.create_ptr(self.tinfo)
        return ptr_tinfo

    def get_udt_member(self):
        udt_member = ida_typeinf.udt_member_t()
        udt_member.type = self.get_ptr_tinfo()
        udt_member.offset = self.offset
        udt_member.name = self.name
        udt_member.size = types.width
        return udt_member

    def show_location(self):
        ida_hexrays.open_pseudocode(self.address, ida_hexrays.OPF_NEW_WINDOW)

    @property
    def tinfo(self) -> ida_typeinf.tinfo_t:
        """
        Returns the t of the virtual function
        :return: Type of the virtual function
        """
        try:
            decompiled_function = decompile(self.address)
            if decompiled_function and decompiled_function.type:
                return decompiled_function.type
            return types["func_t"].type
        except ida_hexrays.DecompilationFailure:
            log_error(f"Failed to decompile function at {hex(self.address)}")
            return types["func_t"].type

    @property
    def name(self) -> str:
        """
        Gets the name of the function. If the function name is invalid or not available, generates a default virtual
        function name.

        :return: Function name or default virtual function name
        """
        name = ida_funcs.get_func_name(self.address)
        if ida_name.is_valid_typename(name):
            if name.startswith("sub_"):
                return self._def_generate_vfunc_name()
            return name
        # TODO: add support for C++ name mangling with itanium mangler or create MSVC mangler
        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if not demangled_name:
            raise ValueError(f"Could not demangle name {name} at {hex(self.address)}")
        return demangled_name_to_c_str(demangled_name)

    def _def_generate_vfunc_name(self) -> str:
        """
        Generates a default name for a virtual function
        Example: "vtable_name::function_1"
        :return: Default name for a virtual function
        """
        # TODO: Add support for C and C++ naming conventions
        idx = int(self.offset / types.width)
        return f"{self.vtable_name}_function_{idx}"

    def __repr__(self):
        return f"{self.name} @ {hex(self.address)}"


class ImportedVirtualFunction(VirtualFunction):
    def __init__(self, address, offset):
        super().__init__(address, offset)

    @property
    def tinfo(self):
        print("[INFO] Ignoring import function at 0x{:08X}".format(self.address))
        tinfo = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tinfo, self.address):
            return tinfo
        return types["func_t"].type

    def show_location(self):
        ida_kernwin.jumpto(self.address)


class VirtualTable(AbstractMember):
    def __init__(self, offset, address, scanned_variable=None, origin=None):
        super().__init__(offset, address, scanned_variable, origin)
        self.address = address
        self.virtual_functions = []
        self.name = "_vftable" + f"_{hex(self.offset)}" if self.address else ""
        self.vtable_name, self.has_nice_vtable_name = self._parse_vtable_name()
        self.populate_virtual_functions()

    def populate_virtual_functions(self):
        address = self.address
        while True:
            ptr = get_ptr(address)
            if is_code(ptr):
                virtual_function = VirtualFunction(
                    ptr, address - self.address, self.vtable_name
                )
                ida_name.set_name(ptr, virtual_function.name)
                self.virtual_functions.append(virtual_function)
            elif is_imported(ptr):
                virtual_function = ImportedVirtualFunction(ptr, address - self.address)
                self.virtual_functions.append(virtual_function)
            else:
                break
            address += types.width

            # If the address has a data reference, we have reached the end of the vtable
            if ida_xref.get_first_dref_to(address) != idaapi.BADADDR:
                break

        log_debug(f"Found {len(self.virtual_functions)} virtual functions")
        log_debug(f"Vtable name: {self.vtable_name}")
        log_debug(f"Functions: {self.virtual_functions}")

    def create_tinfo(self):
        # print "(Virtual table) at address: 0x{:08X} name: {}".format(self.address, self.name)
        udt_data = ida_typeinf.udt_type_data_t()
        for function in self.virtual_functions:
            udt_data.push_back(function.get_udt_member())

        for duplicates in self.search_duplicate_fields(udt_data):
            first_entry_idx = duplicates.pop(0)
            log_warning(
                "Found duplicate virtual functions", udt_data[first_entry_idx].name
            )
            for num, dup in enumerate(duplicates):
                udt_data[dup].name = "duplicate_{}_{}".format(first_entry_idx, num + 1)
                tinfo = ida_typeinf.tinfo_t()
                tinfo.create_ptr(types["func_t"].type)
                udt_data[dup].type = tinfo

        final_tinfo = ida_typeinf.tinfo_t()
        if final_tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT):
            return final_tinfo
        log_error("Virtual table creation failed")

    def scan_virtual_function(self, index: int, structure):
        if is_imported(self.virtual_functions[index].address):
            log_debug(
                f"Skipping import function at {hex(self.virtual_functions[index].address)}"
            )
            return
        try:
            function = decompile(self.virtual_functions[index].address)
        except ida_hexrays.DecompilationFailure:
            log_error(
                f"Failed to decompile function at {hex(self.virtual_functions[index].address)}"
            )
            return
        if FunctionTouchVisitor(function).process():
            function = decompile(self.virtual_functions[index].address)
        if function.arguments and function.arguments[0].is_arg_var:
            log_debug(
                f"Scanning function's this ptr at {hex(self.virtual_functions[index].address)}"
            )
            obj = VariableObject(function.get_lvars()[0], 0)
            scanner = NewDeepScanVisitor(function, self.offset, obj, structure)
            scanner.process()
        else:
            log_warning(
                f"Function at {hex(self.virtual_functions[index].address)} does not have a this ptr"
            )

    def scan_virtual_functions(self, structure):
        for index, _ in enumerate(self.virtual_functions):
            self.scan_virtual_function(index, structure)

    def import_to_structures(self, ask=False):
        """
        Imports virtual tables and returns tid_t of new structure

        :return: idaapi.tid_t
        """
        tinfo = self.create_tinfo()
        cdecl_typedef = idaapi.print_tinfo(
            None,
            4,
            5,
            idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
            tinfo,
            self.vtable_name,
            None,
        )

        log_debug(f"Created virtual table typedef:\n{cdecl_typedef}")

        if ask:
            cdecl_typedef = idaapi.ask_text(
                0x10000, cdecl_typedef, "The following new type will be created"
            )
            if not cdecl_typedef:
                return
        previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, self.vtable_name)
        if previous_ordinal:
            idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
            ordinal = idaapi.idc_set_local_type(
                previous_ordinal, cdecl_typedef, idaapi.PT_TYP
            )
        else:
            ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)

        if not ordinal:
            log_error(
                f"Failed to add virtual table {self.vtable_name} to local types\n"
                f"{'*' * 80}\n"
                f"{cdecl_typedef}\n"
                f"{'*' * 80}\n"
            )
        else:
            log_info(f"Virtual table {self.vtable_name} added to local types")
            return forge_types.import_type(self.vtable_name)

    def get_udt_member(self, offset=0):
        udt_member = ida_typeinf.udt_member_t()
        tid = self.import_to_structures()
        if tid != idaapi.BADADDR:
            udt_member.name = self.name

            tmp_tinfo = idaapi.create_typedef(self.vtable_name)
            tmp_tinfo.create_ptr(tmp_tinfo)

            udt_member.type = tmp_tinfo
            udt_member.offset = self.offset - offset
            udt_member.size = types.width

        return udt_member

    def type_equals_to(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        udt_data = ida_typeinf.udt_type_data_t()
        if tinfo.is_ptr() and tinfo.get_pointed_object().get_udt_details(udt_data):
            if udt_data[0].type.is_funcptr():
                return True
        return False

    def switch_array_flag(self):
        pass

    @staticmethod
    def is_virtual_table(address: int) -> int:
        """
        Check if an address is a virtual table, returns the number of functions found within the virtual table.

        :param address: The address to check.
        :return: The number of functions found.
        """
        # If the address is code, then it cannot be a virtual table
        if is_code(address):
            return 0

        # If the address has no name, then IDA has not seen the address referenced, so return 0
        if not ida_name.get_name(address):
            return 0

        function_count = 0

        # Iterate until we find a non-function address
        while True:
            # Get the pointer to the next potential function
            func_address = get_ptr(address)

            # If the address is code or an imported function, then it is a function
            if is_code(func_address) or is_imported(func_address):
                # Increment the function count and the address to the next potential function
                function_count += 1
                address += types.width
            else:
                # If the address is not a function, then check if it is executable
                segment = ida_segment.getseg(func_address)
                if segment and segment.perm & ida_segment.SEGPERM_EXEC:
                    # If the address is executable, then add it to the list of functions
                    ida_bytes.del_items(func_address, 1, ida_bytes.DELIT_SIMPLE)
                    if ida_funcs.add_func(func_address):
                        # If the address was added as a function, then increment the function count and address
                        function_count += 1
                        address += types.width
                        continue
                # If the address is not executable or was not added as a function, then break out of the loop
                break
            # Wait for IDA to finish processing before continuing the loop
            ida_auto.auto_wait()

        # Return the number of functions found
        return function_count

    def _parse_vtable_name(self):
        """
        Parse the name of the virtual table.

        :return: A tuple containing the name of the virtual table and a boolean indicating whether the name was mangled.
        """
        original_name = ida_name.get_name(self.address)

        if ida_name.is_valid_typename(original_name):
            if original_name.startswith("off_"):
                # case off_XXXXXXXX
                return f"vtbl{original_name[3:]}", False
            elif "table" in original_name:
                return original_name, True

        demangled_name = ida_name.demangle_name(
            original_name, idc.get_inf_attr(idc.INF_SHORT_DN)
        )
        assert (
            demangled_name
        ), "Virtual table must have either a legal C++ type name or a mangled name"
        name = (
            demangled_name_to_c_str(demangled_name)
            .replace("const_", "")
            .replace("const ", "")
            .replace("::_vftable", "_vtbl")
            .replace("::`vftable'", "_vtbl")
        )

        return name, True

    @staticmethod
    def search_duplicate_fields(udt_data):
        """
        Returns a list of lists with duplicate fields
        """
        # Create a defaultdict to group fields by name
        default_dict = defaultdict(list)
        for idx, udt_member in enumerate(udt_data):
            default_dict[udt_member.name].append(idx)

        # Return only lists with more than one index
        return [indices for indices in list(default_dict.values()) if len(indices) > 1]

    @property
    def score(self):
        return 0x2000

    @property
    def cmt(self):
        return ""

    @property
    def size(self):
        return types.width

    @property
    def type_name(self):
        return f"{self.vtable_name} *"

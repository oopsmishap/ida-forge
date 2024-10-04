from typing import Optional, List

import ida_bytes
import ida_funcs
import ida_hexrays
import idaapi
import ida_typeinf

from forge.api.hexrays import is_legal_type, find_expr_address, is_code, decompile, ctype, get_func_argument_info, \
    get_funcs_calling_address, ctype_to_str, to_hex
from forge.api.scan_object import ScanObject, ObjectType
from forge.api.types import types
from forge.api.visitor import ObjectVisitor, DownwardsObjectVisitor, RecursiveDownwardsObjectVisitor
from forge.util.logging import *


class ScannedObject(object):
    def __init__(self, name: str, expression_address: int, origin: int, applicable: bool = True):
        self.name = name
        self.ea = expression_address
        self.func_ea = ida_funcs.get_func(self.ea).start_ea
        self.origin = origin
        self._applicable = applicable

    def apply_type(self, tinfo: ida_typeinf.tinfo_t):
        raise NotImplementedError

    @staticmethod
    def create(obj, expression_address, origin, applicable=True):
        if obj.id == ObjectType.global_object:
            return ScannedGlobalObject(obj.ea, obj.name, expression_address, origin, applicable)
        elif obj.id == ObjectType.local_variable:
            return ScannedVariableObject(obj.lvar, obj.name, expression_address, origin, applicable)
        elif obj.id in (ObjectType.structure_pointer, ObjectType.structure_reference):
            return ScannedStructureMemberObject(obj.struct_name, obj.name, expression_address, origin, applicable)
        else:
            return AssertionError

    @property
    def function_name(self) -> str:
        return ida_funcs.get_func_name(self.func_ea)

    def to_list(self):
        """ Creates list that is acceptable to MyChoose2 viewer """
        return [
            f"0x{self.origin:04X}",
            self.function_name,
            self.name,
            to_hex(self.ea)
        ]

    # def __eq__(self, other: 'ScannedObject'):
    #     log_debug(f"Comparing {self} to {other}")
    #     return self.func_ea == other.func_ea and\
    #            self.name == other.name and \
    #            self.ea == other.ea

    def __hash__(self):
        return hash((self.func_ea, self.name, self.ea))

    def __repr__(self):
        return f"{self.name} @ {hex(self.ea)}"


class ScannedGlobalObject(ScannedObject):
    def __init__(self, obj_ea: int, name: str, expression_address: int, origin: int, applicable: bool = True):
        super().__init__(name, expression_address, origin, applicable)
        self._obj_ea = obj_ea

    def apply_type(self, tinfo: ida_typeinf.tinfo_t):
        ida_typeinf.apply_tinfo(self._obj_ea, tinfo)


class ScannedVariableObject(ScannedObject):
    def __init__(self, lvar: ida_hexrays.lvar_t, name: str, expression_address: int, origin: int,
                 applicable: bool = True):

        super().__init__(name, expression_address, origin, applicable)
        self._lvar = ida_hexrays.lvar_locator_t(lvar.location, lvar.defea)

    def apply_type(self, tinfo: ida_typeinf.tinfo_t):
        if not self._applicable:
            return

        hx_view = ida_hexrays.open_pseudocode(self.func_ea, -1)
        if hx_view:
            log_debug(f"Applying t info to variable {self.name} in {self.function_name}")
            # Finding lvar of new window that have the same name that saved one and applying tinfo_t
            lvar = [x for x in hx_view.cfunc.get_lvars() if x == self._lvar]
            if lvar:
                log_debug("Successful")
                hx_view.set_lvar_type(lvar[0], tinfo)
            else:
                log_warning("Failed to find previously scanned local variable {} from {}".format(
                    self.name, to_hex(self.ea)))

class ScannedStructureMemberObject(ScannedObject):
    def __init__(self, struct_name, struct_offset, name, expression_address, origin, applicable=True):
        super().__init__(name, expression_address, origin, applicable)
        self._name = struct_name
        self._offset = struct_offset

    def apply_type(self, tinfo: ida_typeinf.tinfo_t):
        if not self._applicable:
            return
        # TODO: implement changing structure member types
        log_warning(f"Changing structure member types is not supported yet. Address - {hex(self.ea)}")


class ScanVisitor(ObjectVisitor):
    def __init__(self, cfunc: ida_hexrays.cfunc_t, origin: int, obj: ScanObject, structure):
        super().__init__(cfunc, obj, None, True)
        self._origin = origin
        self._structure = structure

    def _manipulate(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject):
        super()._manipulate(cexpr, obj)

        member = None

        if obj.tinfo and not is_legal_type(obj.tinfo):
            # TODO: if this is triggered look into why and how to solve it
            expr_ea = find_expr_address(cexpr, self.parents)
            log_warning(f"Type {obj.tinfo.dstr()} @ {to_hex(expr_ea)} is not supported")
            return
        elif cexpr.type.is_ptr():
            member = self._extract_member_from_ptr(cexpr, obj)
        else:
            member = self._extract_member_from_expr(cexpr, obj)

        # if member exists and not a VoidMember
        from forge.api.members import VoidMember
        if member and not isinstance(member, VoidMember):
            log_debug(f"\tCreating member {member}")
            self._structure.add_member(member)

    def _get_member(self, offset: int, cexpr: ida_hexrays.cexpr_t, obj: ScanObject, tinfo: ida_typeinf.tinfo_t,
                    obj_ea: int = None):
        """
        Extracts a member from a given expression.

        :param offset: The offset of the member from the beginning of the object.
        :param cexpr: The expression containing the member.
        :param obj: The object containing the member.
        :param tinfo: The t information of the object.
        :param obj_ea: The effective address of the object.
        :return: The extracted AbstracMember.
        """
        expr_ea = find_expr_address(cexpr, self.parents)

        # Ensure that the offset is positive
        if offset < 0:
            log_warning(f"Considered to be impossible: offset: {offset}, obj: {to_hex(expr_ea)}")
            raise AssertionError

        applicable = not self.crippled
        scan_obj = ScannedObject.create(obj, expr_ea, self._origin, applicable)

        if obj_ea is not None:
            # Check if the effective address is a virtual table
            from forge.api.members import VirtualTable
            if VirtualTable.is_virtual_table(obj_ea) != 0:
                return VirtualTable(offset, obj_ea, scan_obj, self._origin)
            # Check if the effective address is in code
            if is_code(obj_ea):
                func = decompile(obj_ea)
                if func:
                    tinfo = func.type
                    tinfo.create_ptr(tinfo)
                else:
                    tinfo = types["func_t"].type
                    # tinfo = const.DUMMY_FUNC
                from forge.api.members import Member
                return Member(offset, tinfo, scan_obj, self._origin)

        tinfo.clr_const()


        # convert `unsigned int` -> `u32` / `int` -> `i32`, etc.
        tinfo = types.convert_to_simple_type(tinfo)

        # Check if the t information is void
        if not tinfo or tinfo.equals_to(types["void"].type):
            from forge.api.members import VoidMember
            return VoidMember(offset, scan_obj, self._origin)

        from forge.api.members import Member
        return Member(offset, tinfo, scan_obj, self._origin)

    def _extract_member_from_ptr(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject):
        """
        Extracts an AbstractMember from the given pointer expression and a ScanObject.

        :param cexpr: The expression of the pointer.
        :param obj: The object containing the member.
        :return: The extracted member or None if the extraction fails.
        """
        parents_type = [x.cexpr.op for x in list(self.parents)[:0:-1]]
        parents = [x.cexpr for x in list(self.parents)[:0:-1]]

        # Extracting offset and removing expression parents making this offset
        if parents[0].op in (ctype.idx, ctype.add):
            # `expr[idx]`
            # `(TYPE*) + x`
            if parents[0].y.op != ctype.num:
                # cannot handle non-constant offsets
                return None

            offset = parents[0].y.numval() * cexpr.type.get_ptrarr_objsize()
            cexpr = self.parent_expr()
            if parents_type[0] == ctype.add:
                parents_type.pop(0)
                parents.pop(0)

        elif parents_type[0:2] == [ctype.cast, ctype.add]:
            # `(TYPE*)expr + offset`
            # `(TYPE)expr + offset`
            if parents[1].y.op != ctype.num:
                # cannot handle non-constant offsets
                return None
            elif parents[0].type.is_ptr():
                size = parents[0].type.get_ptrarr_objsize()
            else:
                size = 1

            offset = parents[1].theother(parents[0]).numval() * size
            cexpr = parents[1]
            del parents_type[0:2]
            del parents[0:2]
        else:
            offset = 0

        return self._extract_member(cexpr, obj, offset, parents, parents_type)

    def _extract_member_from_expr(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject):
        """
        Extracts an AbstractMember from an expression and a ScanObject.

        :param cexpr: the expression from which to extract the member
        :param obj: the ScanObject to which the member belongs
        :return: the extracted AbstractMember or None if it couldn't be extracted
        """
        parents_type = [x.cexpr.op for x in list(self.parents)[:0:-1]]
        parents = [x.cexpr for x in list(self.parents)[:0:-1]]

        log_debug(f"Extracting member from expression: {obj.name}, parents: '{ctype_to_str(parents_type)}'")

        # If the parent expression is a sum (i.e. `obj + offset`) then offset should be
        # the second operand of the parent expression, and we delete the parent's `ctype.add`
        # and its other operand
        if parents_type and parents_type[0] == ctype.add:
            if parents[0].theother(cexpr).op != ctype.num:
                # Cannot handle non-constant offsets
                return None

            offset = parents[0].theother(cexpr).numval()
            cexpr = self.parent_expr()
            parents_type.pop(0)
            parents.pop(0)
        else:
            offset = 0

        # Extract the member using the expression and the parents
        return self._extract_member(cexpr, obj, offset, parents, parents_type)

    def _extract_member(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject, offset: int,
                        parents: List[ida_hexrays.cexpr_t], parents_type: List[ctype]):

        log_debug(f"Extracting member: {obj.name}, parents: '{ctype_to_str(parents_type)}'")

        # Clear and store cast type
        if parents_type[0] == ctype.cast:
            # `(TYPE)expr`
            tinfo = parents[0].type
            cexpr = parents[0]
            parents_type.pop(0)
            parents.pop(0)
        else:
            tinfo = types.get_ptr()

        log_debug(f"1st default_tinfo: {tinfo.dstr()}")

        if parents_type[0] in (ctype.idx, ctype.ptr):
            # Clear and store cast type
            if parents_type[1] == ctype.cast:
                # `*(TYPE*)expr`
                # `*(TYPE*)expr[idx]`
                tinfo = parents[1].type
                cexpr = parents[0]
                parents_type.pop(0)
                parents.pop(0)
            else:
                tinfo = self._deref_tinfo(tinfo)

            log_debug(f"2nd default_tinfo: {tinfo.dstr()}")

            if parents_type[1] == ctype.asg:
                if parents[1].x == parents[0]:
                    # `*((TYPE*)expr + x) = ...`
                    obj_ea = self._extract_obj_ea(parents[1].y)
                    log_debug(f"pointer assignment to object")
                    return self._get_member(offset, cexpr, obj, parents[1].y.type, obj_ea)
                else:
                    # `*(TYPE*)expr = ...`
                    log_debug(f"cast assignment to object")
                    return self._get_member(offset, cexpr, obj, parents[1].x.type)
            elif parents_type[1] == ctype.call:
                log_debug(f"pointer passed as argument to function at {hex(parents[1].ea)}")
                if parents[1].x == parents[0]:
                    # ((void (__some_call*)(..., expr[idx], ...)
                    # ((void (__some_call*)(..., *(TYPE*)(expr + x), ...)
                    log_debug(f"object passed as argument to function at {hex(parents[1].ea)}")
                    return self._get_member(offset, cexpr, obj, parents[0].type)
                _, tinfo = get_func_argument_info(parents[1], parents[0])
                if tinfo is None:
                    log_warning(f"Failed to get function argument info for {parents[1]}, ea: {hex(parents[1].ea)}")
                    tinfo = types["u8"].ptr
                return self._get_member(offset, cexpr, obj, tinfo)
            return self._get_member(offset, cexpr, obj, tinfo)

        elif parents_type[0] == ctype.call:
            # `void (__some_call*)(..., (TYPE)(expr + x), ...)`
            log_debug(f'function call with cast, parent: {parents[0].type.dstr()} {parents[0].dstr()}, cexpr: {cexpr.type.dstr()} {cexpr.dstr()}')
            tinfo = self._parse_call(parents[0], cexpr)
            return self._get_member(offset, cexpr, obj, tinfo)

        elif parents_type[0] == ctype.asg:
            # `TYPE parent.x = expr(...);`
            log_debug(f"assignment to object")
            if parents[0].x == cexpr:
                tinfo = parents[0].x.type
                return self._get_member(offset, cexpr, obj, tinfo)

        return self._get_member(offset, cexpr, obj, self._deref_tinfo(tinfo))

    @staticmethod
    def _deref_tinfo(tinfo: ida_typeinf.tinfo_t) -> Optional[ida_typeinf.tinfo_t]:
        """
        Get the pointed object from a pointer tinfo.

        :param tinfo: A pointer tinfo.
        :t tinfo: ida_typeinf.tinfo_t
        :return: The pointed object tinfo or None if it is not a valid pointer t.
        :rtype: Optional[ida_typeinf.tinfo_t]
        """
        log_debug(f"Dereferencing tinfo: {tinfo.dstr()}")

        if not tinfo.is_ptr():
            return tinfo
        
        if tinfo.get_ptrarr_objsize() != 1:
            return tinfo.get_pointed_object()
        
        if tinfo.equals_to(types["void"].ptr):
            return tinfo

        if tinfo.equals_to(types["u8"].ptr):
            return types["u8"].type

        return None  # Turns into VoidMember

    @staticmethod
    def _extract_obj_ea(cexpr: ida_hexrays.cexpr_t) -> Optional[int]:
        """
        Extracts the effective address of an object from a cexpr.

        :param cexpr: The cexpr from which to extract the effective address.
        :return: The effective address of the object if found, otherwise None.
        """
        # If the cexpr is a reference, get its content.
        if cexpr.op == ctype.ref:
            cexpr = cexpr.x
        # If the cexpr is an object, return its effective address.
        if cexpr.op == ctype.obj:
            if cexpr.obj_ea != idaapi.BADADDR:
                return cexpr.obj_ea

    def _parse_call(self, call_cexpr: ida_hexrays.cexpr_t, arg_cexpr: ida_hexrays.cexpr_t) -> ida_typeinf.tinfo_t:
        """
        Parse call and argument expressions to get t information.

        :param call_cexpr: Call expression to parse.
        :param arg_cexpr: Argument expression to parse.
        :return: Type information.
        """
        idx, tinfo = get_func_argument_info(call_cexpr, arg_cexpr)
        log_debug(f"Argument {idx} type: {tinfo.dstr()}")
        if tinfo:
            return self._deref_tinfo(tinfo)
        # TODO: Find example with UTF-16 strings
        return types["char"].type

    def _parse_left_assignee(self, x, offset):
        pass


class NewShallowScanVisitor(ScanVisitor, DownwardsObjectVisitor):
    def __init__(self, cfunc: ida_hexrays.cfunc_t, origin: int, obj: ScanObject, structure):
        super().__init__(cfunc, origin, obj, structure)


class NewDeepScanVisitor(ScanVisitor, RecursiveDownwardsObjectVisitor):
    def __init__(self, cfunc: ida_hexrays.cfunc_t, origin: int, obj: ScanObject, structure):
        super().__init__(cfunc, origin, obj, structure)


class DeepScanReturnVisitor(NewDeepScanVisitor):
    def __init__(self, cfunc: ida_hexrays.cfunc_t, origin: int, obj: ScanObject, structure):
        super().__init__(cfunc, origin, obj, structure)
        self._callers_ea = get_funcs_calling_address(cfunc.entry_ea)
        self._call_obj = obj

    def _start(self):
        for ea in self._callers_ea:
            self._add_scan_tree_info(ea, -1)
        assert self._prepare_scanner()

    def _finish(self):
        if self._prepare_scanner():
            self._recursive_process()

    def _prepare_scanner(self):
        try:
            cfunc = next(self._iter_callers())
        except StopIteration:
            return False

    def _iter_callers(self):
        for ea in self._callers_ea:
            cfunc = decompile(ea)
            if cfunc:
                yield cfunc

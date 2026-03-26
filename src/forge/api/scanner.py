from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import ida_funcs
import ida_hexrays
import idaapi
import ida_typeinf

from forge.api.hexrays import (
    ctype,
    ctype_to_str,
    decompile,
    find_expr_address,
    get_func_argument_info,
    get_funcs_calling_address,
    is_code,
    is_legal_type,
    to_hex,
)
from forge.api.scan_object import ScanObject, ObjectType
from forge.api.types import types
from forge.api.visitor import (
    DownwardsObjectVisitor,
    ObjectVisitor,
    RecursiveDownwardsObjectVisitor,
)
from forge.util.logging import log_debug, log_warning


@dataclass
class ParentExpressionContext:
    expressions: list[ida_hexrays.cexpr_t]

    @property
    def ops(self) -> list[ctype]:
        return [expression.op for expression in self.expressions]

    def expr_at(self, index: int) -> Optional[ida_hexrays.cexpr_t]:
        return self.expressions[index] if index < len(self.expressions) else None

    def op_at(self, index: int) -> Optional[ctype]:
        ops = self.ops
        return ops[index] if index < len(ops) else None

    def pop_front(self, count: int = 1) -> None:
        del self.expressions[:count]


class ScannedObject:
    def __init__(
        self,
        name: str,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ):
        self.name = name
        self.ea = expression_address
        self.func_ea = self._get_function_start(expression_address)
        self.origin = origin
        self._applicable = applicable

    @staticmethod
    def _get_function_start(ea: int) -> int:
        func = ida_funcs.get_func(ea)
        return func.start_ea if func is not None else idaapi.BADADDR

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
        raise NotImplementedError

    @staticmethod
    def create(
        obj: ScanObject,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ) -> "ScannedObject":
        if obj.id == ObjectType.global_object:
            return ScannedGlobalObject(
                obj.object_ea, obj.name, expression_address, origin, applicable
            )
        if obj.id == ObjectType.local_variable:
            return ScannedVariableObject(
                obj.lvar, obj.name, expression_address, origin, applicable
            )
        if obj.id in (ObjectType.structure_pointer, ObjectType.structure_reference):
            return ScannedStructureMemberObject(
                obj.struct_name, obj.name, expression_address, origin, applicable
            )
        raise AssertionError(f"Unsupported scan object type: {obj.id}")

    @property
    def function_name(self) -> str:
        if self.func_ea == idaapi.BADADDR:
            return "<unknown>"
        return ida_funcs.get_func_name(self.func_ea)

    def to_list(self) -> list[str]:
        """Return a row suitable for an IDA chooser widget."""
        return [
            f"0x{self.origin:04X}",
            self.function_name,
            self.name,
            to_hex(self.ea),
        ]

    def __hash__(self):
        return hash((self.func_ea, self.name, self.ea))

    def __repr__(self):
        return f"{self.name} @ {hex(self.ea)}"


class ScannedGlobalObject(ScannedObject):
    def __init__(
        self,
        obj_ea: int,
        name: str,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ):
        super().__init__(name, expression_address, origin, applicable)
        self._obj_ea = obj_ea

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
        ida_typeinf.apply_tinfo(self._obj_ea, tinfo, ida_typeinf.TINFO_DEFINITE)


class ScannedVariableObject(ScannedObject):
    def __init__(
        self,
        lvar: ida_hexrays.lvar_t,
        name: str,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ):
        super().__init__(name, expression_address, origin, applicable)
        self._lvar = ida_hexrays.lvar_locator_t(lvar.location, lvar.defea)

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
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
                log_warning(
                    "Failed to find previously scanned local variable "
                    f"{self.name} from {to_hex(self.ea)}"
                )


class ScannedStructureMemberObject(ScannedObject):
    def __init__(
        self,
        struct_name,
        struct_offset,
        name,
        expression_address,
        origin,
        applicable=True,
    ):
        super().__init__(name, expression_address, origin, applicable)
        self._name = struct_name
        self._offset = struct_offset

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
        if not self._applicable:
            return
        # TODO: implement changing structure member types
        log_warning(
            "Changing structure member types is not supported yet. "
            f"Address - {hex(self.ea)}"
        )


class ScanVisitor(ObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        origin: int,
        obj: ScanObject,
        structure,
    ):
        super().__init__(cfunc, obj, None, True)
        self._origin = origin
        self._structure = structure

    @staticmethod
    def _describe_tinfo(tinfo: Optional[ida_typeinf.tinfo_t]) -> str:
        return "<none>" if tinfo is None else tinfo.dstr()

    def _get_parent_context(self) -> ParentExpressionContext:
        expressions = [parent.cexpr for parent in list(self.parents)[:0:-1]]
        return ParentExpressionContext(expressions)

    def _manipulate(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject) -> None:
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

    def _get_member(
        self,
        offset: int,
        cexpr: ida_hexrays.cexpr_t,
        obj: ScanObject,
        tinfo: Optional[ida_typeinf.tinfo_t],
        obj_ea: Optional[int] = None,
    ):
        """Build a structure member from the expression/type context."""
        expr_ea = find_expr_address(cexpr, self.parents)

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
                from forge.api.members import Member
                return Member(offset, tinfo, scan_obj, self._origin)

        if tinfo is not None:
            tinfo.clr_const()

        tinfo = types.convert_to_simple_type(tinfo)

        if not tinfo or tinfo.equals_to(types["void"].type):
            from forge.api.members import VoidMember
            return VoidMember(offset, scan_obj, self._origin)

        from forge.api.members import Member
        return Member(offset, tinfo, scan_obj, self._origin)

    def _extract_member_from_ptr(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject):
        """Extract a member from a pointer expression."""
        context = self._get_parent_context()
        first_parent = context.expr_at(0)
        second_parent = context.expr_at(1)

        if first_parent is None:
            return self._extract_member(cexpr, obj, 0, context)

        if first_parent.op in (ctype.idx, ctype.add):
            # `expr[idx]`
            # `(TYPE*) + x`
            if first_parent.y.op != ctype.num:
                return None

            offset = first_parent.y.numval() * cexpr.type.get_ptrarr_objsize()
            cexpr = self.parent_expr()
            if first_parent.op == ctype.add:
                context.pop_front()
        elif context.op_at(0) == ctype.cast and context.op_at(1) == ctype.add and second_parent is not None:
            # `(TYPE*)expr + offset`
            # `(TYPE)expr + offset`
            if second_parent.y.op != ctype.num:
                return None
            if first_parent.type.is_ptr():
                size = first_parent.type.get_ptrarr_objsize()
            else:
                size = 1

            offset = second_parent.theother(first_parent).numval() * size
            cexpr = second_parent
            context.pop_front(2)
        else:
            offset = 0

        return self._extract_member(cexpr, obj, offset, context)

    def _extract_member_from_expr(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject):
        """Extract a member from a non-pointer expression."""
        context = self._get_parent_context()

        log_debug(
            "Extracting member from expression: "
            f"{obj.name}, parents: '{ctype_to_str(context.ops)}'"
        )

        first_parent = context.expr_at(0)
        if context.op_at(0) == ctype.add and first_parent is not None:
            other = first_parent.theother(cexpr)
            if other.op != ctype.num:
                return None

            offset = other.numval()
            cexpr = self.parent_expr()
            context.pop_front()
        else:
            offset = 0

        return self._extract_member(cexpr, obj, offset, context)

    def _extract_member(
        self,
        cexpr: ida_hexrays.cexpr_t,
        obj: ScanObject,
        offset: int,
        context: ParentExpressionContext,
    ):
        log_debug(
            f"Extracting member: {obj.name}, parents: '{ctype_to_str(context.ops)}'"
        )

        if context.op_at(0) == ctype.cast and context.expr_at(0) is not None:
            # `(TYPE)expr`
            tinfo = context.expr_at(0).type
            cexpr = context.expr_at(0)
            context.pop_front()
        else:
            tinfo = types.get_ptr()

        log_debug(f"1st default_tinfo: {self._describe_tinfo(tinfo)}")

        if context.op_at(0) in (ctype.idx, ctype.ptr):
            if context.op_at(1) == ctype.cast and context.expr_at(1) is not None:
                # `*(TYPE*)expr`
                # `*(TYPE*)expr[idx]`
                tinfo = context.expr_at(1).type
                cexpr = context.expr_at(0)
                context.pop_front()
            else:
                tinfo = self._deref_tinfo(tinfo)

            log_debug(f"2nd default_tinfo: {self._describe_tinfo(tinfo)}")

            second_expr = context.expr_at(1)
            first_expr = context.expr_at(0)

            if context.op_at(1) == ctype.asg and second_expr is not None and first_expr is not None:
                if second_expr.x == first_expr:
                    # `*((TYPE*)expr + x) = ...`
                    obj_ea = self._extract_obj_ea(second_expr.y)
                    log_debug(f"pointer assignment to object")
                    return self._get_member(offset, cexpr, obj, second_expr.y.type, obj_ea)
                else:
                    # `*(TYPE*)expr = ...`
                    log_debug(f"cast assignment to object")
                    return self._get_member(offset, cexpr, obj, second_expr.x.type)
            elif context.op_at(1) == ctype.call and second_expr is not None and first_expr is not None:
                log_debug(f"pointer passed as argument to function at {hex(second_expr.ea)}")
                if second_expr.x == first_expr:
                    # ((void (__some_call*)(..., expr[idx], ...)
                    # ((void (__some_call*)(..., *(TYPE*)(expr + x), ...)
                    log_debug(f"object passed as argument to function at {hex(second_expr.ea)}")
                    return self._get_member(offset, cexpr, obj, first_expr.type)
                _, tinfo = get_func_argument_info(second_expr, first_expr)
                if tinfo is None:
                    log_warning(
                        f"Failed to get function argument info for {second_expr}, "
                        f"ea: {hex(second_expr.ea)}"
                    )
                    tinfo = types["u8"].ptr
                return self._get_member(offset, cexpr, obj, tinfo)
            return self._get_member(offset, cexpr, obj, tinfo)

        if context.op_at(0) == ctype.call and context.expr_at(0) is not None:
            # `void (__some_call*)(..., (TYPE)(expr + x), ...)`
            call_parent = context.expr_at(0)
            log_debug(
                "function call with cast, parent: "
                f"{call_parent.type.dstr()} {call_parent.dstr()}, "
                f"cexpr: {cexpr.type.dstr()} {cexpr.dstr()}"
            )
            tinfo = self._parse_call(call_parent, cexpr)
            return self._get_member(offset, cexpr, obj, tinfo)

        if context.op_at(0) == ctype.asg and context.expr_at(0) is not None:
            # `TYPE parent.x = expr(...);`
            log_debug(f"assignment to object")
            assignment_parent = context.expr_at(0)
            if assignment_parent.x == cexpr:
                tinfo = assignment_parent.x.type
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
        if tinfo is None:
            return None

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

    def _parse_call(
        self,
        call_cexpr: ida_hexrays.cexpr_t,
        arg_cexpr: ida_hexrays.cexpr_t,
    ) -> Optional[ida_typeinf.tinfo_t]:
        """Infer the argument type used at a call site."""
        idx, tinfo = get_func_argument_info(call_cexpr, arg_cexpr)
        if tinfo is not None:
            log_debug(f"Argument {idx} type: {tinfo.dstr()}")
            return self._deref_tinfo(tinfo)

        log_warning(
            "Could not infer argument type from call expression; "
            f"falling back to char for argument {idx} at {to_hex(call_cexpr.ea)}"
        )
        return types["char"].type

    def _parse_left_assignee(self, x, offset):
        pass


class NewShallowScanVisitor(ScanVisitor, DownwardsObjectVisitor):
    def __init__(self, cfunc: ida_hexrays.cfunc_t, origin: int, obj: ScanObject, structure):
        super().__init__(cfunc, origin, obj, structure)


class NewDeepScanVisitor(ScanVisitor, RecursiveDownwardsObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        origin: int,
        obj: ScanObject,
        structure,
    ):
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

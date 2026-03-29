from enum import Enum
import traceback

import ida_hexrays
import idaapi
import ida_funcs
import ida_name

from forge.api.hexrays import get_member_name, ctype
from forge.util.logging import log_debug
TYPE_IGNORED_TOKENS = {"const", "volatile", "struct", "class", "union", "&"}


def _type_identity_key(name: str) -> str:
    # IDA decorates the same structure with qualifiers and reference markers; keep
    # pointer depth, but compare the underlying identity.
    normalized = name.replace("*", " * ").replace("&", " & ")
    return " ".join(
        token for token in normalized.split() if token not in TYPE_IGNORED_TOKENS
    )


def _unwrap_struct_type(tinfo):
    if tinfo is None:
        return None
    if hasattr(tinfo, "is_ptr") and tinfo.is_ptr() and hasattr(tinfo, "get_pointed_object"):
        pointed = tinfo.get_pointed_object()
        if pointed is not None:
            return pointed
    if hasattr(tinfo, "is_array") and tinfo.is_array() and hasattr(tinfo, "get_array_element"):
        array_element = tinfo.get_array_element()
        if array_element is not None:
            return array_element
    return tinfo


def _type_name_matches(tinfo, expected_name: str) -> bool:
    if tinfo is None:
        return False
    return _type_identity_key(tinfo.dstr()) == _type_identity_key(expected_name)


def _strip_casts_and_refs(expr):
    while expr is not None and hasattr(expr, "op") and expr.op in (ctype.cast, ctype.ref):
        expr = expr.x
    return expr



def _extract_offset_expression(expr):
    offset = 0
    current = expr
    while current is not None and hasattr(current, "op") and current.op in (ctype.cast, ctype.ref):
        current = current.x
    while current is not None and hasattr(current, "op") and current.op in (ctype.add, ctype.sub, ctype.idx):

        if current.op == ctype.idx:
            if not hasattr(current, "y") or current.y is None:
                current = _strip_casts_and_refs(getattr(current, "x", None))
                continue
            if current.y.op != ctype.num:
                return None, None
            offset += current.y.numval()
            current = _strip_casts_and_refs(current.x)
            continue

        if not hasattr(current, "x") or not hasattr(current, "y"):
            current = _strip_casts_and_refs(getattr(current, "x", None))
            continue

        left = _strip_casts_and_refs(current.x)
        right = _strip_casts_and_refs(current.y)
        if left is not None and hasattr(left, "op") and left.op == ctype.num and right is not None:
            offset += left.numval() if current.op == ctype.add else -left.numval()
            current = right
            continue
        if right is not None and hasattr(right, "op") and right.op == ctype.num and left is not None:
            offset += right.numval() if current.op == ctype.add else -right.numval()
            current = left
            continue
        current = left if right is None else right
        continue


    return current, offset



def _get_struct_tinfo(tinfo):
    if tinfo is None:
        return None
    if hasattr(tinfo, "is_ptr") and tinfo.is_ptr() and hasattr(tinfo, "get_pointed_object"):
        pointed = tinfo.get_pointed_object()
        if pointed is not None:
            return pointed
    return tinfo


def _make_offset_scan_object(base_obj, offset: int):
    base_tinfo = _get_struct_tinfo(getattr(base_obj, "tinfo", None))
    if base_tinfo is None or offset == 0:
        return base_obj

    struct_name = base_tinfo.dstr()
    if not struct_name:
        return base_obj

    result = StructureReferenceObject(struct_name, offset)
    try:
        result.name = get_member_name(base_tinfo, offset) or base_obj.name
    except Exception:
        result.name = base_obj.name
    result.tinfo = base_tinfo
    result.ea = getattr(base_obj, "ea", idaapi.BADADDR)
    if hasattr(result, "inherit_scan_root_from"):
        result.inherit_scan_root_from(base_obj)
    return result




class ObjectType(Enum):
    unknown = 0
    local_variable = 1
    structure_pointer = 2
    structure_reference = 3
    global_object = 4
    call_argument = 5
    memory_allocator = 6
    returned_object = 7


class ScanObject:
    """
    A class representing an object in the decompiled code.
    """

    def __init__(self):
        self.ea = idaapi.BADADDR
        self.name = None
        self.tinfo = None
        self.id = ObjectType.unknown
        self.scan_root_ea = idaapi.BADADDR
        self.scan_root_function_ea = idaapi.BADADDR
        self.scan_root_function_name = None

    def set_scan_root(
        self,
        function_ea: int | None,
        *,
        expression_ea: int | None = None,
        function_name: str | None = None,
    ) -> None:
        if function_ea is not None and function_ea != idaapi.BADADDR:
            self.scan_root_function_ea = function_ea
        if expression_ea is not None and expression_ea != idaapi.BADADDR:
            self.scan_root_ea = expression_ea
        if function_name is not None:
            self.scan_root_function_name = function_name

    def inherit_scan_root_from(self, other: "ScanObject") -> None:
        if getattr(other, "scan_root_function_ea", idaapi.BADADDR) != idaapi.BADADDR:
            self.scan_root_function_ea = other.scan_root_function_ea
        if getattr(other, "scan_root_ea", idaapi.BADADDR) != idaapi.BADADDR:
            self.scan_root_ea = other.scan_root_ea
        if getattr(other, "scan_root_function_name", None):
            self.scan_root_function_name = other.scan_root_function_name

    @staticmethod
    def create(cfunc: ida_hexrays.cfunc_t, arg):
        """
        Creates a ScanObject based on the given argument.

        :param cfunc: The cfunc_t object.
        :param arg: The argument to create a ScanObject from.
        :return: The created ScanObject or None.
        """
        if isinstance(arg, ida_hexrays.ctree_item_t):
            # If the argument is a ctree_item_t, check if it's a local variable.
            lvar = arg.get_lvar()
            if lvar:
                index = list(cfunc.get_lvars()).index(lvar)
                result = VariableObject(lvar, index)
                if arg.e:
                    result.ea = ScanObject.get_expression_address(cfunc, arg.e)
                return result
            # If it's not a local variable, check if it's an expression.
            elif arg.citype != ida_hexrays.VDI_EXPR:
                return None
            else:
                cexpr = arg.e
        else:
            cexpr = arg

        # Create ScanObjects for different expression types.
        if cexpr.op == ctype.var:
            lvar = cfunc.get_lvars()[cexpr.v.idx]
            result = VariableObject(lvar, cexpr.v.idx)
            result.ea = ScanObject.get_expression_address(cfunc, cexpr)
        elif cexpr.op == ctype.memptr:
            t = cexpr.x.type.get_pointed_object()
            result = StructurePointerObject(t.dstr(), cexpr.m)
            result.name = get_member_name(t, cexpr.m)
        elif cexpr.op == ctype.memref:
            t = cexpr.x.type
            result = StructureReferenceObject(t.dstr(), cexpr.m)
            result.name = get_member_name(t, cexpr.m)
        elif cexpr.op == ctype.obj:
            result = GlobalVariableObject(cexpr.obj_ea)
            result.name = ida_name.get_short_name(cexpr.obj_ea)
        else:
            return

        result.tinfo = cexpr.type
        result.ea = ScanObject.get_expression_address(cfunc, cexpr)
        result.set_scan_root(
            cfunc.entry_ea,
            expression_ea=result.ea,
            function_name=getattr(ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}")(cfunc.entry_ea),
        )

        return result


    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        raise NotImplementedError()

    @staticmethod
    def get_expression_address(cfunc: ida_hexrays.cfunc_t, cexpr: ida_hexrays.cexpr_t):
        """
        Return address of the expression.
        """
        expr = cexpr
        while expr and expr.ea == idaapi.BADADDR:
            expr = expr.to_specific_type
            expr = cfunc.body.find_parent_of(expr)

        assert expr is not None
        return expr.ea

    def __hash__(self):
        return hash((self.id, self.name))

    def __eq__(self, rhs):
        return self.id == rhs.id and self.name == rhs.name

    def __repr__(self):
        return self.name


class VariableObject(ScanObject):
    """
    Represents a local variable in HexRays decompiled code.
    """

    def __init__(self, lvar: ida_hexrays.lvar_t, index: int):
        super().__init__()
        self.lvar = lvar
        self.tinfo = lvar.type()
        self.name = lvar.name
        self.index = index
        self.id = ObjectType.local_variable
        log_debug(f"Creating VariableObject {self.name}, {self.tinfo.dstr()}")


    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        """
        Checks if the given expression is the local variable represented by this object.

        :param cexpr: The expression to check.
        :return: True if the expression is the local variable, False otherwise.
        """
        return cexpr.op == ctype.var and cexpr.v.idx == self.index


class StructurePointerObject(ScanObject):
    """
    Represents a HexRays `x->m` expression
    """

    def __init__(self, struct_name: str, offset: int):
        super(StructurePointerObject, self).__init__()
        self.struct_name = struct_name
        self.offset = offset
        self.id = ObjectType.structure_pointer
        log_debug(f"Creating StructurePointerObject {self.struct_name}, {self.offset}")

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        """
        Checks if expression is a pointer member of a structure
        """
        if cexpr.op != ctype.memptr or not hasattr(cexpr, "x") or cexpr.x is None:
            return False
        pointed_type = _unwrap_struct_type(getattr(cexpr.x, "type", None))
        return cexpr.m == self.offset and _type_name_matches(pointed_type, self.struct_name)



class StructureReferenceObject(ScanObject):
    """
    Represents a HexRays `x.m` expression
    """

    def __init__(self, struct_name: str, offset: int):
        """
        Initialize a new instance of the StructureReferenceObject class

        :param parent_name: The name of the parent structure
        :param offset: The offset of the member in the structure
        """
        super().__init__()
        self.struct_name = struct_name
        self.offset = offset
        self.id = ObjectType.structure_reference
        log_debug(f"Creating StructureReferenceObject {self.struct_name}, {self.offset}")

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        """
        Checks if expression is a member of a structure
        """
        if cexpr.op == ctype.memref:
            if not hasattr(cexpr, "x") or cexpr.x is None:
                return False
            struct_type = _unwrap_struct_type(getattr(cexpr.x, "type", None))
            return cexpr.m == self.offset and _type_name_matches(struct_type, self.struct_name)

        base_expr, offset = _extract_offset_expression(cexpr)
        if base_expr is None or offset != self.offset:
            return False

        base_type = _unwrap_struct_type(getattr(base_expr, "type", None))
        return base_type is None or _type_name_matches(base_type, self.struct_name)





class GlobalVariableObject(ScanObject):
    """
    Represents a HexRays global object
    """

    def __init__(self, object_address):
        super().__init__()
        self.object_ea = object_address
        self.id = ObjectType.global_object
        log_debug(f"Creating GlobalVariableObject {self.object_ea}")

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        """
        Checks if expression is a global object

        :param cexpr: ida_hexrays.cexpr_t
        :return: returns True if expression is a global variable
        """
        return cexpr.op == ctype.obj and self.object_ea == cexpr.obj_ea


class CallArgumentObject(ScanObject):
    """
    Represents an argument of a function call.
    """

    def __init__(self, func_address: int, arg_idx: int):
        super().__init__()
        self.func_ea = func_address
        self.arg_idx = arg_idx
        self.id = ObjectType.call_argument
        log_debug(f"Creating CallArgumentObject {self.func_ea}, {self.arg_idx}")

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        """
        Checks if expression is the call to the function containing the argument
        """
        if cexpr.op != ctype.call or not hasattr(cexpr, "x") or cexpr.x is None:
            return False
        return getattr(cexpr.x, "obj_ea", idaapi.BADADDR) == self.func_ea


    def create_scan_object(
        self, cfunc: ida_hexrays.cfunc_t, cexpr: ida_hexrays.cexpr_t
    ) -> ScanObject:
        """
        Creates a ScanObject for the argument expression.

        :param cfunc: ida_hexrays.cfunc_t
        :param cexpr: ida_hexrays.cexpr_t
        :return: a ScanObject representing the argument expression
        """
        if self.arg_idx < 0 or self.arg_idx >= len(cexpr.a):
            return None

        e = cexpr.a[self.arg_idx]
        base_expr, offset = _extract_offset_expression(e)
        if base_expr is None:
            return None

        base_obj = ScanObject.create(cfunc, base_expr)
        if base_obj is None:
            return None

        return _make_offset_scan_object(base_obj, offset)

    @staticmethod
    def create(cfunc: ida_hexrays.cfunc_t, arg_idx):
        """
        Creates a new CallArgumentObject

        :param cfunc: ida_hexrays.cfunc_t
        :param arg_idx: call-argument ordinal
        :return: CallArgumentObject
        """
        argidx = getattr(cfunc, "argidx", ())
        if arg_idx < 0 or arg_idx >= len(argidx):
            return None
        result = CallArgumentObject(cfunc.entry_ea, arg_idx)
        lvar_idx = argidx[arg_idx]
        lvars = cfunc.get_lvars()
        if lvar_idx < 0 or lvar_idx >= len(lvars):
            return None
        result.name = lvars[lvar_idx].name
        result.tinfo = ida_hexrays.cfunc_type(cfunc)
        result.set_scan_root(
            cfunc.entry_ea,
            function_name=getattr(ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}")(cfunc.entry_ea),
        )
        return result



    def __repr__(self):
        return self.name


class ReturnedObject(ScanObject):
    """
    Represents a HexRays `return` expression
    """

    def __init__(self, func_address):
        """
        Constructor for ReturnedObject class

        :param func_address: Address of the function
        """
        super().__init__()
        self.__func_ea = func_address
        self.id = ObjectType.returned_object
        log_debug(f"Creating ReturnedObject {self.__func_ea}")

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        """
        Checks if expression is a call and its object address is the same as the function address
        """
        if cexpr.op != ctype.call or not hasattr(cexpr, "x") or cexpr.x is None:
            return False
        return getattr(cexpr.x, "obj_ea", idaapi.BADADDR) == self.__func_ea



class MemoryAllocationObject(ScanObject):
    def __init__(self, name: str, size: int):
        super().__init__()
        self.name = name
        self.size = size
        self.id = ObjectType.memory_allocator
        log_debug(f"Creating MemoryAllocationObject {self.name}, {self.size}")

    @staticmethod
    def create(cfunc: ida_hexrays.cfunc_t, cexpr: ida_hexrays.cexpr_t):
        """
        Creates a new `MemoryAllocationObject` if `malloc` or `operator new` is found at expression

        :param cfunc: cfunc_t object representing the current decompiled function
        :param cexpr: cexpr_t object representing the current expression
        :return: a MemoryAllocationObject instance if the expression is a memory allocation, otherwise None
        """
        if cexpr.op == ctype.call:
            call_expr = cexpr
        elif (
            cexpr.op == ctype.cast
            and hasattr(cexpr, "x")
            and cexpr.x is not None
            and cexpr.x.op == ctype.call
        ):
            call_expr = cexpr.x
        else:
            return None

        func_name = ida_name.get_short_name(getattr(call_expr.x, "obj_ea", idaapi.BADADDR))

        if "malloc" in func_name or "operator new" in func_name or "operator_new" in func_name:
            # if we find `malloc` or `new` we get the size of the allocation
            size_expr = call_expr.a[0] if len(call_expr.a) else None
            # Missing size arguments should not crash the scan; treat them as unknown.
            if size_expr is not None and size_expr.op == ctype.num:
                size = size_expr.numval()
            else:
                size = 0
            result = MemoryAllocationObject(func_name, size)
            result.ea = ScanObject.get_expression_address(cfunc, call_expr)
            result.set_scan_root(
                cfunc.entry_ea,
                expression_ea=result.ea,
                function_name=getattr(ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}")(cfunc.entry_ea),
            )
            return result


    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        return True

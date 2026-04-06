from enum import Enum
import re
import traceback

import ida_hexrays
import idaapi
import ida_funcs
import ida_name

from forge.api.hexrays import get_member_name, ctype
from forge.util.logging import log_debug
TYPE_IGNORED_TOKENS = {"const", "volatile", "struct", "class", "union", "&"}

_ALLOCATOR_NAME_PREFIXES = ("j_", "imp_", "thunk_")
_SINGLE_SIZE_ALLOCATORS = {
    # ISO / POSIX / CRT
    "malloc": 0,
    "malloc_base": 0,
    "realloc": 1,
    "realloc_base": 1,
    "aligned_alloc": 1,
    "memalign": 1,
    "valloc": 0,
    "pvalloc": 0,
    "aligned_malloc": 0,
    "aligned_offset_malloc": 0,
    "aligned_realloc": 1,
    "aligned_offset_realloc": 1,
    # C++
    "new": 0,
    "new[]": 0,
    "operatornew": 0,
    "operatornew[]": 0,
    "operator_new": 0,
    "operator_new[]": 0,
    # GLib
    "g_malloc": 0,
    "g_malloc0": 0,
    "g_try_malloc": 0,
    "g_try_malloc0": 0,
    "g_realloc": 1,
    # Linux kernel
    "kmalloc": 0,
    "kzalloc": 0,
    "krealloc": 1,
    # Win32 / NT heap APIs
    "heapalloc": 2,
    "heaprealloc": 3,
    "localalloc": 1,
    "globalalloc": 1,
    "cotaskmemalloc": 0,
    "rtlallocateheap": 2,
    "rtlreallocateheap": 3,
    "exallocatepool": 1,
    "exallocatepoolwithtag": 1,
    "exallocatepool2": 1,
}
_PRODUCT_SIZE_ALLOCATORS = {
    # ISO / CRT
    "calloc": (0, 1),
    "calloc_base": (0, 1),
    "recalloc": (1, 2),
    "recalloc_base": (1, 2),
    "reallocarray": (1, 2),
    # GLib
    "g_malloc_n": (0, 1),
    "g_malloc0_n": (0, 1),
    "g_realloc_n": (1, 2),
    # Linux kernel
    "kcalloc": (0, 1),
    "kmalloc_array": (0, 1),
}



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



def _extract_offset_expression(expr, offset: int = 0, scale: int = 1, ctype_ops=None):
    if ctype_ops is None:
        ctype_ops = ctype

    cast_op = getattr(ctype_ops, "cast", None)
    ref_op = getattr(ctype_ops, "ref", None)
    memref_op = getattr(ctype_ops, "memref", None)
    memptr_op = getattr(ctype_ops, "memptr", None)
    ptr_op = getattr(ctype_ops, "ptr", None)
    idx_op = getattr(ctype_ops, "idx", None)
    add_op = getattr(ctype_ops, "add", None)
    sub_op = getattr(ctype_ops, "sub", None)
    num_op = getattr(ctype_ops, "num", None)

    def strip_wrappers(value):
        while value is not None and hasattr(value, "op") and value.op in (cast_op, ref_op):
            value = value.x
        return value

    current = expr
    while current is not None and hasattr(current, "op") and current.op in (cast_op, ref_op):
        current = current.x

    while current is not None and hasattr(current, "op"):
        if current.op in (memref_op, memptr_op):
            base = getattr(current, "x", None)
            if base is None:
                return None, None
            return base, offset + getattr(current, "m", 0)

        if current.op in (ptr_op, idx_op):
            next_scale = scale
            current_type = getattr(current, "type", None)
            get_ptrarr_objsize = getattr(current_type, "get_ptrarr_objsize", None)
            if callable(get_ptrarr_objsize):
                try:
                    next_scale = get_ptrarr_objsize() or scale
                except Exception:
                    next_scale = scale

            index_expr = getattr(current, "y", None)
            if current.op == idx_op and index_expr is not None and getattr(index_expr, "op", None) == num_op:
                offset += index_expr.numval() * next_scale

            current = strip_wrappers(getattr(current, "x", None))
            scale = next_scale
            continue

        if current.op in (add_op, sub_op):
            # Hex-Rays add/sub nodes already encode byte deltas; only idx carries
            # element-size scaling.
            left = strip_wrappers(getattr(current, "x", None))
            right = strip_wrappers(getattr(current, "y", None))
            if left is not None and getattr(left, "op", None) == num_op and right is not None:
                delta = left.numval()
                if current.op == sub_op:
                    delta = -delta
                offset += delta
                current = right
                continue
            if right is not None and getattr(right, "op", None) == num_op and left is not None:
                delta = right.numval()
                if current.op == sub_op:
                    delta = -delta
                offset += delta
                current = left
                continue
            current = left if right is None else right
            continue

        break

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
        self.func_ea = idaapi.BADADDR
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
        result.func_ea = getattr(cfunc, "entry_ea", idaapi.BADADDR)
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

    def identity_key(self):
        return (
            self.id,
            self.name,
            getattr(self, "func_ea", idaapi.BADADDR),
            self.ea,
        )

    def __hash__(self):
        # Preserve distinct scan evidence for the same variable at different locations.
        return hash(self.identity_key())

    def __eq__(self, rhs):
        return isinstance(rhs, ScanObject) and self.identity_key() == rhs.identity_key()

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
        super().__init__()
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
    def _unwrap_call_expression(cexpr: ida_hexrays.cexpr_t):
        expr = cexpr
        while expr is not None and getattr(expr, "op", None) == ctype.cast:
            expr = getattr(expr, "x", None)
        if expr is not None and getattr(expr, "op", None) == ctype.call:
            return expr
        return None

    @staticmethod
    def _normalize_allocator_name(func_name: str) -> str:
        normalized = (func_name or "").strip().lower()
        if not normalized:
            return ""

        normalized = normalized.split("::")[-1].split(".")[-1]
        normalized = re.sub(r"@@.*$", "", normalized)
        normalized = re.sub(r"@\d+$", "", normalized)
        normalized = normalized.replace(" ", "")

        while normalized:
            stripped = normalized.lstrip("_")
            updated = stripped
            for prefix in _ALLOCATOR_NAME_PREFIXES:
                if updated.startswith(prefix):
                    updated = updated[len(prefix):]
                    break
            if updated == normalized:
                normalized = updated
                break
            normalized = updated

        return normalized

    @staticmethod
    def _extract_numeric_argument(args, index: int) -> int:
        if index < 0 or index >= len(args):
            return 0

        expr = args[index]
        while expr is not None and getattr(expr, "op", None) == ctype.cast:
            expr = getattr(expr, "x", None)

        if expr is not None and getattr(expr, "op", None) == ctype.num:
            return expr.numval()
        return 0

    @classmethod
    def _resolve_size(cls, allocator_name: str, args) -> int | None:
        if allocator_name in _SINGLE_SIZE_ALLOCATORS:
            return cls._extract_numeric_argument(
                args, _SINGLE_SIZE_ALLOCATORS[allocator_name]
            )

        if allocator_name in _PRODUCT_SIZE_ALLOCATORS:
            left_index, right_index = _PRODUCT_SIZE_ALLOCATORS[allocator_name]
            return cls._extract_numeric_argument(
                args, left_index
            ) * cls._extract_numeric_argument(args, right_index)

        return None

    @staticmethod
    def create(cfunc: ida_hexrays.cfunc_t, cexpr: ida_hexrays.cexpr_t):
        """
        Creates a new `MemoryAllocationObject` when the expression matches a known allocator call.


        :param cfunc: cfunc_t object representing the current decompiled function
        :param cexpr: cexpr_t object representing the current expression
        :return: a MemoryAllocationObject instance if the expression is a supported allocation, otherwise None
        """
        call_expr = MemoryAllocationObject._unwrap_call_expression(cexpr)
        if call_expr is None:
            return None

        raw_func_name = ida_name.get_short_name(
            getattr(call_expr.x, "obj_ea", idaapi.BADADDR)
        )
        allocator_name = MemoryAllocationObject._normalize_allocator_name(raw_func_name)
        size = MemoryAllocationObject._resolve_size(allocator_name, getattr(call_expr, "a", ()))
        if size is None:
            return None

        result = MemoryAllocationObject(raw_func_name or allocator_name, size)
        result.ea = ScanObject.get_expression_address(cfunc, call_expr)
        result.set_scan_root(
            cfunc.entry_ea,
            expression_ea=result.ea,
            function_name=getattr(ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}")(cfunc.entry_ea),
        )
        return result

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        return True
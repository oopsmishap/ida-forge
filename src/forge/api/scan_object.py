from enum import Enum
import traceback

import ida_hexrays
import idaapi
import ida_name

from forge.api.hexrays import get_member_name, ctype
from forge.util.logging import log_debug


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
            return result
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

        :param cexpr: ida_hexrays.cexpr_t
        :return: returns True if expression is a pointer member of a structure
        """
        return (
            cexpr.op == ctype.memptr
            and cexpr.m == self.offset
            and cexpr.x.type.get_pointed_object().dstr() == self.struct_name
        )


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

        :param cexpr: The expression to check
        :return: True if the expression is a member of the structure, False otherwise
        """
        return (
            cexpr.op == ctype.memref
            and cexpr.m == self.offset
            and cexpr.x.type.dstr() == self.struct_name
        )


class GlobalVariableObject(ScanObject):
    """
    Represents a HexRays global object
    """

    def __init__(self, object_address):
        super(GlobalVariableObject, self).__init__()
        self.ea = object_address
        self.id = ObjectType.global_object
        log_debug(f"Creating GlobalVariableObject {self.ea}")

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        """
        Checks if expression is a global object

        :param cexpr: ida_hexrays.cexpr_t
        :return: returns True if expression is a global variable
        """
        return cexpr.op == ctype.obj and self.ea == cexpr.obj_ea


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

        :param cexpr: ida_hexrays.cexpr_t
        :return: True if expression is the call to the function containing the argument
        """
        return cexpr.op == ctype.call and cexpr.x.obj_ea == self.func_ea

    def create_scan_object(
        self, cfunc: ida_hexrays.cfunc_t, cexpr: ida_hexrays.cexpr_t
    ) -> ScanObject:
        """
        Creates a ScanObject for the argument expression.

        :param cfunc: ida_hexrays.cfunc_t
        :param cexpr: ida_hexrays.cexpr_t
        :return: a ScanObject representing the argument expression
        """
        e = cexpr.a[self.arg_idx]
        while e.op in (ctype.cast, ctype.ref, ctype.add, ctype.sub, ctype.idx):
            e = e.x
        return ScanObject.create(cfunc, e)

    @staticmethod
    def create(cfunc: ida_hexrays.cfunc_t, arg_idx):
        """
        Creates a new CallArgumentObject

        :param cfunc: ida_hexrays.cfunc_t
        :param arg_idx: argument index of variable
        :return: CallArgumentObject
        """
        result = CallArgumentObject(cfunc.entry_ea, arg_idx)
        result.name = cfunc.get_lvars()[arg_idx].name
        result.tinfo = ida_hexrays.cfunc_type(cfunc)
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

        :param cexpr: ida_hexrays.cexpr_t
        :return: Returns True if expression is a call and its object address is the same as the function address
        """
        return cexpr.op == ctype.call and cexpr.x.obj_ea == self.__func_ea


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
        elif cexpr.op == ctype.cast and cexpr.x.op == ctype.call:
            call_expr = cexpr.x
        else:
            return None

        func_name = ida_name.get_short_name(call_expr.x.obj_ea)
        if "malloc" in func_name or "operator new" in func_name or "operator_new" in func_name:
            # if we find `malloc` or `new` we get the size of the allocation
            size_expr = call_expr.a[0]
            # ensure the value is a number, if not set size to zero
            if size_expr.op == ctype.num:
                size = size_expr.numval()
            else:
                size = 0
            result = MemoryAllocationObject(func_name, size)
            result.ea = ScanObject.get_expression_address(cfunc, call_expr)
            return result

    def is_target(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        return True

# standalone hexrays helper functions
from typing import List, Tuple

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import idaapi
import ida_lines
import ida_typeinf
import ida_xref
import ida_nalt
import idc

from forge.api import cache
from forge.api.types import types
from forge.util.logging import *
from forge.util.util import DocIntEnum


def to_hex(ea: int) -> str:
    """
    Formats int to hex string, so it can be double-clicked at console

    :param ea: number to convert to hex string
    :return: Hex string of input int
    """
    if types.width == 8:
        return f"0x{ea:016X}"
    return f"0x{ea:08X}"


def decompile(ea: int):
    try:
        # https://hex-rays.com/products/ida/news/8_2sp1/
        # seems like they've finally fixed the issue of needing to check both exception and return value
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is not None:
            return cfunc
    except ida_hexrays.DecompilationFailure as e:
        log_error(f"Decompilation failed at 0x{ea:X}: {e}")


def get_line(ctree: ida_hexrays.ctree_parentee_t, cfunc) -> str:
    for p in reversed(ctree.parents):
        if not p.is_expr():
            return ida_lines.tag_remove(p.print1(cfunc.__ref__()))
    log_warning("Parent instruction is not found")


def get_ordinal(tinfo: ida_typeinf.tinfo_t):
    ordinal = tinfo.get_ordinal()
    if ordinal == 0:
        struct_name = tinfo.dstr().split()[-1]
        t = ida_typeinf.tinfo_t()
        t.get_named_type(ida_typeinf.cvar.idati, struct_name)
        ordinal = t.get_ordinal()
    return ordinal


def get_ptr(ea):
    if types.width == 8:
        return ida_bytes.get_64bit(ea)
    else:
        ptr = ida_bytes.get_32bit(ea)
        if ida_ida.idainfo.procname == "ARM":
            ptr &= -2  # clear thumb bit
        return ptr


def is_code(ea: int):
    if ida_ida.idainfo.procname == "ARM":
        flags = ida_bytes.get_full_flags(ea & -2)
    else:
        flags = ida_bytes.get_full_flags(ea)
    return ida_bytes.is_code(flags)


def is_imported(ea: int):
    if idc.get_segm_name(ea) == ".plt":
        return True
    return ea + ida_nalt.get_imagebase() in cache.imported_ea


def get_argument(
    cfunc: ida_hexrays.cfunc_t, idx: int
) -> Tuple[ida_hexrays.lvar_t, int]:
    """
    Returns the argument at the specified index in the specified function.
    :param cfunc: The function to get the argument from.
    :param idx: The index of the argument to get.
    :return: The argument at the specified index.
    """
    assert idx < len(cfunc.argidx), f"Argument index {idx} is out of range"
    # arguments are not guaranteed to be in lvar order, so we need to find the correct index from argidx
    arg_idx = cfunc.argidx[idx]
    lvars = cfunc.get_lvars()
    return lvars[arg_idx], arg_idx


def get_func_argument_info(
    function: ida_hexrays.cexpr_t, expression: ida_hexrays.cexpr_t
):
    """
    Returns information about the argument of the specified expression in the specified function.

    :param function: The function expression.
    :param expression: The expression to get argument information for.
    :return: A tuple containing the argument index and t if available, else None.
    """
    log_debug(f"match: {expression.dstr()}, type: {expression.type.dstr()}")
    for idx, arg in enumerate(function.a):
        log_debug(
            f"arg: {idx}, name: {arg.dstr()}, type: {function.x.type.get_nth_arg(idx).dstr()}"
        )
        if expression == arg.cexpr:
            func_tinfo = function.x.type
            if idx < func_tinfo.get_nargs():
                return idx, func_tinfo.get_nth_arg(idx)
            return idx, None
    return None, None


def get_funcs_calling_address(ea):
    """
    Returns a set of function start addresses that call the specified address.

    :param ea: The address to search for.
    :return: A set of function start addresses.
    """
    xref_ea = ida_xref.get_first_cref_to(ea)
    xrefs = set()
    while xref_ea != idaapi.BADADDR:
        xref_func = ida_funcs.get_func(xref_ea)
        if xref_func:
            xrefs.add(xref_func.start_ea)
        else:
            log_warning(f"Could not find function for address 0x{to_hex(xref_ea)}")
        xref_ea = ida_xref.get_next_cref_to(ea, xref_ea)
    return xrefs


def get_member_name(tinfo: ida_typeinf.tinfo_t, offset: int) -> str:
    """
    Acquires the member name based on the given struct/union

    :param tinfo: ida_typeinf.tinfo_t
    :param offset: index of member within struct/union
    :return: Member name
    """
    udt_member = ida_typeinf.udt_member_t()
    udt_member.offset = offset * 4
    tinfo.find_udt_member(udt_member, ida_typeinf.STRMEM_OFFSET)
    return udt_member.name


def is_legal_type(tinfo: ida_typeinf.tinfo_t) -> bool:
    tinfo.clr_const()
    if tinfo.is_ptr() and tinfo.get_pointed_object().is_forward_decl():
        return tinfo.get_pointed_object().get_size() == ida_typeinf.BADSIZE
    # TODO: look into restricting scan types to only those that are legal
    return True


def find_expr_address(cexpr: ida_hexrays.cexpr_t, parents):
    """
    Returns the closest virtual address to the given expression

    :param cexpr: ida_hexrays.cexpr_t
    :param parents:
    :return: Closest virtual address to given expression
    """
    ea = cexpr.ea
    if ea != idaapi.BADADDR:
        return ea
    for p in reversed(parents):
        if p.ea != idaapi.BADADDR:
            return p.ea


def print_expr_address(cexpr: ida_hexrays.cexpr_t, parents) -> str:
    return to_hex(find_expr_address(cexpr, parents))


def ctype_to_str(t):
    if isinstance(t, int):
        return ctype(t).name
    elif isinstance(t, list):
        return [ctype_to_str(x) for x in t]
    else:
        return str(t)


def create_udt_padding_member(offset, size):
    udt_member = ida_typeinf.udt_member_t()
    udt_member.name = f"padding_{offset:x}"
    udt_member.offset = offset
    udt_member.size = size

    if size == 1:
        udt_member.type = types["u8"].type
    else:
        if size < 1 or size > 0xFFFFFFFF:
            raise ValueError(
                f"Size is out of u32 range offset: 0x{offset:x} size: 0x{size:x}"
            )
        array_data = ida_typeinf.array_type_data_t()
        array_data.base = 0
        array_data.elem_type = types["u8"].type
        array_data.nelems = size
        tmp_tinfo = ida_typeinf.tinfo_t()
        tmp_tinfo.create_array(array_data)
        udt_member.type = tmp_tinfo
    return udt_member


# Enums


# noinspection PyPep8Naming
# noinspection SpellCheckingInspection
class e_mopt(DocIntEnum):
    """
    Instruction operand types
    """
    z = 0, "none"
    r = 1, "register (they exist until MMAT_LVARS)"
    n = 2, "immediate number constant"
    str = 3, "immediate string constant"
    d = 4, "result of another instruction"
    S = 5, "local stack variable (they exist until MMAT_LVARS)"
    v = 6, "global variable"
    b = 7, "micro basic block (mblock_t)"
    f = 8, "list of arguments"
    l = 9, "local variable"
    a = 10, "mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)"
    h = 11, "helper function"
    c = 12, "mcases"
    fn = 13, "floating point constant"
    p = 14, "operand pair"
    sc = 15, "scattered"


# noinspection PyPep8Naming
# noinspection SpellCheckingInspection
class ctype(DocIntEnum):
    """
    Ctree item code. At the beginning of this list there are expression
    codes (cot_...), followed by statement codes (cit_...).
    """
    empty = 0, "empty"
    comma = 1, "x, y"
    asg = 2, "x = y"
    asgbor = 3, "x |= y"
    asgxor = 4, "x ^= y"
    asgband = 5, "x &= y"
    asgadd = 6, "x += y"
    asgsub = 7, "x -= y"
    asgmul = 8, "x *= y"
    asgsshr = 9, "x >>= y signed"
    asgushr = 10, "x >>= y unsigned"
    asgshl = 11, "x <<= y"
    asgsdiv = 12, "x /= y signed"
    asgudiv = 13, "x /= y unsigned"
    asgsmod = 14, "x %= y signed"
    asgumod = 15, "x %= y unsigned"
    tern = 16, "x ? y : z"
    lor = 17, "x || y"
    land = 18, "x && y"
    bor = 19, "x | y"
    xor = 20, "x ^ y"
    band = 21, "x & y"
    eq = 22, "x == y int or fpu (see EXFL_FPOP)"
    ne = 23, "x != y int or fpu (see EXFL_FPOP)"
    sge = 24, "x >= y signed or fpu (see EXFL_FPOP)"
    uge = 25, "x >= y unsigned"
    sle = 26, "x <= y signed or fpu (see EXFL_FPOP)"
    ule = 27, "x <= y unsigned"
    sgt = 28, "x > y signed or fpu (see EXFL_FPOP)"
    ugt = 29, "x > y unsigned"
    slt = 30, "x < y signed or fpu (see EXFL_FPOP)"
    ult = 31, "x < y unsigned"
    sshr = 32, "x >> y signed"
    ushr = 33, "x >> y unsigned"
    shl = 34, "x << y"
    add = 35, "x + y"
    sub = 36, "x - y"
    mul = 37, "x * y"
    sdiv = 38, "x / y signed"
    udiv = 39, "x / y unsigned"
    smod = 40, "x % y signed"
    umod = 41, "x % y unsigned"
    fadd = 42, "x + y fp"
    fsub = 43, "x - y fp"
    fmul = 44, "x * y fp"
    fdiv = 45, "x / y fp"
    fneg = 46, "-x fp"
    neg = 47, "-x"
    cast = 48, "(t)x"
    lnot = 49, "!x"
    bnot = 50, "~x"
    ptr = 51, '*x, access size in "ptrsize"'
    ref = 52, "&x"
    postinc = 53, "x++"
    postdec = 54, "x–"
    preinc = 55, "++x"
    predec = 56, "–x"
    call = 57, "x(...)"
    idx = 58, "x[y]"
    memref = 59, "x.m"
    memptr = 60, 'x->m, access size in "ptrsize"'
    num = 61, "n"
    fnum = 62, "fpc"
    str = 63, "string constant (user representation)"
    obj = 64, "obj_ea"
    var = 65, "v"
    insn = 66, "instruction in expression, internal representation only"
    sizeof = 67, "sizeof(x)"
    helper = 68, "arbitrary name"
    type = 69, "arbitrary t"
    cit_empty = 70, "instruction types start here"
    cit_block = 71, "block-statement: { ... }"
    cit_expr = 72, "expression-statement: expr;"
    cit_if = 73, "if-statement"
    cit_for = 74, "for-statement"
    cit_while = 75, "while-statement"
    cit_do = 76, "do-statement"
    cit_switch = 77, "switch-statement"
    cit_break = 78, "break-statement"
    cit_continue = 79, "continue-statement"
    cit_return = 80, "return-statement"
    cit_goto = 81, "goto-statement"
    cit_asm = 82, "asm-statement"
    cit_try = 83, "C++ try-statement"
    cit_throw = 84, "C++ throw-statement"
    cit_end = 85, "end marker"

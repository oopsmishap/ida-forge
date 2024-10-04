import ida_hexrays

from .helper import inverse_if, inverse_if_condition

from forge.api.hexrays import ctype
from forge.util.logging import log_debug


class SwapThenElseVisitor(ida_hexrays.ctree_parentee_t):
    def __init__(self, inverted):
        super().__init__()
        self._inverted = inverted

    def visit_insn(self, insn):
        log_debug(f"visit_insn: {insn.ea:x}")
        if insn.op != ctype.cit_if or insn.cif.ielse is None:
            return 0

        if insn.ea in self._inverted:
            inverse_if(insn.cif)
        return 0

    def apply_to(self, *args):
        if self._inverted:
            super().apply_to(*args)


class SpaghettiVisitor(ida_hexrays.ctree_parentee_t):
    def __init__(self):
        super().__init__()

    def visit_insn(self, insn):
        if insn.op != ctype.cit_block:
            return 0

        while True:
            cblock = insn.cblock
            size = cblock.size()
            # Find block that has "If" and "return" as last 2 statements
            if size < 2:
                break

            if cblock.at(size - 2).op != ctype.cit_if:
                break

            cif = cblock.at(size - 2).cif
            if cblock.back().op != ctype.cit_return or cif.ielse:
                break

            cit_then = cif.ithen

            # Skip if only one (not "if") statement in "then" branch
            if (
                cit_then.cblock.size() == 1
                and cit_then.cblock.front().op != ctype.cit_if
            ):
                return 0

            inverse_if_condition(cif)

            # Take return from list of statements and later put it back
            cit_return = ida_hexrays.cinsn_t()
            cit_return.assign(insn.cblock.back())
            cit_return.thisown = False
            insn.cblock.pop_back()

            # Fill main block with statements from "Then" branch
            while cit_then.cblock:
                insn.cblock.push_back(cit_then.cblock.front())
                cit_then.cblock.pop_front()

            # Put return if there's no other return or GOTO
            if insn.cblock.back().op not in (ctype.cit_return, ctype.cit_goto):
                new_return = ida_hexrays.cinsn_t()
                new_return.thisown = False
                new_return.assign(cit_return)
                insn.cblock.push_back(new_return)

            cit_then.cblock.push_back(cit_return)

        return 0

import ida_hexrays
import ida_kernwin
import ida_idaapi

from forge.api.hooks import HexRaysHook, register_hook
from forge.api.ui_actions import HexRaysPopupAction, register_action
from forge.util.logging import log_debug
from .helper import inverse_if
from .storage import set_inverted, has_inverted, get_inverted
from .visitor import SwapThenElseVisitor, SpaghettiVisitor


@register_action
class SwapThenElse(HexRaysPopupAction):
    name = "SwapThenElse"
    description = "Swap then/else"
    hotkey = "Shift+Ctrl+S"

    def __init__(self):
        super().__init__()

    def check(self, hx_view):
        if hx_view.item.citype != ida_hexrays.VDI_EXPR:
            return False
        insn = hx_view.item.it.to_specific_type
        if insn.op != ida_hexrays.cit_if or insn.cif.ielse is None:
            return False
        return insn.op == ida_hexrays.cit_if and insn.cif.ielse

    def activate(self, ctx):
        hx_view = ida_hexrays.get_widget_vdui(ctx.widget)
        if self.check(hx_view):
            insn = hx_view.item.it.to_specific_type
            inverse_if(insn.cif)
            hx_view.refresh_ctext()

            log_debug(
                f"Setting inverted for {hex(hx_view.cfunc.entry_ea)}: {hex(insn.ea)}"
            )
            set_inverted(hx_view.cfunc.entry_ea, insn.ea)

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


@register_hook
class SilentIfSwapper(HexRaysHook):
    name = "SilentIfSwapper"

    def __init__(self):
        super().__init__()

    def maturity(self, *args):
        cfunc, level_of_maturity = args

        if level_of_maturity == ida_hexrays.CMAT_TRANS1 and has_inverted(
            cfunc.entry_ea
        ):
            log_debug(f"Swapping then/else in {hex(cfunc.entry_ea)}")
            inverted = [
                n + ida_idaapi.get_imagebase() for n in get_inverted(cfunc.entry_ea)
            ]
            log_debug(f"Got inverted: {inverted}")
            visitor = SwapThenElseVisitor(inverted)
            visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == ida_hexrays.CMAT_TRANS2:
            visitor = SpaghettiVisitor()
            visitor.apply_to(cfunc.body, None)

        return 0

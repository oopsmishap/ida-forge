import ida_hexrays
import ida_kernwin

from forge.api.ctree_transform import SilentIfSwapper  # F.6: hook moved to the DSL core
from forge.api.hooks import register_hook
from forge.api.ui_actions import HexRaysPopupAction, register_action
from forge.util.logging import log_debug

from .helper import inverse_if
from .storage import set_inverted


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


register_hook(SilentIfSwapper)  # F.6: the class moved to forge.api.ctree_transform

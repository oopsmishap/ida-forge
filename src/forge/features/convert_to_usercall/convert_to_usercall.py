import ida_hexrays
import ida_typeinf

from forge.api.config import ForgeConfig
from forge.api.ui_actions import HexRaysPopupAction, register_action
from forge.util.logging import *


class ConvertToUsercallConfig(ForgeConfig):
    name = "ConvertToUsercall"
    default_config = {
        "enabled": True,
    }


@register_action
class ConvertToUsercall(HexRaysPopupAction):
    name = "ConvertToUsercall"
    description = "Convert to __usercall"
    hotkey = None

    def __init__(self):
        super().__init__()
        self.config = ConvertToUsercallConfig()

    def check(self, hx_view):
        return hx_view.item.citype == ida_hexrays.VDI_FUNC

    def activate(self, ctx):
        log_debug("Converting to __usercall")
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        function_tinfo = ida_typeinf.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            log_debug("Failed to get function t")
            return
        function_details = ida_typeinf.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        convention = ida_typeinf.CM_CC_MASK & function_details.cc
        if convention == ida_typeinf.CM_CC_CDECL:
            function_details.cc = ida_typeinf.CM_CC_SPECIAL
        elif convention in (
            ida_typeinf.CM_CC_STDCALL,
            ida_typeinf.CM_CC_FASTCALL,
            ida_typeinf.CM_CC_THISCALL,
            ida_typeinf.CM_CC_PASCAL,
        ):
            function_details.cc = ida_typeinf.CM_CC_SPECIALP
        elif convention == ida_typeinf.CM_CC_ELLIPSIS:
            function_details.cc = ida_typeinf.CM_CC_SPECIALE
        else:
            log_debug("Unknown calling convention")
            return

        function_tinfo.create_func(function_details)
        ida_typeinf.apply_tinfo(
            vu.cfunc.entry_ea, function_tinfo, ida_typeinf.TINFO_DEFINITE
        )
        vu.refresh_view(True)

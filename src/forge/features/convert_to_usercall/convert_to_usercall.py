from __future__ import annotations

from typing import ClassVar

import ida_hexrays
import ida_typeinf

from forge.api.config import ForgeConfig
from forge.api.ui_actions import HexRaysPopupAction, register_action
from forge.util.logging import log_debug


def _cc_of(details):
    get_cc = getattr(details, "get_cc", None)
    if callable(get_cc):
        return get_cc()
    return details.cc


def _set_cc(details, cc) -> None:
    set_cc = getattr(details, "set_cc", None)
    if callable(set_cc):
        set_cc(cc)
        return
    details.cc = cc


def convert_to_usercall(cfunc) -> str | None:
    """Convert ``cfunc``'s calling convention to a ``__usercall`` family.

    Shared by :class:`ConvertToUsercall` (widget-driven) and the headless
    ``forge_api`` facade. Returns the convention name on success
    (``"__usercall"``, ``"__usercall_"``, ``"__usercalle_"``) or ``None``
    when the function has no type or an unrecognized convention.
    """
    function_tinfo = ida_typeinf.tinfo_t()
    if not cfunc.get_func_type(function_tinfo):
        log_debug("Failed to get function t")
        return None
    function_details = ida_typeinf.func_type_data_t()
    function_tinfo.get_func_details(function_details)
    convention = ida_typeinf.CM_CC_MASK & _cc_of(function_details)
    if convention == ida_typeinf.CM_CC_CDECL:
        _set_cc(function_details, ida_typeinf.CM_CC_SPECIAL)
        convention_name = "__usercall"
    elif convention in (
        ida_typeinf.CM_CC_STDCALL,
        ida_typeinf.CM_CC_FASTCALL,
        ida_typeinf.CM_CC_THISCALL,
        ida_typeinf.CM_CC_PASCAL,
    ):
        _set_cc(function_details, ida_typeinf.CM_CC_SPECIALP)
        convention_name = "__usercall_"
    elif convention == ida_typeinf.CM_CC_ELLIPSIS:
        _set_cc(function_details, ida_typeinf.CM_CC_SPECIALE)
        convention_name = "__usercalle_"
    else:
        log_debug("Unknown calling convention")
        return None

    function_tinfo.create_func(function_details)
    ida_typeinf.apply_tinfo(cfunc.entry_ea, function_tinfo, ida_typeinf.TINFO_DEFINITE)
    return convention_name


class ConvertToUsercallConfig(ForgeConfig):
    name = "ConvertToUsercall"
    default_config: ClassVar[dict] = {
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
        return (
            self.config["enabled"]
            and hx_view.item.citype == ida_hexrays.VDI_FUNC
        )

    def activate(self, ctx):
        log_debug("Converting to __usercall")
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        name = convert_to_usercall(vu.cfunc)
        if name:
            log_debug(f"Converted to {name}")
            vu.refresh_view(True)

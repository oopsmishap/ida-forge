import re
from typing import ClassVar

import ida_hexrays
import ida_idaapi
import ida_typeinf

from forge.api.config import ForgeConfig
from forge.api.hexrays import create_udt_padding_member
from forge.api.types import types
from forge.api.ui_actions import HexRaysPopupAction, register_action
from forge.util.logging import log_error, log_warning


class CreateNewFieldConfig(ForgeConfig):
    name = "CreateNewField"
    default_config: ClassVar[dict] = {"enabled": True, "hotkey": "Ctrl+F"}


_config = CreateNewFieldConfig()


@register_action
class CreateNewField(HexRaysPopupAction):
    name = "CreateNewField"
    description = "Create new field"
    hotkey = _config["hotkey"]

    def __init__(self):
        if _config["enabled"]:
            super().__init__()

    def check(self, hx_view):
        """Checks if the current item is a gap member within a structure."""
        item = hx_view.item
        if item.citype != ida_hexrays.VDI_EXPR:
            return False

        cexpr = item.it.to_specific_type
        return cexpr.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref)

        # TODO: Look into why the names do not match what is being attempted to apply
        # struct_type = cexpr.x.type
        # struct_type.remove_ptr_or_array()
        # member_name = get_member_name(struct_type, cexpr.m)
        # return "gap" in member_name

    def activate(self, ctx):
        hx_view: ida_hexrays.vdui_t = ida_hexrays.get_widget_vdui(ctx.widget)
        if not self.check(hx_view):
            return

        item = hx_view.item.it.to_specific_type
        parent = hx_view.cfunc.body.find_parent_of(item).to_specific_type

        idx = (
            parent.y.numval()
            if parent.op == ida_hexrays.cot_idx and parent.y.op == ida_hexrays.cot_num
            else 0
        )

        struct_tinfo = item.x.type
        struct_tinfo.remove_ptr_or_array()

        offset = item.m

        if (offset + idx) % 2:
            default_field_type = types["u8"].name
        elif (offset + idx) % 4:
            default_field_type = types["u16"].name
        elif (offset + idx) % 8:
            default_field_type = types["u32"].name
        else:
            default_field_type = types.get_ptr_type().name

        declaration = ida_idaapi.ask_text(
            0x10000,
            f"{default_field_type} field_{offset + idx:X}",
            "Enter new structure member:",
        )
        if declaration is None:
            return

        apply_new_field(struct_tinfo, offset, idx, declaration)
        hx_view.refresh_view(True)

    @staticmethod
    def parse_declaration(declaration):
        m = re.match(
            r"^(\w+[ *]+)(\w+)(\[(\d+)\])?$", declaration
        )  # Use re.match for beginning of string
        if not m:
            log_error(
                "Member declaration should be like `TYPE_NAME NAME[SIZE]` (Array is optional)",
                True,
            )
            return None, None

        type_name, field_name, _, arr_size = m.groups()
        if field_name[0].isdigit():
            log_error("Bad field name", True)
            return None, None

        result = ida_idaapi.idc_parse_decl(type_name, 0)
        if result is None:
            log_error("Failed to parse member type.", True)
            return None, None

        _, tp, fld = result
        tinfo = ida_typeinf.tinfo_t()
        tinfo.deserialize(ida_typeinf.get_idati(), tp, fld, None)
        if arr_size:
            tinfo.create_array(tinfo, int(arr_size))
        return tinfo, field_name


def apply_new_field(struct_tinfo, offset: int, idx: int, declaration: str) -> bool:
    """Insert a new field into an existing struct type (headless).

    Shared by :class:`CreateNewField` (widget-driven) and the ``forge_api``
    facade. ``offset`` is the struct gap's byte offset, ``idx`` the byte
    offset of the new field inside that gap, and ``declaration`` a
    ``TYPE_NAME NAME[SIZE]`` string. Returns ``True`` on success (the
    numbered type is rewritten in place); on failure logs and returns
    ``False``.
    """
    result = CreateNewField.parse_declaration(declaration)
    if result is None:
        log_warning("Bad member declaration!", True)
        return False

    field_tinfo, field_name = result
    field_size = field_tinfo.get_size()
    udt_data = ida_typeinf.udt_type_data_t()
    udt_member = ida_typeinf.udt_member_t()

    struct_tinfo.get_udt_details(udt_data)
    udt_member.offset = offset * 8
    struct_tinfo.find_udt_member(udt_member, ida_typeinf.STRMEM_OFFSET)
    gap_size = udt_member.size // 8

    gap_leftover = gap_size - idx - field_size

    if gap_leftover < 0:
        log_error(
            f"Too big size for the field. Type with maximum {gap_size - idx} bytes can be used"
        )
        return False

    iterator = udt_data.find(udt_member)
    iterator = udt_data.erase(iterator)

    if gap_leftover > 0:
        udt_data.insert(
            iterator,
            create_udt_padding_member(offset + idx + field_size, gap_leftover),
        )

    udt_member = ida_typeinf.udt_member_t()
    udt_member.offset = offset * 8 + idx
    udt_member.name = field_name
    udt_member.type = field_tinfo
    udt_member.size = field_size

    iterator = udt_data.insert(iterator, udt_member)

    if idx > 0:
        udt_data.insert(iterator, create_udt_padding_member(offset, idx))

    struct_tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT)
    struct_tinfo.set_numbered_type(
        ida_typeinf.get_idati(),
        struct_tinfo.get_ordinal(),
        ida_typeinf.BTF_STRUCT,
        struct_tinfo.dstr(),
    )
    return True

import idaapi
import idc
import re

from forge.api.config import ForgeConfig
from forge.api.hexrays import get_member_name, create_udt_padding_member
from forge.api.types import types
from forge.api.ui_actions import HexRaysPopupAction, register_action
from forge.util.logging import *


class CreateNewFieldConfig(ForgeConfig):
    name = "CreateNewField"
    default_config = {"enabled": True, "hotkey": "Ctrl+F"}


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
        if item.citype != idaapi.VDI_EXPR:
            return False

        cexpr = item.it.to_specific_type
        if cexpr.op not in (idaapi.cot_memptr, idaapi.cot_memref):
            log_warning(f"{cexpr.dstr()} is not a member pointer!")
            return False

        return True

        # TODO: Look into why the names do not match what is being attempted to apply
        # struct_type = cexpr.x.type
        # struct_type.remove_ptr_or_array()
        # member_name = get_member_name(struct_type, cexpr.m)
        # return "gap" in member_name

    def activate(self, ctx):
        hx_view: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        if not self.check(hx_view):
            return

        item = hx_view.item.it.to_specific_type
        parent = hx_view.cfunc.body.find_parent_of(item).to_specific_type

        idx = (
            parent.y.numval()
            if parent.op == idaapi.cot_idx and parent.y.op == idaapi.cot_num
            else 0
        )

        struct_tinfo = item.x.type
        struct_tinfo.remove_ptr_or_array()

        offset = item.m
        ordinal = struct_tinfo.get_ordinal()
        struct_name = struct_tinfo.dstr()

        if (offset + idx) % 2:
            default_field_type = types["u8"].name
        elif (offset + idx) % 4:
            default_field_type = types["u16"].name
        elif (offset + idx) % 8:
            default_field_type = types["u32"].name
        else:
            default_field_type = types.get_ptr_type().name

        declaration = idaapi.ask_text(
            0x10000,
            f"{default_field_type} field_{offset + idx:X}",
            "Enter new structure member:",
        )
        if declaration is None:
            return

        result = self.parse_declaration(declaration)
        if result is None:
            log_warning("Bad member declaration!", True)
            return

        field_tinfo, field_name = result
        field_size = field_tinfo.get_size()
        udt_data = idaapi.udt_type_data_t()
        udt_member = idaapi.udt_member_t()

        struct_tinfo.get_udt_details(udt_data)
        udt_member.offset = offset * 8
        struct_tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
        gap_size = udt_member.size // 8

        gap_leftover = gap_size - idx - field_size

        if gap_leftover < 0:
            log_error(
                f"Too big size for the field. Type with maximum {gap_size - idx} bytes can be used"
            )
            return

        iterator = udt_data.find(udt_member)
        iterator = udt_data.erase(iterator)

        if gap_leftover > 0:
            udt_data.insert(
                iterator,
                create_udt_padding_member(offset + idx + field_size, gap_leftover),
            )

        udt_member = idaapi.udt_member_t()
        udt_member.offset = offset * 8 + idx
        udt_member.name = field_name
        udt_member.type = field_tinfo
        udt_member.size = field_size

        iterator = udt_data.insert(iterator, udt_member)

        if idx > 0:
            udt_data.insert(iterator, create_udt_padding_member(offset, idx))

        struct_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        struct_tinfo.set_numbered_type(
            idaapi.get_idati(), ordinal, idaapi.BTF_STRUCT, struct_name
        )
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

        result = idc.parse_decl(type_name, 0)
        if result is None:
            log_error("Failed to parse member type.", True)
            return None, None

        _, tp, fld = result
        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(idaapi.get_idati(), tp, fld, None)
        if arr_size:
            tinfo.create_array(tinfo, int(arr_size))
        return tinfo, field_name

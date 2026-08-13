import re
from typing import ClassVar

import ida_hexrays
import ida_idaapi
import ida_typeinf
import idc

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

        # E1 (eval review 2026-08-13): ``ida_idaapi.idc_parse_decl`` does not
        # exist on IDA 9.4 and ``idc.parse_decl`` is the legacy 2-arg
        # (decl, flags) form returning (ret, tp, fld) — deserialize the
        # type bytes; accept a direct tinfo return on newer builds too.
        result = idc.parse_decl(type_name, ida_typeinf.PT_TYP)
        if isinstance(result, tuple):
            _, tp, fld = result
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.deserialize(ida_typeinf.get_idati(), tp, fld, None):
                log_error("Failed to parse member type.", True)
                return None, None
        else:
            tinfo = result
        if tinfo is None:
            log_error("Failed to parse member type.", True)
            return None, None
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
    struct_name = struct_tinfo.get_type_name() or struct_tinfo.dstr()

    # IDA 9.x keeps udt member offsets in BYTES (the pre-9 bit convention
    # lands every member 8x out and silently fails the gap math — eval
    # review round 2 §3.2: create_field returned True/False with no
    # persisted change).
    udt_member.offset = offset
    struct_tinfo.find_udt_member(udt_member, ida_typeinf.STRMEM_OFFSET)
    gap_size = udt_member.size

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
    udt_member.offset = offset + idx
    udt_member.name = field_name
    udt_member.type = field_tinfo
    udt_member.size = field_size

    iterator = udt_data.insert(iterator, udt_member)

    if idx > 0:
        udt_data.insert(iterator, create_udt_padding_member(offset, idx))

    struct_tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT)

    # Commit through the same delete+re-file path the vtable importer uses
    # (members.py import_to_structures — live-proven on 9.4);
    # ``set_numbered_type``'s argument shape drifted across versions, so
    # the in-memory udt is serialized to a full cdecl instead.
    import idaapi as _idaapi

    cdecl = _idaapi.print_tinfo(
        None,
        4,
        5,
        _idaapi.PRTYPE_MULTI | _idaapi.PRTYPE_TYPE | _idaapi.PRTYPE_SEMI,
        struct_tinfo,
        struct_name,
        None,
    )
    if not cdecl:
        log_error("Failed to serialize the updated struct declaration", True)
        return False
    previous_ordinal = _idaapi.get_type_ordinal(_idaapi.cvar.idati, struct_name)
    if previous_ordinal:
        _idaapi.del_numbered_type(_idaapi.cvar.idati, previous_ordinal)
        ordinal = _idaapi.idc_set_local_type(previous_ordinal, cdecl, _idaapi.PT_TYP)
    else:
        ordinal = _idaapi.idc_set_local_type(-1, cdecl, _idaapi.PT_TYP)
    if not ordinal:
        log_error(f"Failed to re-file {struct_name} after field insert", True)
        return False
    return True

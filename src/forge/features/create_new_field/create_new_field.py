from __future__ import annotations

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


    @staticmethod
    def _default_type_for_offset(offset: int) -> str:
        if offset % types.width == 0:
            return types.get_ptr_type().name
        if offset % 4 == 0:
            return types["u32"].name
        if offset % 2 == 0:
            return types["u16"].name
        return types["u8"].name

    @staticmethod
    def _element_size_of(expr) -> int:
        tinfo = getattr(expr, "type", None)
        if tinfo is None:
            return 1
        try:
            if tinfo.is_ptr():
                element = tinfo.get_pointed_object()
            elif tinfo.is_array():
                element = tinfo.get_array_element()
            else:
                return 1
            size = element.get_size() if element is not None else 1
            return size if size and size > 0 else 1
        except Exception:  # noqa: BLE001 — degraded tinfo on partial decompile
            return 1

    @staticmethod
    def _numeric_operand(binary_expr, current):
        other = None
        if hasattr(binary_expr, "theother"):
            try:
                other = binary_expr.theother(current)
            except Exception:  # noqa: BLE001 — best-effort operand lookup
                other = None
        candidates = [
            other,
            getattr(binary_expr, "y", None),
            getattr(binary_expr, "x", None),
        ]
        for candidate in candidates:
            if candidate is not None and candidate.op == ida_hexrays.cot_num:
                return candidate.numval()
        return None

    def _offset_delta_from_context(self, item, cfunc) -> int:
        """Total byte offset the parent chain adds to the clicked member.

        Handles ``field[idx]`` (scaled) and ``(char *)&field + N`` (byte)
        forms, transparently walking through casts and the address-of
        operator, so a field created on ``*(T *)((char *)&this->field + 2)``
        lands at ``field + 2``.
        """
        delta = 0
        current = item
        for _ in range(8):
            parent = cfunc.body.find_parent_of(current)
            if parent is None or not parent.is_expr():
                break
            parent_expr = parent.to_specific_type
            op = parent_expr.op
            if op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
                current = parent_expr
                continue
            if op in (ida_hexrays.cot_add, ida_hexrays.cot_sub):
                number = self._numeric_operand(parent_expr, current)
                if number is None:
                    break
                sign = -1 if op == ida_hexrays.cot_sub else 1
                delta += sign * number * self._element_size_of(current)
                current = parent_expr
                continue
            if op == ida_hexrays.cot_idx:
                index = getattr(parent_expr, "y", None)
                if index is None or index.op != ida_hexrays.cot_num:
                    break
                delta += index.numval() * self._element_size_of(current)
                current = parent_expr
                continue
            break
        return delta

    @staticmethod
    def _guess_type_from_context(cexpr, cfunc):
        """Walk the expression's parent chain looking for a cast that reveals
        the field's actual type. For the ``*(T *)field`` pattern the field
        holds a ``T`` (the pointee), so unwrap one level; otherwise return
        the cast."""
        current = cexpr
        for _ in range(5):
            parent = cfunc.body.find_parent_of(current)
            if parent is None or not parent.is_expr():
                break
            parent_expr = parent.to_specific_type
            if parent_expr.op == ida_hexrays.cot_cast:
                cast_type = getattr(parent_expr, "type", None)
                grandparent = cfunc.body.find_parent_of(parent_expr)
                if (
                    cast_type is not None
                    and cast_type.is_ptr()
                    and grandparent is not None
                    and grandparent.is_expr()
                    and grandparent.to_specific_type.op == ida_hexrays.cot_ptr
                ):
                    return cast_type.get_pointed_object()
                return cast_type
            current = parent_expr
        return None

    def activate(self, ctx):
        hx_view: ida_hexrays.vdui_t = ida_hexrays.get_widget_vdui(ctx.widget)
        if not self.check(hx_view):
            return

        item = hx_view.item.it.to_specific_type
        idx = self._offset_delta_from_context(item, hx_view.cfunc)

        struct_tinfo = item.x.type
        struct_tinfo.remove_ptr_or_array()

        offset = item.m
        field_offset = offset + idx
        guessed_tinfo = self._guess_type_from_context(item, hx_view.cfunc)
        if guessed_tinfo is not None:
            default_field_type = guessed_tinfo.dstr()
        else:
            default_field_type = self._default_type_for_offset(field_offset)

        default_field_name = f"field_{field_offset:X}"
        declaration = ida_idaapi.ask_text(
            0x10000,
            f"{default_field_type} {default_field_name}",
            "Enter new structure member:",
        )
        if declaration is None:
            return

        parsed = self.parse_declaration(declaration)
        if parsed == (None, None) and guessed_tinfo is not None:
            # Complex type (e.g. function pointer) that cannot round-trip
            # through a ``TYPE NAME`` string; use the guessed tinfo directly.
            name_match = re.search(r"(\w+)(?:\[\d+\])?\s*$", declaration.strip())
            field_name = name_match.group(1) if name_match else default_field_name
            apply_new_field(
                struct_tinfo,
                offset,
                idx,
                field_tinfo=guessed_tinfo,
                field_name=field_name,
            )
        else:
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


_GAP_NAME_RE = re.compile(r"gap(?:_[0-9a-fA-F]+)?")
_FIELD_NAME_RE = re.compile(r"field_[0-9a-fA-F]+")
_ANONYMOUS_NAME_RE = re.compile(r"anonymous(?:_[0-9a-fA-F]+)?")
_TYPED_GAP_NAME_RE = re.compile(r"(?:u|i|f)\d+_[0-9a-fA-F]+")
_LEGACY_GAP_NAME_RE = re.compile(r"gap[0-9a-fA-F]+")


def _is_byte_array_padding(member) -> bool:
    """True when the member is an autogenerated byte-array padding blob."""
    tinfo = getattr(member, "type", None)
    if tinfo is None:
        return False
    try:
        if not tinfo.is_array():
            return False
        element = tinfo.get_array_element()
        if element is None or element.get_size() != 1:
            return False
        # IDA 9.x udt offsets/sizes are BYTES in this codebase.
        return tinfo.get_size() == member.size
    except (AttributeError, TypeError, ValueError):
        return False


def _is_consumable_member(member) -> bool:
    """True when an overlapping member is autogenerated padding we may
    replace; user-named members are never consumed."""
    name = getattr(member, "name", "") or ""
    if not name:
        return True
    if (
        _GAP_NAME_RE.fullmatch(name)
        or _FIELD_NAME_RE.fullmatch(name)
        or _ANONYMOUS_NAME_RE.fullmatch(name)
        or _TYPED_GAP_NAME_RE.fullmatch(name)
    ):
        return True
    return bool(
        _LEGACY_GAP_NAME_RE.fullmatch(name) and _is_byte_array_padding(member)
    )


def apply_new_field(
    struct_tinfo,
    offset: int,
    idx: int,
    declaration: str | None = None,
    *,
    field_tinfo=None,
    field_name: str | None = None,
) -> bool:
    """Insert a new field into an existing struct type (headless).

    Shared by :class:`CreateNewField` (widget-driven) and the ``forge_api``
    facade. ``offset`` is the struct gap's byte offset, ``idx`` the byte
    offset of the new field inside that gap, and ``declaration`` a
    ``TYPE_NAME NAME[SIZE]`` string. Alternatively pass a pre-resolved
    ``field_tinfo``/``field_name`` pair (used when the GUI guessed a type
    that cannot round-trip through a declaration string). Overlapping
    autogenerated gap/placeholder members are consumed so a field larger
    than its starting gap still lands; overlapping user-named members are
    reported as conflicts instead of destroyed. Returns ``True`` on success
    (the numbered type is rewritten in place); on failure logs and returns
    ``False``.
    """
    if declaration is not None:
        result = CreateNewField.parse_declaration(declaration)
        if result is None or result == (None, None):
            log_warning("Bad member declaration!", True)
            return False
        field_tinfo, field_name = result

    if field_tinfo is None or not field_name:
        log_warning("Bad member declaration!", True)
        return False

    field_size = field_tinfo.get_size()
    if not field_size or field_size <= 0:
        log_warning("Cannot determine the size of the new field type.", True)
        return False

    udt_data = ida_typeinf.udt_type_data_t()
    struct_tinfo.get_udt_details(udt_data)
    struct_name = struct_tinfo.get_type_name() or struct_tinfo.dstr()

    # IDA 9.x keeps udt member offsets in BYTES (the pre-9 bit convention
    # lands every member 8x out and silently fails the gap math — eval
    # review round 2 §3.2: create_field returned True/False with no
    # persisted change).
    field_start = offset + idx
    field_end = field_start + field_size

    # Consume every autogenerated member overlapping the new field's byte
    # range so the field can be created even when it is larger than the
    # gap it starts in.
    kept: list = []
    overlapping: list = []
    for index in range(len(udt_data)):
        member = udt_data[index]
        member_start = member.offset
        member_end = member.offset + member.size
        if member_end <= field_start or member_start >= field_end:
            kept.append(member)
        else:
            overlapping.append(member)

    if not overlapping:
        log_error(
            f"No room for the field at 0x{field_start:X}: no member covers that offset"
        )
        return False

    conflicts = [
        getattr(member, "name", "") or f"member_{member.offset:X}"
        for member in overlapping
        if not _is_consumable_member(member)
    ]
    if conflicts:
        log_warning(
            f"Cannot create {field_name} at 0x{field_start:X}: it overlaps "
            f"user-defined member(s) {', '.join(conflicts)}. Rename or remove "
            "them first.",
            True,
        )
        return False

    covered_start = field_start
    covered_end = field_end
    for member in overlapping:
        covered_start = min(covered_start, member.offset)
        covered_end = max(covered_end, member.offset + member.size)

    new_field = ida_typeinf.udt_member_t()
    new_field.offset = field_start
    new_field.name = field_name
    new_field.type = field_tinfo
    new_field.size = field_size

    rebuilt = list(kept)
    rebuilt.append(new_field)
    if covered_start < field_start:
        rebuilt.append(
            create_udt_padding_member(covered_start, field_start - covered_start)
        )
    if covered_end > field_end:
        rebuilt.append(
            create_udt_padding_member(field_end, covered_end - field_end)
        )
    rebuilt.sort(key=lambda member: member.offset)

    new_udt = ida_typeinf.udt_type_data_t()
    for member in rebuilt:
        new_udt.push_back(member)

    if not struct_tinfo.create_udt(new_udt, ida_typeinf.BTF_STRUCT):
        log_error(f"Failed to rebuild structure {struct_name}.", True)
        return False

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
        # Replace in place first: deleting the IDB type before the re-file
        # leaves no type behind if idc_set_local_type fails (data-loss window).
        if _idaapi.idc_set_local_type(previous_ordinal, cdecl, _idaapi.PT_TYP):
            return True
        # Live-proven delete+re-create fallback (members.py import_to_structures
        # on 9.4): drop the stale entry, then re-file fresh.
        _idaapi.del_numbered_type(_idaapi.cvar.idati, previous_ordinal)
        ordinal = _idaapi.idc_set_local_type(-1, cdecl, _idaapi.PT_TYP)
    else:
        ordinal = _idaapi.idc_set_local_type(-1, cdecl, _idaapi.PT_TYP)
    if not ordinal:
        log_error(f"Failed to re-file {struct_name} after field insert", True)
        return False
    return True

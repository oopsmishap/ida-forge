from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge.api.structure import Structure

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_typeinf
import idaapi

from forge.api.domain import current_database as _current_domain_database
from forge.api.domain import try_domain_method as _try_domain_method
from forge.api.hexrays import (
    ctype,
    ctype_to_str,
    decompile,
    find_expr_address,
    get_func_argument_info,
    is_code,
    is_legal_type,
    to_hex,
)
from forge.api.scan_object import ObjectType, ScanObject, _extract_offset_expression
from forge.api.tinfo import is_incomplete_tinfo
from forge.api.types import types
from forge.api.visitor import (
    DownwardsObjectVisitor,
    ObjectVisitor,
    RecursiveCallFrame,
    RecursiveDownwardsObjectVisitor,
)


def _function_at(ea: int):
    handled, function = _try_domain_method(
        _current_domain_database(required=False),
        "functions",
        "get_at",
        ea,
        capability="functions.scanner",
        unavailable_reason="ida-domain scanner function lookup unavailable on this build/session",
        failure_reason="ida-domain scanner function lookup failed",
        exceptions=(Exception,),
    )
    if handled:
        return function
    return ida_funcs.get_func(ea)


def _function_name(ea: int) -> str:
    function = _function_at(ea)
    if function is not None and hasattr(function, "name"):
        return function.name or ""
    return ida_funcs.get_func_name(ea)
from forge.util.logging import log_debug, log_warning


@dataclass
class ParentExpressionContext:
    expressions: list[ida_hexrays.cexpr_t]

    @property
    def ops(self) -> list[ctype]:
        return [expression.op for expression in self.expressions]

    def expr_at(self, index: int) -> ida_hexrays.cexpr_t | None:
        return self.expressions[index] if index < len(self.expressions) else None

    def op_at(self, index: int) -> ctype | None:
        ops = self.ops
        return ops[index] if index < len(ops) else None

    def pop_front(self, count: int = 1) -> None:
        del self.expressions[:count]


class ScannedObject:
    def __init__(
        self,
        name: str,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ):
        self.name = name
        self.ea = expression_address
        self.func_ea = self._get_function_start(expression_address)
        self.origin = origin
        self.scan_root_ea = idaapi.BADADDR
        self.scan_root_function_ea = idaapi.BADADDR
        self.scan_root_function_name = None
        self._applicable = applicable

    def inherit_scan_root_from(self, other: ScanObject) -> None:
        if getattr(other, "scan_root_function_ea", idaapi.BADADDR) != idaapi.BADADDR:
            self.scan_root_function_ea = other.scan_root_function_ea
        if getattr(other, "scan_root_ea", idaapi.BADADDR) != idaapi.BADADDR:
            self.scan_root_ea = other.scan_root_ea
        if getattr(other, "scan_root_function_name", None):
            self.scan_root_function_name = other.scan_root_function_name


    @staticmethod
    def _get_function_start(ea: int) -> int:
        func = _function_at(ea)
        return func.start_ea if func is not None else idaapi.BADADDR

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
        raise NotImplementedError

    @staticmethod
    def create(
        obj: ScanObject,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ) -> ScannedObject:
        obj_id = obj.id
        if obj_id == ObjectType.global_object:
            result = ScannedGlobalObject(
                obj.object_ea, obj.name, expression_address, origin, applicable
            )
        elif obj_id == ObjectType.local_variable:
            result = ScannedVariableObject(
                obj.lvar, obj.name, expression_address, origin, applicable
            )
        elif obj_id in (ObjectType.structure_pointer, ObjectType.structure_reference):
            result = ScannedStructureMemberObject(
                obj.struct_name, obj.name, expression_address, origin, applicable
            )
        else:
            raise AssertionError(f"Unsupported scan object type: {obj_id}")

        for attr in ("scan_root_function_ea", "scan_root_ea", "scan_root_function_name"):
            value = getattr(obj, attr, None)
            if value is not None and value != idaapi.BADADDR:
                setattr(result, attr, value)
        return result

    @property
    def function_name(self) -> str:
        if self.func_ea == idaapi.BADADDR:
            return "<unknown>"
        return _function_name(self.func_ea)

    def to_list(self) -> list[str]:
        """Return a row suitable for an IDA chooser widget."""
        return [
            f"0x{self.origin:04X}",
            self.function_name,
            self.name,
            to_hex(self.ea),
        ]

    def identity_key(self) -> tuple[int, int, object, str]:
        return (
            self.func_ea,
            self.ea,
            getattr(self, "id", None),
            self.name,
        )

    def __hash__(self):
        return hash(self.identity_key())

    def __eq__(self, other):
        if other is None:
            return False

        other_identity_key = getattr(other, "identity_key", None)
        if callable(other_identity_key):
            return self.identity_key() == other_identity_key()

        return self.identity_key() == (
            getattr(other, "func_ea", None),
            getattr(other, "ea", None),
            getattr(other, "id", None),
            getattr(other, "name", None),
        )

    def __repr__(self):
        return f"{self.name} @ {hex(self.ea)}"


class ScannedGlobalObject(ScannedObject):
    def __init__(
        self,
        obj_ea: int,
        name: str,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ):
        super().__init__(name, expression_address, origin, applicable)
        self._obj_ea = obj_ea

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
        ida_typeinf.apply_tinfo(self._obj_ea, tinfo, ida_typeinf.TINFO_DEFINITE)


class ScannedVariableObject(ScannedObject):
    def __init__(
        self,
        lvar: ida_hexrays.lvar_t,
        name: str,
        expression_address: int,
        origin: int,
        applicable: bool = True,
    ):
        super().__init__(name, expression_address, origin, applicable)
        self._lvar = ida_hexrays.lvar_locator_t(lvar.location, lvar.defea)

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
        if not self._applicable:
            return

        try:
            cfunc = decompile(self.func_ea)
        except Exception:  # noqa: BLE001 — GUI/hx version tolerance
            log_warning(
                f"Failed to re-decompile {self.function_name} to apply "
                f"{to_hex(self.ea)}"
            )
            return

        # Headless-safe replacement for the GUI-only ``vdui_t.set_lvar_type``
        # (``open_pseudocode`` crashes native in idalib). Commits the type via
        # ``modify_user_lvar_info`` with the ``MLI_TYPE`` flag — the same
        # mechanism the headless root-retype uses.
        lvar = next(
            (
                x
                for x in list(cfunc.get_lvars())
                if x.location == self._lvar.location and x.defea == self._lvar.defea
            ),
            None,
        )
        if lvar is None:
            log_warning(
                f"Failed to find previously scanned local variable "
                f"{self.name} from {to_hex(self.ea)}"
            )
            return

        lvi = ida_hexrays.lvar_saved_info_t()
        lvi.ll = ida_hexrays.lvar_locator_t(lvar.location, lvar.defea)
        lvi.type = tinfo
        log_debug(f"Applying t info to variable {self.name} in {self.function_name}")
        ida_hexrays.modify_user_lvar_info(
            cfunc.entry_ea, ida_hexrays.MLI_TYPE, lvi
        )


# Integral pseudo/named spellings that never denote a struct — casts
# like ``*(_DWORD *)p + n`` make the scanner record member evidence
# against the pointee NAME; applying "member types" into a scalar is
# meaningless (and the IDA til does not even carry ``_DWORD`` as a
# named type — it is Hex-Rays cast syntax, resolved by parse_decl
# through the R2.5 alias map, never by get_named_type).
_INTEGRAL_POINTEE_NAMES = frozenset(
    {
        "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD",
        "BYTE", "WORD", "DWORD", "QWORD", "OWORD",
        "BOOL", "BOOLEAN", "CHAR", "UCHAR",
        "void", "bool", "char", "signed char", "unsigned char",
        "short", "unsigned short", "int", "unsigned int",
        "long", "unsigned long", "long long", "unsigned long long",
        "__int8", "__int16", "__int32", "__int64", "__int128",
        "unsigned __int8", "unsigned __int16", "unsigned __int32",
        "unsigned __int64", "unsigned __int128",
        "float", "double", "long double",
        "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64",
    }
)


class ScannedStructureMemberObject(ScannedObject):
    def __init__(
        self,
        struct_name,
        struct_offset,
        name,
        expression_address,
        origin,
        applicable=True,
    ):
        super().__init__(name, expression_address, origin, applicable)
        self._name = struct_name
        self._offset = struct_offset

    def apply_type(self, tinfo: ida_typeinf.tinfo_t) -> None:
        """Apply ``tinfo`` to the udt member at ``struct_offset`` (F.1).

        Loads the udt details of the member's structure type, finds the
        member by its byte offset, replaces its type via
        ``udt_member.set_type`` and commits with ``set_udt_details``.
        Best-effort: any failure logs the reason; the warning that used
        to say "not supported yet" only remains when nothing could be
        applied. Integral pointees (``*(_DWORD *)p`` casts) have no
        udt to edit — those skips are debug-level, not warnings.
        """
        if not self._applicable:
            return
        try:
            struct_tinfo = ida_typeinf.tinfo_t()
            if not struct_tinfo.get_named_type(
                ida_typeinf.get_idati(), self._name
            ):
                if self._name in _INTEGRAL_POINTEE_NAMES:
                    log_debug(
                        f"{self._name} is an integral pointee, not a "
                        f"struct; member {self.name} apply skipped"
                    )
                    return
                log_warning(
                    f"Structure {self._name} is not a known type; "
                    f"member {self.name} type was not applied"
                )
                return
            if not struct_tinfo.is_udt():
                log_debug(
                    f"{self._name} is not a struct/union; member "
                    f"{self.name} apply skipped"
                )
                return
            udt = ida_typeinf.udt_type_data_t()
            if not struct_tinfo.get_udt_details(udt):
                log_warning(
                    f"Structure {self._name} has no udt details; "
                    f"member {self.name} type was not applied"
                )
                return
            member = next(
                (
                    udt_member
                    for udt_member in udt
                    if getattr(udt_member, "offset", None) == self._offset
                ),
                None,
            )
            if member is None:
                log_warning(
                    f"Structure {self._name} has no member at offset "
                    f"0x{self._offset:x}; type was not applied"
                )
                return
            member.set_type(tinfo)
            if not struct_tinfo.set_udt_details(udt):
                log_warning(
                    f"set_udt_details failed for {self._name} member "
                    f"{self.name} @ 0x{self._offset:x}"
                )
                return
            log_debug(
                f"Applied type {tinfo.dstr()} to {self._name} member "
                f"{self.name} @ {hex(self.ea)}"
            )
        except Exception as exc:  # noqa: BLE001 — apply is best-effort
            log_warning(
                f"Failed to apply type to {self._name} member {self.name}: {exc}"
            )


def _is_bare_variable_assignee(x) -> bool:
    """True when ``x`` is the bare variable (optionally under cast/ref
    wrappers) with no member-access node anywhere in the chain.

    ``v0 = calloc(...)`` / ``v4 = v0`` are pointer re-bindings, not
    member-0 writes. ``v0->field_8 = x`` has a memptr node and is NOT
    bare. ``LODWORD(v0->field_0) = y`` is a cast of a memptr — also not
    bare.
    """
    member_ops = (
        getattr(ctype, "memptr", None),
        getattr(ctype, "memref", None),
        getattr(ctype, "dot", None),
        getattr(ctype, "idx", None),
        getattr(ctype, "add", None),
    )
    walk = x
    while walk is not None and hasattr(walk, "op"):
        if walk.op in member_ops:
            return False
        if walk.op in (getattr(ctype, "cast", None), getattr(ctype, "ref", None)):
            walk = getattr(walk, "x", None)
            continue
        return walk.op == getattr(ctype, "var", None)
    return False


class ScanVisitor(ObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        origin: int,
        obj: ScanObject,
        structure,
        recurse_calls: bool | None = None,
        member_sink: Callable[[object, RecursiveCallFrame], None] | None = None,
    ):
        if recurse_calls is None:
            DownwardsObjectVisitor.__init__(self, cfunc, obj, None, True)
        else:
            RecursiveDownwardsObjectVisitor.__init__(self, cfunc, obj, None, True, None, recurse_calls=recurse_calls)

        self._origin = origin
        self._callee_base_offset = 0
        self._structure = structure
        self._member_sink = member_sink
        # Pointee members discovered through a pointer FIELD dereference,
        # grouped into a child structure keyed by that field's offset (e.g. a
        # vtable / function-pointer table reached through field_0).
        self._pointer_child_structures: dict[int, Structure] = {}



    @staticmethod
    def _describe_tinfo(tinfo: ida_typeinf.tinfo_t | None) -> str:
        if tinfo is None:
            return "<none>"
        return getattr(tinfo, "dstr", lambda: str(tinfo))()

    @staticmethod
    def _describe_call_argument(
        idx: int | None, call_cexpr: ida_hexrays.cexpr_t
    ) -> str:
        label = f"argument {idx}" if idx is not None else "unmatched argument"
        return f"{label} at {to_hex(call_cexpr.ea)}"

    @staticmethod
    def _is_unknown_tinfo(tinfo: ida_typeinf.tinfo_t | None) -> bool:
        return is_incomplete_tinfo(tinfo)

    @staticmethod
    def _is_structure_like_tinfo(tinfo: ida_typeinf.tinfo_t | None) -> bool:
        return tinfo is not None and (tinfo.is_ptr() or tinfo.is_udt())

    def _prefer_object_tinfo(
        self, obj: ScanObject, tinfo: ida_typeinf.tinfo_t | None
    ) -> ida_typeinf.tinfo_t | None:
        obj_tinfo = obj.tinfo
        if obj_tinfo is None or tinfo is None:
            return tinfo
        if self._is_unknown_tinfo(tinfo) and self._is_structure_like_tinfo(obj_tinfo):
            # The ctree could not tell us the member's type; fall back to the
            # scanned object's structure-like type.
            return obj_tinfo
        return tinfo

    @staticmethod
    def _create_byte_array_tinfo(size: int) -> ida_typeinf.tinfo_t:
        if size <= 1:
            return ida_typeinf.tinfo_t(types["u8"].type)

        array_data = ida_typeinf.array_type_data_t()
        array_data.base = 0
        array_data.elem_type = ida_typeinf.tinfo_t(types["u8"].type)
        array_data.nelems = size

        array_tinfo = ida_typeinf.tinfo_t()
        array_tinfo.create_array(array_data)
        return array_tinfo

    def _infer_data_object_tinfo(
        self,
        obj_ea: int,
        current_tinfo: ida_typeinf.tinfo_t | None,
    ) -> ida_typeinf.tinfo_t | None:
        if not self._is_unknown_tinfo(current_tinfo):
            return current_tinfo

        if current_tinfo is not None:
            log_debug(
                f"Object type at {to_hex(obj_ea)} is incomplete: "
                f"{self._describe_tinfo(current_tinfo)}"
            )

        guessed_tinfo = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(guessed_tinfo, obj_ea):
            if not self._is_unknown_tinfo(guessed_tinfo):
                log_debug(
                    f"Inferred object type from {to_hex(obj_ea)}: {guessed_tinfo.dstr()}"
                )
                return guessed_tinfo

            log_debug(
                f"Guessed object type from {to_hex(obj_ea)} remained incomplete: "
                f"{self._describe_tinfo(guessed_tinfo)}"
            )

        item_size = ida_bytes.get_item_size(obj_ea)
        if item_size > 0:
            fallback_tinfo = self._create_byte_array_tinfo(item_size)
            log_debug(
                f"Object type for {to_hex(obj_ea)} remained incomplete; "
                f"falling back to sized byte array {fallback_tinfo.dstr()}"
            )
            return fallback_tinfo

        return current_tinfo

    def _get_parent_context(self) -> ParentExpressionContext:
        expressions = [parent.cexpr for parent in list(self.parents)[:0:-1]]
        return ParentExpressionContext(expressions)

    def _manipulate(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject) -> None:
        super()._manipulate(cexpr, obj)

        obj_tinfo = obj.tinfo
        if obj_tinfo and not is_legal_type(obj_tinfo):
            # The tinfo is corrupt or incomplete — even dstr() can throw on bad tinfo_t objects.
            expr_ea = find_expr_address(cexpr, self.parents)
            try:
                type_str = obj_tinfo.dstr()
            except Exception:  # noqa: BLE001 — corrupt tinfo; reported as "?" below
                type_str = "?"
            log_warning(f"Type {type_str} @ {to_hex(expr_ea)} is not supported")
            return


        parent_ops = self._get_parent_context().ops
        has_pointer_context = cexpr.type.is_ptr() or any(
            op in (ctype.ptr, ctype.idx, ctype.add) for op in parent_ops
        )
        if has_pointer_context:
            member = self._extract_member_from_ptr(cexpr, obj)
            if member is None:
                member = self._extract_member_from_expr(cexpr, obj)
        else:
            member = self._extract_member_from_expr(cexpr, obj)

        # if member exists and not a VoidMember
        from forge.api.members import VoidMember
        if member and not isinstance(member, VoidMember):
            log_debug(f"\tCreating member {member}")
            self._emit_member(member)
        # A dereference through a pointer FIELD of the scanned object means
        # the observed member belongs to the field's pointee — collect it in
        # a child structure (keyed by the field offset) alongside the normal
        # extraction, which stays untouched (R3.14 suppression included).
        self._maybe_record_pointer_child(cexpr, obj)

    def _get_member(
        self,
        offset: int,
        cexpr: ida_hexrays.cexpr_t,
        obj: ScanObject,
        tinfo: ida_typeinf.tinfo_t | None,
        obj_ea: int | None = None,
    ):
        """Build a structure member from the expression/type context."""
        offset += self._callee_base_offset
        expr_ea = find_expr_address(cexpr, self.parents)

        if offset < 0:
            return None

        applicable = not self.crippled and self._callee_base_offset == 0
        scan_obj = ScannedObject.create(obj, expr_ea, self._origin, applicable)

        if obj_ea is not None:
            # Check if the effective address is a virtual table
            from forge.api.members import VirtualTable
            if VirtualTable.is_virtual_table(obj_ea) != 0:
                return VirtualTable(offset, obj_ea, scan_obj, self._origin)
            # Check if the effective address is in code
            if is_code(obj_ea):
                func = decompile(obj_ea)
                if func:
                    func_tinfo = ida_typeinf.tinfo_t(func.type)
                    tinfo = ida_typeinf.tinfo_t()
                    tinfo.create_ptr(func_tinfo)
                else:
                    tinfo = ida_typeinf.tinfo_t(types["func_t"].type)
                from forge.api.members import Member
                return Member(offset, tinfo, scan_obj, self._origin)

            tinfo = self._infer_data_object_tinfo(obj_ea, tinfo)

        tinfo = self._prefer_object_tinfo(obj, tinfo)

        # R3.14: the same write can be extracted twice — once through the
        # assignment walk (which now prefers the RHS ``child_t *``) and once
        # through the standalone ``*((_QWORD *)v0 + N)`` deref walk (which
        # sees only the storage width ``u64``).  Once a member at the offset
        # is a pointer to a real struct, the scalar width row is redundant
        # AND the worse type — skip it so the store keeps the typed member.
        existing = None
        if tinfo is not None:
            get_member = getattr(self._structure, "get_member_by_offset", None)
            if callable(get_member):
                existing = get_member(offset)
            existing_tinfo = getattr(existing, "tinfo", None) if existing is not None else None
            is_integral = getattr(tinfo, "is_integral", None)
            if (
                callable(is_integral)
                and is_integral()
                and existing_tinfo is not None
                and existing_tinfo.is_ptr()
            ):
                pointed = existing_tinfo.get_pointed_object()
                if pointed is not None:
                    is_udt = getattr(pointed, "is_udt", None)
                    if callable(is_udt) and is_udt():
                        log_debug(
                            f"skipping scalar-width duplicate at "
                            f"{hex(offset)} (member {existing.name} "
                            "is a struct pointer)"
                        )
                        return None
            # R3.14: the REVERSE read-cast artifact — `*(_DWORD **)v0` reads
            # the slot as a pointer value when the written member is an
            # integral (`u32_0`).  The store's integral member is the true
            # type; the pointer-shaped read redeclaration only appears
            # because the root lvar is `_DWORD *` and hexrays re-casts every
            # access.  Suppress pointer-to-scalar rows that hit an existing
            # integral member of the same width.
            is_ptr = getattr(tinfo, "is_ptr", None)
            if callable(is_ptr) and is_ptr() and existing_tinfo is not None:
                ex_integral = getattr(existing_tinfo, "is_integral", None)
                if callable(ex_integral) and ex_integral():
                    pointed = None
                    get_pointed = getattr(tinfo, "get_pointed_object", None)
                    if callable(get_pointed):
                        pointed = get_pointed()
                    if pointed is None or not (
                        getattr(pointed, "is_udt", lambda: False)
                        and pointed.is_udt()
                    ):
                        log_debug(
                            f"skipping pointer-shaped read cast at "
                            f"{hex(offset)} (member {existing.name} is "
                            "integral)"
                        )
                        return None

        if tinfo is not None:
            tinfo = ida_typeinf.tinfo_t(tinfo)
            tinfo.clr_const()
            tinfo = types.convert_to_simple_type(tinfo)

        if not tinfo or tinfo.equals_to(types["void"].type):
            from forge.api.members import VoidMember
            return VoidMember(offset, scan_obj, self._origin)

        from forge.api.members import Member
        return Member(offset, tinfo, scan_obj, self._origin)

    def _emit_member(self, member) -> None:
        member_sink = getattr(self, "_member_sink", None)
        if member_sink is None:
            self._structure.add_member(member)
            return
        member_sink(member, self._current_frame)

    @property
    def pointer_child_structures(self) -> dict[int, Structure]:
        """Reconstructed child structures keyed by the pointer field offset
        that reaches them (e.g. a vtable / function-pointer table behind
        field_0)."""
        return self._pointer_child_structures

    def _record_pointer_child_member(self, field_offset: int, member) -> None:
        """Record a member observed through a pointer field's pointee.

        Members are grouped by the pointer field they came from and collected
        in their own Structure so the normal dedup/collision/scoring logic
        applies. The caller resolves a globally-unique name (and provenance)
        when it integrates and links these children.
        """
        from forge.api.members import VoidMember
        from forge.api.structure import Structure

        if member is None or isinstance(member, VoidMember):
            return
        store = getattr(self, "_pointer_child_structures", None)
        if store is None:
            return
        child = store.get(field_offset)
        if child is None:
            parent_name = getattr(self._structure, "name", "struct")
            child = Structure(f"{parent_name}_field_{field_offset:x}")
            store[field_offset] = child
        child.add_member(member)

    def _pointer_child_field_access(self, cexpr):
        """Detect a member access that dereferences a pointer FIELD of the
        scanned object.

        Read innermost-out, the parent chain of the matched object reference
        looks like ``*(*(TYPE *)<obj + field_offset> + pointee_offset)``: a
        pointer value loaded from a field of the scanned object and then
        dereferenced again. The member observed on the far side belongs to a
        child structure keyed by that field's offset, not to the scanned
        structure itself.

        Returns ``(field_offset, pointee_offset, element_tinfo, access_expr)``
        or ``None`` when the chain is a plain member access, carries dynamic
        (non-numeric) addressing, or never dereferences twice. Offsets are
        BYTES, matching the rest of this scanner.
        """
        context = self._get_parent_context()
        field_offset: int | None = None
        offset = 0
        pending_cast_tinfo = None
        deref_count = 0
        index = 0
        while True:
            node = context.expr_at(index)
            op = context.op_at(index)
            if node is None:
                return None
            if op == ctype.cast:
                pending_cast_tinfo = getattr(node, "type", None)
                index += 1
                continue
            if op in (ctype.add, ctype.sub):
                left = getattr(node, "x", None)
                right = getattr(node, "y", None)
                if getattr(right, "op", None) == ctype.num:
                    number = right.numval()
                    negative = op == ctype.sub
                elif getattr(left, "op", None) == ctype.num:
                    number = left.numval()
                    negative = op == ctype.sub
                else:
                    return None  # dynamic addressing is not recordable
                delta = number * self._add_pointee_scale(node)
                offset += -delta if negative else delta
                index += 1
                continue
            if op == getattr(ctype, "memptr", None):
                # `x->m` — the dereference itself carries the member offset.
                offset += int(getattr(node, "m", 0) or 0)
                deref_count += 1
                element_tinfo = getattr(node, "type", None)
            elif op == ctype.idx:
                index_expr = getattr(node, "y", None)
                if getattr(index_expr, "op", None) != ctype.num:
                    return None
                node_type = getattr(node, "type", None)
                get_size = getattr(node_type, "get_ptrarr_objsize", None)
                element_size = 1
                if callable(get_size):
                    try:
                        element_size = int(get_size()) or 1
                    except Exception:  # noqa: BLE001 — broken tinfo wrapper
                        element_size = 1
                offset += index_expr.numval() * element_size
                deref_count += 1
                element_tinfo = self._access_element_tinfo(
                    pending_cast_tinfo or node_type
                )
            elif op == ctype.ptr:
                deref_count += 1
                element_tinfo = self._access_element_tinfo(
                    pending_cast_tinfo or getattr(node, "type", None)
                )
            else:
                # The chain left the member-access pattern without a second
                # dereference: this is an ordinary member of the scan object.
                return None
            if deref_count == 1:
                field_offset = offset
                offset = 0
                pending_cast_tinfo = None
                index += 1
                continue
            return (field_offset, offset, element_tinfo, node)

    def _maybe_record_pointer_child(self, cexpr, obj) -> None:
        # The store is initialised EMPTY at ScanVisitor.__init__ and this is
        # the only path to its writer — gate on presence, not truthiness, or
        # pointer-child/vtable-child reconstruction is dead code.
        if getattr(self, "_pointer_child_structures", None) is None:
            return
        observation = self._pointer_child_field_access(cexpr)
        if observation is None:
            return
        field_offset, pointee_offset, element_tinfo, access_expr = observation
        self._record_pointer_child_member(
            field_offset + getattr(self, "_callee_base_offset", 0),
            self._build_child_member(
                pointee_offset, element_tinfo, access_expr, obj
            ),
        )

    def _build_child_member(self, offset, tinfo, cexpr, obj):
        """Build a member of a pointer-linked child structure (child-local
        base).

        A function-pointer slot is specialized so its first parameter is the
        owning object (``<structure> *``) ONLY when there is dataflow evidence
        that this loaded entry is actually invoked with the tracked owner as
        argument 0 (the vtable/callback pattern). Otherwise the decompiler
        cast signature is preserved, so ordinary ``(*)(int)`` tables are not
        corrupted.
        """
        from forge.api.members import Member

        if offset is None or offset < 0 or tinfo is None:
            return None
        if self._tinfo_predicate(tinfo, "is_funcptr") and (
            self._callback_invoked_with_owner(cexpr, obj)
        ):
            tinfo = self._specialize_child_callback_tinfo(tinfo)
        expr_ea = find_expr_address(cexpr, self.parents)
        # Child members carry their own (non-applicable) scan target: the
        # child's pointer type is what gets applied to the parent field, not
        # these.
        scan_obj = ScannedObject.create(obj, expr_ea, self._origin, False)
        return Member(offset, tinfo, scan_obj, 0)

    @staticmethod
    def _tinfo_predicate(tinfo, name: str) -> bool:
        predicate = getattr(tinfo, name, None)
        if not callable(predicate):
            return False
        try:
            return bool(predicate())
        except Exception:  # noqa: BLE001 — corrupt tinfo wrappers happen
            return False

    @classmethod
    def _access_element_tinfo(cls, tinfo):
        if tinfo is None:
            return None
        if cls._tinfo_predicate(tinfo, "is_ptr"):
            try:
                pointed = tinfo.get_pointed_object()
            except Exception:  # noqa: BLE001 — corrupt tinfo wrapper
                pointed = None
            return pointed or tinfo
        if cls._tinfo_predicate(tinfo, "is_array"):
            try:
                element = tinfo.get_array_element()
            except Exception:  # noqa: BLE001 — corrupt tinfo wrapper
                element = None
            return element or tinfo
        return tinfo

    def _structure_pointer_tinfo(self):
        """A (possibly forward-referenced) pointer to the structure being
        scanned."""
        name = getattr(self._structure, "name", None)
        if not name:
            return None
        pointer_tinfo = ida_typeinf.tinfo_t()
        try:
            parsed = ida_typeinf.parse_decl(
                pointer_tinfo, ida_typeinf.get_idati(), f"struct {name} *x;", 0
            )
        except Exception:  # noqa: BLE001 — missing til/type system in tests
            return None
        return pointer_tinfo if parsed else None

    def _specialize_child_callback_tinfo(self, tinfo):
        """Retype a function pointer's first parameter to the owning object."""
        pointed = getattr(tinfo, "get_pointed_object", lambda: None)()
        if pointed is None:
            return tinfo
        func_data = ida_typeinf.func_type_data_t()
        if not pointed.get_func_details(func_data) or len(func_data) == 0:
            return tinfo
        owner_ptr = self._structure_pointer_tinfo()
        if owner_ptr is None:
            return tinfo
        func_data[0].type = owner_ptr
        new_func = ida_typeinf.tinfo_t()
        if not new_func.create_func(func_data):
            return tinfo
        specialized = ida_typeinf.tinfo_t()
        if not specialized.create_ptr(new_func):
            return tinfo
        return specialized

    @staticmethod
    def _expr_obj_id(expr):
        value = getattr(expr, "obj_id", None)
        if callable(value):
            try:
                value = value()
            except Exception:  # noqa: BLE001 — identity probes are best-effort
                return None
        return value

    def _expr_contains(self, root, target) -> bool:
        if root is None or target is None:
            return False
        target_id = self._expr_obj_id(target)
        for expression in self._walk_expression_tree(root):
            if expression is target:
                return True
            if target_id is not None and self._expr_obj_id(expression) == target_id:
                return True
        return False

    def _call_arg0_references_owner(self, call_expr, obj) -> bool:
        args = getattr(call_expr, "a", None)
        if not args:
            return False
        try:
            first = args[0]
        except (IndexError, TypeError):
            return False
        if first is None:
            return False
        if hasattr(self, "_expression_references_object"):
            return self._expression_references_object(first)
        return self._matches_object(obj, first)

    def _callback_invoked_with_owner(self, load_expr, obj) -> bool:
        """True when the value loaded at ``load_expr`` is invoked as a function
        with the tracked owner ``obj`` as its first argument.

        Handles both the inline form ``(*(field + n))(owner, ...)`` and the
        assigned-then-called form ``v = *(field + n); ...; v(owner, ...)``.
        Expressions are visited in pre-order, so the assignment precedes its
        later call use.
        """
        call_op = getattr(ctype, "call", None)
        asg_op = getattr(ctype, "asg", None)
        var_op = getattr(ctype, "var", None)
        if call_op is None:
            return False

        def target_var_idx(expr):
            return getattr(getattr(expr, "v", None), "idx", None)

        for statements in self._collect_linear_expression_statements():
            ordered = [
                expression
                for _flag, expressions in statements
                for expression in expressions
            ]
            aliased_to_load: set[int] = set()
            for expression in ordered:
                op = getattr(expression, "op", None)
                if op == call_op:
                    callee = getattr(expression, "x", None)
                    if self._call_arg0_references_owner(expression, obj) and (
                        self._expr_contains(callee, load_expr)
                        or (
                            getattr(callee, "op", None) == var_op
                            and target_var_idx(callee) in aliased_to_load
                        )
                    ):
                        return True
                elif op == asg_op and getattr(
                    getattr(expression, "x", None), "op", None
                ) == var_op:
                    assigned_idx = target_var_idx(getattr(expression, "x", None))
                    if self._expr_contains(
                        getattr(expression, "y", None), load_expr
                    ):
                        aliased_to_load.add(assigned_idx)
                    else:
                        aliased_to_load.discard(assigned_idx)
        return False

    def _collect_linear_expression_statements(self):
        cfunc = getattr(self, "_cfunc", None)
        body = getattr(cfunc, "body", None)
        statements = getattr(body, "cblock", None)
        expression_op = getattr(ida_hexrays, "cit_expr", None)
        if statements is None or expression_op is None:
            return []

        class ExpressionCollector(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)
                self.expressions = []

            def visit_expr(self, expression):
                self.expressions.append(expression)
                return 0

        collected_statements = []
        try:
            for statement in statements:
                collector = ExpressionCollector()
                collector.apply_to(statement, None)
                collected_statements.append(
                    (
                        getattr(statement, "op", None) == expression_op,
                        collector.expressions,
                    )
                )
        except Exception:  # noqa: BLE001 — dataflow probing is best-effort
            return []
        return [collected_statements]

    @staticmethod
    def _walk_expression_tree(root):
        pending = [root]
        visited = set()
        while pending:
            expression = pending.pop()
            if expression is None or id(expression) in visited:
                continue
            visited.add(id(expression))
            yield expression
            arguments = getattr(expression, "a", None)
            if arguments is not None:
                with suppress(TypeError):
                    pending.extend(reversed(list(arguments)))
            pending.extend(
                expression
                for expression in (
                    getattr(expression, "z", None),
                    getattr(expression, "y", None),
                    getattr(expression, "x", None),
                )
                if expression is not None
            )

    def _extract_member_from_ptr(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject):
        """Extract a member from a pointer expression."""
        context = self._get_parent_context()
        first_parent = context.expr_at(0)
        second_parent = context.expr_at(1)

        if first_parent is None:
            return self._extract_member(cexpr, obj, 0, context)

        if first_parent.op == getattr(ctype, "memptr", None):
            # `obj->member` — typed structure dereference. The member offset
            # is the memptr delta itself; outer add/idx nodes operate on the
            # member value and are resolved by `_extract_member` (which
            # consumes add/idx wrappers ahead of casts).
            offset = first_parent.m
            cexpr = first_parent
            context.pop_front()
            return self._extract_member(cexpr, obj, offset, context)

        if first_parent.op in (ctype.idx, ctype.add):
            # `expr[idx]`
            # `(TYPE*) + x`
            if first_parent.y.op != ctype.num:
                return None

            if first_parent.op == ctype.idx:
                offset = first_parent.y.numval() * cexpr.type.get_ptrarr_objsize()
            else:
                # R3.14: `(_QWORD *)v0 + 2` — the add node's y counts
                # ELEMENTS of the pointee type, not bytes (`char *` keeps
                # scale 1; `_QWORD *` scales by 8).  Using the raw numval
                # planted `u64_1/u64_2/u64_3` rows at 0x1/0x2/0x3 that
                # overlapped the correct 0x8/0x10/0x18 members.
                pointee_scale = self._add_pointee_scale(first_parent)
                offset = first_parent.y.numval() * pointee_scale
            cexpr = self.parent_expr()
            if first_parent.op == ctype.add:
                context.pop_front()
        elif context.op_at(0) == ctype.cast and context.op_at(1) == ctype.add and second_parent is not None:
            # `(TYPE*)expr + offset`
            # `(TYPE)expr + offset`
            if second_parent.y.op != ctype.num:
                return None
            offset = (
                second_parent.theother(first_parent).numval()
                * self._add_pointee_scale(second_parent)
            )
            cexpr = second_parent
            context.pop_front(2)
        else:
            offset = 0

        return self._extract_member(cexpr, obj, offset, context)

    def _extract_member_from_expr(self, cexpr: ida_hexrays.cexpr_t, obj: ScanObject):
        """Extract a member from a non-pointer expression."""
        context = self._get_parent_context()

        first_parent = context.expr_at(0)
        if first_parent is not None and first_parent.op == ctype.memptr:
            # `obj->member` outside an explicit pointer context (plain value
            # read). The member offset is the memptr delta.
            return self._extract_member(first_parent, obj, first_parent.m, context)
        if context.op_at(0) == ctype.add and first_parent is not None:
            other = first_parent.theother(cexpr)
            if other.op != ctype.num:
                return None

            # R3.14: scale add-numval by the pointee size exactly like the
            # ptr path (see _extract_member_from_ptr) — otherwise
            # `(_QWORD *)v0 + 2` records byte-offset 2 instead of 16.
            offset = other.numval() * self._add_pointee_scale(first_parent)
            cexpr = self.parent_expr()
            context.pop_front()
        else:
            offset = 0

        if offset == 0 and (
            first_parent is None or first_parent.op >= ctype.cit_empty
        ):
            log_debug(
                f"Skipping bare expression {obj.name} with no member access context"
            )
            return None

        return self._extract_member(cexpr, obj, offset, context)

    @staticmethod
    def _obj_has_no_member_wrapper(first_parent) -> bool:
        """True when ``first_parent`` is not a member-access node.

        ``memptr``/``dot``/``idx``/``add`` wrappers mean the expression
        reads a structure field; anything else (a bare ``ne``/``eq``
        comparison, a call, a cast) reads the variable itself.
        """
        if first_parent is None:
            return True
        return first_parent.op not in (
            getattr(ctype, "memptr", None),
            getattr(ctype, "dot", None),
            ctype.idx,
            ctype.add,
        )

    def _extract_member(
        self,
        cexpr: ida_hexrays.cexpr_t,
        obj: ScanObject,
        offset: int,
        context: ParentExpressionContext,
    ):
        log_debug(
            f"Extracting member: {obj.name}, parents: '{ctype_to_str(context.ops)}'"
        )

        # R3.10: `v0 != nullptr` / `v0 == 0` reads the POINTER, not member
        # 0. The `ne`/`eq` parent of the bare variable (reached from both
        # the pointer and the plain-expression entry points) planted a
        # `u64:0x0` row for every null-checked allocation. Comparison
        # contexts with no member-access wrapper are not member reads.
        if offset == 0 and (
            context.op_at(0) in (getattr(ctype, "ne", None), getattr(ctype, "eq", None))
            and self._obj_has_no_member_wrapper(context.expr_at(0))
        ):
            log_debug(
                f"Skipping comparison of {obj.name} with no member access context"
            )
            return None

        asg_index = None
        for index, op in enumerate(context.ops):
            if op == ctype.asg:
                asg_index = index
                break
        if asg_index is not None:
            assignment_parent = context.expr_at(asg_index)
            if assignment_parent is not None and getattr(assignment_parent, "x", None) is not None:
                parsed_assignee = self._parse_left_assignee(assignment_parent.x, 0)
                if parsed_assignee is not None:
                    _assignee, assignee_offset = parsed_assignee
                    if _is_bare_variable_assignee(assignment_parent.x):
                        # R3.10: the ROOT variable itself as assignee
                        # (`v0 = calloc(...)`, `v4 = v0`) is a POINTER
                        # re-binding, not a structure member write. Treating
                        # it as member 0 planted bogus `void*`/`test*` rows
                        # (and phi-merge `v4 = v0` aliases polluted the root
                        # struct). Only member-access assignees count.
                        log_debug(
                            f"assignee is the scanned variable {obj.name}; "
                            "no member extracted"
                        )
                        return None
                    if not self._assignee_is_same_lvar(assignment_parent.x, obj):
                        # R3.13: `*(_QWORD *)&v0->u32_18 = v2` — the LHS
                        # base (v0) is a DIFFERENT lvar than the matched
                        # obj (v2).  The write targets v0's memory; the
                        # RHS lvar match must not deposit a member into
                        # v2's structure.
                        log_debug(
                            f"refusing member extraction for {obj.name}: "
                            "assignee base is a different lvar"
                        )
                        return None
                    obj_ea = self._extract_obj_ea(getattr(assignment_parent, "y", None))
                    log_debug("assignment to object")
                    return self._get_member(
                        assignee_offset,
                        cexpr,
                        obj,
                        self._prefer_rhs_pointer_type(
                            assignment_parent.x.type,
                            getattr(assignment_parent, "y", None),
                        ),
                        obj_ea,
                    )

        has_explicit_tinfo = False
        if (
            context.op_at(0) in (ctype.add, ctype.idx, getattr(ctype, "memptr", None))
            and context.op_at(1) == ctype.cast
            and context.expr_at(0) is not None
            and context.expr_at(1) is not None
        ):
            # `(TYPE)obj->member[+k]` — in typed functions the struct deref
            # rides under add/idx ahead of the cast; the cast carries the
            # member's expression type. Peel the wrapper so the cast branch
            # below can consume the type.
            tinfo = context.expr_at(1).type
            has_explicit_tinfo = True
            cexpr = context.expr_at(0)
            context.pop_front()

        if context.op_at(0) == ctype.cast and context.expr_at(0) is not None:
            # `(TYPE)expr`
            tinfo = context.expr_at(0).type
            has_explicit_tinfo = True
            cexpr = context.expr_at(0)
            context.pop_front()
        else:
            tinfo = types.get_ptr_tinfo()

        log_debug(f"1st default_tinfo: {self._describe_tinfo(tinfo)}")

        if context.op_at(0) in (ctype.idx, ctype.ptr):
            if context.op_at(1) == ctype.cast and context.expr_at(1) is not None:
                # `*(TYPE*)expr`
                # `*(TYPE*)expr[idx]`
                tinfo = context.expr_at(1).type
                has_explicit_tinfo = True
                cexpr = context.expr_at(0)
                context.pop_front()
            else:
                tinfo = self._deref_tinfo(tinfo)

            log_debug(f"2nd default_tinfo: {self._describe_tinfo(tinfo)}")

            second_expr = context.expr_at(1)
            first_expr = context.expr_at(0)

            if context.op_at(1) == ctype.asg and second_expr is not None and first_expr is not None:
                if second_expr.x == first_expr:
                    # `*((TYPE*)expr + x) = ...`
                    obj_ea = self._extract_obj_ea(second_expr.y)
                    log_debug("pointer assignment to object")
                    return self._get_member(
                        offset,
                        cexpr,
                        obj,
                        self._prefer_rhs_pointer_type(
                            second_expr.y.type,
                            second_expr.y,
                        ),
                        obj_ea,
                    )
                # `*(TYPE*)expr = ...`
                log_debug("cast assignment to object")
                return self._get_member(
                    offset,
                    cexpr,
                    obj,
                    self._prefer_rhs_pointer_type(
                        second_expr.x.type,
                        getattr(second_expr, "y", None),
                    ),
                )
            if context.op_at(1) == ctype.call and second_expr is not None and first_expr is not None:
                log_debug(f"pointer passed as argument to function at {hex(second_expr.ea)}")
                if second_expr.x == first_expr:
                    # ((void (__some_call*)(..., expr[idx], ...)
                    # ((void (__some_call*)(..., *(TYPE*)(expr + x), ...)
                    log_debug(f"object passed as argument to function at {hex(second_expr.ea)}")
                    return self._get_member(offset, cexpr, obj, first_expr.type)
                if has_explicit_tinfo:
                    return self._get_member(offset, cexpr, obj, tinfo)
                tinfo = self._parse_call(second_expr, first_expr, types["u8"].ptr)
                return self._get_member(offset, cexpr, obj, tinfo)

        if context.op_at(0) == ctype.call and context.expr_at(0) is not None:
            # `void (__some_call*)(..., (TYPE)(expr + x), ...)`
            call_parent = context.expr_at(0)
            log_debug(
                f"function call with cast, parent: {call_parent.type.dstr()} {call_parent.dstr()}, cexpr: {cexpr.type.dstr()} {cexpr.dstr()}"
            )
            if has_explicit_tinfo:
                return self._get_member(offset, cexpr, obj, tinfo)
            tinfo = self._parse_call(call_parent, cexpr, types["char"].type)
            return self._get_member(offset, cexpr, obj, tinfo)

        if context.op_at(0) == ctype.asg and context.expr_at(0) is not None:
            # `TYPE parent.x = expr(...);`
            log_debug("assignment to object")
            assignment_parent = context.expr_at(0)
            if assignment_parent.x == cexpr:
                tinfo = assignment_parent.x.type
                return self._get_member(offset, cexpr, obj, tinfo)

        return self._get_member(offset, cexpr, obj, self._deref_tinfo(tinfo))

    @staticmethod
    def _deref_tinfo(tinfo: ida_typeinf.tinfo_t) -> ida_typeinf.tinfo_t | None:
        """
        Get the pointed object from a pointer tinfo.

        :param tinfo: A pointer tinfo.
        :t tinfo: ida_typeinf.tinfo_t
        :return: The pointed object tinfo or None if it is not a valid pointer t.
        :rtype: Optional[ida_typeinf.tinfo_t]
        """
        if tinfo is None:
            return None

        log_debug(f"Dereferencing tinfo: {tinfo.dstr()}")

        if not tinfo.is_ptr():
            return tinfo
        
        if tinfo.get_ptrarr_objsize() != 1:
            return tinfo.get_pointed_object()
        
        if tinfo.equals_to(types["void"].ptr):
            return tinfo

        if tinfo.equals_to(types["u8"].ptr):
            return types["u8"].type

        return None  # Turns into VoidMember

    @staticmethod
    def _assignee_base_lvar_index(x) -> int | None:
        """Find the base ``var`` node under casts/refs/memptrs/memrefs in an
        assignment LHS and return its lvar index, or None if the LHS has no
        local-variable base.

        Used by R3.13's cross-lvar guard: for ``*(_QWORD *)&v0->u32_18 = v2``
        the LHS base is v0's lvar, which must not write members into a scan
        rooted on v2.
        """
        walk = x
        while walk is not None and hasattr(walk, "op"):
            op = walk.op
            if op in (
                getattr(ctype, "ref", None),
                getattr(ctype, "cast", None),
                getattr(ctype, "memptr", None),
                getattr(ctype, "memref", None),
                getattr(ctype, "dot", None),
                getattr(ctype, "idx", None),
                getattr(ctype, "add", None),
                getattr(ctype, "ptr", None),
            ):
                walk = getattr(walk, "x", None)
                continue
            if op == getattr(ctype, "var", None) and hasattr(walk, "v"):
                return getattr(walk.v, "idx", None)
            return None
        return None

    def _assignee_is_same_lvar(self, x, obj) -> bool:
        """True when the assignment LHS's base lvar is the same lvar as the
        matched scan obj (R3.13).  Non-variable objs (structure pointers,
        globals, ...) have no lvar identity and are always allowed.
        """
        from forge.api.scan_object import VariableObject

        if not isinstance(obj, VariableObject):
            return True
        lhs_index = self._assignee_base_lvar_index(x)
        if lhs_index is None:
            return True  # can't disprove; global/member-LHS sites still count
        return lhs_index == getattr(obj, "index", -1)

    @staticmethod
    def _add_pointee_scale(add_node) -> int:
        """The element size hexrays' ``add``-numval counts in.

        ``(_QWORD *)v0 + 2`` -> 8 (byte offset 16); ``(char *)v0 + 28`` -> 1
        (byte offset 28).  Mirrors scan_object._extract_offset_expression's
        add handling (R3.14).
        """
        add_type = getattr(add_node, "type", None)
        get_objsize = getattr(add_type, "get_ptrarr_objsize", None)
        if callable(get_objsize):
            try:
                return get_objsize() or 1
            except Exception:  # noqa: BLE001 — broken tinfo wrapper
                log_debug("get_ptrarr_objsize failed on add node; keeping scale 1")
        return 1

    @staticmethod
    def _prefer_rhs_pointer_type(lhs_tinfo, rhs_cexpr):
        """R3.14: when assigning a struct pointer into a member slot, the
        MEMBER type should be the RHS pointer type (``child_t *``), NOT the
        LHS storage cast (``_QWORD``).  ``v0->u64_10 = v1`` in a typed
        fixture decompiles to ``*((_QWORD *)v0 + 2) = v1;`` — the write is
        the pointer VALUE, so the member must carry the pointer's struct
        type or the parent/child relationship is lost.

        Returns the RHS pointer tinfo when it points at a named UDT/struct;
        falls back to ``lhs_tinfo`` otherwise (integral stores, bare ``void *``,
        strings, casts to scalars).
        """
        if rhs_cexpr is None:
            return lhs_tinfo
        rhs = rhs_cexpr
        while rhs is not None and getattr(rhs, "op", None) in (
            getattr(ctype, "cast", None),
            getattr(ctype, "ref", None),
        ):
            rhs = getattr(rhs, "x", None)
        rhs_tinfo = getattr(rhs, "type", None)
        if rhs_tinfo is None or not rhs_tinfo.is_ptr():
            return lhs_tinfo
        try:
            pointed = rhs_tinfo.get_pointed_object()
        except Exception:  # noqa: BLE001 — broken tinfo wrappers
            return lhs_tinfo
        if pointed is None:
            return lhs_tinfo
        is_udt = getattr(pointed, "is_udt", None)
        is_struct = getattr(pointed, "is_struct", None)
        if callable(is_struct) and is_struct():
            return rhs_tinfo
        if callable(is_udt) and is_udt():
            return rhs_tinfo
        return lhs_tinfo

    @staticmethod
    def _extract_obj_ea(cexpr: ida_hexrays.cexpr_t) -> int | None:
        """
        Extracts the effective address of an object from a cexpr.

        :param cexpr: The cexpr from which to extract the effective address.
        :return: The effective address of the object if found, otherwise None.
        """
        while cexpr is not None and hasattr(cexpr, "op") and cexpr.op in (
            getattr(ctype, "cast", None),
            getattr(ctype, "ref", None),
        ):
            cexpr = cexpr.x

        if cexpr is not None and cexpr.op == ctype.obj and cexpr.obj_ea != idaapi.BADADDR:
            return cexpr.obj_ea

    def _parse_call(
        self,
        call_cexpr: ida_hexrays.cexpr_t,
        arg_cexpr: ida_hexrays.cexpr_t,
        fallback_tinfo: ida_typeinf.tinfo_t | None = None,
    ) -> ida_typeinf.tinfo_t | None:
        """Infer the argument type used at a call site."""
        idx, tinfo = get_func_argument_info(call_cexpr, arg_cexpr)
        argument_context = self._describe_call_argument(idx, call_cexpr)

        if tinfo is not None and not self._is_unknown_tinfo(tinfo):
            log_debug(
                f"Recovered prototype type {self._describe_tinfo(tinfo)} for {argument_context}"
            )
            return self._deref_tinfo(tinfo)

        if tinfo is not None:
            log_debug(
                f"Prototype type for {argument_context} is incomplete: "
                f"{self._describe_tinfo(tinfo)}"
            )
        elif idx is None:
            log_debug(f"Could not match {argument_context} to a callable prototype")

        arg_tinfo = getattr(arg_cexpr, "type", None)
        if not self._is_unknown_tinfo(arg_tinfo):
            reason = "incomplete prototype type" if tinfo is not None else "no prototype match"
            log_debug(
                f"Using expression type {self._describe_tinfo(arg_tinfo)} for "
                f"{argument_context} after {reason}"
            )
            return self._deref_tinfo(arg_tinfo)

        if fallback_tinfo is not None:
            log_warning(
                f"{argument_context.capitalize()} has incomplete upstream type info; "
                f"falling back to {self._describe_tinfo(fallback_tinfo)}"
            )
            return fallback_tinfo

        log_warning(
            f"{argument_context.capitalize()} has incomplete upstream type info; "
            "falling back to char"
        )
        return types["char"].type

    def _parse_left_assignee(self, x, offset, scale: int = 1):
        return _extract_offset_expression(x, offset, scale, ctype)



class NewShallowScanVisitor(ScanVisitor, DownwardsObjectVisitor):
    def __init__(self, cfunc: ida_hexrays.cfunc_t, origin: int, obj: ScanObject, structure):
        super().__init__(cfunc, origin, obj, structure)


class NewDeepScanVisitor(ScanVisitor, RecursiveDownwardsObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        origin: int,
        obj: ScanObject,
        structure,
        recurse_calls: bool = False,
        max_depth: int | None = None,
        skip_until_object: bool = True,
        member_sink: Callable[[object, RecursiveCallFrame], None] | None = None,
    ):
        super().__init__(
            cfunc,
            origin,
            obj,
            structure,
            recurse_calls=recurse_calls,
            member_sink=member_sink,
        )
        self._max_depth = max_depth
        self._skip = skip_until_object and self._skip

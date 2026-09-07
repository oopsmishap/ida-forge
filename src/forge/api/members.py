from __future__ import annotations

import re
from collections import defaultdict

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import ida_segment
import ida_typeinf
import ida_xref
import idaapi
import idc

import forge.api.types as forge_types
from forge.api.domain import current_database as _current_domain_database
from forge.api.domain import sdk_fallback as _sdk_fallback
from forge.api.domain import try_domain_method as _try_domain_method
from forge.api.hexrays import decompile, is_code, is_imported, read_pointer
from forge.api.scanner import NewDeepScanVisitor
from forge.api.types import types
from forge.api.visitor import FunctionTouchVisitor
from forge.util.cxx_to_c_name import demangled_name_to_c_str


def _name_at(ea: int) -> str:
    handled, name = _try_domain_method(
        _current_domain_database(required=False),
        "names",
        "get_at",
        ea,
        capability="names.member",
        unavailable_reason="ida-domain database/name lookup unavailable",
        failure_reason="ida-domain name lookup failed",
        exceptions=(Exception,),
    )
    if handled:
        return name or ""
    return ida_name.get_name(ea)


def _function_name(ea: int) -> str:
    handled, name = _try_domain_method(
        _current_domain_database(required=False),
        "names",
        "get_at",
        ea,
        capability="names.vtable_function",
        unavailable_reason="ida-domain database/name lookup unavailable for vtable function",
        failure_reason="ida-domain function name lookup failed",
        exceptions=(Exception,),
    )
    if handled:
        return name or ""
    return ida_funcs.get_func_name(ea)

def _set_function_name(ea: int, name: str) -> bool:
    domain_db = _current_domain_database(required=False)
    handled, result = _try_domain_method(
        domain_db,
        "names",
        "set_name",
        ea,
        name,
        capability="names.vtable_function_set",
        unavailable_reason="ida-domain name mutation unavailable on this build/session",
        failure_reason="ida-domain function name mutation failed",
        exceptions=(Exception,),
    )
    if handled:
        return bool(result)
    return bool(ida_name.set_name(ea, name))


def _segment_is_executable(ea: int) -> bool:
    domain_db = _current_domain_database(required=False)
    handled, segment = _try_domain_method(
        domain_db,
        "segments",
        "get_at",
        ea,
        capability="segments.executable",
        unavailable_reason="ida-domain segment lookup unavailable on this build/session",
        failure_reason="ida-domain executable-segment lookup failed",
        exceptions=(Exception,),
    )
    if handled:
        if segment is None:
            return False
        permissions = getattr(segment, "perm", 0)
        try:
            from ida_domain.segments import SegmentPermissions

            return bool(permissions & SegmentPermissions.EXEC)
        except (ImportError, AttributeError, TypeError):
            return bool(permissions & 1)
    segment = ida_segment.getseg(ea)
    return bool(segment and segment.perm & ida_segment.SEGPERM_EXEC)
from forge.util.logging import log_debug, log_error, log_info, log_warning

TYPE_DECL_ALIASES = {
    "_BYTE": "u8",
    "BYTE": "u8",
    "byte": "u8",
    "_WORD": "u16",
    "WORD": "u16",
    "word": "u16",
    "_DWORD": "u32",
    "DWORD": "u32",
    "dword": "u32",
    "_QWORD": "u64",
    "QWORD": "u64",
    "qword": "u64",
    "_OWORD": "u128",
    "OWORD": "u128",
    "oword": "u128",
    "BOOL": "bool",
    "BOOLEAN": "bool",
    "CHAR": "char",
    "UCHAR": "u8",
    "uchar": "u8",
    "unsigned char": "u8",
    "unsigned short": "u16",
    "unsigned int": "u32",
    "unsigned __int64": "u64",
    "unsigned long long": "u64",
    # R2.5 (recovery eval 2026-08-13): the intN/uintN shorthand family must
    # parse like the __intN spellings — members typed ``int32``/``uint64``
    # were silently dropped before. Unknown tokens still fail loudly.
    "int8": "i8",
    "int16": "i16",
    "int32": "i32",
    "int64": "i64",
    "uint8": "u8",
    "uint16": "u16",
    "uint32": "u32",
    "uint64": "u64",
    # R3.2: the intN/uintN family must land on IDA-native tokens (the
    # R2.5 map only reached the aliases themselves).
    "u8": "unsigned __int8",
    "u16": "unsigned __int16",
    "u32": "unsigned __int32",
    "u64": "unsigned __int64",
    "i8": "__int8",
    "i16": "__int16",
    "i32": "__int32",
    "i64": "__int64",
    "u128": "unsigned __int128",
}


def normalize_type_declaration(declaration: str) -> str:
    normalized = declaration.strip()
    for source, target in TYPE_DECL_ALIASES.items():
        normalized = re.sub(rf"\b{re.escape(source)}\b", target, normalized)
    return normalized


# O2: signed 8-bit spellings that must display as a single canonical name so
# the same semantic field never shows as both "char *" and "i8 *".
_SIGNED_8_TOKENS = frozenset({"i8", "char", "signed char", "__int8", "signed __int8"})


def normalize_type_display(name: str) -> str:
    """Canonical display for an IDA type string (signed-8 → ``char``).

    Only the leading type token is rewritten, so pointer/array forms
    (``i8 *``, ``signed __int8 [4]``) normalize without touching the rest.
    """
    if not name:
        return name
    head, sep, tail = name.partition("[")
    had_space = head.endswith(" ")
    core = head.rstrip()
    if core in _SIGNED_8_TOKENS:
        core = "char"
    elif core.endswith(" *") and core[:-2].rstrip() in _SIGNED_8_TOKENS:
        core = "char *"
    return core + (" " if had_space and not core.endswith(" ") else "") + (sep + tail if sep else "")


def _domain_parse_decl(declaration: str):
    handled, result = _try_domain_method(
        _current_domain_database(required=False),
        "types",
        "parse_one_declaration",
        None,
        declaration,
        capability="types.member_parse",
        unavailable_reason="ida-domain member declaration parser unavailable on this build/session",
        failure_reason="ida-domain member declaration parser rejected the declaration",
        exceptions=(AttributeError, RuntimeError, TypeError, ValueError),
    )
    return result if handled else None


def _parse_decl_attempt(declaration: str) -> ida_typeinf.tinfo_t | None:
    tinfo = ida_typeinf.tinfo_t()
    flags = ida_typeinf.PT_TYP | ida_typeinf.PT_SIL
    if ida_typeinf.parse_decl(tinfo, None, declaration, flags):
        return tinfo
    return None


def _parse_idc_decl_attempt(declaration: str) -> ida_typeinf.tinfo_t | None:
    """Decl parse via the idc wrapper (E1 live finding, 2026-08-13).

    On the 9.4 build ``idc.parse_decl`` is the legacy 2-argument form
    ``(decl, flags) -> (ret, type_bytes, field_bytes)`` (the 3-arg til
    form raises TypeError), and ``ida_typeinf.parse_decl`` returns None
    for function prototypes. Prefer the 2-arg form, fall back to the
    3-arg shape on older builds, and accept either return kind.
    """
    import idc as _idc

    result = None
    try:
        result = _idc.parse_decl(declaration, idaapi.PT_TYP)
    except TypeError:
        try:
            result = _idc.parse_decl(
                ida_typeinf.get_idati(), declaration, idaapi.PT_TYP
            )
        except Exception:  # noqa: BLE001 — parse failure degrades to None
            return None
    if result is None:
        return None
    if isinstance(result, tuple):
        if len(result) != 3:
            # An idc build returning an unexpected arity cannot be
            # deserialized here; degrade to None (parse failure), never
            # raise.
            return None
        _, type_bytes, field_bytes = result
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.deserialize(
            ida_typeinf.get_idati(), type_bytes, field_bytes, None
        ):
            return None
        return tinfo
    return result


def _build_pointer_tinfo(base_declaration: str, pointer_depth: int) -> ida_typeinf.tinfo_t | None:
    _sdk_fallback(
        "types.pointer_array_construction",
        "ida-domain declaration parsing could not construct a pointer type",
    )
    base_tinfo = parse_user_tinfo(base_declaration)
    if base_tinfo is None:
        return None

    resolved_tinfo = ida_typeinf.tinfo_t(base_tinfo)
    for _ in range(pointer_depth):
        pointer_tinfo = ida_typeinf.tinfo_t()
        pointer_tinfo.create_ptr(resolved_tinfo)
        resolved_tinfo = pointer_tinfo
    return resolved_tinfo


def _build_array_tinfo(base_declaration: str, element_count: int) -> ida_typeinf.tinfo_t | None:
    if element_count <= 0:
        return None

    _sdk_fallback(
        "types.pointer_array_construction",
        "ida-domain declaration parsing could not construct an array type",
    )
    base_tinfo = parse_user_tinfo(base_declaration)
    if base_tinfo is None:
        return None

    array_data = ida_typeinf.array_type_data_t()
    array_data.base = 0
    array_data.elem_type = ida_typeinf.tinfo_t(base_tinfo)
    array_data.nelems = element_count
    array_tinfo = ida_typeinf.tinfo_t()
    if array_tinfo.create_array(array_data):
        return array_tinfo
    return None


def _parse_named_like_type(normalized: str) -> ida_typeinf.tinfo_t | None:
    array_match = re.fullmatch(
        r"(?P<base>.+?)\s*\[\s*(?P<count>0x[0-9a-fA-F]+|\d+)\s*\]",
        normalized,
    )
    if array_match:
        return _build_array_tinfo(
            array_match.group("base"),
            int(array_match.group("count"), 0),
        )

    pointer_match = re.fullmatch(r"(?P<base>.+?)(?P<pointers>(?:\s*\*\s*)+)", normalized)
    if pointer_match:
        pointer_depth = pointer_match.group("pointers").count("*")
        return _build_pointer_tinfo(pointer_match.group("base").strip(), pointer_depth)

    named_type = ida_typeinf.tinfo_t()
    if named_type.get_named_type(ida_typeinf.get_idati(), normalized):
        return named_type
    return None


def parse_user_tinfo(declaration: str) -> ida_typeinf.tinfo_t | None:
    normalized = normalize_type_declaration(declaration)
    # E28: braceless bare-union/struct bodies (``union { int a; float b; }``)
    # fail to parse on IDA with the plain or semicolon forms — the member
    # suffix must come first. ``{`` in the text guards struct/union bodies
    # generally; the later generic attempts still run for everything else.
    if normalized.startswith("union") or "{" in normalized:
        tinfo = _parse_decl_attempt(f"{normalized} __forge_member;")
        if tinfo is not None:
            return tinfo
    attempts = [
        normalized,
        f"{normalized};",
        f"{normalized} __forge_member;",
    ]
    for attempt in attempts:
        tinfo = _domain_parse_decl(attempt)
        if tinfo is not None:
            return tinfo
    for attempt in attempts:
        tinfo = _parse_decl_attempt(attempt)
        if tinfo is not None:
            return tinfo

    named_like_tinfo = _parse_named_like_type(normalized)
    if named_like_tinfo is not None:
        return named_like_tinfo

    for attempt in attempts:
        tinfo = _parse_idc_decl_attempt(attempt)
        if tinfo is not None:
            return tinfo

    return None

def materialize_linked_child_member_type(
    member, child_type_name: str | None, relation_kind: str
 ) -> bool:
    if not child_type_name:
        return False

    type_decl = f"{child_type_name} *" if relation_kind == "pointer" else child_type_name
    tinfo = parse_user_tinfo(type_decl)
    if tinfo is None:
        return False

    member.tinfo = tinfo
    member.is_array = False
    member.decl_src = type_decl
    if hasattr(member, "invalidate_score"):
        member.invalidate_score()
    return True


class AbstractMember:
    def __init__(self, offset: int, scanned_variable, origin: int, tinfo=None):
        self.offset: int = offset
        self.origin: int = origin
        self.enabled: bool = True
        self.comment: str = ""
        self.is_array: bool = False
        self._score: int = 0
        self.scanned_variables = {scanned_variable} if scanned_variable else set()
        self.tinfo: ida_typeinf.tinfo_t = tinfo
        # E4 (eval review 2026-08-13): the textual type declaration this
        # member was created from, when it came from a string. Packing
        # re-parses it fresh so stale tinfo ordinals (the overwrite flow
        # deletes + recreates types, freeing ordinals mid-session) can
        # never serialize as ``#NN *`` into a committed cdecl.
        self.decl_src: str | None = None

    def invalidate_score(self) -> None:
        self._score = 0

    def type_equals_to(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        return self.tinfo.equals_to(tinfo)

    def switch_array_flag(self):
        self.is_array ^= True
        self.invalidate_score()

    def activate(self):
        raise NotImplementedError

    def set_enabled(self, enabled):
        self.enabled = enabled
        self.is_array = False
        self.invalidate_score()

    def has_collision(self, other):
        if self.offset <= other.offset:
            return self.offset + self.effective_size() > other.offset
        return (other.offset + other.effective_size()) >= self.offset

    def is_simple_type(self):
        return re.match(r"((i|u|f)(8|16|32|64|128))", self.tinfo.dstr())

    @property
    def score(self):
        """Return the cached non-negative type confidence score.

        Scores combine size/alignment evidence, scanned-variable evidence, and
        type-shape weighting; function pointers and named UDT pointers receive
        stronger evidence than simple scalar aliases. The first calculation is
        cached until ``invalidate_score()`` resets it.
        """
        if self._score != 0:
            return self._score
        # Calculate the score based on the size and alignment of the type
        score = 0
        if self.alignment == 0:
            if self.size in (8, 4, 2, 1):
                score += 8 // self.size
        elif self.alignment == 4:
            if self.size in (4, 2, 1):
                score += 8 // self.size
        elif self.alignment in (2, 6):
            if self.size in (2, 1):
                score += 8 // self.size
        elif self.alignment in (1, 3, 5, 7) and self.size == 1:
            score += 8 // self.size

        # Add the number of scanned variables to the score
        score += len(self.scanned_variables)

        # Adjust the score based on the type.  R3.15: named struct/union
        # pointer types (`child_t *`) and named struct values must outscore
        # the integral aliases (`_DWORD`/`_QWORD`/`u64`/...) — collision
        # resolution keeps the higher score, and the alias-width row for a
        # slot that actually holds a recovered struct pointer is the WEAKER
        # evidence (it only reflects the storage width of the write).
        if self.is_simple_type():
            score -= 1
        elif self.tinfo.is_funcptr():
            score += 1000 + len(self.tinfo.dstr())
        elif self.tinfo.is_ptr():
            # A pointer whose pointee is a real named struct/union/class
            # (`child_t *`, `struct Foo *`) is the strongest scalar shape.
            pointed = self.tinfo.get_pointed_object()
            if pointed is not None and pointed.is_udt():
                score += 3
            else:
                # `void *` / integral pointee — still just a BYTE or scalar
                # pointer; no named-type recovery happened.
                score += 1
        elif self.tinfo.is_udt():
            # Embedded (non-pointer) named struct/union member.
            score += 2
        elif "struct " in self.tinfo.dstr() or "class " in self.tinfo.dstr():
            score -= 10
        else:
            score += 1

        # Ensure the score is not negative
        score = max(0, score)

        self._score = score
        return self._score

    @property
    def alignment(self):
        return self.offset % types.width

    @property
    def type_name(self):
        return self.tinfo.dstr()

    @property
    def size(self):
        if self.tinfo is None:
            return 1
        size = self.tinfo.get_size()
        return size if size != ida_typeinf.BADSIZE else 1
    def effective_size(self) -> int:
        """Default pack-time size: the stored size.

        ``Member`` overrides this to re-resolve from a fresh pack tinfo
        (R2.1); ``VirtualTable`` and any other ``AbstractMember`` subclass
        use the stored size, which is already correct for them.
        """
        return self.size

    @property
    def type_alias(self):
        if self.tinfo is None:
            return "field"

        aliases = []

        # future proofing I guess??
        if self.tinfo.is_floating():
            aliases = ["f8", "f16", "f32", "f64", "f128", "f256", "f512", "f1024"]
        elif self.tinfo.is_integral():
            if self.tinfo.is_signed():
                aliases = ["i8", "i16", "i32", "i64", "i128"]
            else:
                aliases = ["u8", "u16", "u32", "u64", "u128"]
        else:
            return "field"

        n = self._log_base_2_lookup(self.size)
        try:
            return aliases[n]
        except IndexError:
            return "field"

    def _log_base_2_lookup(self, v):
        """
        Find the log base 2 of an N-bit integer in O(lg(N)) operations with multiply and lookup
        http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
        :param v: No of bits (t width)
        :return: log base 2 of n
        """
        # fmt: off
        multiply_de_bruijn_bit_position_2 = [ 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
                                             31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9]
        # fmt: on

        n = ((v * 0x077CB531) & 0xFFFFFFFF) >> 27
        return multiply_de_bruijn_bit_position_2[n]

    def __repr__(self):
        return f"{self.type_name}:{hex(self.offset)}[{hex(self.size)}]"

    __hash__ = None  # __eq__ merges state; hashing would be unstable

    def __eq__(self, other):
        if self.offset == other.offset and self.type_name == other.type_name:
            self.scanned_variables |= other.scanned_variables
            self.invalidate_score()
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.offset < other.offset or (
            self.offset == other.offset and self.type_name < other.type_name
        )

    def __le__(self, other):
        return self.offset <= other.offset

    def __gt__(self, other):
        return self.offset > other.offset or (
            self.offset == other.offset and self.type_name > other.type_name
        )

    def __ge__(self, other):
        return self.offset >= other.offset


class Member(AbstractMember):
    def __init__(
        self, offset: int, tinfo: ida_typeinf.tinfo_t, scanned_variable, origin: int = 0
    ):
        super().__init__(offset, scanned_variable, origin, tinfo)
        self.array_count = None
        self.name = f"{self.type_alias}_{self.offset:x}"

    def _resolve_pack_tinfo(self) -> ida_typeinf.tinfo_t | None:
        """The tinfo to serialize for this member at pack time.

        E4 (eval review 2026-08-13): members created from a declaration
        string re-parse it fresh on every pack. The overwrite flow (and
        the vtable importer) deletes + recreates types, freeing the ordinal
        a stored tinfo points at — a stale handle then serializes as a
        bare ``#NN *`` in the committed cdecl and breaks ``push_type``.
        Re-parsing keeps the member's self/cross references on the current
        type table. Members persisted before ``decl_src`` existed (no
        source string) heal through the ordinal: ``#NN *`` resolves to the
        ordinal's current name and re-parses. Returns None when the stored
        tinfo must be used as-is.
        """
        decl_src = getattr(self, "decl_src", None)
        if decl_src:
            try:
                fresh = parse_user_tinfo(decl_src)
                if fresh is not None:
                    return fresh
            except Exception as exc:  # noqa: BLE001 — degraded tils degrade to the stored handle
                log_debug(f"decl_src re-parse failed for {decl_src!r}: {exc}")
        try:
            raw = self.tinfo.dstr()
        except Exception:  # noqa: BLE001 — stub/degraded tinfo
            return None
        ordinal_match = re.match(r"#(\d+)(?:\s+(.*))?$", raw or "")
        if ordinal_match:
            ordinal = int(ordinal_match.group(1))
            suffix = ordinal_match.group(2) or ""
            type_name = ida_typeinf.get_numbered_type_name(
                ida_typeinf.get_idati(), ordinal
            )
            if type_name:
                rebuilt = parse_user_tinfo(f"{type_name} {suffix}".rstrip())
                if rebuilt is not None:
                    return rebuilt
        # Recovery-eval gap #5 (2026-08-13): scanner-copied tinfos also go
        # stale when a named type is re-filed (inline-child members kept
        # binding the 48-byte child after it shrank to 44). Re-parse the
        # CURRENT declaration text — the fresh til resolve re-binds the
        # size/ordinal. Anything that no longer parses keeps the stored
        # handle.
        if raw:
            try:
                fresh = parse_user_tinfo(raw)
                if fresh is not None:
                    return fresh
            except Exception as exc:  # noqa: BLE001 — degraded tils degrade to the stored handle
                log_debug(f"pack re-parse of {raw!r} failed: {exc}")
        return None

    def effective_size(self) -> int:
        """The member's byte size at PACK time, not storage time.

        R2.1 (recovery eval 2026-08-13): a member whose type was added
        while the IDB only had forge's 1-byte seed placeholder keeps a
        stale small ``size`` — packing then placed every later member at
        the poisoned offset (``Outer.bag`` 16 → 1 B shifted grid/dispatch/
        stacks). Resolve the size from the FRESH pack tinfo (the same
        re-parse :meth:`_resolve_pack_tinfo` uses for the serialized
        type), falling back to the stored size only when the pack resolve
        has no size at all.
        """
        pack_tinfo = self._resolve_pack_tinfo() or self.tinfo
        if pack_tinfo is None:
            # R3.10: a member with no tinfo at all has no size; the pack
            # path skips it (build_cdecl), but size queries from collision
            # walking must not crash on it either.
            return getattr(self, "size", 1)
        try:
            size = pack_tinfo.get_size()
        except Exception:  # noqa: BLE001 — degraded tinfos have no size
            size = ida_typeinf.BADSIZE
        if size == ida_typeinf.BADSIZE:
            return getattr(self, "size", 1)
        return size

    def get_udt_member(self, array_size: int = 0, offset: int = 0):
        udt_member = ida_typeinf.udt_member_t()

        udt_member.name = (
            f"{self.type_alias}_{self.offset - offset:x}"
            if self._is_name_aliased()
            else self.name
        )
        pack_tinfo = self._resolve_pack_tinfo() or self.tinfo
        if pack_tinfo is None:
            # R3.10: a member with no tinfo is skipped by build_cdecl; use a
            # scalar fallback for direct UDT assembly callers.
            pack_tinfo = types["u64"].type
        if array_size:
            array_data = ida_typeinf.array_type_data_t()
            array_data.base = 0
            array_data.elem_type = ida_typeinf.tinfo_t(pack_tinfo)
            array_data.nelems = array_size
            array_tinfo = ida_typeinf.tinfo_t()
            array_tinfo.create_array(array_data)
            udt_member.type = array_tinfo
        else:
            udt_member.type = ida_typeinf.tinfo_t(pack_tinfo)
        udt_member.offset = self.offset - offset
        # R2.1 (recovery eval 2026-08-13): the size must come from the
        # PACK-resolved tinfo — the stored size can still be the 1-byte
        # seed placeholder's, and packing with it chain-shifts every
        # later member (Outer bag → grid/dispatch/stacks).
        udt_member.size = (
            self.effective_size() * array_size if array_size else self.effective_size()
        )
        udt_member.cmt = self.comment
        return udt_member

    def activate(self):
        new_type_decl = ida_kernwin.ask_str(
            self.type_name,
            ida_kernwin.HIST_TYPE,
            "Enter type:",
        )
        if not new_type_decl:
            return

        tinfo = parse_user_tinfo(new_type_decl)
        if tinfo is None:
            log_warning(f"Failed to parse type declaration: {new_type_decl}", True)
            return

        self.tinfo = tinfo
        self.is_array = False
        self.invalidate_score()

    def _is_name_aliased(self):
        return re.match(r"((i|u|f)(8|16|32|64|128|256|512|1024))|(field)_", self.name)


class VoidMember(Member):
    def __init__(
        self, offset: int, scanned_variable, origin: int = 0, char: bool = False
    ):
        tinfo = types["i8"].type if char else types["u8"].type
        # tinfo = const.CHAR_TINFO if char else const.BYTE_TINFO
        super().__init__(offset, tinfo, scanned_variable, origin)
        self.is_array = True

    def type_equals_to(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        return True

    def switch_array_flag(self):
        return None

    def set_enabled(self, enabled) -> None:
        self.enabled = enabled


class LinkedStructureMember(AbstractMember):
    """Placeholder member that links a parent layout to a child structure.

    The child type is materialized later (``materialize_linked_child_member_
    type``); until then the member carries only the child's name, a byte
    extent, and the scanned-variable evidence collected for the parent.
    """

    def __init__(
        self,
        offset: int,
        child_structure_name: str,
        conservative_extent: int,
        name: str,
        *,
        relation_kind: str = "embedded",
        scanned_variables=None,
    ):
        super().__init__(offset, None, 0, None)
        self.child_structure_name = child_structure_name
        self.conservative_extent = max(1, int(conservative_extent))
        self.name = name
        self.linked_child_structure_name = child_structure_name
        self.child_relation_kind = relation_kind
        self.scanned_variables = set(scanned_variables or ())

    @property
    def type_name(self):
        suffix = " *" if self.child_relation_kind == "pointer" else ""
        return f"{self.child_structure_name}{suffix}"

    @property
    def size(self):
        if self.child_relation_kind == "pointer":
            return types.width
        return self.conservative_extent

    @property
    def score(self):
        return 10_000

    def get_udt_member(self, array_size: int = 0, offset: int = 0):
        if self.tinfo is None:
            raise RuntimeError(
                f"Linked child {self.child_structure_name} has not been materialized"
            )
        tinfo = self.tinfo
        decl_src = self.decl_src
        if decl_src:
            # E4 mirror of Member._resolve_pack_tinfo: the child type may
            # have been re-committed under a fresh ordinal, so the stored
            # tinfo could render as a stale ``#NN *`` at pack time. Re-parse
            # the declaration first; only a failed re-parse falls back to
            # the stored handle.
            try:
                fresh = parse_user_tinfo(decl_src)
            except Exception as exc:  # noqa: BLE001 — degraded til falls back
                log_debug(
                    f"linked child decl_src re-parse failed for {decl_src!r}: {exc}"
                )
            else:
                if fresh is not None:
                    tinfo = fresh
        udt_member = ida_typeinf.udt_member_t()
        udt_member.name = self.name
        udt_member.type = ida_typeinf.tinfo_t(tinfo)
        udt_member.offset = self.offset - offset
        udt_member.cmt = self.comment
        udt_member.size = self.size
        return udt_member

    def activate(self):
        return None


class VirtualFunction:
    def __init__(self, address: int, offset: int, table_name: str = ""):
        self.address = address
        self.offset = offset
        self.vtable_name = table_name
        self.visited = False

    @staticmethod
    def _is_generated_name(name: str) -> bool:
        return name.startswith(("sub_", "nullsub_", "j_sub_", "unknown_libname_"))

    def try_rename(self) -> None:
        self.try_rename_to(self._def_generate_vfunc_name())

    def try_rename_to(self, desired_name: str) -> bool:
        current_name = _function_name(self.address)
        if current_name == desired_name:
            return True
        if not current_name or not self._is_generated_name(current_name):
            return False

        existing_ea = ida_name.get_name_ea(idaapi.BADADDR, desired_name)
        if existing_ea not in (idaapi.BADADDR, self.address):
            log_debug(
                "Skipping vtable function rename "
                f"{hex(self.address)} -> {desired_name}: name already used at {hex(existing_ea)}"
            )
            return False

        return _set_function_name(self.address, desired_name)

    def get_ptr_tinfo(self):
        ptr_tinfo = ida_typeinf.tinfo_t()
        ptr_tinfo.create_ptr(self.tinfo)
        return ptr_tinfo

    def get_udt_member(self):
        udt_member = ida_typeinf.udt_member_t()
        udt_member.type = self.get_ptr_tinfo()
        udt_member.offset = self.offset
        udt_member.name = self.name
        udt_member.size = types.width
        return udt_member

    def show_location(self):
        ida_hexrays.open_pseudocode(self.address, ida_hexrays.OPF_NEW_WINDOW)

    @property
    def tinfo(self) -> ida_typeinf.tinfo_t:
        """
        Returns the t of the virtual function
        :return: Type of the virtual function
        """
        try:
            decompiled_function = decompile(self.address)
            if decompiled_function and decompiled_function.type:
                return decompiled_function.type
            return types["func_t"].type
        except ida_hexrays.DecompilationFailure:
            log_error(f"Failed to decompile function at {hex(self.address)}")
            return types["func_t"].type

    @property
    def name(self) -> str:
        """Return the function name or a generated vtable name."""
        name = _function_name(self.address)
        if not name:
            return self._def_generate_vfunc_name()
        if ida_name.is_valid_typename(name):
            if name.startswith("sub_"):
                return self._def_generate_vfunc_name()
            return name
        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if not demangled_name:
            log_warning(
                f"Could not demangle name {name!r} at {hex(self.address)}, using generated name"
            )
            return self._def_generate_vfunc_name()
        return demangled_name_to_c_str(demangled_name)

    def _def_generate_vfunc_name(self) -> str:
        """Generate ``<vtable>_function_<slot>`` from the byte offset.

        The slot is the integer byte offset divided by ``types.width``. This
        deterministic fallback is used when IDA has no usable function name;
        C and C++ naming-convention mangling is intentionally not attempted.
        """
        idx = int(self.offset / types.width)
        return f"{self.vtable_name}_function_{idx}"

    def __repr__(self):
        return f"{self.name} @ {hex(self.address)}"


class ImportedVirtualFunction(VirtualFunction):
    def __init__(self, address, offset):
        super().__init__(address, offset)

    @property
    def tinfo(self):
        print(f"[INFO] Ignoring import function at 0x{self.address:08X}")
        tinfo = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tinfo, self.address):
            return tinfo
        return types["func_t"].type

    def show_location(self):
        ida_kernwin.jumpto(self.address)


def _vtable_has_data_reference(ea: int) -> bool:
    domain_db = _current_domain_database(required=False)
    if domain_db is not None:
        handled, refs = _try_domain_method(
            domain_db,
            "xrefs",
            "data_refs_to_ea",
            ea,
            capability="xrefs.vtable_boundary",
            unavailable_reason="ida-domain database unavailable for vtable boundary lookup",
            failure_reason="ida-domain data-reference lookup failed for vtable boundary",
            exceptions=(Exception,),
        )
        if handled:
            return next(iter(refs), None) is not None
    else:
        _sdk_fallback(
            "xrefs.vtable_boundary",
            "ida-domain database unavailable for vtable boundary lookup",
        )
    return ida_xref.get_first_dref_to(ea) != idaapi.BADADDR


class VirtualTable(AbstractMember):
    def __init__(self, offset, address, scanned_variable=None, origin=None):
        super().__init__(offset, scanned_variable, origin)
        self.address = address
        self.virtual_functions = []
        self.name = "_vftable" + f"_{hex(self.offset)}" if self.address else ""
        self.vtable_name, self.has_nice_vtable_name = self._parse_vtable_name()
        self.populate_virtual_functions()


    def populate_virtual_functions(self):
        address = self.address
        seen = set()
        while True:
            if address in seen or address < 0 or address > 0x00007FFFFFFFFFFF:
                break
            seen.add(address)
            try:
                ptr = read_pointer(address)
            except Exception:
                break
            if not isinstance(ptr, int) or ptr <= 0 or ptr > 0x00007FFFFFFFFFFF:
                break
            try:
                code = is_code(ptr)
            except Exception:
                code = False
            try:
                imported = is_imported(ptr)
            except Exception:
                imported = False
            if code:
                try:
                    virtual_function = VirtualFunction(
                        ptr, address - self.address, self.vtable_name
                    )
                    virtual_function.try_rename()
                except Exception:
                    break
                self.virtual_functions.append(virtual_function)
            elif imported:
                self.virtual_functions.append(
                    ImportedVirtualFunction(ptr, address - self.address)
                )
            else:
                break
            address += types.width

            # A data reference marks the vtable boundary. Boundary lookup is
            # best-effort because malformed table addresses are common in
            # stack-object scans.
            try:
                if _vtable_has_data_reference(address):
                    break
            except Exception:
                break
        log_debug(f"Found {len(self.virtual_functions)} virtual functions")
        log_debug(f"Vtable name: {self.vtable_name}")
        log_debug(f"Functions: {self.virtual_functions}")

    def create_tinfo(self):
        # print "(Virtual table) at address: 0x{:08X} name: {}".format(self.address, self.name)
        udt_data = ida_typeinf.udt_type_data_t()
        for function in self.virtual_functions:
            udt_data.push_back(function.get_udt_member())

        for duplicates in self.search_duplicate_fields(udt_data):
            first_entry_idx = duplicates.pop(0)
            log_warning(
                "Found duplicate virtual functions", udt_data[first_entry_idx].name
            )
            for num, dup in enumerate(duplicates):
                udt_data[dup].name = f"duplicate_{first_entry_idx}_{num + 1}"
                tinfo = ida_typeinf.tinfo_t()
                tinfo.create_ptr(types["func_t"].type)
                udt_data[dup].type = tinfo

        final_tinfo = ida_typeinf.tinfo_t()
        if final_tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT):
            return final_tinfo
        log_error("Virtual table creation failed")

    def scan_virtual_function(self, index: int, structure):
        if is_imported(self.virtual_functions[index].address):
            log_debug(
                f"Skipping import function at {hex(self.virtual_functions[index].address)}"
            )
            return
        try:
            function = decompile(self.virtual_functions[index].address)
        except ida_hexrays.DecompilationFailure:
            log_error(
                f"Failed to decompile function at {hex(self.virtual_functions[index].address)}"
            )
            return
        if FunctionTouchVisitor(function).process():
            function = decompile(self.virtual_functions[index].address)
        if function.arguments and function.arguments[0].is_arg_var:
            log_debug(
                f"Scanning function's this ptr at {hex(self.virtual_functions[index].address)}"
            )
            from forge.api.scan_object import VariableObject

            obj = VariableObject(function.get_lvars()[0], 0)
            scanner = NewDeepScanVisitor(function, self.offset, obj, structure)
            scanner.process()
        else:
            log_warning(
                f"Function at {hex(self.virtual_functions[index].address)} does not have a this ptr"
            )

    def scan_virtual_functions(self, structure):
        for index, _ in enumerate(self.virtual_functions):
            self.scan_virtual_function(index, structure)

    def import_to_structures(self, ask=False):
        """
        Imports virtual tables and returns tid_t of new structure

        :return: idaapi.tid_t
        """
        tinfo = self.create_tinfo()
        cdecl_typedef = idaapi.print_tinfo(
            None,
            4,
            5,
            idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
            tinfo,
            self.vtable_name,
            None,
        )

        log_debug(f"Created virtual table typedef:\n{cdecl_typedef}")

        if ask:
            cdecl_typedef = idaapi.ask_text(
                0x10000, cdecl_typedef, "The following new type will be created"
            )
            if not cdecl_typedef:
                return None
        previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, self.vtable_name)
        if previous_ordinal:
            idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
            ordinal = idaapi.idc_set_local_type(
                previous_ordinal, cdecl_typedef, idaapi.PT_TYP
            )
        else:
            ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)

        if not ordinal:
            log_error(
                f"Failed to add virtual table {self.vtable_name} to local types\n"
                f"{'*' * 80}\n"
                f"{cdecl_typedef}\n"
                f"{'*' * 80}\n"
            )
        else:
            log_info(f"Virtual table {self.vtable_name} added to local types")
            return forge_types.import_type(self.vtable_name)

    def get_udt_member(self, offset=0):
        udt_member = ida_typeinf.udt_member_t()
        tid = self.import_to_structures()
        if tid != idaapi.BADADDR:
            udt_member.name = self.name

            base_tinfo = idaapi.create_typedef(self.vtable_name)
            tmp_tinfo = ida_typeinf.tinfo_t()
            tmp_tinfo.create_ptr(base_tinfo)

            udt_member.type = tmp_tinfo
            udt_member.offset = self.offset - offset
            udt_member.size = types.width

        return udt_member

    def type_equals_to(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        udt_data = ida_typeinf.udt_type_data_t()
        return (
            tinfo.is_ptr()
            and tinfo.get_pointed_object().get_udt_details(udt_data)
            and udt_data[0].type.is_funcptr()
        )

    def switch_array_flag(self):
        return None

    @staticmethod
    def is_virtual_table(address: int) -> int:
        """Return the number of function slots in a plausible vtable.

        IDA Domain rejects malformed effective addresses instead of treating
        them as unmapped data. Stack-object scans can expose arbitrary qwords,
        so probing must stop at the first unreadable address rather than
        aborting the whole scan.
        """
        try:
            if is_code(address):
                return 0
            if not _name_at(address):
                return 0
        except Exception:
            return 0

        function_count = 0
        while True:
            try:
                func_address = read_pointer(address)
            except Exception:
                break
            try:
                code = is_code(func_address)
            except Exception:
                code = False
            try:
                imported = is_imported(func_address)
            except Exception:
                imported = False
            if code or imported:
                function_count += 1
                address += types.width
            else:
                try:
                    executable = _segment_is_executable(func_address)
                except Exception:
                    executable = False
                if executable:
                    try:
                        ida_bytes.del_items(func_address, 1, ida_bytes.DELIT_SIMPLE)
                        added = ida_funcs.add_func(func_address)
                    except Exception:
                        added = False
                    if added:
                        function_count += 1
                        address += types.width
                        continue
                break
            try:
                ida_auto.auto_wait()
            except Exception:
                pass
        return function_count

    def _parse_vtable_name(self):
        """
        Parse the name of the virtual table.

        :return: A tuple containing the name of the virtual table and a boolean indicating whether the name was mangled.
        """
        original_name = _name_at(self.address)

        if ida_name.is_valid_typename(original_name):
            if original_name.startswith("off_"):
                # case off_XXXXXXXX
                return f"vtbl{original_name[3:]}", False
            if "table" in original_name:
                return original_name, True

        demangled_name = ida_name.demangle_name(
            original_name, idc.get_inf_attr(idc.INF_SHORT_DN)
        )
        # E2 (eval review 2026-08-13): an unnamed pointer table used to
        # AssertionError here. Fall back to ``vtbl_<addr>`` like the GUI's
        # auto-naming instead, so to_vtable/vtable_name compose on any data
        # table (the eval fixture's dispatch table was exactly this shape).
        if not demangled_name:
            return f"vtbl_{self.address:X}", False
        normalized_name = (
            demangled_name
            .replace("const_", "")
            .replace("const ", "")
            .replace("::_vftable", "_vtbl")
            .replace("::`vftable'", "_vtbl")
        )
        name = demangled_name_to_c_str(normalized_name)

        return name, True

    @staticmethod
    def search_duplicate_fields(udt_data):
        """
        Returns a list of lists with duplicate fields
        """
        # Create a defaultdict to group fields by name
        default_dict = defaultdict(list)
        for idx, udt_member in enumerate(udt_data):
            default_dict[udt_member.name].append(idx)

        # Return only lists with more than one index
        return [indices for indices in list(default_dict.values()) if len(indices) > 1]

    @property
    def score(self):
        return 0x2000

    @property
    def cmt(self):
        return ""

    @property
    def size(self):
        return types.width

    @property
    def type_name(self):
        return f"{self.vtable_name} *"


# ---------------------------------------------------------------------------
# Dependency-aware authored-declaration resolution (recovery-eval gap #9,
# 2026-08-30). Members created from a declaration string (``decl_src``) may
# reference store types that are not committed to the IDB yet. The old pack
# path silently degraded those members to a stored/fallback placeholder
# tinfo, poisoning offsets and sizes. The resolver below answers "can this
# member's authored declaration pack right now, and if not, exactly which
# named types are missing" as a STRUCTURED result, so callers (facade
# ``create_type`` packing) can return an error instead of packing a
# placeholder.
# ---------------------------------------------------------------------------

# C declaration words that are keywords or compiler extensions — never
# named-type references.
_DECL_KEYWORDS = frozenset(
    {
        "struct",
        "union",
        "enum",
        "class",
        "const",
        "volatile",
        "signed",
        "unsigned",
        "int",
        "char",
        "short",
        "long",
        "float",
        "double",
        "void",
        "bool",
        "_Bool",
        "__int8",
        "__int16",
        "__int32",
        "__int64",
        "__int128",
        "__stdcall",
        "__cdecl",
        "__fastcall",
        "__thiscall",
        "__ptr32",
        "__ptr64",
        "__unaligned",
    }
)


def _builtin_type_tokens() -> frozenset[str]:
    """Every token that can never be a named-type reference.

    Language keywords, the ``TYPE_DECL_ALIASES`` spellings (``u32``,
    ``_DWORD``, ``unsigned __int64``, ...) and the IDA scalar family are
    all parseable without a named type, so they are excluded up front.
    """
    tokens = set(_DECL_KEYWORDS)
    for source, target in TYPE_DECL_ALIASES.items():
        tokens.update(source.split())
        tokens.update(target.split())
    return frozenset(tokens)


_BUILTIN_TYPE_TOKENS = _builtin_type_tokens()

_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")
# Declarator names directly follow pointer stars in a type expression
# (``World *w``, ``int (__stdcall *)(World *, int)`` slot position), or
# directly precede an array subscript (``World players[8]``) — they name
# the MEMBER, never a type.
_DECLARATOR_RE = re.compile(r"\*+\s*([A-Za-z_]\w*)")
_ARRAY_DECLARATOR_RE = re.compile(r"([A-Za-z_]\w*)\s*\[")


def declaration_type_references(declaration: str | None) -> list[str]:
    """The candidate named-type identifiers a C declaration references.

    Ordered, de-duplicated, and conservative: every identifier that is not
    a keyword/builtin scalar spelling counts as a reference. Callers
    confirm each candidate against the type table with
    :func:`named_type_exists` — the split exists so tests and callers can
    stub the existence check independently of tokenization.

    A declarator name (the identifier directly following pointer stars, or
    directly preceding an array subscript ``World players[8]``) names the
    member, never a type, and is excluded.
    """
    if not declaration:
        return []
    seen: set[str] = set()
    references: list[str] = []
    declarators = set(_DECLARATOR_RE.findall(declaration)) | set(
        _ARRAY_DECLARATOR_RE.findall(declaration)
    )
    for token in _IDENTIFIER_RE.findall(declaration):
        if token in _BUILTIN_TYPE_TOKENS or token in seen or token in declarators:
            continue
        seen.add(token)
        references.append(token)
    return references


def named_type_exists(name: str) -> bool:
    """True when ``name`` resolves to a type in the current type table.

    The direct named-type lookup covers the local til; the
    :func:`parse_user_tinfo` probe covers forward decls/types living in
    other tils (and forge's lazy placeholder structs, which parse by
    design so self/forward references work).
    """
    if not name:
        return False
    try:
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_named_type(ida_typeinf.get_idati(), name):
            return True
    except Exception:  # noqa: BLE001 — degraded til: fall through to parse
        pass
    return parse_user_tinfo(name) is not None


# MemberTypeResolution.status values
RESOLVED = "resolved"  # fresh pack tinfo from the authored declaration
STORED = "stored"  # no authored decl; stored tinfo used as-is (legacy shape)
UNTYPED = "untyped"  # no decl and no tinfo (build_cdecl skips these)
UNRESOLVED_REFERENCE = "unresolved_reference"  # decl names missing types
MALFORMED = "malformed"  # decl parses nowhere even though every name exists

BLOCKING_STATUSES = frozenset({UNRESOLVED_REFERENCE, MALFORMED})


class MemberTypeResolution:
    """Structured result of resolving one member's pack-time type.

    ``tinfo`` is the tinfo a pack uses for the member when the resolution
    is not blocking. ``degraded_tinfo`` (blocking results only) is what a
    SILENT pack would have fallen back to — the placeholder the caller is
    refusing to commit — so the error can say exactly what was avoided.
    """

    __slots__ = (
        "member_name",
        "offset",
        "declaration",
        "status",
        "unresolved",
        "tinfo",
        "degraded_tinfo",
    )

    def __init__(
        self,
        member_name: str | None,
        offset: int,
        declaration: str | None,
        status: str,
        *,
        unresolved: tuple[str, ...] = (),
        tinfo=None,
        degraded_tinfo=None,
    ):
        self.member_name = member_name
        self.offset = offset
        self.declaration = declaration
        self.status = status
        self.unresolved = tuple(unresolved)
        self.tinfo = tinfo
        self.degraded_tinfo = degraded_tinfo

    @property
    def ok(self) -> bool:
        return self.status not in BLOCKING_STATUSES

    def error(self) -> str | None:
        if self.ok:
            return None
        name = self.member_name or f"member_{self.offset:x}"
        decl = f" (decl {self.declaration!r})" if self.declaration else ""
        if self.status == UNRESOLVED_REFERENCE:
            return (
                f"member {name!r} @ 0x{self.offset:x} references unresolved "
                f"types: {', '.join(self.unresolved)}{decl}"
            )
        return f"member {name!r} @ 0x{self.offset:x} has a malformed declaration{decl}"

    def to_dict(self) -> dict:
        return {
            "member_name": self.member_name,
            "offset": self.offset,
            "declaration": self.declaration,
            "status": self.status,
            "unresolved": list(self.unresolved),
            "ok": self.ok,
            "error": self.error(),
        }

    def __repr__(self):
        return f"MemberTypeResolution({self.status}, {self.member_name!r}, {self.unresolved!r})"


def _member_pack_tinfo(member):
    """The member's own pack-time tinfo, when it can compute one."""
    resolver = getattr(member, "_resolve_pack_tinfo", None)
    if not callable(resolver):
        return None
    try:
        return resolver()
    except Exception:  # noqa: BLE001 — degraded tinfos must not raise here
        return None


def resolve_member_pack_type(member) -> MemberTypeResolution:
    """Resolve one member's pack-time type with dependency awareness.

    Authored declarations (``decl_src``) are re-parsed first; a failure is
    classified as unresolved references (named types missing from the type
    table — commit the referenced store structures first) or a malformed
    declaration, instead of silently packing the stored fallback.
    """
    decl = getattr(member, "decl_src", None)
    tinfo = getattr(member, "tinfo", None)
    member_name = getattr(member, "name", None)
    offset = getattr(member, "offset", 0)
    if decl:
        try:
            fresh = parse_user_tinfo(decl)
        except Exception:  # noqa: BLE001 — degraded tils classify below
            fresh = None
        if fresh is not None:
            return MemberTypeResolution(
                member_name, offset, decl, RESOLVED, tinfo=fresh
            )
        unresolved = tuple(
            name
            for name in declaration_type_references(decl)
            if not named_type_exists(name)
        )
        if unresolved:
            return MemberTypeResolution(
                member_name,
                offset,
                decl,
                UNRESOLVED_REFERENCE,
                unresolved=unresolved,
                degraded_tinfo=_member_pack_tinfo(member),
            )
        return MemberTypeResolution(
            member_name,
            offset,
            decl,
            MALFORMED,
            degraded_tinfo=_member_pack_tinfo(member),
        )
    if tinfo is None:
        if isinstance(member, LinkedStructureMember):
            # Gap #9 follow-up: an unmaterialized linked member would pass
            # the UNTYPED gate and then silently vanish from the pack
            # (build_cdecl skips tinfo-less members and pads the extent).
            # It must block instead, naming the child type that has never
            # been committed. Materializing the child re-runs readiness.
            return MemberTypeResolution(
                member_name,
                offset,
                member.type_name,
                UNRESOLVED_REFERENCE,
                unresolved=(member.child_structure_name,),
            )
        return MemberTypeResolution(member_name, offset, None, UNTYPED)
    healed = _member_pack_tinfo(member)
    if healed is not None:
        return MemberTypeResolution(
            member_name, offset, None, RESOLVED, tinfo=healed
        )
    return MemberTypeResolution(member_name, offset, None, STORED, tinfo=tinfo)


class PackReadiness:
    """Structured pre-pack report over a structure's enabled members.

    ``blocked`` entries are the members that would pack as placeholders —
    callers must refuse to pack and surface ``error`` instead. Virtual
    table members are skipped (they build their own type at pack time) and
    disabled members are skipped (they never pack).
    """

    def __init__(self, entries, structure_name: str | None = None):
        self.entries = tuple(entries)
        self.structure_name = structure_name

    @property
    def blocked(self) -> tuple[MemberTypeResolution, ...]:
        return tuple(entry for entry in self.entries if not entry.ok)

    @property
    def ok(self) -> bool:
        return not self.blocked

    @property
    def error(self) -> str | None:
        messages = [entry.error() for entry in self.blocked]
        if not messages:
            return None
        scope = f" in {self.structure_name!r}" if self.structure_name else ""
        return f"cannot pack{scope}: " + "; ".join(messages)

    def to_dict(self) -> dict:
        blocked = self.blocked
        return {
            "ok": self.ok,
            "structure": self.structure_name,
            "checked": len(self.entries),
            "blocked": [entry.to_dict() for entry in blocked],
            "unresolved_types": sorted(
                {name for entry in blocked for name in entry.unresolved}
            ),
            "error": self.error,
        }


def resolve_pack_readiness(members, structure_name: str | None = None) -> PackReadiness:
    """Run :func:`resolve_member_pack_type` over the packable members."""
    entries = []
    for member in members:
        if isinstance(member, VirtualTable):
            continue
        if not getattr(member, "enabled", True):
            continue
        entries.append(resolve_member_pack_type(member))
    return PackReadiness(entries, structure_name)


# ---------------------------------------------------------------------------
# Provenance-safe member merge (recovery-eval gap #8, 2026-08-30). The scan
# merge used to replace a same-offset authored member with the scan-built
# one, dropping its authored ``decl_src``/name/type/comment; the repair was
# re-asserting them via ``set_member``. :func:`merge_member_evidence` makes
# the safe direction the only direction: authored identity fields survive,
# scan evidence (scanned variables) merges in.
# ---------------------------------------------------------------------------

_AUTO_MEMBER_NAME_RE = re.compile(
    r"(?:(?:[uif](?:8|16|32|64|128|256|512|1024))|field)_[0-9a-fA-F]+"
)


def is_authored_member(member) -> bool:
    """True when the member carries authored identity (decl or human name).

    Scan-built members keep the auto ``u32_10``/``field_10`` name shape and
    carry no ``decl_src``; facade-created members always set ``decl_src``.
    A :class:`VirtualTable` is scan evidence, never authored — its
    generated ``_vftable_...`` name does not match the auto-name regex and
    would otherwise masquerade as authored identity. A
    :class:`LinkedStructureMember` classifies by its (authored) name, like
    any other member; materialization gives it a ``tinfo``, not identity.
    """
    if isinstance(member, VirtualTable):
        return False
    if getattr(member, "decl_src", None):
        return True
    name = getattr(member, "name", None)
    return bool(name) and not _AUTO_MEMBER_NAME_RE.fullmatch(name)


def _merge_base(existing, incoming):
    """Pick the surviving member for a same-offset merge.

    Precedence model (gap #8): authored identity wins over scan evidence
    in either direction; a :class:`VirtualTable` is scan evidence even
    though its generated ``_vftable_...`` name never matches the
    auto-name regex (see :func:`is_authored_member`); between two
    scan-built members the vtable is the stronger shape, otherwise the
    higher score survives.
    """
    existing_authored = is_authored_member(existing)
    incoming_authored = is_authored_member(incoming)
    if existing_authored != incoming_authored:
        return existing if existing_authored else incoming
    if isinstance(existing, VirtualTable) != isinstance(incoming, VirtualTable):
        # A vtable is scan evidence; authored identity still wins, and
        # between two scan-built members the vtable is the stronger shape.
        if existing_authored or incoming_authored:
            return existing if existing_authored else incoming
        return incoming if isinstance(incoming, VirtualTable) else existing
    if not existing_authored and not incoming_authored:
        try:
            if incoming.score > existing.score:
                return incoming
        except Exception:  # noqa: BLE001 — score is a heuristic only
            pass
    return existing


def merge_member_evidence(existing, incoming):
    """Merge a same-offset scan-built member into the surviving member.

    Provenance-safe (gap #8): the surviving member keeps its authored
    ``decl_src``, name, type, comment, array shape and enabled state; the
    other member contributes its scan evidence (``scanned_variables``) and
    link metadata when the survivor has none. Returns the surviving member
    (mutated in place), the other member unchanged, or ``None`` when the
    members cannot merge (both ``None`` is ``None``; different offsets
    cannot merge).

    Facade contract: after the call, drop the non-surviving member from
    ``structure.members`` when it is present there
    (``loser = incoming if merged is existing else existing``).
    """
    if existing is None and incoming is None:
        return None
    if existing is None:
        return incoming
    if incoming is None:
        return existing
    if getattr(existing, "offset", 0) != getattr(incoming, "offset", 0):
        return None
    if existing is incoming:
        return existing

    base = _merge_base(existing, incoming)
    absorbed = incoming if base is existing else existing
    base.scanned_variables = set(getattr(base, "scanned_variables", None) or ()) | set(
        getattr(absorbed, "scanned_variables", None) or ()
    )
    if getattr(base, "linked_child_structure_name", None) is None and getattr(
        absorbed, "linked_child_structure_name", None
    ):
        base.linked_child_structure_name = absorbed.linked_child_structure_name
        base.child_relation_kind = absorbed.child_relation_kind
    if hasattr(base, "invalidate_score"):
        base.invalidate_score()
    return base

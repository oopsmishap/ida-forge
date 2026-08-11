from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import ida_ida
import ida_idaapi
import ida_typeinf

from forge.api.config import ForgeConfig
from forge.util.util import DocIntEnum
from forge.util.logging import log_debug, log_error, log_warning

# Design note: this module never caches live ``tinfo_t`` objects.
# IDA invalidates existing ``tinfo_t`` handles whenever new types are created
# (a known footgun — the original implementation cached derived handles here and
# they went stale mid-session), and this plugin creates types constantly
# (create_type / set_cdecl / save_tinfo). Only the *descriptors* of canonical
# types (typedef name, ordinal, fallback enum) are cached; every access builds
# fresh handles from the IDB, so results always reflect the current type table.


class TypesConfig(ForgeConfig):
    name = "Types"
    default_config = {
        "u8": "u8",
        "u16": "u16",
        "u32": "u32",
        "u64": "u64",
        "u128": "u128",
        "i8": "i8",
        "i16": "i16",
        "i32": "i32",
        "i64": "i64",
        "i128": "i128",
        "f32": "f32",
        "f64": "f64",
        "bool": "bool",
        "char": "char",
        "size_t": "size_t",
        "func_t": "func_t",
    }


@dataclass
class Type:
    """Canonical type plus its common variations.

    Instances are built on demand and must not be stored beyond the immediate
    operation they were requested for: the ``tinfo_t`` members are only valid
    until the next type-table mutation.
    """

    name: str
    type: ida_typeinf.tinfo_t
    ptr: ida_typeinf.tinfo_t
    const: ida_typeinf.tinfo_t
    const_ptr: ida_typeinf.tinfo_t
    ordinal: int


@dataclass(frozen=True)
class _TypeEntry:
    """Persistent descriptor for a canonical type.

    ``typedef_name`` is the named IDA type to load (empty when the type is only
    representable via ``type_enum``); ``save`` records whether the typedef was
    committed to the IDB. ``func_t`` is special-cased in :meth:`Types._get_type`.
    """

    typedef_name: str
    ordinal: int
    type_enum: int
    save: bool


# noinspection PyPep8Naming, SpellCheckingInspection
class tinfo_code(DocIntEnum):
    TERR_OK = 0, "ok"
    TERR_SAVE = -1, "failed to save"
    TERR_SERIALIZE = -2, "failed to serialize"
    TERR_WRONGNAME = -3, "name is not acceptable"
    TERR_BADSYNC = -4, "failed to sync with the IDB"


# noinspection PyPep8Naming
class Types:
    def __init__(self):
        self._typedefs = TypesConfig()
        self._idati = ida_typeinf.get_idati()
        self._type_width = self._get_ptr_width()
        if self._type_width not in (2, 4, 8):
            raise RuntimeError(f"Unsupported pointer width: {self._type_width}")
        self._type_cache: Dict[str, _TypeEntry] = {}

        self._load_types()

        for name, entry in self._type_cache.items():
            log_debug(
                f"{name}: typedef={entry.typedef_name}, ordinal={entry.ordinal}, "
                f"enum={entry.type_enum}, save={entry.save}"
            )

    @property
    def width(self):
        return self._get_ptr_width()

    def _save_or_load_typedef_to_idb(
        self, name: str, type_enum: int
    ) -> int:
        """
        Save a type to the IDB, or load it from the IDB if it already exists.

        :param name: The name of the type.
        :param type_enum: The enum value of the type.
        :return: The ordinal of the type in the IDB.
        """
        # Check if the type already exists in the IDB
        named_type = ida_typeinf.get_named_type(
            self._idati, self._typedefs[name], ida_typeinf.NTF_TYPE
        )

        if named_type is None:
            # Create a new tinfo_t object and save it to the IDB if it does not exist
            type_def = ida_typeinf.tinfo_t(type_enum)
            if (
                ida_typeinf.save_tinfo(
                    type_def, self._idati, 0, self._typedefs[name], ida_typeinf.NTF_TYPE
                )
                != tinfo_code.TERR_OK
            ):
                # Some IDB states refuse names that alias IDA builtins (e.g.
                # "u8" -> unsigned __int8). This is not fatal: the enum-based
                # (ordinal 0) entry yields the same underlying type.
                log_warning(
                    f"Failed to save type '{name}' to IDB; "
                    "falling back to the built-in type"
                )
                return 0

            named_type = ida_typeinf.get_named_type(
                self._idati, self._typedefs[name], ida_typeinf.NTF_TYPE
            )

        if named_type is None:
            log_warning(f"Type '{name}' could not be located after save; using ordinal 0")
            return 0

        # The tuple returned by get_named_type carries the type ordinal at [6]
        return named_type[6]

    def _add_type_to_cache(self, name: str, type_enum: int, save: bool = True) -> None:
        """
        Register a canonical type descriptor.

        :param name: The name of the type.
        :param type_enum: The enum value of the type.
        """
        if save:
            ordinal = self._save_or_load_typedef_to_idb(name, type_enum)
        else:
            ordinal = 0

        self._type_cache[name] = _TypeEntry(name, ordinal, type_enum, save)

    def _build_func_type(self) -> Type:
        """Build a fresh ``func_t`` placeholder type (no arguments, unknown cc)."""
        func_data = ida_typeinf.func_type_data_t()
        func_data.rettype = self._get_type("void").ptr
        func_data.cc = ida_typeinf.CM_CC_UNKNOWN
        dummy_func = ida_typeinf.tinfo_t()
        dummy_func.create_func(func_data, ida_typeinf.BT_FUNC)

        return Type("func_t", dummy_func, dummy_func, dummy_func, dummy_func, 0)

    def _load_types(self) -> None:
        """
        Load all the types into the type cache.
        :return: None
        """

        # https://www.hex-rays.com/products/ida/support/sdkdoc/typeinf_8hpp.html

        self._add_type_to_cache("void", ida_typeinf.BT_VOID, False)
        self._add_type_to_cache("bool", ida_typeinf.BTF_BOOL, False)
        self._add_type_to_cache("char", ida_typeinf.BTF_CHAR, False)
        self._add_type_to_cache("u8", ida_typeinf.BTF_UINT8)
        self._add_type_to_cache("u16", ida_typeinf.BTF_UINT16)
        self._add_type_to_cache("u32", ida_typeinf.BTF_UINT32)
        self._add_type_to_cache("u64", ida_typeinf.BTF_UINT64)
        self._add_type_to_cache("u128", ida_typeinf.BTF_UINT128)
        self._add_type_to_cache("i8", ida_typeinf.BTF_INT8)
        self._add_type_to_cache("i16", ida_typeinf.BTF_INT16)
        self._add_type_to_cache("i32", ida_typeinf.BTF_INT32)
        self._add_type_to_cache("i64", ida_typeinf.BTF_INT64)
        self._add_type_to_cache("i128", ida_typeinf.BTF_INT128)
        self._add_type_to_cache("f32", ida_typeinf.BTF_FLOAT)
        self._add_type_to_cache("f64", ida_typeinf.BTF_DOUBLE)
        self._add_type_to_cache("size_t", self._size_t_enum(self._type_width))
        # TODO: add any more types that are needed

    @staticmethod
    def _size_t_enum(width: int) -> int:
        """Pick the ``size_t`` type constant for the pointer width (16/32/64)."""
        if width <= 2:
            return ida_typeinf.BTF_UINT16
        if width == 4:
            return ida_typeinf.BTF_UINT32
        return ida_typeinf.BTF_UINT64

    def _load_base_tinfo(self, entry: _TypeEntry) -> ida_typeinf.tinfo_t:
        """Return a fresh ``tinfo_t`` for a canonical type descriptor.

        Prefers the committed typedef so user redefinitions are honored;
        falls back to the enum constant when the typedef is missing.
        """
        if entry.save and entry.typedef_name:
            resolved = ida_typeinf.tinfo_t()
            if resolved.get_named_type(self._idati, entry.typedef_name):
                return resolved

        return ida_typeinf.tinfo_t(entry.type_enum)

    def _base_type_of(self, name: str) -> ida_typeinf.tinfo_t:
        """Return a fresh base ``tinfo_t`` for a canonical type name."""
        if name == "func_t":
            return self._build_func_type().type
        return self._load_base_tinfo(self._type_cache[name])

    def _get_type(self, name: str) -> Type:
        """Build a fresh :class:`Type` with all variations for ``name``.

        Every access re-loads the base type from the IDB so the returned
        ``tinfo_t`` handles reflect the current type table — never cached.
        """
        if name == "func_t":
            return self._build_func_type()

        entry = self._type_cache[name]
        base_type = self._load_base_tinfo(entry)

        # Create a pointer variation of the type
        type_def_ptr = ida_typeinf.tinfo_t()
        type_def_ptr.create_ptr(base_type)

        # Create a const variation of the type
        type_def_const = ida_typeinf.tinfo_t(base_type)
        type_def_const.set_const()

        # Create a const pointer variation of the type
        type_def_const_ptr = ida_typeinf.tinfo_t()
        type_def_const_ptr.create_ptr(type_def_const)

        return Type(name, base_type, type_def_ptr, type_def_const, type_def_const_ptr, entry.ordinal)

    @staticmethod
    def _is_meaningful_type_shape(tinfo: ida_typeinf.tinfo_t) -> bool:
        return any(
            predicate()
            for predicate in (
                tinfo.is_udt,
                tinfo.is_func,
                tinfo.is_funcptr,
                tinfo.is_array,
            )
        )

    def _is_canonical_scalar_type(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        scalar_names = (
            "bool",
            "char",
            "u8",
            "u16",
            "u32",
            "u64",
            "u128",
            "i8",
            "i16",
            "i32",
            "i64",
            "i128",
            "f32",
            "f64",
            "size_t",
        )
        return any(
            tinfo.equals_to(self._base_type_of(name))
            for name in scalar_names
            if name in self._type_cache
        )

    def convert_to_simple_type(
        self,
        in_type: Optional[ida_typeinf.tinfo_t],
    ) -> Optional[ida_typeinf.tinfo_t]:
        """
        Canonicalize scalar aliases while preserving meaningful type structure.


        :param in_type: The type to canonicalize.

        :return: The canonicalized type.
        """
        if in_type is None:
            return None

        work_type = ida_typeinf.tinfo_t(in_type)

        if self._is_meaningful_type_shape(work_type):
            return work_type

        if work_type.is_ptr():
            pointed = work_type.get_pointed_object()
            if pointed is None:
                return work_type

            if (
                pointed.is_ptr()
                or self._is_meaningful_type_shape(pointed)
                or self._is_canonical_scalar_type(pointed)
            ):
                return work_type

            simplified_pointed = self.convert_to_simple_type(pointed)
            pointer_tinfo = ida_typeinf.tinfo_t()
            pointer_tinfo.create_ptr(simplified_pointed)
            return pointer_tinfo

        if self._is_canonical_scalar_type(work_type):
            return work_type

        size = work_type.get_size()
        if size in [1, 2, 4, 8, 16]:
            if work_type.is_integral():
                return ida_typeinf.tinfo_t(
                    self._base_type_of(
                        f"{'i' if work_type.is_signed() else 'u'}{size * 8}"
                    )
                )
            if work_type.is_float():
                return ida_typeinf.tinfo_t(self._base_type_of(f"f{size * 8}"))

        return work_type

    def get_ptr_tinfo(self):
        """Return a fresh ``void *``-like pointer tinfo for the pointer width."""
        return ida_typeinf.tinfo_t(self.get_ptr_type().ptr)

    def get_ptr_type(self):
        if self.width == 8:
            return self._get_type("u64")
        elif self.width == 4:
            return self._get_type("u32")
        elif self.width == 2:
            return self._get_type("u16")
        else:
            raise Exception("Unsupported architecture")

    @staticmethod
    def _get_ptr_width():
        if ida_ida.inf_is_64bit():
            width = 8
        elif ida_ida.inf_is_32bit_exactly():
            width = 4
        elif ida_ida.inf_is_16bit():
            width = 2
        else:
            raise Exception("Unsupported architecture")
        return width

    def __getitem__(self, item):
        return self._get_type(item)

    def __contains__(self, item):
        return item in self._type_cache


types = Types()


def create_type(name: str, declaration: str) -> bool:
    """
    Creates a new type in the IDA database.

    :param str name: The name of the type to create.
    :param str declaration: The declaration of the type to create.
    :return bool: True if the type was created successfully, False otherwise.
    """
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, name):
        log_error(f"Type with name '{name}' already exists")
        return False
    ida_typeinf.idc_parse_types(declaration, 0)
    if not tif.get_named_type(None, name):
        log_error(f"Failed to create type '{name}'")
        return False
    return True


def import_type(name):
    """
    Imports a type from a library into the IDA database.

    :param str name: The name of the type to import.
    :return int: The ordinal number of the imported type.
    """
    last_ordinal = ida_typeinf.get_ordinal_count(ida_typeinf.get_idati())
    type_id = ida_typeinf.import_type(ida_typeinf.get_idati(), -1, name)
    if type_id != ida_idaapi.BADORD:
        return last_ordinal
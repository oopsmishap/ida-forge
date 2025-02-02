from dataclasses import dataclass
from typing import Dict, Tuple

import ida_ida
import ida_typeinf
import idc

from forge.api.config import ForgeConfig
from forge.util.util import DocIntEnum
from forge.util.logging import log_debug, log_error


# leimurr — Today at 5:11 PM
# watch out with anything that "caches" tinfo_t objects; I used to do things like that in my project, but I found that
# IDA would invalidate existing tinfo_t objects any time I created new ones. if you use this code further, and you get
# issues where the types coming out of the cache are invalid, something like that is probably happening


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
    name: str
    type: ida_typeinf.tinfo_t
    ptr: ida_typeinf.tinfo_t
    const: ida_typeinf.tinfo_t
    const_ptr: ida_typeinf.tinfo_t
    ordinal: int


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
        assert self._type_width in (4, 8), f"Invalid pointer width: {self._type_width}"
        self._type_cache: Dict[str, Type] = {}

        self._load_types()
        self._create_dummy_func()

        for k, v in self._type_cache.items():
            log_debug(f"{k}: {v.type}, {v.ptr}, {v.const}, {v.const_ptr}")

    @property
    def width(self):
        return self._get_ptr_width()

    def _save_or_load_typedef_to_idb(
        self, name: str, type_enum: int
    ) -> Tuple[ida_typeinf.tinfo_t, int]:
        """
        Save a type to the IDB, or load it from the IDB if it already exists.
        :param name: The name of the type.
        :param type_enum: The enum value of the type.
        :return: The type info object.
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
                raise RuntimeError(f"Failed to save type '{name}' to IDB")

            named_type = ida_typeinf.get_named_type(
                self._idati, self._typedefs[name], ida_typeinf.NTF_TYPE
            )

        # Load the type from the IDB into a tinfo_t object
        out_type = ida_typeinf.tinfo_t()
        if out_type.get_numbered_type(self._idati, named_type[6]):
            # Return the tinfo_t object and the ordinal
            return out_type, named_type[6]
        else:
            # Return a new tinfo_t object if the type could not be loaded
            return ida_typeinf.tinfo_t(type_enum), 0

    def _add_type_to_cache(self, name: str, type_enum: int, save: bool = True) -> None:
        """
        Add a type to the type cache, along with its variations (pointer, const, const pointer).

        :param name: The name of the type.
        :param type_enum: The enum value of the type.
        """
        # Create the base type and add it to the type cache
        if save:
            type_def, ordinal = self._save_or_load_typedef_to_idb(name, type_enum)
        else:
            type_def = ida_typeinf.tinfo_t(type_enum)
            ordinal = 0

        # Create a pointer variation of the type
        type_def_ptr = ida_typeinf.tinfo_t()
        type_def_ptr.create_ptr(type_def)

        # Create a const variation of the type
        type_def_const = ida_typeinf.tinfo_t(type_def)
        type_def_const.set_const()

        # Create a const pointer variation of the type
        type_def_const_ptr = ida_typeinf.tinfo_t()
        type_def_const_ptr.create_ptr(type_def_const)

        # Add the type to the type cache
        self._type_cache[name] = Type(
            name, type_def, type_def_ptr, type_def_const, type_def_const_ptr, ordinal
        )

    def _create_dummy_func(self):
        func_data = ida_typeinf.func_type_data_t()
        func_data.rettype = self._type_cache["void"].ptr
        func_data.cc = ida_typeinf.CM_CC_UNKNOWN
        dummy_func = ida_typeinf.tinfo_t()
        dummy_func.create_func(func_data, ida_typeinf.BT_FUNC)

        func = Type("func_t", dummy_func, dummy_func, dummy_func, dummy_func, 0)
        self._type_cache["func_t"] = func

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
        self._add_type_to_cache(
            "size_t",
            ida_typeinf.BTF_UINT32 if self._type_width == 4 else ida_typeinf.BTF_UINT64,
        )
        # TODO: add any more types that are needed

    def convert_to_simple_type(
        self, in_type: ida_typeinf.tinfo_t, was_pointer: bool = False
    ) -> ida_typeinf.tinfo_t:
        """
        Convert a type to a simple type (i.e. remove any pointers, arrays, etc.).

        :param in_type: The type to convert.
        :param was_pointer: Flag to indicate if the type was a pointer.
        :return: The converted type.
        """
        out_type = ida_typeinf.tinfo_t()

        if in_type.is_ptr():
            if in_type.remove_ptr_or_array():
                return self.convert_to_simple_type(in_type, True)
            else:
                raise Exception(f"Failed to remove pointer from type {in_type.dstr()}")

        # gets the width of the type in bytes
        size = in_type.get_size()

        if size in [1, 2, 4, 8, 16]:
            if in_type.is_integral():
                # if signed gets iXX, if unsigned gets uXX (e.g. i8, u16)
                out_type = self._type_cache[
                    f"{'i' if in_type.is_signed() else 'u'}{size * 8}"
                ].type
            elif in_type.is_float():
                out_type = self._type_cache[f"f{size * 8}"].type
            else:
                return in_type
        else:
            return in_type

        if was_pointer:
            out_type.create_ptr(out_type)

        return out_type

    def get_ptr(self):
        return self.get_ptr_type().ptr
        
    def get_ptr_type(self):
        if self.width == 8:
            return self._type_cache["u64"]
        elif self.width == 4:
            return self._type_cache["u32"]
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
        return self._type_cache[item]

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
    type_id = idc.import_type(-1, name)  # tid_t
    if type_id != ida_typeinf.BADORD:
        return last_ordinal

# Based on Rolf Rolles TemplatedTypes script
# https://www.msreverseengineering.com/blog/2021/9/21/automation-in-reverse-engineering-c-template-code

import os
import pathlib

import ida_hexrays
import ida_idaapi
import ida_typeinf
import toml

from forge.util.logging import log_debug, log_error

from .config import config

# IDA 9.4 moved BADORD off ida_idaapi; resolve it wherever the build keeps it.
_BADORD = getattr(ida_idaapi, "BADORD", getattr(ida_typeinf, "BADORD", -1))

# from forge.util.cxx_to_c_name import demangled_name_to_c_str, maybe implement this in later


class TemplatedTypes:
    def __init__(self):
        self._types_dict = {}
        self.keys = []
        self.file_name = config["default_type_file"]
        if self.file_name and config.default_type_file_fullpath:
            self.file_path = config.default_type_file_fullpath
        else:
            self.file_path = (
                pathlib.Path(__file__).resolve().parent / "templated_types.toml"
            )

        log_debug(f"Loading templated types from {self.file_path}")

        self.set_file_path(self.file_path)

    def get_decl_str(self, key: str, args):
        # ensure type is in our dictionary
        if key in self._types_dict:
            type_count = len(self._types_dict[key]["types"])
            # ensure that the number of types is what we expect for format string
            if type_count * 2 == len(args):
                type_struct = self._types_dict[key]["struct"]
                type_name = self._types_dict[key]["base_name"]
                # apply formatting to struct string
                try:
                    type_struct = type_struct.format(*args)
                    type_name = type_name.format(*args)
                    # return tuple
                    return type_name, type_struct
                except Exception as e:  # noqa: BLE001 — malformed TOML entries are skipped
                    log_error(f'failed to parse struct, name: "{type_name}", error: {e}')
                    return None
            else:
                log_error("arg count does not match type")
                return None
        else:
            log_error(f"type is not in type dictionary: {key}")
            return None

    def set_type(self, key, args):
        ret_val = self.get_decl_str(key, args)
        # ret_val is None if failed
        if ret_val is None:
            log_error("could not generate STL type")
            return

        name, cdecl = ret_val
        # apply the decls and clear scanned vars if successful
        ret_val = ida_typeinf.idc_parse_types(cdecl, 0)

        if ret_val != 0:
            log_error(f"Could not parse structure declarations, found {ret_val} errors")
            return

        tid = self._import_named_type(name)
        if tid is _BADORD:
            log_error(f'could not import type "{name}" into idb')
            return
        ida_hexrays.create_typedef(name)

    @staticmethod
    def _import_named_type(name: str):
        """Import a named type into the IDB across IDA 9 API changes.

        IDA 9.4 moved ``import_type`` off the ``ida_typeinf`` module (it is now
        ``til.import_type(tinfo)`` or ``idc.import_type(idati, name)``); older
        builds keep ``ida_typeinf.import_type(idati, -1, name)``. Returns the
        type ordinal or ``BADORD`` on failure.
        """
        idati = ida_typeinf.get_idati()

        module_import = getattr(ida_typeinf, "import_type", None)
        if callable(module_import):
            return module_import(idati, -1, name)

        til_import = getattr(idati, "import_type", None)
        if callable(til_import):
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_named_type(idati, name):
                return _BADORD
            result = til_import(tinfo)
            return name if result is not None else _BADORD

        import idc

        return idc.import_type(idati, name)

    def get_types(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["types"]
        log_error("type is not in type dictionary")
        return None

    def get_struct(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["struct"]
        log_error("struct is not in type dictionary")
        return None

    def get_base_name(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["base_name"]
        log_error("struct is not in type dictionary")
        return None

    def set_file_path(self, path):
        self.file_path = path
        self.file_name = os.path.basename(path)
        self.reload_types()

    def reload_types(self):
        if self.file_path == "":
            return False
        with open(self.file_path) as f:
            types_dict = toml.loads(f.read())
        self._types_dict = types_dict
        self.keys = list(types_dict.keys())
        return True

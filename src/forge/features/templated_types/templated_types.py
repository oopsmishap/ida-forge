# Based on Rolf Rolles TemplatedTypes script
# https://www.msreverseengineering.com/blog/2021/9/21/automation-in-reverse-engineering-c-template-code


import os
import pathlib

import toml


import ida_typeinf
import ida_hexrays
import idc

from forge.util.logging import *
from .config import config


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
                except Exception as e:
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

        tid = idc.import_type(-1, name)
        if tid is idc.BADADDR:
            log_error(f'could not import type "{name}" into idb')
            return

        log_info(f'New type "{name}" was added to Local Types')
        ida_hexrays.create_typedef(name)

    def get_types(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["types"]
        else:
            log_error("type is not in type dictionary")
            return None

    def get_struct(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["struct"]
        else:
            log_error("struct is not in type dictionary")
            return None

    def get_base_name(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["base_name"]
        else:
            log_error("struct is not in type dictionary")
            return None

    def set_file_path(self, path):
        self.file_path = path
        self.file_name = os.path.basename(path)
        self.reload_types()

    def reload_types(self):
        if self.file_path == "":
            return False
        with open(self.file_path, "r") as f:
            types_dict = toml.loads(f.read())
        self._types_dict = types_dict
        self.keys = list(types_dict.keys())
        return True

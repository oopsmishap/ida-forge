# Based on Rolf Rolles TemplatedTypes script
# https://www.msreverseengineering.com/blog/2021/9/21/automation-in-reverse-engineering-c-template-code

import os
import pathlib

import ida_hexrays
import ida_ida
import ida_idaapi
import ida_typeinf

try:  # stdlib tomllib on Python 3.11+ (IDA 9.x ships 3.12) — E7, 2026-08-13
    import tomllib
except ImportError:  # Python 3.9/3.10 falls back to the optional `toml` package
    tomllib = None

from forge.util.logging import log_debug, log_error, log_warning

from .config import config

# IDA 9.4 moved BADORD off ida_idaapi; resolve it wherever the build keeps it.
_BADORD = getattr(ida_idaapi, "BADORD", getattr(ida_typeinf, "BADORD", -1))

# from forge.util.cxx_to_c_name import demangled_name_to_c_str, maybe implement this in later


def _get_compiler_id() -> int:
    """Return the IDB compiler id across IDA 9 API shapes.

    Newer builds expose ``ida_ida.inf_get_cc_id()``; older ones keep the
    value inside ``idaapi.get_inf_structure().cc.id``. Falls back to 0 when
    neither is available so MSVC-only layouts are hidden rather than
    misapplied.
    """
    getter = getattr(ida_ida, "inf_get_cc_id", None)
    if callable(getter):
        return int(getter())
    try:
        inf = ida_idaapi.get_inf_structure()
        cc = getattr(inf, "cc", None)
        return int(getattr(cc, "id", 0))
    except Exception:  # noqa: BLE001 — compiler unknown, hide MSVC layouts
        return 0


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
            if result is not None and result != _BADORD:
                return result
            return _BADORD

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
        # E7 (eval review 2026-08-13): a hard ``import toml`` made the whole
        # templated subsystem dead in headless envs that lack the package.
        # Read via stdlib tomllib, falling back to the optional package.
        if tomllib is not None:
            with open(self.file_path, "rb") as f:
                loaded_types = tomllib.load(f)
        else:
            import toml

            with open(self.file_path, encoding="utf-8") as f:
                loaded_types = toml.loads(f.read())

        # MSVC std::* layouts are only valid on MSVC-built IDBs; hide them
        # when the compiler is GNU/unknown so a wrong layout is never applied.
        compiler_mask = getattr(ida_typeinf, "COMP_MASK", 0)
        msvc_id = getattr(ida_typeinf, "COMP_MS", None)
        is_msvc = (
            msvc_id is not None
            and (_get_compiler_id() & compiler_mask) == msvc_id
        )
        hidden_msvc = False
        types_dict = {}
        for name, template_type in loaded_types.items():
            compiler = template_type.get("compiler", "any")
            if compiler == "msvc" and not is_msvc:
                hidden_msvc = True
                continue
            types_dict[name] = template_type

        if hidden_msvc:
            log_warning(
                "MSVC templated type layouts are hidden because the IDB "
                "compiler is GNU or unknown"
            )

        self._types_dict = types_dict
        self.keys = list(types_dict.keys())
        return True

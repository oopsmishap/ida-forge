from __future__ import annotations

import ida_nalt
import idaapi

from forge.util.logging import log_debug

imported_ea: set[int] = set()


def _collect_imported_ea() -> None:
    image_base = ida_nalt.get_imagebase()

    def imp_cb(ea: int, _name: str, _ordinal: int) -> bool:
        imported_ea.add(ea - image_base)
        return True

    log_debug("Collecting information about imports")
    imported_ea.clear()
    import_count = idaapi.get_import_module_qty()

    for i in range(import_count):
        name = idaapi.get_import_module_name(i)
        if not name:
            log_debug(f"Failed to get import module name for #{i}")
            continue

        idaapi.enum_import_names(i, imp_cb)
    log_debug("Done...")


def initialize_cache() -> None:
    _collect_imported_ea()

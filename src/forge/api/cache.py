from __future__ import annotations

import ida_nalt

from forge.api.domain import current_database as _current_domain_database
from forge.api.domain import try_domain_method as _try_domain_method
from forge.util.logging import log_debug

imported_ea: set[int] = set()


def _collect_imported_ea() -> None:
    """Refresh imported addresses, preferring Domain import enumeration.

    Cached values are **absolute** EAs — the single coordinate system every
    consumer (:func:`forge.api.hexrays.is_imported`) normalizes to — so a
    cached entry matches regardless of the image base.
    """
    log_debug("Collecting information about imports")
    imported_ea.clear()
    handled, entries = _try_domain_method(
        _current_domain_database(required=False),
        "imports",
        "get_all_imports",
        capability="imports.imported_ea",
        unavailable_reason="ida-domain import enumeration unavailable on this build/session",
        failure_reason="ida-domain import enumeration failed",
        exceptions=(Exception,),
    )
    if handled:
        for item in entries or ():
            address = getattr(item, "address", None)
            if address is not None:
                imported_ea.add(address)
        log_debug("Done...")
        return

    def imp_cb(ea: int, _name: str, _ordinal: int) -> bool:
        imported_ea.add(ea)
        return True

    import_count = ida_nalt.get_import_module_qty()
    for i in range(import_count):
        name = ida_nalt.get_import_module_name(i)
        if not name:
            log_debug(f"Failed to get import module name for #{i}")
            continue
        ida_nalt.enum_import_names(i, imp_cb)
    log_debug("Done...")

def initialize_cache() -> None:
    _collect_imported_ea()

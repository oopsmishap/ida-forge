from __future__ import annotations

from typing import Optional

import ida_typeinf


def _call_tinfo_method(tinfo, name: str, default=None):
    method = getattr(tinfo, name, None)
    if not callable(method):
        return default
    try:
        return method()
    except Exception:
        return default



def is_incomplete_tinfo(
    tinfo: Optional[ida_typeinf.tinfo_t], _seen: Optional[set[int]] = None
) -> bool:
    """Return True when a tinfo is missing or structurally incomplete."""
    if tinfo is None:
        return True

    marker = id(tinfo)
    if _seen is None:
        _seen = set()
    elif marker in _seen:
        return False
    _seen.add(marker)

    # Function and void types can legitimately report BADSIZE; they are known.
    if _call_tinfo_method(tinfo, "is_funcptr", False):
        return False
    if _call_tinfo_method(tinfo, "is_func", False):
        return False
    if _call_tinfo_method(tinfo, "is_void", False):
        return False

    if _call_tinfo_method(tinfo, "dstr", None) == "?":
        return True
    if _call_tinfo_method(tinfo, "is_forward_decl", False):
        return True

    if _call_tinfo_method(tinfo, "is_ptr", False):
        pointed = _call_tinfo_method(tinfo, "get_pointed_object", None)
        if pointed is None:
            return True
        return is_incomplete_tinfo(pointed, _seen)

    if _call_tinfo_method(tinfo, "is_array", False):
        element = _call_tinfo_method(tinfo, "get_array_element", None)
        if element is None:
            return True
        return is_incomplete_tinfo(element, _seen)

    return _call_tinfo_method(tinfo, "get_size", None) == ida_typeinf.BADSIZE

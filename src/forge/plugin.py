from __future__ import annotations

from typing import Any, Callable

import ida_expr

AUTHOR: str = "@oopsmishap"

VERSION: tuple = (0, 0, 1)
VERSION_STRING: str = ".".join([str(x) for x in VERSION])

PLUGIN_NAME: str = "Forge"
PLUGIN_COMMENT: str = ""
PLUGIN_HELP: str = ""
PLUGIN_BASE_NETNODE_ID: str = "$forge"
PLUGIN_ACTIONS_PREFIX: str = "forge"
PLUGIN_VERSION = VERSION_STRING


_GET_STATE_NAME: str = "forge_get_state"
_SET_STATE_NAME: str = "forge_set_state"


def register_idc_func(plugmod: Any) -> None:
    """Register IDC accessors for cross-plugin state sharing.

    ``plugmod`` is expected to expose ``get_state(index: int) -> str`` and
    ``add_state(value: str) -> int`` methods.
    """
    try:
        ida_expr.del_idc_func(_GET_STATE_NAME)
    except Exception:
        pass
    try:
        ida_expr.del_idc_func(_SET_STATE_NAME)
    except Exception:
        pass

    ida_expr.add_idc_func(_GET_STATE_NAME, plugmod.get_state, (ida_expr.VT_LONG,))
    ida_expr.add_idc_func(_SET_STATE_NAME, plugmod.add_state, (ida_expr.VT_STR,))


def unregister_idc_func() -> None:
    """Remove the cross-plugin IDC accessors registered by :func:`register_idc_func`."""
    try:
        ida_expr.del_idc_func(_GET_STATE_NAME)
    except Exception:
        pass
    try:
        ida_expr.del_idc_func(_SET_STATE_NAME)
    except Exception:
        pass

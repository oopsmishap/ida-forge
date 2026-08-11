from __future__ import annotations

import logging
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


def _register_idc_func(name: str, func: Callable[..., Any], arg_types: tuple) -> None:
    """Register one IDC accessor; failures must not abort plugin init.

    ``arg_types`` is a tuple of ``ida_expr.VT_*`` codes — verified against real
    IDA 9.x bindings (the docs' ``str`` typing for this parameter is misleading;
    passing a plain string raises ``TypeError``).

    Uses the stdlib logger directly (not :mod:`forge.util.logging`) because this
    module is imported by the logging module itself — importing it here would be
    circular. The forge handler is attached to the same ``forge`` logger.
    """
    try:
        ida_expr.add_idc_func(name, func, arg_types)
    except Exception as exc:  # noqa: BLE001 — IDA-version tolerance
        logging.getLogger("forge").warning(
            f"Failed to register IDC function {name}: {exc}"
        )


def register_idc_func(plugmod: Any) -> None:
    """Register IDC accessors for cross-plugin state sharing.

    ``plugmod`` is expected to expose ``get_state(index: int) -> str`` and
    ``add_state(value: str) -> int`` methods.
    """
    for name in (_GET_STATE_NAME, _SET_STATE_NAME):
        try:
            ida_expr.del_idc_func(name)
        except Exception:  # noqa: BLE001, S110 — removing an unregistered name is expected
            pass

    _register_idc_func(_GET_STATE_NAME, plugmod.get_state, (ida_expr.VT_LONG,))
    _register_idc_func(_SET_STATE_NAME, plugmod.add_state, (ida_expr.VT_STR,))


def unregister_idc_func() -> None:
    """Remove the cross-plugin IDC accessors registered by :func:`register_idc_func`."""
    for name in (_GET_STATE_NAME, _SET_STATE_NAME):
        try:
            ida_expr.del_idc_func(name)
        except Exception:  # noqa: BLE001, S110 — plugin may not have registered yet
            pass

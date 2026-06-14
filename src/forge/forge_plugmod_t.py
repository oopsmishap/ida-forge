from __future__ import annotations

import sys
import traceback
from typing import TYPE_CHECKING

import ida_hexrays
import ida_idp
import ida_idaapi
import ida_kernwin

from forge.core import ForgeCore
from forge.plugin import (
    PLUGIN_COMMENT,
    PLUGIN_HELP,
    PLUGIN_NAME,
    register_idc_func,
    unregister_idc_func,
)
from forge.util.logging import log_debug, log_warning
from forge.util.reload import recursive_reload
from forge.util.versions import (
    is_ida_version_supported,
    is_python_version_supported,
)


class _ReadyHook(ida_kernwin.UI_Hooks):
    """UI hook that attaches the plugin menu when the UI is ready."""

    def __init__(self, plugin: "ForgePlugin") -> None:
        super().__init__()
        self._plugin = plugin

    def ready_to_run(self) -> None:
        if self._plugin._core is not None:
            self._plugin._core.show_menu()


class ForgePlugin(ida_idaapi.plugin_t):
    """IDA plugin entry point for Forge.

    All heavy lifting (core load, menu attach, IDC registration) happens
    in :meth:`init` because Forge is a multi-feature plugin whose setup
    must run exactly once per IDB load. The returned :class:`forge_plugmod_t`
    is a thin handle that owns the active runtime: it forwards
    :meth:`run` to the menu, exposes hot-reload and IDC state-log
    helpers, and runs cleanup in :meth:`__del__` when IDA unloads the
    plugin or the database closes.

    With ``PLUGIN_MULTI`` the ``plugin_t`` exists only to satisfy IDA's
    "give me a descriptor" contract; ``plugin_t.run`` and ``plugin_t.term``
    are not invoked. Activation and teardown go through the
    ``plugmod_t`` instance returned by :meth:`init`.
    """

    flags = ida_idaapi.PLUGIN_MULTI
    version = ida_idp.IDP_INTERFACE_VERSION
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self) -> None:
        super().__init__()
        self._core: ForgeCore | None = None
        self._ready_hook: _ReadyHook | None = None
        self._state_log: list[str] = []
        self._plugmod: "forge_plugmod_t | None" = None

    def init(self) -> ida_idaapi.plugmod_t:
        try:
            return self._do_init()
        except Exception as exc:  # noqa: BLE001
            ida_kernwin.warning(f"Forge: init failed: {exc}")
            traceback.print_exc()
            return ida_idaapi.PLUGIN_SKIP

    def _do_init(self) -> ida_idaapi.plugmod_t:
        log_debug(f"Checking environment for {PLUGIN_NAME}")
        if not is_python_version_supported():
            log_warning("Unsupported Python version")
            return ida_idaapi.PLUGIN_SKIP

        if not is_ida_version_supported():
            log_warning("Unsupported IDA version")
            return ida_idaapi.PLUGIN_SKIP

        if not ida_hexrays.init_hexrays_plugin():
            log_warning("Failed to initialize Hex-Rays SDK")
            return ida_idaapi.PLUGIN_SKIP

        try:
            self._core = ForgeCore()
            self._core.load()

            self._ready_hook = _ReadyHook(self)
            self._ready_hook.hook()

            plugmod = forge_plugmod_t(self)
            self._plugmod = plugmod

            register_idc_func(plugmod)

            main_module = sys.modules.get("__main__")
            if main_module is not None:
                main_module.forge = plugmod

            log_debug(f"{PLUGIN_NAME} loaded successfully!")
            return plugmod
        except Exception as exc:  # noqa: BLE001
            log_warning(f"Failed to initialize {PLUGIN_NAME}: {exc}")
            traceback.print_exc()
            return ida_idaapi.PLUGIN_SKIP

    def _teardown(self) -> None:
        """Release every resource ``_do_init`` acquired.

        Idempotent and safe to call multiple times. Invoked from
        :meth:`forge_plugmod_t.__del__`; the ``PLUGIN_MULTI`` lifecycle
        destroys the plugmod (not this ``plugin_t``) on unload, so this
        method must not be called from ``plugin_t.term``.
        """
        unregister_idc_func()

        if self._ready_hook is not None:
            self._ready_hook.unhook()
            self._ready_hook = None

        if self._core is not None:
            self._core.unload()
            self._core = None

        main_module = sys.modules.get("__main__")
        if main_module is not None and getattr(main_module, "forge", None) is self._plugmod:
            del main_module.forge

        self._plugmod = None

    @property
    def core(self) -> ForgeCore | None:
        """Return the active plugin core."""
        return self._core

    def reload(self) -> None:
        """Hot-reload the plugin modules and recreate the core on the UI thread."""
        log_debug(f"Reloading {PLUGIN_NAME}")
        if not ida_kernwin.execute_ui_requests([lambda: self._reload_inner()]):
            log_warning("Could not schedule Forge reload.")

    def _reload_inner(self) -> None:
        if self._core is not None:
            self._core.unload(keep_menu=True)
            self._core = None

        if self._ready_hook is not None:
            self._ready_hook.unhook()
            self._ready_hook = None

        forge_pkg = sys.modules.get("forge")
        if forge_pkg is None:
            log_warning("Cannot reload: 'forge' package is not in sys.modules")
            return

        recursive_reload(forge_pkg, exclude_prefixes=("forge.api.ui_actions",))

        from forge.core import ForgeCore as _Core

        self._core = _Core()
        self._core.load()

        self._ready_hook = _ReadyHook(self)
        self._ready_hook.hook()

        log_debug(f"{PLUGIN_NAME} reloaded successfully!")

    def get_state(self, index: int) -> str:
        """Return the recorded state entry at ``index`` (IDC accessor)."""
        if not self._state_log:
            return ""
        try:
            return self._state_log[index]
        except (IndexError, TypeError):
            return ""

    def add_state(self, value: str) -> int:
        """Append ``value`` to the state log and return its index (IDC accessor)."""
        self._state_log.append(value or "")
        return len(self._state_log) - 1


class forge_plugmod_t(ida_idaapi.plugmod_t):
    """Active lifecycle for Forge, returned by :meth:`ForgePlugin.init`.

    Cleanup runs in :meth:`__del__` because IDA's ``PLUGIN_MULTI``
    lifecycle destroys the plugmod (not the ``plugin_t``) when the
    plugin is unloaded or the database closes. Activation runs in
    :meth:`run`; the rest of the methods forward to the back-referenced
    :class:`ForgePlugin`.
    """

    def __init__(self, plugin: "ForgePlugin") -> None:
        super().__init__()
        self._plugin = plugin

    def __del__(self) -> None:
        # Best-effort cleanup. IDA may unload the plugmod at any time
        # (database close, plugin unload, IDA exit). Swallow any error
        # so we never raise from a destructor.
        try:
            self._plugin._teardown()
        except Exception:  # noqa: BLE001
            pass

    def run(self, arg: int) -> None:
        # Called by IDA when the user activates the plugin from
        # Edit > Plugins > Forge. Just show the menu.
        if self._plugin._core is not None:
            self._plugin._core.show_menu()

    @property
    def core(self):
        return self._plugin.core

    def reload(self) -> None:
        self._plugin.reload()

    def get_state(self, index: int) -> str:
        return self._plugin.get_state(index)

    def add_state(self, value: str) -> int:
        return self._plugin.add_state(value)

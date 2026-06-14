from __future__ import annotations

import sys
import traceback
from typing import TYPE_CHECKING

import ida_hexrays
import ida_idaapi
import ida_kernwin

from forge.core import ForgeCore
from forge.plugin import (
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


if TYPE_CHECKING:
    pass


class _ReadyHook(ida_kernwin.UI_Hooks):
    """UI hook that attaches the plugin menu when the UI is ready."""

    def __init__(self, plugmod: "forge_plugmod_t") -> None:
        super().__init__()
        self._plugmod = plugmod

    def ready_to_run(self) -> None:
        if self._plugmod._core is not None:
            self._plugmod._core.show_menu()


class forge_plugmod_t(ida_idaapi.plugmod_t):
    """Active lifecycle for the Forge plugin.

    Owns the live :class:`ForgeCore` instance, registers cross-plugin IDC
    accessors, and attaches the top-level menu once IDA's UI is ready.
    """

    def __init__(self) -> None:
        super().__init__()
        self._core: ForgeCore | None = None
        self._ready_hook: _ReadyHook | None = None
        self._state_log: list[str] = []

    def __del__(self) -> None:
        # Best-effort cleanup; IDA may unload the plugmod at any time.
        try:
            self.term()
        except Exception:  # noqa: BLE001
            pass

    def init(self) -> int:
        try:
            return self._do_init()
        except Exception as exc:  # noqa: BLE001
            ida_kernwin.warning(f"Forge: init failed: {exc}")
            traceback.print_exc()
            return ida_idaapi.PLUGIN_SKIP

    def _do_init(self) -> int:
        if not is_python_version_supported():
            log_warning("Unsupported Python version")
            return ida_idaapi.PLUGIN_SKIP

        if not is_ida_version_supported():
            log_warning("Unsupported IDA version")
            return ida_idaapi.PLUGIN_SKIP

        if not ida_hexrays.init_hexrays_plugin():
            log_warning("Failed to initialize Hex-Rays SDK")
            return ida_idaapi.PLUGIN_SKIP

        self._core = ForgeCore()
        self._core.load()

        self._ready_hook = _ReadyHook(self)
        self._ready_hook.hook()

        register_idc_func(self)

        main_module = sys.modules.get("__main__")
        if main_module is not None:
            main_module.forge = self

        log_debug(f"{PLUGIN_NAME} loaded successfully!")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        if self._core is None:
            log_warning("Plugin not initialized yet")
            return
        self._core.show_menu()

    def term(self) -> None:
        unregister_idc_func()

        if self._ready_hook is not None:
            self._ready_hook.unhook()
            self._ready_hook = None

        if self._core is not None:
            self._core.unload()
            self._core = None

        main_module = sys.modules.get("__main__")
        if main_module is not None and getattr(main_module, "forge", None) is self:
            del main_module.forge

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

        # Acquire the `forge` package from sys.modules — `forge.py` imports
        # this module, so we must not import it again at the top level.
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

    @property
    def core(self) -> ForgeCore | None:
        """Return the active plugin core, or ``None`` if unloaded."""
        return self._core

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

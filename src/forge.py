from __future__ import annotations

import sys

import ida_hexrays
import idaapi
from ida_idp import IDP_INTERFACE_VERSION

import forge
from forge.core import ForgeCore as Core
from forge.plugin import PLUGIN_COMMENT, PLUGIN_HELP, PLUGIN_NAME
from forge.util.logging import log_debug, log_warning
from forge.util.reload import recursive_reload
from forge.util.versions import is_ida_version_supported, is_python_version_supported


def PLUGIN_ENTRY():
    return ForgePlugin()


class ForgePlugin(idaapi.plugin_t):
    """IDA plugin entry point for Forge."""

    version: int = IDP_INTERFACE_VERSION
    flags: int = idaapi.PLUGIN_KEEP
    comment: str = PLUGIN_COMMENT
    help: str = PLUGIN_HELP
    wanted_name: str = PLUGIN_NAME
    wanted_hotkey: str = ""

    _core: Core | None = None
    _menu_timer = None

    def init(self) -> int:
        if not is_python_version_supported():
            log_warning("Unsupported Python version")
            return idaapi.PLUGIN_SKIP

        if not is_ida_version_supported():
            log_warning("Unsupported IDA version")
            return idaapi.PLUGIN_SKIP

        if not ida_hexrays.init_hexrays_plugin():
            log_warning("Failed to initialize Hex-Rays SDK")
            return idaapi.PLUGIN_SKIP

        self._core = Core()
        self._core.load()
        sys.modules["__main__"].forge = self

        log_debug(f"{self.wanted_name} loaded successfully!")
        self._show_menu_async()

        return idaapi.PLUGIN_KEEP

    def _show_menu_async(self) -> None:
        """Attach the menu once IDA's UI is ready, retrying if needed."""
        if self._core is None:
            return

        if self._core.show_menu():
            self._clear_menu_timer()
            return

        if self._menu_timer is None:
            self._menu_timer = idaapi.register_timer(250, self._retry_show_menu)

    def _retry_show_menu(self) -> int:
        if self._core is None:
            self._menu_timer = None
            return -1

        if self._core.show_menu():
            self._menu_timer = None
            return -1

        return 250

    def _clear_menu_timer(self) -> None:
        if self._menu_timer is None:
            return

        unregister_timer = getattr(idaapi, "unregister_timer", None)
        if unregister_timer is not None:
            unregister_timer(self._menu_timer)
        self._menu_timer = None

    def run(self, arg: int) -> None:
        if self._core is None:
            log_warning("Plugin not initialized yet")
            return

        self._core.show_menu()

    def term(self) -> None:
        self._clear_menu_timer()
        if self._core is not None:
            self._core.unload()
            self._core = None

    @property
    def core(self) -> Core | None:
        """Return the active plugin core."""
        return self._core

    def reload(self) -> None:
        """Hot-reload the plugin modules and recreate the core."""
        log_debug(f"Reloading {self.wanted_name}")

        if self._core is not None:
            self._core.unload()
            self._core = None

        recursive_reload(forge)

        from forge.core import ForgeCore as Core

        self._core = Core()
        self._core.load()

        log_debug(f"{self.wanted_name} reloaded successfully!")
        self._show_menu_async()

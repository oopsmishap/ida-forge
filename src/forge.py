from __future__ import annotations

import traceback

import ida_idp
import ida_idaapi
import ida_kernwin

from forge.plugin import PLUGIN_COMMENT, PLUGIN_HELP, PLUGIN_NAME


def PLUGIN_ENTRY():
    """Return a fresh ``plugin_t`` instance for Forge."""
    return ForgePlugin()


class ForgePlugin(ida_idaapi.plugin_t):
    """Thin ``plugin_t`` shell — delegates all work to ``forge_plugmod_t``."""

    flags = ida_idaapi.PLUGIN_KEEP
    version = ida_idp.IDP_INTERFACE_VERSION
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        # Late import: `forge.forge_plugmod_t` must not be imported at
        # module load time because the package's hot-reload path needs
        # `sys.modules["forge"]` to be a fully initialised package.
        try:
            from forge.forge_plugmod_t import forge_plugmod_t
        except Exception as exc:  # noqa: BLE001
            ida_kernwin.warning(f"Forge: failed to import plugmod: {exc}")
            traceback.print_exc()
            return ida_idaapi.PLUGIN_SKIP
        return forge_plugmod_t()

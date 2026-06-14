from __future__ import annotations

import ida_idaapi
from ida_idp import IDP_INTERFACE_VERSION

from forge.forge_plugmod_t import forge_plugmod_t
from forge.plugin import PLUGIN_COMMENT, PLUGIN_HELP, PLUGIN_NAME


def PLUGIN_ENTRY():
    """Return a fresh ``plugin_t`` instance for Forge."""
    return forge_plugin_t()


class forge_plugin_t(ida_idaapi.plugin_t):
    """Thin ``plugin_t`` shell that hands off to a ``forge_plugmod_t``."""

    flags = ida_idaapi.PLUGIN_MULTI
    wanted_name = PLUGIN_NAME
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_hotkey = ""
    version = IDP_INTERFACE_VERSION

    def init(self):
        return forge_plugmod_t(self)

    def term(self):
        return None

    def run(self, arg):
        return None

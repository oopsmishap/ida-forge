from __future__ import annotations

import traceback

import ida_idaapi
import ida_kernwin

from forge.forge_plugmod_t import ForgePlugin


def PLUGIN_ENTRY():
    """Return a fresh ``plugin_t`` instance for Forge."""
    return ForgePlugin()

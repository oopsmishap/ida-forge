from __future__ import annotations

import sys

import ida_kernwin

from forge.api.ui_actions import UIMenuAction, register_action
from forge.util.logging import log_warning


@register_action
class ReloadAction(UIMenuAction):
    name = "Reload Forge"
    tooltip = "Hot-reload Forge without restarting IDA"
    menu_path = "Actions"

    def activate(self, ctx):
        main_module = sys.modules.get("__main__")
        plugin = getattr(main_module, "forge", None) if main_module is not None else None

        if plugin is None:
            log_warning("Forge plugin instance is not available; cannot reload.")
            return 0

        def _perform_reload():
            plugin.reload()
            return 0

        if not ida_kernwin.execute_ui_requests([_perform_reload]):
            log_warning("Could not schedule Forge reload.")

        return 0



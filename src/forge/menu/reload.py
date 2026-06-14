from __future__ import annotations

import sys

from forge.api.ui_actions import UIMenuAction, register_action
from forge.util.logging import log_warning


@register_action
class ReloadAction(UIMenuAction):
    name = "Reload Forge"
    tooltip = "Hot-reload Forge without restarting IDA"
    menu_path = "Actions"

    def activate(self, ctx):
        main_module = sys.modules.get("__main__")
        plugmod = getattr(main_module, "forge", None) if main_module is not None else None

        if plugmod is None:
            log_warning("Forge plugin instance is not available; cannot reload.")
            return 0

        plugmod.reload()
        return 0

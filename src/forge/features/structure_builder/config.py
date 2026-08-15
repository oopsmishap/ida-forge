from typing import ClassVar

from forge.api.config import ForgeConfig


class StructureBuilderConfig(ForgeConfig):
    name = "StructureBuilder"

    default_config: ClassVar[dict] = {
        "enabled": True,
        "show_structure_form_hotkey": "Alt+Shift+F9",
        "shallow_scan_hotkey": "Alt+S",
        "deep_scan_hotkey": "Shift+Alt+S",
        "default_deep_scan_depth": 10,
        "form": {
            "cell_background_color": "#2A2A2A",
            "cell_foreground_color": "#E0E0E0",
            "origin_color": "#006699",
            "origin_foreground_color": "#FFFFFF",
            "disabled_color": "#3D3D3D",
            "disabled_foreground_color": "#D0D0D0",
            "collision_background_color": "#CC4B4B",
            # Restored 2026-08-11: the dark-theme rework (b04c129) dropped
            # this key from the defaults while form.py still reads it, so any
            # collision row crashed update_structure_fields with KeyError.
            "collision_foreground_color": "#F0DB2B",
        },
    }


config = StructureBuilderConfig()

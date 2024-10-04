from forge.api.config import ForgeConfig


class StructureBuilderConfig(ForgeConfig):
    name = "StructureBuilder"

    default_config = {
        "enabled": True,
        "show_structure_form_hotkey": "Alt+Shift+F9",
        "shallow_scan_hotkey": "Alt+S",
        "deep_scan_hotkey": "Shift+Alt+S",
        "form": {
            "origin_color": "#006699",
            "disabled_color": "#999999",
            "collision_foreground_color": "#F0DB2B",
            "collision_background_color": "#CC4B4B",
        },
    }


config = StructureBuilderConfig()

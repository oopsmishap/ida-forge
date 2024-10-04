import os

import ida_diskio

from forge.api.config import ForgeConfig


class TemplatedTypesConfig(ForgeConfig):
    name = "TemplatedTypes"
    default_config = {
        "enabled": True,
        "default_type_file": "",
        "show_form_hotkey": "Ctrl+Shift+T",
    }

    @property
    def default_type_file_fullpath(self):
        return os.path.join(
            ida_diskio.get_user_idadir(), "cfg", f'{self["default_type_file"]}'
        )


config = TemplatedTypesConfig()

import os

import ida_diskio
import toml

from forge.util.logging import log_error


class ConfigBase:
    name = None
    default_config = {}

    def __init__(self, config_name):
        self._config_name = config_name
        self._config_path = os.path.join(
            ida_diskio.get_user_idadir(), "cfg", f"{self._config_name}.toml"
        )
        self._config = {}
        self._load_config()

    def _load_config(self):
        try:
            with open(self._config_path, "r") as f:
                self._config = toml.load(f)
        except:
            log_error(
                f"Failed to load {self._config_name} config file at {self._config_path}"
            )

    def _save_config(self):
        try:
            with open(self._config_path, "w") as f:
                toml.dump(self._config, f)
        except:
            raise Exception(
                f"Failed to save {self._config_name} config file at {self._config_path}"
            )

    def get_class_config(self, cls):
        if cls.name not in self._config:
            default_config = cls.default_config
            self.set_class_config(cls, default_config)
            return default_config
        return self._config[cls.name]

    def set_class_config(self, cls, config):
        self._config[cls.name] = config
        self._save_config()

    def get_option(self, cls, option_name):
        config = self.get_class_config(cls)
        if option_name not in config:
            raise Exception(f"Option {option_name} not found in config")
        return config[option_name]

    def set_option(self, cls, option_name, option_value):
        config = self.get_class_config(cls)
        config[option_name] = option_value
        self._save_config()

    def __getitem__(self, item):
        return self.get_option(self.__class__, item)

    def __setitem__(self, key, value):
        self.set_option(self.__class__, key, value)


class ForgeConfig(ConfigBase):
    name = "forge"

    def __init__(self):
        super().__init__("forge")
        self.config = self.get_class_config(self.__class__)

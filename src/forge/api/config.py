from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import toml
import ida_diskio

from forge.util.logging import log_debug, log_error


ConfigDict = dict[str, Any]


class ConfigBase:
    """Base class for TOML-backed configuration management."""

    name: str | None = None
    default_config: ConfigDict = {}

    def __init__(self, config_name: str):
        if not self.name:
            raise ValueError("Config class must define a name attribute.")

        self._config_name = config_name
        self._config_path = Path(ida_diskio.get_user_idadir()) / "cfg" / f"{config_name}.toml"
        self._config: ConfigDict = self._load_config()

    def _load_config(self) -> ConfigDict:
        """Load the full configuration file."""
        try:
            with self._config_path.open("r", encoding="utf-8") as f:
                config = toml.load(f)
                log_debug(
                    f"Loaded {self._config_name} config file at {self._config_path}"
                )
                return config if isinstance(config, dict) else {}
        except FileNotFoundError:
            log_debug(f"Config file not found {self._config_path}. Using default.")
            return {}
        except Exception as e:
            log_error(
                f"Failed to load {self._config_name} config file at {self._config_path}: {e}"
            )
            return {}

    def _save_config(self) -> None:
        """Persist the full configuration file."""
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with self._config_path.open("w", encoding="utf-8") as f:
                toml.dump(self._config, f)
            log_debug(f"Saved {self._config_name} config file at {self._config_path}")
        except Exception as e:
            log_error(
                f"Failed to save {self._config_name} config file at {self._config_path}: {e}"
            )
            raise

    @staticmethod
    def _default_config_for(cls: type["ConfigBase"]) -> ConfigDict:
        """Return a detached copy of a class's default configuration."""
        return deepcopy(getattr(cls, "default_config", {}))

    def get_class_config(self, cls: type["ConfigBase"]) -> ConfigDict:
        """Get the configuration block for a specific config subclass."""
        if cls.name not in self._config:
            default_config = self._default_config_for(cls)
            self.set_class_config(cls, default_config)
            return default_config
        return self._config[cls.name]

    def set_class_config(self, cls: type["ConfigBase"], config: ConfigDict) -> None:
        """Set the configuration block for a specific config subclass."""
        self._config[cls.name] = config
        self._save_config()

    def get_option(self, cls: type["ConfigBase"], option_name: str) -> Any:
        """Get a specific option from a config subclass block."""
        config = self.get_class_config(cls)
        if option_name not in config:
            raise ValueError(
                f"Option {option_name} not found in config for class {cls.name}"
            )
        return config[option_name]

    def set_option(self, cls: type["ConfigBase"], option_name: str, option_value: Any) -> None:
        """Set a specific option in a config subclass block."""
        config = deepcopy(self.get_class_config(cls))
        config[option_name] = option_value
        self.set_class_config(cls, config)

    def __getitem__(self, item: str) -> Any:
        return self.get_option(self.__class__, item)

    def __setitem__(self, key: str, value: Any) -> None:
        self.set_option(self.__class__, key, value)

    def __contains__(self, item: str) -> bool:
        try:
            self.get_option(self.__class__, item)
            return True
        except ValueError:
            return False


class ForgeConfig(ConfigBase):
    """Root config namespace stored in `forge.toml`."""
    name = "forge"
    default_config: ConfigDict = {}

    def __init__(self):
        super().__init__("forge")
        self.config = self.get_class_config(self.__class__)

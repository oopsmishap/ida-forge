import os
from pathlib import Path
import toml
import ida_diskio

from forge.util.logging import log_error, log_debug


class ConfigBase:
    """
    Base class for configuration management.

    :ivar name: The name of the configuration.
    :ivar default_config: The default configuration.
    :ivar _config_name: The name of the configuration file.
    :ivar _config_path: The path to the configuration file.
    :ivar _config: The loaded configuration.
    """

    name = None
    """
    The name of the configuration.
    """

    default_config = {}
    """
    The default configuration.
    """

    def __init__(self, config_name):
        """
        Initialize the configuration.

        :param config_name: The name of the configuration.
        """
        if not self.name:
            raise ValueError("Config class must define a name attribute.")

        self._config_name = config_name
        self._config_path = (
            Path(ida_diskio.get_user_idadir()) / "cfg" / f"{self._config_name}.toml"
        )
        self._config = self._load_config()

    def _load_config(self):
        """
        Load the configuration from the file.

        :return: The loaded configuration.
        """
        try:
            with open(self._config_path, "r") as f:
                config = toml.load(f)
                log_debug(
                    f"Loaded {self._config_name} config file at {self._config_path}"
                )
                return config
        except FileNotFoundError:
            log_debug(f"Config file not found {self._config_path}. Using default.")
            return {}
        except Exception as e:
            log_error(
                f"Failed to load {self._config_name} config file at {self._config_path}: {e}"
            )
            return {}

    def _save_config(self):
        """
        Save the configuration to the file.
        """
        try:
            self._config_path.parent.mkdir(
                parents=True, exist_ok=True
            )  # create the folder if it doesnt exist
            with open(self._config_path, "w") as f:
                toml.dump(self._config, f)
            log_debug(f"Saved {self._config_name} config file at {self._config_path}")
        except Exception as e:
            log_error(
                f"Failed to save {self._config_name} config file at {self._config_path}: {e}"
            )
            raise

    def get_class_config(self, cls):
        """
        Get the configuration for a specific class.

        :param cls: The class to get the configuration for.
        :return: The configuration for the class.
        """
        if cls.name not in self._config:
            default_config = cls.default_config
            self.set_class_config(cls, default_config)
            return default_config
        return self._config[cls.name]

    def set_class_config(self, cls, config):
        """
        Set the configuration for a specific class.

        :param cls: The class to set the configuration for.
        :param config: The configuration to set.
        """
        self._config[cls.name] = config
        self._save_config()

    def get_option(self, cls, option_name):
        """
        Get a specific option from the configuration.

        :param cls: The class to get the option from.
        :param option_name: The name of the option to get.
        :return: The value of the option.
        """
        config = self.get_class_config(cls)
        if option_name not in config:
            raise ValueError(
                f"Option {option_name} not found in config for class {cls.name}"
            )
        return config[option_name]

    def set_option(self, cls, option_name, option_value):
        """
        Set a specific option in the configuration.

        :param cls: The class to set the option for.
        :param option_name: The name of the option to set.
        :param option_value: The value to set the option to.
        """
        config = self.get_class_config(cls)
        config[option_name] = option_value
        self._save_config()

    def __getitem__(self, item):
        """
        Get a specific option from the configuration.

        :param item: The name of the option to get.
        :return: The value of the option.
        """
        return self.get_option(self.__class__, item)

    def __setitem__(self, key, value):
        """
        Set a specific option in the configuration.

        :param key: The name of the option to set.
        :param value: The value to set the option to.
        """
        self.set_option(self.__class__, key, value)

    def __contains__(self, item):
        """
        Check if a specific option exists in the configuration.

        :param item: The name of the option to check.
        :return: True if the option exists, False otherwise.
        """
        try:
            self.get_option(self.__class__, item)
            return True
        except:
            return False


class ForgeConfig(ConfigBase):
    """
    Configuration class for Forge.

    :ivar name: The name of the configuration.
    :ivar default_config: The default configuration.
    """

    name = "forge"
    """
    The name of the configuration.
    """

    default_config = {}  # Add a default config if needed.
    """
    The default configuration.
    """

    def __init__(self):
        """
        Initialize the Forge configuration.

        This method initializes the configuration by calling the parent class's
        constructor and then retrieves the configuration for the Forge class.
        """
        super().__init__("forge")
        self.config = self.get_class_config(self.__class__)
        """
        The configuration for the Forge class.
        """

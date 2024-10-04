import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Dict

from forge.util.logging import log_debug


class FeatureManager:
    """
    Manages dynamic loading, unloading, and reloading of feature modules.
    """

    def __init__(self, folder: str = "features"):
        """
        Initializes the FeatureManager with a folder containing features.

        :param folder: Directory name where features are stored. Defaults to 'features'.
        """
        self._features: Dict[str, ModuleType] = {}
        self._feature_root: Path = Path(__file__).resolve().parent / folder

    def load_features(self) -> None:
        """
        Loads all features from the specified feature directory.
        """
        log_debug(f'Loading features from: "{self._feature_root}"')
        for feature_path in self._feature_root.iterdir():
            if feature_path.is_dir() and "__pycache__" not in feature_path.parts:
                module_name = f"forge.features.{feature_path.stem}"
                self.load_feature(module_name)

    def load_feature(self, name: str) -> None:
        """
        Loads a single feature module by name.

        :param name: The module name of the feature to load.
        :raises ValueError: If the feature is already loaded.
        """
        if name in self._features:
            raise ValueError(f'Feature "{name}" is already loaded.')
        self._features[name] = importlib.import_module(name)
        log_debug(f'Loaded feature: "{name}"')

    def unload_feature(self, name: str) -> None:
        """
        Unloads a single feature module by name.

        :param name: The module name of the feature to unload.
        :raises ValueError: If the feature is not loaded.
        """
        if name not in self._features:
            raise ValueError(f'Feature "{name}" is not loaded.')
        module = self._features.pop(name)
        del sys.modules[module.__name__]
        log_debug(f'Unloaded feature: "{name}"')

    def get_feature(self, name: str) -> ModuleType:
        """
        Retrieves a loaded feature module by name.

        :param name: The module name of the feature to retrieve.
        :return: The loaded feature module.
        :raises ValueError: If the feature is not loaded.
        """
        if name not in self._features:
            raise ValueError(f'Feature "{name}" is not loaded.')
        return self._features[name]

    def reload_feature(self, name: str) -> None:
        """
        Reloads a loaded feature module by name.

        :param name: The module name of the feature to reload.
        :raises ValueError: If the feature is not loaded.
        """
        if name not in self._features:
            raise ValueError(f"Feature '{name}' is not loaded.")
        module = self._features[name]
        importlib.reload(module)
        log_debug(f'Reloaded feature: "{name}"')

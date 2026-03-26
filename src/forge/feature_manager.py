from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterator

from forge.util.logging import log_debug


class FeatureManager:
    """
    Manages dynamic loading, unloading, and reloading of feature modules.
    """

    def __init__(self, root: Path | None = None):
        """Initialize the feature manager."""
        self._features: dict[str, ModuleType] = {}
        self._feature_root = root or Path(__file__).resolve().parent / "features"

    def load_features(self) -> None:
        """Load every feature module discovered under the feature root."""
        log_debug(f'Loading features from: "{self._feature_root}"')
        for module_name in self.iter_feature_module_names():
            self.load_feature(module_name)

    def iter_feature_module_names(self) -> Iterator[str]:
        """Yield importable feature module names in deterministic order."""
        for feature_path in sorted(self._feature_root.iterdir()):
            if feature_path.is_dir() and feature_path.name != "__pycache__":
                yield f"forge.features.{feature_path.stem}"

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
        module = self.get_feature(name)
        self._features[name] = importlib.reload(module)
        log_debug(f'Reloaded feature: "{name}"')

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, ClassVar

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = None

from forge.api.domain import current_database

try:
    import ida_diskio
except ImportError:  # pragma: no cover - outside IDA
    ida_diskio = None

from forge.util.logging import log_debug, log_error


def _toml_write_backend():
    """The write backend — the ``toml`` package, imported only when needed.

    Deliberately lazy: headless workers (idalib) may lack the package and
    only ever *read* config; a hard top-level import made the whole plugin
    unimportable there (2026-08-13, O1 live pass).
    """
    try:
        import toml
    except ImportError as exc:
        raise RuntimeError(
            "writes to forge.toml need the 'toml' package; install it or "
            "read-only mode (reads use stdlib tomllib)"
        ) from exc
    return toml


def _load_toml_file(path: Path) -> dict:
    """Read a TOML file via :mod:`tomllib` (stdlib) or the ``toml`` fallback."""
    if tomllib is not None:
        with path.open("rb") as f:  # tomllib requires binary mode
            return tomllib.load(f)
    with path.open("r", encoding="utf-8") as f:
        return _load_toml_file_legacy(f)


def _load_toml_file_legacy(f) -> dict:
    return _toml_read_fallback().load(f)


def _toml_read_fallback():
    try:
        import toml
    except ImportError as exc:  # pragma: no cover — 3.9/3.10 without toml
        raise RuntimeError("reading forge.toml needs tomllib or the 'toml' package") from exc
    return toml


def _dump_toml_file(path: Path, data: dict) -> None:
    """Persist a dict to a TOML file via the ``toml`` package (no stdlib dumper)."""
    toml = _toml_write_backend()
    with path.open("w", encoding="utf-8") as f:
        toml.dump(data, f)

ConfigDict = dict[str, Any]

def _domain_user_idadir() -> str | None:
    """Return Domain's configured user directory when available."""
    try:
        domain_db = current_database(required=False)
    except Exception:  # noqa: BLE001 — config remains usable outside IDA
        return None
    metadata = getattr(domain_db, "metadata", None) if domain_db is not None else None
    user_dir = getattr(metadata, "user_idadir", None)
    return str(user_dir) if user_dir else None


class ConfigBase:
    """Base class for TOML-backed configuration management."""

    name: str | None = None
    default_config: ClassVar[ConfigDict] = {}

    def __init__(self, config_name: str):
        user_dir = _domain_user_idadir()
        if user_dir is None and ida_diskio is not None:
            user_dir = ida_diskio.get_user_idadir()
        if user_dir is None:
            user_dir = str(Path.home() / ".idapro")
        self._config_path = Path(user_dir) / "cfg" / f"{config_name}.toml"
        self._config_name = config_name
        self._config: ConfigDict = self._load_config()
    def _load_config(self) -> ConfigDict:
        """Load the full configuration file."""
        try:
            config = _load_toml_file(self._config_path)
            log_debug(
                f"Loaded {self._config_name} config file at {self._config_path}"
            )
            return config if isinstance(config, dict) else {}
        except FileNotFoundError:
            log_debug(f"Config file not found {self._config_path}. Using default.")
            return {}
        except Exception as e:  # noqa: BLE001 — corrupt/missing files degrade to defaults
            log_error(
                f"Failed to load {self._config_name} config file at {self._config_path}: {e}"
            )
            return {}

    def _save_config(self) -> None:
        """Persist the full configuration file."""
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            _dump_toml_file(self._config_path, self._config)
            log_debug(f"Saved {self._config_name} config file at {self._config_path}")
        except Exception as e:  # persistence failures surface in the log, then re-raise
            log_error(
                f"Failed to save {self._config_name} config file at {self._config_path}: {e}"
            )
            raise

    @staticmethod
    def _default_config_for(config_cls: type[ConfigBase]) -> ConfigDict:
        """Return a detached copy of a class's default configuration."""
        return deepcopy(getattr(config_cls, "default_config", {}))

    def get_class_config(self, cls: type[ConfigBase]) -> ConfigDict:
        """Get the configuration block for a specific config subclass."""
        if cls.name not in self._config:
            default_config = self._default_config_for(cls)
            self.set_class_config(cls, default_config)
            return default_config
        existing = self._config[cls.name]
        defaults = cls._default_config_for(cls)
        if ConfigBase._merge_defaults(defaults, existing):
            self._save_config()
        return existing

    @staticmethod
    def _merge_defaults(
        defaults: ConfigDict, target: ConfigDict
    ) -> bool:
        """Recursively fold ``defaults`` into ``target`` in place.

        Returns ``True`` if any keys were added (i.e. ``target`` was
        mutated). Existing keys in ``target`` are left untouched so
        user-customized values survive. Used to keep persisted configs
        forward-compatible: when a config class adds a new key to its
        ``default_config``, existing on-disk files pick it up on the
        next read instead of raising ``KeyError`` from ``get_option``.
        """
        changed = False
        for key, default_value in defaults.items():
            if key not in target:
                target[key] = deepcopy(default_value)
                changed = True
            elif isinstance(default_value, dict) and isinstance(target.get(key), dict):
                if ConfigBase._merge_defaults(default_value, target[key]):
                    changed = True
        return changed

    def set_class_config(self, cls: type[ConfigBase], config: ConfigDict) -> None:
        """Set the configuration block for a specific config subclass."""
        self._config[cls.name] = config
        self._save_config()

    def get_option(self, cls: type[ConfigBase], option_name: str) -> Any:
        """Get a specific option from a config subclass block."""
        config = self.get_class_config(cls)
        if option_name not in config:
            raise ValueError(
                f"Option {option_name} not found in config for class {cls.name}"
            )
        return config[option_name]

    def set_option(self, cls: type[ConfigBase], option_name: str, option_value: Any) -> None:
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
    default_config: ClassVar[ConfigDict] = {
        "log_level": "INFO",
    }

    def __init__(self):
        super().__init__("forge")
        self.config = self.get_class_config(self.__class__)

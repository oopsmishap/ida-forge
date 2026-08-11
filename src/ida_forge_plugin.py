from __future__ import annotations

import contextlib
import shutil
from pathlib import Path


def _purge_stale_pycache() -> None:
    """Wipe ``__pycache__`` directories under the install location.

    IDA loads the plugin from a fixed install path
    (e.g. ``%APPDATA%/Hex-Rays/IDA Pro/plugins/ida-forge``). If a
    prior version wrote bytecode there, the cached ``.pyc`` files
    shadow the freshly copied ``.py`` sources and Python runs stale
    code. We delete the caches before the first ``forge.*`` import so
    the live sources always win. Failures are non-fatal — at worst,
    the user restarts IDA once to clear the cache manually.
    """
    install_root = Path(__file__).resolve().parent
    for cache_dir in (install_root, *install_root.iterdir()):
        if not cache_dir.is_dir():
            continue
        pycache = cache_dir / "__pycache__"
        if pycache.is_dir():
            with contextlib.suppress(OSError):
                shutil.rmtree(pycache)


_purge_stale_pycache()

# Importing the plugin module triggers the rest of the package graph.
# Must happen after the cache purge so freshly copied sources win.
from forge.forge_plugmod_t import ForgePlugin  # noqa: E402


def PLUGIN_ENTRY():
    """Return a fresh ``plugin_t`` instance for Forge."""
    return ForgePlugin()

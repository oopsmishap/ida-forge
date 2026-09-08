from __future__ import annotations

import importlib.util
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

# Loader and fake-session helpers
_SCRIPT: Path = (
    Path(__file__).resolve().parents[2] / "scripts" / "domain_clean_binary_smoke.py"
)
_MODULE_NAME: str = "domain_clean_binary_smoke_test"


def _load_smoke_script() -> ModuleType:
    """Load the CLI script without executing its guarded entry point."""
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _successful_session(
    opened: list[tuple[str, bool]], resolved_path: str | None
) -> Callable[..., AbstractContextManager[SimpleNamespace]]:
    """Return a fake context-manager factory for a resolved Domain handle."""

    @contextmanager
    def session(path: str, *, save_on_close: bool) -> Iterator[SimpleNamespace]:
        opened.append((path, save_on_close))
        yield SimpleNamespace(path=resolved_path)

    return session


# Behavioral CLI coverage
def test_loader_exposes_main_without_running_it():
    module = _load_smoke_script()

    assert callable(module.main)
    assert module.main.__module__ == _MODULE_NAME


def test_main_uses_default_path(monkeypatch, capsys):
    module = _load_smoke_script()
    opened = []
    monkeypatch.setattr(module, "database_session", _successful_session(opened, None))

    assert module.main([]) == 0
    assert opened == [(module.DEFAULT_PATH, False)]
    assert capsys.readouterr().out.splitlines() == ["SimpleNamespace", module.DEFAULT_PATH]


def test_main_uses_first_explicit_path(monkeypatch, capsys):
    module = _load_smoke_script()
    opened = []
    monkeypatch.setattr(module, "database_session", _successful_session(opened, "resolved.idb"))

    assert module.main(["fixture.i64", "ignored-extra-argument"]) == 0
    assert opened == [("fixture.i64", False)]
    assert capsys.readouterr().out.splitlines() == ["SimpleNamespace", "resolved.idb"]


def test_main_uses_first_explicit_path(monkeypatch, capsys):
    _load_smoke_script()


def test_main_returns_two_for_unavailable_domain(monkeypatch, capsys):
    module = _load_smoke_script()

    @contextmanager
    def unavailable_session(path, *, save_on_close):
        raise module.DomainUnavailable(f"cannot open {path}")
        yield  # pragma: no cover

    monkeypatch.setattr(module, "database_session", unavailable_session)

    assert module.main(["missing.i64"]) == 2
    assert capsys.readouterr().out == "DomainUnavailable: cannot open missing.i64\n"

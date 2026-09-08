from __future__ import annotations

import importlib.util
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

_SCRIPT: Path = (
    Path(__file__).resolve().parents[2] / "scripts" / "domain_member_udt_commit_smoke.py"
)
_MODULE_NAME: str = "domain_member_udt_commit_smoke_test"


def _load_smoke_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def _okay_session(path: str, *, save_on_close: bool) -> Iterator[SimpleNamespace]:
    yield SimpleNamespace()


def _run_live_stub(result: dict) -> Callable[[object], dict]:
    return lambda db: dict(result)


def test_loader_exposes_main_without_running_live():
    """The smoke is import-safe outside IDA and exposes main()."""
    module = _load_smoke_script()
    assert callable(module.main)
    assert callable(module._run_live)
    assert module._SENTINEL_SIZE == 1
    assert module.main.__module__ == _MODULE_NAME


def test_passes_when_live_commit_is_not_size_one(monkeypatch, capsys):
    module = _load_smoke_script()
    monkeypatch.setattr(module, "database_session", _okay_session)
    monkeypatch.setattr(
        module,
        "_run_live",
        _run_live_stub(
            {"ok": True, "committed_size": 24, "member_count": 4, "non_array": True}
        ),
    )
    assert module.main([]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["committed_size"] == 24


def test_fails_when_live_commit_reports_size_one(monkeypatch, capsys):
    module = _load_smoke_script()
    monkeypatch.setattr(module, "database_session", _okay_session)
    regression = {
        "ok": False,
        "committed_size": 1,
        "member_count": 1,
        "non_array": True,
        "size_is_one": True,
    }
    monkeypatch.setattr(module, "_run_live", _run_live_stub(regression))
    assert module.main([]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["size_is_one"] is True


def test_fails_when_create_udt_returns_false(monkeypatch, capsys):
    module = _load_smoke_script()
    monkeypatch.setattr(module, "database_session", _okay_session)
    monkeypatch.setattr(
        module,
        "_run_live",
        _run_live_stub(
            {"ok": False, "error": "create_udt(BTF_STRUCT) returned False"}
        ),
    )
    assert module.main([]) == 1
    assert "create_udt" in capsys.readouterr().out


def test_returns_two_when_domain_unavailable(monkeypatch, capsys):
    """An unavailable domain session is reported and exits nonzero (2)."""
    module = _load_smoke_script()

    @contextmanager
    def unavailable_session(path: str, *, save_on_close: bool) -> Iterator[SimpleNamespace]:
        raise module.DomainUnavailable(f"cannot open {path}")
        yield  # pragma: no cover

    monkeypatch.setattr(module, "database_session", unavailable_session)
    assert module.main(["missing.i64"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert "cannot open missing.i64" in payload["error"]

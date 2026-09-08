from __future__ import annotations

import importlib.util
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "domain_performance_probe.py"


def _load():
    spec = importlib.util.spec_from_file_location("domain_performance_probe_test", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_measure_reports_bounded_timing_shape():
    module = _load()
    calls = []
    result = module._measure(lambda: calls.append(1), 3)

    assert len(calls) == 3
    assert result["count"] == 3
    assert result["total_ms"] >= 0
    assert result["per_call_ms"] >= 0
    assert result["total_ms"] / 3 == result["per_call_ms"]


def test_run_rejects_invalid_repetitions():
    module = _load()
    assert module.run(repetitions=0) == {
        "ok": False,
        "error": "repetitions must be a positive integer",
    }
    assert module.run(repetitions=-1) == {
        "ok": False,
        "error": "repetitions must be a positive integer",
    }
    assert module.run(warmup=-1) == {
        "ok": False,
        "error": "warmup must be a non-negative integer",
    }
    assert module.run(warmup=True) == {
        "ok": False,
        "error": "warmup must be a non-negative integer",
    }
def test_run_reports_status_and_session_measurements(monkeypatch):
    module = _load()
    calls = []

    class Api:
        @staticmethod
        def domain_status():
            calls.append("domain")

        @staticmethod
        def storage_status():
            calls.append("storage")

        @staticmethod
        def functions():
            calls.append("functions")
            return [{"name": "main", "start_ea": 0x401000}]

        @staticmethod
        def shallow_scan(ea):
            calls.append(("shallow", ea))
            return {"ok": True}

        @staticmethod
        def deep_scan(ea, **kwargs):
            calls.append(("deep", ea, kwargs))
            return {"ok": True}

    @contextmanager
    def session(path, *, save_on_close):
        calls.append((path, save_on_close))
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe", repetitions=2, warmup=1)
    assert result["ok"] is True
    assert result["warmup"] == 1
    assert result["status"]["domain"]["count"] == 2
    assert result["status"]["storage"]["count"] == 2
    assert result["session"]["functions"]["count"] == 2
    assert result["session"]["scan_target"] == 0x401000
    assert result["session"]["scans"]["deep"]["last_ok"] is True
    assert result["session"]["scans"]["all_ok"] is True
    assert calls.count("storage") == 3
    assert calls.count("functions") == 4
    assert calls.count(("fixture.exe", False)) == 1


def test_run_skips_scans_without_discovered_functions(monkeypatch):
    module = _load()

    class Api:
        @staticmethod
        def domain_status():
            return None

        @staticmethod
        def storage_status():
            return None

        @staticmethod
        def functions():
            return []

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe", repetitions=1)
    assert result["session"]["scan_target"] is None
    assert result["session"]["scans"] == {
        "skipped": True,
        "reason": "no discovered function row",
    }
def test_run_reports_failed_scan_outcome(monkeypatch):
    module = _load()

    class Api:
        @staticmethod
        def domain_status():
            return None

        @staticmethod
        def storage_status():
            return None

        @staticmethod
        def functions():
            return [{"start_ea": 0x401000}]

        @staticmethod
        def shallow_scan(ea):
            return {"ok": True}

        @staticmethod
        def deep_scan(ea, **kwargs):
            return {"ok": False, "error": "no scan root"}

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe", repetitions=1)
    assert result["session"]["scans"]["deep"]["last_ok"] is False
    assert result["session"]["scans"]["deep"]["last_error"] == "no scan root"
    assert result["session"]["scans"]["all_ok"] is False

def test_run_converts_scan_exception_to_outcome(monkeypatch):
    module = _load()

    class Api:
        @staticmethod
        def domain_status():
            return None

        @staticmethod
        def storage_status():
            return None

        @staticmethod
        def functions():
            return [{"start_ea": 0x401000}]

        @staticmethod
        def shallow_scan(ea):
            return {"ok": True}

        @staticmethod
        def deep_scan(ea, **kwargs):
            raise RuntimeError("scan unavailable")

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe", repetitions=1)

    assert result["ok"] is True
    assert result["session"]["scans"]["deep"]["last_ok"] is False
    assert result["session"]["scans"]["deep"]["last_error"] == "RuntimeError: scan unavailable"

def test_main_keeps_json_on_stdout_and_forwards_diagnostics(monkeypatch, capsys):
    module = _load()

    def fake_run(path, *, repetitions, warmup):
        print("IDA diagnostic")
        return {"ok": True, "path": path, "repetitions": repetitions, "warmup": warmup}

    monkeypatch.setattr(module, "run", fake_run)

    assert module.main(["fixture.exe", "--repetitions", "2", "--warmup", "1"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == (
        '{"ok": true, "path": "fixture.exe", "repetitions": 2, "warmup": 1}'
    )
    assert captured.err == "IDA diagnostic\n"

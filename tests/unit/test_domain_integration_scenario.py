from __future__ import annotations

import importlib.util
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "domain_integration_scenario.py"


def _load():
    spec = importlib.util.spec_from_file_location("domain_integration_scenario_test", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_run_orchestrates_non_destructive_probe(monkeypatch):
    module = _load()
    calls = []
    persisted = {"members": []}

    class FakeForge:
        @staticmethod
        def domain_status():
            return {"available": True, "preferred": "ida-domain", "fallbacks": []}

        @staticmethod
        def named_types():
            calls.append("named_types")
            return ["Existing"]

        @staticmethod
        def create_structure(name):
            return {"ok": True, "result": {"name": name}}
        @staticmethod
        def functions():
            return []

        @staticmethod
        def add_member(structure, offset, member_type, *, name=None):
            calls.append(("add_member", structure, offset, member_type, name))
            persisted["members"] = [{"name": name, "offset": offset, "type": member_type}]
            return {"ok": True}

        @staticmethod
        def get_structure(name):
            return {"name": name, "members": list(persisted["members"])}
        @staticmethod
        def remove_structure(name):
            calls.append(("remove_structure", name))
            return True

    @contextmanager
    def session(path, *, save_on_close):
        calls.append(("session", path, save_on_close))
        yield SimpleNamespace(path="resolved.idb")

    monkeypatch.setitem(__import__("sys").modules, "forge_api", FakeForge)
    monkeypatch.setattr(module, "database_session", session)

    result = module.run("fixture.exe")

    assert result["ok"] is True
    assert result["persistence_verified"] is True
    assert result["database_path"] == "resolved.idb"
    assert calls.count(("session", "fixture.exe", True)) == 1
    assert calls.count(("session", "fixture.exe", False)) == 1
    assert ("add_member", module.DEFAULT_STRUCTURE, 0, "u32", "probe_value") in calls
    assert ("remove_structure", module.DEFAULT_STRUCTURE) in calls

    assert set(result["phases"]) == {"open", "inspect", "scan_type", "persist", "reopen", "close"}
    assert result["phases"]["open"]["ok"] is True
    assert result["phases"]["persist"]["ok"] is True
    assert result["phases"]["reopen"]["ok"] is True
    assert result["phases"]["close"]["ok"] is True

    assert result["phases"]["persist"]["evidence"] == {
        "snapshot_available": True,
        "snapshot_member_count": 1,
        "scan_sites_available": False,
    }
    assert result["phases"]["reopen"]["evidence"] == {
        "structure_available": True,
        "persistence_verified": True,
    }


def test_run_reports_domain_unavailable(monkeypatch):
    module = _load()

    @contextmanager
    def unavailable(path, *, save_on_close):
        raise module.DomainUnavailable(f"cannot open {path}")
        yield  # pragma: no cover

    monkeypatch.setattr(module, "database_session", unavailable)
    monkeypatch.setitem(
        __import__("sys").modules,
        "forge_api",
        SimpleNamespace(domain_status=lambda: {"available": False}),
    )
    result = module.run("missing.exe")
    assert result["ok"] is False
    assert result["matrix_ok"] is False
    assert result["phase_matrix"]["complete"] is False
    assert result["phase_matrix"]["names"] == [
        "open", "inspect", "scan_type", "persist", "reopen", "close"
    ]
def test_find_function_ea_uses_only_enumerated_rows():
    module = _load()

    class Api:
        @staticmethod
        def functions():
            return [{"name": "other", "start_ea": 1}, {"name": "run_nested_fixture", "start_ea": 2}]

    assert module._find_function_ea(Api, "run_nested_fixture") == 2
    assert module._find_function_ea(Api, "missing") is None


def test_find_function_ea_does_not_guess_when_enumeration_is_unavailable():
    module = _load()
    assert module._find_function_ea(object(), "run_nested_fixture") is None


def test_function_row_evidence_is_bounded_and_deterministic():
    module = _load()

    class Api:
        @staticmethod
        def functions():
            return [
                {"name": "zeta", "start_ea": 3},
                {"name": "alpha", "start_ea": 1},
                {"name": "ignored", "start_ea": 2},
            ]

    assert module._function_row_evidence(Api, sample_size=2) == {
        "available": True,
        "count": 3,
        "names": ["alpha", "ignored"],
    }


def test_function_row_evidence_reports_unavailable_operation():
    module = _load()
    assert module._function_row_evidence(object()) == {
        "available": False,
        "count": 0,
        "names": [],
        "error": "forge_api.functions unavailable",
    }

def test_call_optional_propagates_structured_status():
    module = _load()

    class Api:
        @staticmethod
        def failing():
            return {"ok": False, "error": "root unavailable"}

        @staticmethod
        def succeeding():
            return {"ok": True, "members": []}

        @staticmethod
        def unmarked():
            return {"members": []}

    assert module._call_optional(Api, "failing") == {
        "ok": False,
        "available": True,
        "result": {"ok": False, "error": "root unavailable"},
    }
    assert module._call_optional(Api, "succeeding")["ok"] is True
    assert module._call_optional(Api, "unmarked")["ok"] is True


def test_phase_matrix_includes_bounded_error_when_present():
    module = _load()
    matrix = module._phase_matrix(
        {
            "open": {"ok": False, "available": True, "error": "cannot open"},
            "close": {"ok": True, "available": True, "error": 42},
        }
    )
    assert matrix["rows"] == [
        {"name": "open", "ok": False, "available": True, "error": "cannot open"},
        {"name": "close", "ok": True, "available": True},
    ]

def test_run_uses_discovered_function_for_scan(monkeypatch):
    module = _load()
    calls = []

    class Api:
        @staticmethod
        def domain_status():
            return {"available": True}

        @staticmethod
        def functions():
            return [{"name": "main", "start_ea": 0x1000, "end_ea": 0x1010}]

        @staticmethod
        def function_info(ea):
            return {"name": "main", "start_ea": ea}

        @staticmethod
        def named_types():
            return []

        @staticmethod
        def create_structure(name):
            return {"ok": True, "result": {"name": name}}

        @staticmethod
        def add_member(*args, **kwargs):
            return {"ok": True}

        @staticmethod
        def deep_scan(ea, **kwargs):
            calls.append((ea, kwargs))
            return {"ok": True, "structure": kwargs["structure"], "members": []}

        @staticmethod
        def get_structure(name):
            return {"ok": True, "result": {"name": name, "members": [{"name": "probe_value"}]}}

        @staticmethod
        def scan_sites(name):
            return []

        @staticmethod
        def remove_structure(name):
            return True

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe")

    assert result["scan_target"] == 0x1000
    assert calls == [(0x1000, {"structure": module.DEFAULT_STRUCTURE, "clear_first": False})]
    assert result["phases"]["scan_type"]["ok"] is True

def test_run_marks_nested_scan_failure_as_unsuccessful_phase(monkeypatch):
    module = _load()

    class Api:
        @staticmethod
        def domain_status():
            return {"available": True}

        @staticmethod
        def functions():
            return [{"name": "main", "start_ea": 0x1000}]

        @staticmethod
        def function_info(ea):
            return {"name": "main", "start_ea": ea}

        @staticmethod
        def named_types():
            return []

        @staticmethod
        def create_structure(name):
            return {"ok": True, "result": {"name": name}}

        @staticmethod
        def add_member(*args, **kwargs):
            return {"ok": True}

        @staticmethod
        def deep_scan(ea, **kwargs):
            return {"ok": False, "error": "could not resolve a scan root"}

        @staticmethod
        def get_structure(name):
            return {"ok": True, "result": {"name": name, "members": []}}

        @staticmethod
        def scan_sites(name):
            return []

        @staticmethod
        def remove_structure(name):
            return True

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe")

    assert result["scan"]["ok"] is False
    assert result["scan"]["result"]["ok"] is False
    assert result["phases"]["scan_type"] == {"ok": False, "available": True}
    assert result["phase_matrix"]["complete"] is False


def test_run_reports_missing_inspection_candidate(monkeypatch):
    module = _load()

    class Api:
        @staticmethod
        def domain_status():
            return {"available": True}

        @staticmethod
        def functions():
            return []

        @staticmethod
        def named_types():
            return []

        @staticmethod
        def create_structure(name):
            return {"ok": False, "result": None}

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe")
    assert result["inspection_target"] is None
    assert result["inspection"]["error"] == "no discovered function row"

def test_phase_matrix_is_ordered_and_requires_all_phases():
    module = _load()
    phases = {
        "open": {"ok": True, "available": True},
        "inspect": {"ok": True, "available": True},
        "close": {"ok": False, "available": True},
    }

    assert module._phase_matrix(phases) == {
        "names": ["open", "inspect", "close"],
        "rows": [
            {"name": "open", "ok": True, "available": True},
            {"name": "inspect", "ok": True, "available": True},
            {"name": "close", "ok": False, "available": True},
        ],
        "complete": False,
    }


def test_run_exposes_phase_matrix(monkeypatch):
    module = _load()

    class Api:
        @staticmethod
        def domain_status():
            return {"available": True}

        @staticmethod
        def functions():
            return [{"name": "main", "start_ea": 0x1000, "end_ea": 0x1010}]

        @staticmethod
        def function_info(ea):
            return {"name": "main", "start_ea": ea}

        @staticmethod
        def named_types():
            return []

        @staticmethod
        def create_structure(name):
            return {"ok": False, "result": None}

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe")

    assert result["phase_matrix"]["names"] == [
        "open", "inspect", "scan_type", "persist", "reopen", "close"
    ]
    assert result["phase_matrix"]["complete"] is False

def test_run_exposes_matrix_completion_separately(monkeypatch):
    module = _load()

    class Api:
        @staticmethod
        def domain_status():
            return {"available": True}

        @staticmethod
        def functions():
            return []

        @staticmethod
        def named_types():
            return []

        @staticmethod
        def create_structure(name):
            return {"ok": False, "result": None}

    @contextmanager
    def session(path, *, save_on_close):
        yield SimpleNamespace(path=path)

    monkeypatch.setitem(__import__("sys").modules, "forge_api", Api)
    monkeypatch.setattr(module, "database_session", session)
    result = module.run("fixture.exe")

    assert result["ok"] is False
    assert result["matrix_ok"] is False
    assert result["matrix_ok"] is result["phase_matrix"]["complete"]

def test_main_keeps_json_on_stdout_and_forwards_diagnostics(monkeypatch, capsys):
    module = _load()

    def fake_run(path, *, structure_name):
        print("IDA diagnostic")
        return {"ok": True, "path": path, "structure": structure_name}

    monkeypatch.setattr(module, "run", fake_run)

    assert module.main(["fixture.exe", "--structure", "Probe"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == '{"ok": true, "path": "fixture.exe", "structure": "Probe"}'
    assert captured.err == "IDA diagnostic\n"
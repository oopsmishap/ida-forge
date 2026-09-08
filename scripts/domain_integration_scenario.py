"""Run a small, deterministic ida-domain/forge_api integration scenario.

The scenario is intentionally conservative: it only creates a uniquely named
probe structure, performs an optional type inspection, persists the structure
through Forge's existing store, reopens the same database, and removes the
probe structure before close. It is safe to run repeatedly against the cold
fixture and import-safe outside IDA.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
from typing import Any

from forge.api.domain import DomainUnavailable, database_session

DEFAULT_PATH = ".scratch_probe_cold/pure_c_struct_fixture.exe"
DEFAULT_STRUCTURE = "_forge_domain_integration_probe"
DEFAULT_MEMBER = (0, "probe_value", "u32")

def _call_optional(api: Any, operation_name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    operation = getattr(api, operation_name, None)
    if not callable(operation):
        return {"ok": False, "available": False, "error": f"forge_api.{operation_name} unavailable"}
    try:
        result = operation(*args, **kwargs)
    except Exception as exc:  # integration diagnostics must be serializable
        return {"ok": False, "available": True, "error": f"{type(exc).__name__}: {exc}"}
    status = result.get("ok") if isinstance(result, dict) and isinstance(result.get("ok"), bool) else True
    return {"ok": status, "available": True, "result": result}


def _function_row_evidence(api: Any, *, sample_size: int = 12) -> dict[str, Any]:
    """Return bounded evidence from the public function enumeration operation."""
    operation = getattr(api, "functions", None)
    if not callable(operation):
        return {"available": False, "count": 0, "names": [], "error": "forge_api.functions unavailable"}
    try:
        rows = operation()
    except Exception as exc:
        return {"available": True, "count": 0, "names": [], "error": f"{type(exc).__name__}: {exc}"}
    if not isinstance(rows, list):
        return {"available": True, "count": 0, "names": [], "error": "forge_api.functions returned a non-list"}
    names = sorted(
        {row.get("name") for row in rows if isinstance(row, dict) and isinstance(row.get("name"), str)}
    )
    return {"available": True, "count": len(rows), "names": names[:sample_size]}

def _phase_matrix(phases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    names = tuple(phases)
    rows = []
    for name in names:
        phase = phases[name]
        row = {
            "name": name,
            "ok": bool(phase.get("ok")),
            "available": bool(phase.get("available")),
        }
        if isinstance(phase.get("error"), str):
            row["error"] = phase["error"]
        rows.append(row)
    return {
        "names": list(names),
        "rows": rows,
        "complete": bool(rows) and all(row["ok"] and row["available"] for row in rows),
    }


def _find_function_ea(api: Any, target_name: str) -> int | None:
    """Find a target function EA from the public function-listing facade."""
    operation = getattr(api, "functions", None)
    if not callable(operation):
        return None
    try:
        rows = operation()
    except Exception:
        return None
    for row in rows if isinstance(rows, list) else ():
        if isinstance(row, dict) and row.get("name") == target_name:
            return row.get("start_ea")
    return None


def run(path: str | Path = DEFAULT_PATH, *, structure_name: str = DEFAULT_STRUCTURE) -> dict[str, Any]:
    """Execute the non-destructive integration scenario and return JSON data."""
    path = str(path)
    result: dict[str, Any] = {
        "path": path,
        "structure": structure_name,
        "matrix_ok": False,
        "phases": {
            "open": {"ok": False, "available": True},
            "inspect": {"ok": False, "available": True},
            "scan_type": {"ok": False, "available": True},
            "persist": {"ok": False, "available": True},
            "reopen": {"ok": False, "available": True},
            "close": {"ok": False, "available": True},
        },
    }
    result["phase_matrix"] = _phase_matrix(result["phases"])
    try:
        import forge_api
    except Exception as exc:
        return {**result, "ok": False, "error": f"forge_api import failed: {type(exc).__name__}: {exc}"}

    result["domain_status"] = forge_api.domain_status()
    try:
        with database_session(path, save_on_close=True) as database:
            result["phases"]["open"] = {"ok": True, "available": True}
            result["function_rows"] = _function_row_evidence(forge_api)
            rows = forge_api.functions()
            candidate = next(
                (row for row in rows if isinstance(row, dict) and row.get("start_ea") is not None),
                None,
            ) if isinstance(rows, list) else None
            result["inspection_target"] = candidate
            result["inspection"] = (
                _call_optional(forge_api, "function_info", candidate["start_ea"])
                if candidate is not None
                else {"ok": False, "available": False, "error": "no discovered function row"}
            )
            result["phases"]["inspect"] = {
                "ok": result["inspection"].get("ok", False),
                "available": result["inspection"].get("available", False),
            }
            result["database_type"] = type(database).__name__
            result["database_path"] = str(getattr(database, "path", None) or path)
            result["named_types"] = _call_optional(forge_api, "named_types")
            created = _call_optional(forge_api, "create_structure", structure_name)
            if created.get("ok") and created.get("result") is not None:
                result["add_member"] = _call_optional(
                    forge_api, "add_member", structure_name, 0, "u32", name="probe_value"
                )
                target_ea = candidate.get("start_ea") if isinstance(candidate, dict) else None
                result["scan_target"] = target_ea
                if target_ea is None:
                    result["scan"] = {
                        "ok": False,
                        "available": False,
                        "error": "no discovered function row; no address guessed",
                    }
                else:
                    result["scan"] = _call_optional(
                        forge_api, "deep_scan", target_ea,
                        structure=structure_name, clear_first=False,
                    )
                result["structure_snapshot"] = _call_optional(
                    forge_api, "get_structure", structure_name
                )
                result["scan_sites"] = _call_optional(forge_api, "scan_sites", structure_name)
            scan_result = result.get("scan", {})
            nested_scan = scan_result.get("result") if isinstance(scan_result, dict) else None
            result["phases"]["scan_type"] = {
                "ok": bool(
                    nested_scan.get("ok")
                    if isinstance(nested_scan, dict) and "ok" in nested_scan
                    else scan_result.get("ok", False)
                ),
                "available": scan_result.get("available", False),
            }
            result["persist_evidence"] = {
                "snapshot_available": result.get("structure_snapshot", {}).get("ok", False),
                "snapshot_member_count": len(
                    result.get("structure_snapshot", {}).get("result", {}).get("members", [])
                ) if isinstance(result.get("structure_snapshot", {}).get("result"), dict) else 0,
                "scan_sites_available": result.get("scan_sites", {}).get("available", False),
            }
            result["phases"]["persist"] = {
                "ok": result.get("structure_snapshot", {}).get("ok", False),
                "available": result.get("structure_snapshot", {}).get("available", False),
                "evidence": result["persist_evidence"],
            }
    except DomainUnavailable as exc:
        return {**result, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    except Exception as exc:
        return {**result, "ok": False, "error": f"{type(exc).__name__}: {exc}"}

    try:
        with database_session(path, save_on_close=False) as database:
            result["phases"]["reopen"] = {"ok": True, "available": True}
            reopened = _call_optional(forge_api, "get_structure", structure_name)
            result["reopened_structure"] = reopened
            result["reopen_evidence"] = {
                "structure_available": reopened.get("available", True),
                "persistence_verified": bool(
                    reopened.get("ok")
                    and reopened.get("result", {}).get("name") == structure_name
                    and any(
                        member.get("name") == "probe_value"
                        for member in reopened.get("result", {}).get("members", [])
                    )
                ),
            }
            result["persistence_verified"] = result["reopen_evidence"]["persistence_verified"]
            result["phases"]["reopen"]["evidence"] = result["reopen_evidence"]
            result["remove_structure"] = _call_optional(
                forge_api, "remove_structure", structure_name
            )
    except DomainUnavailable as exc:
        return {**result, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    except Exception as exc:
        return {**result, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    result["phases"]["close"] = {"ok": True, "available": True}
    result["phase_matrix"] = _phase_matrix(result["phases"])
    result["matrix_ok"] = result["phase_matrix"]["complete"]
    result["ok"] = result.get("persistence_verified", False)
    if not result["ok"]:
        result["error"] = "persisted structure/member was not observed after reopen"
    return result
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=DEFAULT_PATH)
    parser.add_argument("--structure", default=DEFAULT_STRUCTURE)
    args = parser.parse_args(argv)
    diagnostics = io.StringIO()
    with contextlib.redirect_stdout(diagnostics):
        report = run(args.path, structure_name=args.structure)
    captured = diagnostics.getvalue()
    if captured:
        print(captured, end="", file=__import__("sys").stderr)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

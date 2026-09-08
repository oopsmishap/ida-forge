"""Measure bounded headless forge_api operations on a clean IDB."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

from forge.api.domain import DomainUnavailable, database_session

DEFAULT_PATH = ".scratch_probe_cold/pure_c_struct_fixture.exe"
DEFAULT_REPETITIONS = 3


def _measure(operation: Callable[[], Any], repetitions: int) -> dict[str, Any]:
    started = time.perf_counter()
    for _ in range(repetitions):
        operation()
    total_ms = (time.perf_counter() - started) * 1000
    return {
        "count": repetitions,
        "total_ms": total_ms,
        "per_call_ms": total_ms / repetitions,
    }


def run(
    path: str | Path = DEFAULT_PATH,
    *,
    repetitions: int = DEFAULT_REPETITIONS,
    warmup: int = 0,
) -> dict[str, Any]:
    """Measure status calls and function enumeration with optional warmup calls."""
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions <= 0:
        return {"ok": False, "error": "repetitions must be a positive integer"}
    if not isinstance(warmup, int) or isinstance(warmup, bool) or warmup < 0:
        return {"ok": False, "error": "warmup must be a non-negative integer"}
    path = str(path)
    result: dict[str, Any] = {
        "ok": False,
        "path": path,
        "repetitions": repetitions,
        "warmup": warmup,
    }
    try:
        import forge_api

        status_operations = (forge_api.domain_status, forge_api.storage_status)
        for operation in status_operations:
            for _ in range(warmup):
                operation()
        result["status"] = {
            "domain": _measure(forge_api.domain_status, repetitions),
            "storage": _measure(forge_api.storage_status, repetitions),
        }
        with database_session(path, save_on_close=False):
            for _ in range(warmup):
                forge_api.functions()
            function_rows = forge_api.functions()
            result["session"] = {
                "functions": _measure(lambda: forge_api.functions(), repetitions),
                "scan_target": None,
            }
            candidate_ea = next(
                (
                    row.get("start_ea")
                    for row in function_rows
                    if isinstance(row, dict) and isinstance(row.get("start_ea"), int)
                    and not isinstance(row.get("start_ea"), bool)
                ),
                None,
            ) if isinstance(function_rows, list) else None
            result["session"]["scan_target"] = candidate_ea
            if candidate_ea is None:
                result["session"]["scans"] = {
                    "skipped": True,
                    "reason": "no discovered function row",
                }
            else:
                scan_state: dict[str, dict[str, Any]] = {}
                scan_operations = {
                    "shallow": lambda: forge_api.shallow_scan(candidate_ea),
                    "deep": lambda: forge_api.deep_scan(
                        candidate_ea, recurse_calls=False, max_depth=2
                    ),
                }
                measured_scans: dict[str, Callable[[], Any]] = {}
                for name, operation in scan_operations.items():
                    last_response: Any = None

                    def measured_operation(
                        operation: Callable[[], Any] = operation,
                        name: str = name,
                    ) -> Any:
                        nonlocal last_response
                        try:
                            last_response = operation()
                        except Exception as exc:
                            last_response = {
                                "ok": False,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        return last_response
                    for _ in range(warmup):
                        measured_operation()
                    measured_scans[name] = measured_operation
                    scan_state[name] = {"last_response": lambda: last_response}
                result["session"]["scans"] = {}
                scan_outcomes: list[bool] = []
                for name, operation in measured_scans.items():
                    timing = _measure(operation, repetitions)
                    response = scan_state[name]["last_response"]()
                    if isinstance(response, dict) and isinstance(response.get("ok"), bool):
                        timing["last_ok"] = response["ok"]
                        scan_outcomes.append(response["ok"])
                    if isinstance(response, dict) and isinstance(response.get("error"), str):
                        timing["last_error"] = response["error"]
                    result["session"]["scans"][name] = timing
                if len(scan_outcomes) == len(measured_scans):
                    result["session"]["scans"]["all_ok"] = all(scan_outcomes)
    except DomainUnavailable as exc:
        return {**result, "error": f"{type(exc).__name__}: {exc}"}
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return {**result, "error": f"{type(exc).__name__}: {exc}"}
    result["ok"] = True
    return result
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=DEFAULT_PATH)
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--warmup", type=int, default=0)
    args = parser.parse_args(argv)
    diagnostics = io.StringIO()
    with contextlib.redirect_stdout(diagnostics):
        report = run(args.path, repetitions=args.repetitions, warmup=args.warmup)
    captured = diagnostics.getvalue()
    if captured:
        print(captured, end="", file=sys.stderr)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

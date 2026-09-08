from pathlib import Path

README = Path(__file__).parents[2] / "README.md"


def test_readme_documents_storage_recovery_contract():
    text = README.read_text(encoding="utf-8")
    assert "`storage_status()` reports detached recovery counters" in text
    for counter in ("`load_failures`", "`corrupt_entries`", "`write_failures`"):
        assert counter in text
    for detail in ("`last_error`", "`operation`", "exception `type`", "`message`"):
        assert detail in text
    assert "Persistence is best-effort" in text

def test_readme_documents_diagnostics_and_live_matrix():
    text = README.read_text(encoding="utf-8")
    for phrase in (
        "`ida_domain.health`",
        "`fallback_counts`",
        "`fallback_clear_requested`",
        "`fallbacks_cleared`",
        "explicit destructive read-and-clear",
        "`health` (`healthy` or `degraded`)",
        "`phase_matrix`",
        "`matrix_ok`",
        "Top-level `ok` reports persistence verification",
        "`open`, `inspect`, `scan_type`, `persist`, `reopen`, and `close`",
        "does not guess fixture addresses",
    ):
        assert phrase in text
def test_readme_documents_performance_probe_contract():
    text = README.read_text(encoding="utf-8")
    for phrase in (
        "`domain_performance_probe.py`",
        "`session.scan_target`",
        "`shallow_scan`",
        "`deep_scan`",
        "`last_ok`",
        "bounded `last_error`",
        "final measured invocation",
        "`session.scans.all_ok`",
        "Timings are comparative evidence, not",
        "no target is guessed",
    ):
        assert phrase in text
def test_ci_runs_compile_gate_before_lint_and_tests():
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    compile_step = workflow.index("python -m compileall -q src tests scripts")
    lint_step = workflow.index("ruff check src tests")
    test_step = workflow.index("python -m pytest")
    assert compile_step < lint_step < test_step

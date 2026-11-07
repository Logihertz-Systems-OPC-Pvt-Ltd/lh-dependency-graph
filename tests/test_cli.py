# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the lh-dependency-graph command-line interface.

Validates CLI commands 'scan' and 'rules', parameter flags, output formats,
and exit status codes (0, 1, 2) using typer.testing.CliRunner.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_dependency_graph.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_rules_command() -> None:
    """Test 'rules' command lists all LH-DEP rules and exits with 0."""
    result = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert result.exit_code == 0
    assert "LH-DEP-001" in result.stdout
    assert "LH-DEP-010" in result.stdout
    assert "Reachable Dangerous Sink" in result.stdout


def test_cli_scan_clean_project(clean_project: Path) -> None:
    """Test scanning a clean project returns exit code 0 and clean audit banner."""
    result = runner.invoke(app, ["scan", str(clean_project)], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Clean Audit" in result.stdout


def test_cli_scan_vulnerable_project_fails(vulnerable_sinks_project: Path) -> None:
    """Test scanning a vulnerable project exits with 1 when findings meet fail-on threshold."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_sinks_project), "--fail-on", "HIGH"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    assert "LH-DEP-001" in result.stdout


def test_cli_scan_fail_on_threshold(hygiene_and_integrity_project: Path) -> None:
    """Test fail-on threshold suppresses failure exit if findings are below threshold."""
    # hygiene_app has HIGH, MEDIUM, LOW findings (no CRITICAL)
    result = runner.invoke(
        app,
        ["scan", str(hygiene_and_integrity_project), "--fail-on", "CRITICAL"],
        env=CLI_ENV,
    )
    assert result.exit_code == 0


def test_cli_scan_format_json(vulnerable_reachability_project: Path) -> None:
    """Test JSON output formatting to stdout."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_reachability_project), "--format", "json"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["report_type"] == "dependency_reachability_audit"
    assert data["summary"]["critical"] >= 1


def test_cli_scan_format_sarif(vulnerable_reachability_project: Path) -> None:
    """Test SARIF v2.1.0 output formatting to stdout."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_reachability_project), "--format", "sarif"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "lh-dependency-graph"


def test_cli_scan_output_file(clean_project: Path, tmp_path: Path) -> None:
    """Test writing audit report directly to an output file."""
    out_file = tmp_path / "reports" / "audit.json"
    result = runner.invoke(
        app,
        ["scan", str(clean_project), "--format", "json", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["report_type"] == "dependency_reachability_audit"
    assert data["summary"]["total_findings"] == 0


def test_cli_scan_nonexistent_path() -> None:
    """Test scanning a nonexistent path exits with code 2."""
    result = runner.invoke(app, ["scan", "/nonexistent/project/path"], env=CLI_ENV)
    assert result.exit_code == 2
    assert "Error: Target path '/nonexistent/project/path' does not exist." in result.stdout


def test_cli_min_severity_filter(hygiene_and_integrity_project: Path) -> None:
    """Test min-severity filtering excludes lower severity findings."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(hygiene_and_integrity_project),
            "--format",
            "json",
            "--min-severity",
            "HIGH",
        ],
        env=CLI_ENV,
    )
    data = json.loads(result.stdout)
    # Findings should only be HIGH or CRITICAL
    for res in data["results"]:
        for f in res["findings"]:
            assert f["severity"] in ("HIGH", "CRITICAL")

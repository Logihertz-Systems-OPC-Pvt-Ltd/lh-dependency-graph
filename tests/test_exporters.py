# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for table, JSON, and SARIF v2.1.0 exporters.

Validates terminal rendering, schema compliance, and format structures.
"""

from __future__ import annotations

import json

from lh_dependency_graph.exporters import (
    _get_reachability_badge,
    _get_severity_badge,
    _severity_to_sarif_level,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_dependency_graph.models import (
    AuditReport,
    Finding,
    FindingSeverity,
    ReachabilityStatus,
    RuleCategory,
    ScanTargetResult,
)


def _build_sample_report(has_findings: bool = True) -> AuditReport:
    """Construct sample audit report for exporter tests."""
    findings = []
    if has_findings:
        findings = [
            Finding(
                rule_id="LH-DEP-001",
                severity=FindingSeverity.CRITICAL,
                category=RuleCategory.DANGEROUS_SINK,
                title="Dangerous Sink Call",
                message="Dangerous sink yaml.load reached",
                target="/tmp/app/main.py",
                package_or_symbol="yaml.load",
                remediation="Use yaml.safe_load",
                reachability=ReachabilityStatus.REACHABLE,
                line_number=10,
            ),
            Finding(
                rule_id="LH-DEP-003",
                severity=FindingSeverity.HIGH,
                category=RuleCategory.DEPENDENCY_HYGIENE,
                title="Unpinned Version",
                message="Package unpinned",
                target="/tmp/app/requirements.txt",
                package_or_symbol="requests",
                remediation="Pin version with ==",
                reachability=ReachabilityStatus.STATIC_DIRECT,
                line_number=2,
            ),
        ]

    res = ScanTargetResult(
        target="/tmp/app",
        manifests_scanned=1,
        source_files_scanned=1,
        dependencies_count=2,
        findings=findings,
    )
    report = AuditReport(
        results=[res],
        parameters={"format": "table"},
    )
    report.compute_summary()
    return report


def test_render_table_report_with_findings() -> None:
    """Test table rendering when findings are present."""
    report = _build_sample_report(has_findings=True)
    rendered = render_table_report(report)

    assert "lh-dependency-graph" in rendered
    assert "Dependency Audit Executive Summary" in rendered
    assert "Supply Chain & Reachability Findings" in rendered
    assert "LH-DEP-001" in rendered
    assert "CRITICAL" in rendered
    assert "yaml.load" in rendered


def test_render_table_report_clean() -> None:
    """Test table rendering for a clean audit."""
    report = _build_sample_report(has_findings=False)
    rendered = render_table_report(report)

    assert "Clean Audit" in rendered


def test_export_json_schema() -> None:
    """Test structured JSON export schema and keys."""
    report = _build_sample_report(has_findings=True)
    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "dependency_reachability_audit"
    assert "summary" in data
    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 1
    assert len(data["results"]) == 1
    assert len(data["results"][0]["findings"]) == 2


def test_export_sarif_schema() -> None:
    """Test OASIS SARIF v2.1.0 document format compliance."""
    report = _build_sample_report(has_findings=True)
    sarif_str = export_sarif(report)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-dependency-graph"
    assert len(run["results"]) == 2

    first_res = run["results"][0]
    assert first_res["ruleId"] == "LH-DEP-001"
    assert first_res["level"] == "error"
    assert "physicalLocation" in first_res["locations"][0]


def test_severity_and_badge_helpers() -> None:
    """Test severity level mappings and Rich badges."""
    assert _severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert _severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert _severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert _severity_to_sarif_level(FindingSeverity.LOW) == "note"

    badge = _get_severity_badge(FindingSeverity.CRITICAL)
    assert "CRITICAL" in badge.plain

    reach_badge = _get_reachability_badge(ReachabilityStatus.REACHABLE)
    assert "REACHABLE" in reach_badge.plain

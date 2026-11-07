# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        src.lh_dependency_graph.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Exporters for dependency reachability audit reports in table, JSON, and SARIF v2.1.0 formats.

Provides terminal presentation via Rich, machine-readable structured JSON,
and OASIS SARIF output for CI/CD, SBOM pipelines, and compliance dashboards.
"""

from __future__ import annotations

import io
import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_dependency_graph.models import (
    RULES_REGISTRY,
    AuditReport,
    Finding,
    FindingSeverity,
    ReachabilityStatus,
)

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"


class OutputFormat(StrEnum):
    """Supported output formats for dependency reachability audit reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def _severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF rule level."""
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        return "error"
    if severity == FindingSeverity.MEDIUM:
        return "warning"
    return "note"


def _get_severity_badge(severity: FindingSeverity) -> Text:
    """Return styled Rich Text badge for finding severity."""
    if severity == FindingSeverity.CRITICAL:
        return Text("CRITICAL", style="bold white on red")
    if severity == FindingSeverity.HIGH:
        return Text("HIGH", style="bold red")
    if severity == FindingSeverity.MEDIUM:
        return Text("MEDIUM", style="bold yellow")
    if severity == FindingSeverity.LOW:
        return Text("LOW", style="bold cyan")
    return Text(severity.value, style="bold")


def _get_reachability_badge(status: ReachabilityStatus) -> Text:
    """Return styled Rich Text badge for reachability status."""
    if status == ReachabilityStatus.REACHABLE:
        return Text("REACHABLE", style="bold red")
    if status == ReachabilityStatus.POTENTIAL:
        return Text("POTENTIAL", style="bold yellow")
    if status == ReachabilityStatus.UNREACHABLE:
        return Text("UNREACHABLE", style="dim")
    return Text(status.value, style="cyan")


def render_table_report(report: AuditReport, console: Console | None = None) -> str:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render complete AuditReport to terminal or capture to string."""
    report.compute_summary()
    string_io = io.StringIO()
    target_console = console or Console(file=string_io, color_system="auto", width=120)

    title = "lh-dependency-graph: AST Reachability & Supply-Chain Posture Audit"
    subtitle = f"Generated at {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    target_console.print(
        Panel(
            Text(f"{title}\n{subtitle}", justify="center", style="bold cyan"),
            border_style="cyan",
        )
    )

    summary = report.summary
    summary_table = Table(title="Dependency Audit Executive Summary", border_style="blue")
    summary_table.add_column("Targets", justify="right")
    summary_table.add_column("Manifests", justify="right")
    summary_table.add_column("Sources", justify="right")
    summary_table.add_column("Dependencies", justify="right")
    summary_table.add_column("Findings", justify="right")
    summary_table.add_column("Critical", justify="right")
    summary_table.add_column("High", justify="right")
    summary_table.add_column("Medium", justify="right")
    summary_table.add_column("Low", justify="right")
    summary_table.add_column("Reachable Sinks", justify="right")

    crit_style = "bold red" if summary.get("critical", 0) > 0 else "dim"
    high_style = "bold red" if summary.get("high", 0) > 0 else "dim"
    med_style = "bold yellow" if summary.get("medium", 0) > 0 else "dim"
    low_style = "bold cyan" if summary.get("low", 0) > 0 else "dim"
    sink_style = "bold red" if summary.get("reachable_sinks", 0) > 0 else "dim"

    summary_table.add_row(
        str(summary.get("total_targets", 0)),
        str(summary.get("manifests_scanned", 0)),
        str(summary.get("source_files_scanned", 0)),
        str(summary.get("dependencies_scanned", 0)),
        str(summary.get("total_findings", 0)),
        f"[{crit_style}]{summary.get('critical', 0)}[/{crit_style}]",
        f"[{high_style}]{summary.get('high', 0)}[/{high_style}]",
        f"[{med_style}]{summary.get('medium', 0)}[/{med_style}]",
        f"[{low_style}]{summary.get('low', 0)}[/{low_style}]",
        f"[{sink_style}]{summary.get('reachable_sinks', 0)}[/{sink_style}]",
    )
    target_console.print(summary_table)

    all_findings: list[Finding] = []
    for res in report.results:
        all_findings.extend(res.findings)

    if not all_findings:
        target_console.print(
            Panel(
                Text(
                    "✔ Clean Audit: No vulnerable reachable sinks, unpinned dependencies, "
                    "or supply-chain risks detected.",
                    justify="center",
                    style="bold green",
                ),
                border_style="green",
            )
        )
    else:
        findings_table = Table(
            title=f"Supply Chain & Reachability Findings ({len(all_findings)})",
            border_style="red"
            if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0
            else "yellow",
        )
        findings_table.add_column("Target", style="bold white")
        findings_table.add_column("Package / Symbol", style="cyan")
        findings_table.add_column("Line", justify="right")
        findings_table.add_column("Rule ID", style="bold magenta", no_wrap=True)
        findings_table.add_column("Severity", justify="center", no_wrap=True)
        findings_table.add_column("Reachability", justify="center", no_wrap=True)
        findings_table.add_column("Finding Message")

        for f in all_findings:
            target_label = Path(f.target).name if len(f.target) > 28 else f.target
            pkg_str = f.package_or_symbol or "-"
            line_str = str(f.line_number) if f.line_number else "-"
            findings_table.add_row(
                target_label,
                pkg_str,
                line_str,
                f.rule_id,
                _get_severity_badge(f.severity),
                _get_reachability_badge(f.reachability),
                f.message,
            )
        target_console.print(findings_table)

    for res in report.results:
        if res.error_message:
            target_console.print(
                Panel(
                    Text(
                        f"Scan Error on '{res.target}': {res.error_message}",
                        style="bold red",
                    ),
                    border_style="red",
                )
            )

    return string_io.getvalue()


def export_json(report: AuditReport, indent: int = 2) -> str:
    """Export AuditReport as structured JSON string."""
    return json.dumps(report.to_dict(), indent=indent)


def export_sarif(report: AuditReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export AuditReport as OASIS SARIF v2.1.0 document."""
    report.compute_summary()

    rules_meta: list[dict[str, Any]] = []
    for r_def in sorted(RULES_REGISTRY.values(), key=lambda r: r.rule_id):
        rules_meta.append(
            {
                "id": r_def.rule_id,
                "name": r_def.title.replace(" ", ""),
                "shortDescription": {"text": r_def.title},
                "fullDescription": {"text": r_def.description},
                "defaultConfiguration": {"level": _severity_to_sarif_level(r_def.severity)},
                "help": {
                    "text": f"Remediation: {r_def.remediation}",
                    "markdown": f"**Remediation**: {r_def.remediation}",
                },
                "properties": {
                    "severity": r_def.severity.value,
                    "category": r_def.category.value,
                },
            }
        )

    sarif_results: list[dict[str, Any]] = []
    for res in report.results:
        for f in res.findings:
            line = f.line_number or 1
            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": _severity_to_sarif_level(f.severity),
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.target,
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": line,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "severity": f.severity.value,
                        "category": f.category.value,
                        "package_or_symbol": f.package_or_symbol,
                        "reachability": f.reachability.value,
                        "remediation": f.remediation,
                    },
                }
            )

    sarif_payload = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-dependency-graph",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dependency-graph",
                        "rules": rules_meta,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_payload, indent=indent)

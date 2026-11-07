# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        src.lh_dependency_graph.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and findings representations for lh-dependency-graph.

Provides structured types for dependency specifications, AST call reachability,
detection rules, security findings, and consolidated audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for dependency and reachability posture findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparisons."""
        order = {
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class RuleCategory(StrEnum):
    """Categorization for dependency and reachability detection rules."""

    DANGEROUS_SINK = "Dangerous Sink"
    VULNERABILITY_REACHABILITY = "Vulnerability Reachability"
    DEPENDENCY_HYGIENE = "Dependency Hygiene"
    SUPPLY_CHAIN_INTEGRITY = "Supply Chain Integrity"
    DEPENDENCY_BLOAT = "Dependency Bloat"
    PHANTOM_DEPENDENCY = "Phantom Dependency"
    GRAPH_TOPOLOGY = "Graph Topology"
    INTEGRITY_VERIFICATION = "Integrity Verification"


class ReachabilityStatus(StrEnum):
    """Call-graph reachability status of a dependency or dangerous sink."""

    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    STATIC_DIRECT = "STATIC_DIRECT"
    POTENTIAL = "POTENTIAL"


@dataclass
class DependencyInfo:
    """Declared or resolved package dependency metadata."""

    name: str
    version_spec: str
    version: str | None = None
    is_pinned: bool = False
    source_url: str | None = None
    hashes: list[str] = field(default_factory=list)
    is_dev: bool = False
    transitive: bool = False
    line_number: int | None = None
    manifest_file: str = ""


@dataclass
class ImportReference:
    """Source code import reference resolved via AST analysis."""

    module_name: str
    imported_symbol: str | None = None
    alias: str | None = None
    source_file: str = ""
    line_number: int = 1
    is_called: bool = False


@dataclass
class SinkCall:
    """Dangerous sink invocation identified via AST inspection."""

    sink_type: str
    caller_module: str
    source_file: str
    line_number: int
    call_snippet: str
    argument_details: str


@dataclass
class RuleDefinition:
    """Formal definition and guidance for a dependency graph detection rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: RuleCategory
    description: str
    remediation: str


@dataclass
class Finding:
    """Specific supply-chain risk or reachable dangerous sink finding."""

    rule_id: str
    severity: FindingSeverity
    category: RuleCategory
    title: str
    message: str
    target: str
    package_or_symbol: str
    remediation: str
    reachability: ReachabilityStatus = ReachabilityStatus.STATIC_DIRECT
    line_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "message": self.message,
            "target": self.target,
            "package_or_symbol": self.package_or_symbol,
            "reachability": self.reachability.value,
            "line_number": self.line_number,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclass
class ScanTargetResult:
    """Audit results for a scanned project directory or manifest."""

    target: str
    manifests_scanned: int = 0
    dependencies_count: int = 0
    source_files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "target": self.target,
            "manifests_scanned": self.manifests_scanned,
            "dependencies_count": self.dependencies_count,
            "source_files_scanned": self.source_files_scanned,
            "error_message": self.error_message,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AuditReport:
    """Consolidated audit report across scanned project targets."""

    report_type: str = "dependency_reachability_audit"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    category_breakdown: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Compute aggregated findings counts by severity and category."""
        counts = {
            "total_targets": len(self.results),
            "manifests_scanned": sum(r.manifests_scanned for r in self.results),
            "dependencies_scanned": sum(r.dependencies_count for r in self.results),
            "source_files_scanned": sum(r.source_files_scanned for r in self.results),
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "reachable_sinks": 0,
        }
        cat_counts = {cat.value: 0 for cat in RuleCategory}

        for res in self.results:
            for f in res.findings:
                counts["total_findings"] += 1
                if f.severity == FindingSeverity.CRITICAL:
                    counts["critical"] += 1
                elif f.severity == FindingSeverity.HIGH:
                    counts["high"] += 1
                elif f.severity == FindingSeverity.MEDIUM:
                    counts["medium"] += 1
                elif f.severity == FindingSeverity.LOW:
                    counts["low"] += 1

                if f.reachability == ReachabilityStatus.REACHABLE:
                    counts["reachable_sinks"] += 1

                cat_counts[f.category.value] = cat_counts.get(f.category.value, 0) + 1

        self.summary = counts
        self.category_breakdown = cat_counts

    def has_failures(self, threshold: FindingSeverity | None) -> bool:
        """Check if any finding meets or exceeds the failure threshold."""
        if threshold is None:
            return False
        for res in self.results:
            for f in res.findings:
                if f.severity.meets_threshold(threshold):
                    return True
        return False

    def filter_min_severity(self, min_sev: FindingSeverity) -> None:
        """Filter out findings below the specified minimum severity."""
        for res in self.results:
            res.findings = [f for f in res.findings if f.severity.meets_threshold(min_sev)]
        self.compute_summary()

    def to_dict(self) -> dict[str, Any]:
        """Convert complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "category_breakdown": self.category_breakdown,
            "results": [r.to_dict() for r in self.results],
        }


RULES_REGISTRY: dict[str, RuleDefinition] = {
    "LH-DEP-001": RuleDefinition(
        rule_id="LH-DEP-001",
        title="Reachable Dangerous Sink Call in Module",
        severity=FindingSeverity.CRITICAL,
        category=RuleCategory.DANGEROUS_SINK,
        description=(
            "Source code calls an unsafe deserialization, command execution, or evaluation sink "
            "(e.g. yaml.load without SafeLoader, pickle.loads, subprocess with shell=True, eval)."
        ),
        remediation=(
            "Use safe alternatives such as yaml.safe_load, subprocess with argument lists, "
            "and avoid pickle/eval."
        ),
    ),
    "LH-DEP-002": RuleDefinition(
        rule_id="LH-DEP-002",
        title="Vulnerable Dependency Version with Confirmed Reachability",
        severity=FindingSeverity.CRITICAL,
        category=RuleCategory.VULNERABILITY_REACHABILITY,
        description=(
            "Manifest/lockfile declares a package version with known vulnerabilities, and AST "
            "analysis confirms imported symbols are actively called in application code."
        ),
        remediation=(
            "Upgrade the vulnerable dependency to a patched non-vulnerable version release."
        ),
    ),
    "LH-DEP-003": RuleDefinition(
        rule_id="LH-DEP-003",
        title="Unpinned or Wildcard Dependency Version Specifier",
        severity=FindingSeverity.HIGH,
        category=RuleCategory.DEPENDENCY_HYGIENE,
        description=(
            "Dependency specification uses unpinned wildcards (*, latest, >= without upper bound, "
            "or bare package name), risking unexpected breaking or malicious upstream releases."
        ),
        remediation=(
            "Pin exact dependencies with '==' in production manifests and maintain lockfiles."
        ),
    ),
    "LH-DEP-004": RuleDefinition(
        rule_id="LH-DEP-004",
        title="Dependency Sourced from Insecure URL or Mutable VCS Branch",
        severity=FindingSeverity.HIGH,
        category=RuleCategory.SUPPLY_CHAIN_INTEGRITY,
        description=(
            "Dependency is retrieved over plaintext HTTP or tracks a mutable branch (e.g. @main, "
            "@master, @HEAD) without pinning an immutable commit SHA."
        ),
        remediation=(
            "Enforce HTTPS package registries and pin immutable commit SHAs for VCS sources."
        ),
    ),
    "LH-DEP-005": RuleDefinition(
        rule_id="LH-DEP-005",
        title="Dependency Confusion or Module Shadowing Risk",
        severity=FindingSeverity.HIGH,
        category=RuleCategory.SUPPLY_CHAIN_INTEGRITY,
        description=(
            "Local application module or filename shadows a third-party package name, or unscoped "
            "internal package names expose the build to public registry dependency confusion."
        ),
        remediation=(
            "Rename colliding local files and use scoped packages or private registry mirrors."
        ),
    ),
    "LH-DEP-006": RuleDefinition(
        rule_id="LH-DEP-006",
        title="Unused Bloated Dependency Declared in Manifest",
        severity=FindingSeverity.MEDIUM,
        category=RuleCategory.DEPENDENCY_BLOAT,
        description=(
            "Package declared in project manifest has zero import references across source files, "
            "inflating deployment size and expanding the attack surface unnecessarily."
        ),
        remediation=(
            "Remove unused dependencies from the project manifest to eliminate dependency bloat."
        ),
    ),
    "LH-DEP-007": RuleDefinition(
        rule_id="LH-DEP-007",
        title="Phantom or Undeclared Dependency Imported in Source Code",
        severity=FindingSeverity.HIGH,
        category=RuleCategory.PHANTOM_DEPENDENCY,
        description=(
            "Source code directly imports a third-party module not listed as a direct project "
            "dependency, relying on fragile transitive dependency resolution."
        ),
        remediation=(
            "Declare all directly imported third-party packages explicitly in project manifests."
        ),
    ),
    "LH-DEP-008": RuleDefinition(
        rule_id="LH-DEP-008",
        title="Circular Dependency Cycle or Excessive Graph Depth",
        severity=FindingSeverity.MEDIUM,
        category=RuleCategory.GRAPH_TOPOLOGY,
        description=(
            "Dependency graph contains recursive circular references or excessive dependency "
            "chain depth (> 5 hops), increasing fragility and supply-chain risk."
        ),
        remediation="Refactor dependency chains to break cycles and flatten dependency tree depth.",
    ),
    "LH-DEP-009": RuleDefinition(
        rule_id="LH-DEP-009",
        title="Deprecated, Abandoned, or Insecure Legacy Package",
        severity=FindingSeverity.MEDIUM,
        category=RuleCategory.SUPPLY_CHAIN_INTEGRITY,
        description=(
            "Project depends on known deprecated, abandoned, or cryptographically broken packages "
            "(e.g. pycrypto, imp, optparse, request, event-stream)."
        ),
        remediation=(
            "Replace legacy deprecated libraries with actively maintained modern equivalents."
        ),
    ),
    "LH-DEP-010": RuleDefinition(
        rule_id="LH-DEP-010",
        title="Missing Cryptographic Integrity Hashes in Lockfile",
        severity=FindingSeverity.LOW,
        category=RuleCategory.INTEGRITY_VERIFICATION,
        description=(
            "Lockfile or pinned requirements file lacks cryptographic integrity hashes "
            "(sha256/sha512), leaving package artifacts vulnerable to tampering."
        ),
        remediation="Generate lockfiles with cryptographic hash verification (--generate-hashes).",
    ),
}

# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        tests.test_graph_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for dependency graph analyzer and security detection rules.

Validates detection rules LH-DEP-001 through LH-DEP-010, clean baseline posture,
cycle detection, and graph topology traversal.
"""

from __future__ import annotations

from pathlib import Path

from lh_dependency_graph.graph_analyzer import (
    _is_version_vulnerable,
    analyze_project,
    compute_max_chain_depth,
    detect_cycles,
)
from lh_dependency_graph.models import FindingSeverity, ReachabilityStatus


def test_clean_project_posture(clean_project: Path) -> None:
    """Validate that a properly pinned and safe project generates zero findings."""
    result = analyze_project(clean_project)
    assert result.error_message is None
    assert result.manifests_scanned == 1
    assert result.source_files_scanned == 1
    assert len(result.findings) == 0
    # --------------------------------------------------------------------------
    # --- Rule LH-DEP-001 (CRITICAL):
    #     Reachability Match: Vulnerable Function Invoked in Code Path
    # ---
    # Evaluates security posture against reachability match: vulnerable function
    # invoked in code path.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_001_dangerous_sinks(vulnerable_sinks_project: Path) -> None:
    """Validate rule LH-DEP-001 catches dangerous deserialization and subprocess sinks."""
    result = analyze_project(vulnerable_sinks_project)
    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-DEP-001" in rule_ids

    sink_findings = [f for f in result.findings if f.rule_id == "LH-DEP-001"]
    assert len(sink_findings) >= 5
    for f in sink_findings:
        assert f.severity == FindingSeverity.CRITICAL
        assert f.reachability == ReachabilityStatus.REACHABLE
    # --------------------------------------------------------------------------
    # --- Rule LH-DEP-002 (HIGH):
    #     Unpinned Transitive Dependency with Known High-Severity CVE
    # ---
    # Evaluates security posture against unpinned transitive dependency with known
    # high-severity cve.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_002_vulnerable_reachability(vulnerable_reachability_project: Path) -> None:
    """Validate rule LH-DEP-002 flags vulnerable dependency when actively called."""
    result = analyze_project(vulnerable_reachability_project)
    rule_ids = [f.rule_id for f in result.findings]
    assert "LH-DEP-002" in rule_ids

    vuln_findings = [f for f in result.findings if f.rule_id == "LH-DEP-002"]
    assert len(vuln_findings) == 1
    f = vuln_findings[0]
    assert f.severity == FindingSeverity.CRITICAL
    assert f.reachability == ReachabilityStatus.REACHABLE
    assert "requests" in f.package_or_symbol


def test_rules_003_004_009_010_hygiene(hygiene_and_integrity_project: Path) -> None:
    """Validate detection of unpinned versions, insecure URLs, and missing hashes."""
    result = analyze_project(hygiene_and_integrity_project)
    rule_ids = {f.rule_id for f in result.findings}

    # LH-DEP-003: Unpinned / wildcard
    assert "LH-DEP-003" in rule_ids
    # LH-DEP-004: Insecure HTTP / mutable VCS branch
    assert "LH-DEP-004" in rule_ids
    # LH-DEP-009: Deprecated package (pycrypto)
    assert "LH-DEP-009" in rule_ids
    # LH-DEP-010: Missing hashes in lockfile
    assert "LH-DEP-010" in rule_ids


def test_rules_005_006_007_shadow_bloat_phantom(bloat_phantom_shadow_project: Path) -> None:
    """Validate detection of module shadowing (005), bloat (006), and phantom imports (007)."""
    result = analyze_project(bloat_phantom_shadow_project)
    rule_ids = {f.rule_id for f in result.findings}

    # LH-DEP-005: Local requests.py shadows external requests
    assert "LH-DEP-005" in rule_ids
    # LH-DEP-006: unused-bloat-lib declared but never imported
    assert "LH-DEP-006" in rule_ids
    # LH-DEP-007: phantom_thirdparty imported but not declared
    assert "LH-DEP-007" in rule_ids


def test_rule_008_cycles_and_depth(circular_and_deep_graph_project: Path) -> None:
    """Validate detection of circular dependency cycle and excessive chain depth."""
    result = analyze_project(circular_and_deep_graph_project)
    findings = [f for f in result.findings if f.rule_id == "LH-DEP-008"]
    assert len(findings) >= 2

    messages = " ".join(f.message for f in findings)
    assert "Circular dependency cycle detected" in messages
    assert "Excessive transitive dependency chain depth" in messages


def test_detect_cycles_utility() -> None:
    """Test cycle detection in isolated directed graph."""
    edges = {
        "a": ["b"],
        "b": ["c"],
        "c": ["a"],
        "d": ["e"],
    }
    cycles = detect_cycles(edges)
    assert len(cycles) == 1
    assert cycles[0] == ["a", "b", "c", "a"]


def test_compute_max_chain_depth_utility() -> None:
    """Test chain depth calculation in isolated graph."""
    edges = {
        "root": ["step1"],
        "step1": ["step2"],
        "step2": ["step3"],
    }
    depth, chain = compute_max_chain_depth(edges, ["root"])
    assert depth == 3
    assert chain == ["root", "step1", "step2", "step3"]


def test_is_version_vulnerable_utility() -> None:
    """Test semver comparison utility."""
    assert _is_version_vulnerable("2.30.0", "2.31.0") is True
    assert _is_version_vulnerable("2.31.0", "2.31.0") is False
    assert _is_version_vulnerable("2.32.0", "2.31.0") is False
    assert _is_version_vulnerable("1.25.9", "1.26.18") is True

# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        src.lh_dependency_graph.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-dependency-graph: AST-driven dependency reachability and supply-chain auditor.

Logihertz Systems (OPC) Private Limited.
"""

from __future__ import annotations

from lh_dependency_graph.models import (
    RULES_REGISTRY,
    AuditReport,
    Finding,
    FindingSeverity,
    RuleCategory,
    ScanTargetResult,
)

__version__ = "0.1.0"
__all__ = [
    "RULES_REGISTRY",
    "AuditReport",
    "Finding",
    "FindingSeverity",
    "RuleCategory",
    "ScanTargetResult",
    "__version__",
]

# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared pytest fixtures for lh-dependency-graph test suite.

Provides temporary mock project structures, clean codebases, vulnerable manifests,
and AST source code snippets for validating rules LH-DEP-001 through LH-DEP-010.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def clean_project(tmp_path: Path) -> Path:
    """Create a clean project with pinned safe dependencies and safe AST calls."""
    proj = tmp_path / "clean_app"
    proj.mkdir()

    # requirements.txt with pinned safe versions and hashes
    req_file = proj / "requirements.txt"
    req_file.write_text(
        "requests==2.32.3 --hash=sha256:abcd1234abcd1234abcd1234abcd1234\n"
        "pydantic==2.7.4 --hash=sha256:ef015678ef015678ef015678ef015678\n",
        encoding="utf-8",
    )

    # Safe source code
    src_dir = proj / "src"
    src_dir.mkdir()
    app_file = src_dir / "main.py"
    app_file.write_text(
        "import requests\n"
        "from pydantic import BaseModel\n"
        "\n"
        "class User(BaseModel):\n"
        "    name: str\n"
        "\n"
        "def fetch_data():\n"
        "    res = requests.get('https://example.com/api')\n"
        "    return res.json()\n",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def vulnerable_sinks_project(tmp_path: Path) -> Path:
    """Create project triggering LH-DEP-001 (dangerous sinks in AST)."""
    proj = tmp_path / "sinks_app"
    proj.mkdir()

    req_file = proj / "requirements.txt"
    req_file.write_text(
        "pyyaml==6.0.1 --hash=sha256:1111222233334444\n",
        encoding="utf-8",
    )

    app_file = proj / "vuln_sinks.py"
    app_file.write_text(
        "import yaml\n"
        "import pickle\n"
        "import marshal\n"
        "import subprocess\n"
        "import xml.etree.ElementTree as ET\n"
        "\n"
        "def unsafe_actions(raw_data, cmd):\n"
        "    y = yaml.load(raw_data)\n"
        "    p = pickle.loads(raw_data)\n"
        "    m = marshal.loads(raw_data)\n"
        "    subprocess.run(cmd, shell=True)\n"
        "    eval(cmd)\n"
        "    tree = ET.fromstring(raw_data)\n"
        "    return y, p, m, tree\n",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def vulnerable_reachability_project(tmp_path: Path) -> Path:
    """Create project triggering LH-DEP-002 (vulnerable version with confirmed call)."""
    proj = tmp_path / "reachable_vuln_app"
    proj.mkdir()

    req_file = proj / "requirements.txt"
    req_file.write_text("requests==2.28.0\n", encoding="utf-8")

    app_file = proj / "app.py"
    app_file.write_text(
        "import requests\n\ndef run():\n    requests.get('https://insecure.internal')\n",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def hygiene_and_integrity_project(tmp_path: Path) -> Path:
    """Create project triggering LH-DEP-003, LH-DEP-004, LH-DEP-009, LH-DEP-010."""
    proj = tmp_path / "hygiene_app"
    proj.mkdir()

    # Manifest with unpinned specifier, insecure URL, mutable VCS branch, deprecated package
    req_file = proj / "requirements.txt"
    req_file.write_text(
        "unpinned-pkg>=1.0.0\n"
        "wildcard-pkg==*\n"
        "insecure-http-pkg @ http://insecure.repo/pkg.tar.gz\n"
        "git-branch-pkg @ git+https://github.com/org/repo@main\n"
        "pycrypto==2.6.1\n",
        encoding="utf-8",
    )

    # Empty lockfile missing hashes
    lock_file = proj / "requirements.lock"
    lock_file.write_text("unpinned-pkg==1.2.0\n", encoding="utf-8")

    app_file = proj / "dummy.py"
    app_file.write_text(
        "import pycrypto\n",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def bloat_phantom_shadow_project(tmp_path: Path) -> Path:
    """Create project triggering LH-DEP-005, LH-DEP-006, and LH-DEP-007."""
    proj = tmp_path / "bloat_phantom_app"
    proj.mkdir()

    # Manifest declares requests and unused-bloat-pkg
    req_file = proj / "requirements.txt"
    req_file.write_text(
        "requests==2.32.0 --hash=sha256:12345\nunused-bloat-lib==1.0.0 --hash=sha256:67890\n",
        encoding="utf-8",
    )

    # Local file named requests.py (shadowing)
    shadow_file = proj / "requests.py"
    shadow_file.write_text("# Local requests module shadowing external package\n", encoding="utf-8")

    # App imports phantom-dependency (not in requirements.txt)
    app_file = proj / "worker.py"
    app_file.write_text(
        "import phantom_thirdparty\n\nphantom_thirdparty.execute()\n",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def circular_and_deep_graph_project(tmp_path: Path) -> Path:
    """Create project triggering LH-DEP-008 (circular cycle & excessive graph depth)."""
    proj = tmp_path / "graph_app"
    proj.mkdir()

    graph_file = proj / "dependency-graph.json"
    graph_data = {
        "packages": [
            {"name": "pkg-a", "version": "1.0.0"},
            {"name": "pkg-b", "version": "1.0.0"},
            {"name": "pkg-c", "version": "1.0.0"},
            {"name": "n1", "version": "1.0.0"},
            {"name": "n2", "version": "1.0.0"},
            {"name": "n3", "version": "1.0.0"},
            {"name": "n4", "version": "1.0.0"},
            {"name": "n5", "version": "1.0.0"},
            {"name": "n6", "version": "1.0.0"},
            {"name": "n7", "version": "1.0.0"},
        ],
        "dependencies": {
            # Circular cycle: pkg-a -> pkg-b -> pkg-c -> pkg-a
            "pkg-a": ["pkg-b"],
            "pkg-b": ["pkg-c"],
            "pkg-c": ["pkg-a"],
            # Deep chain: n1 -> n2 -> n3 -> n4 -> n5 -> n6 -> n7 (6 hops > 5)
            "n1": ["n2"],
            "n2": ["n3"],
            "n3": ["n4"],
            "n4": ["n5"],
            "n5": ["n6"],
            "n6": ["n7"],
        },
    }
    graph_file.write_text(json.dumps(graph_data), encoding="utf-8")
    return proj

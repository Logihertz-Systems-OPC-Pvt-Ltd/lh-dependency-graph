# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        tests.test_manifest_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for multi-ecosystem manifest and lockfile parsers.

Validates parsing logic for requirements.txt, pyproject.toml, package.json,
package-lock.json, and dependency-graph.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from lh_dependency_graph.manifest_parser import (
    parse_dependency_graph_json,
    parse_package_json,
    parse_package_lock_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)


def test_parse_requirements_txt(tmp_path: Path) -> None:
    """Test parsing Python requirements.txt with various specifiers and hashes."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "# Production dependencies\n"
        "requests==2.31.0 --hash=sha256:1234567890abcdef\n"
        "urllib3>=1.26.0,<2.0.0\n"
        "fastapi\n"
        "git+https://github.com/org/repo.git@v1.0.0#egg=my-pkg\n"
        "-r other-reqs.txt\n"
        "--extra-index-url https://pypi.org/simple\n",
        encoding="utf-8",
    )

    deps = parse_requirements_txt(req_file)
    assert len(deps) == 4

    reqs_dep = next(d for d in deps if d.name == "requests")
    assert reqs_dep.version == "2.31.0"
    assert reqs_dep.is_pinned is True
    assert len(reqs_dep.hashes) == 1

    urllib_dep = next(d for d in deps if d.name == "urllib3")
    assert urllib_dep.is_pinned is False
    assert urllib_dep.version_spec == ">=1.26.0,<2.0.0"

    fastapi_dep = next(d for d in deps if d.name == "fastapi")
    assert fastapi_dep.is_pinned is False
    assert fastapi_dep.version_spec == ""

    git_dep = next(d for d in deps if d.name == "my-pkg")
    assert git_dep.source_url is not None


def test_parse_pyproject_toml(tmp_path: Path) -> None:
    """Test parsing PEP 621 and Poetry dependencies from pyproject.toml."""
    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text(
        """[project]
name = "test-pkg"
version = "0.1.0"
dependencies = [
    "pydantic==2.5.0",
    "httpx>=0.24.0",
]

[tool.poetry.dependencies]
python = "^3.11"
rich = "==13.7.0"
pyyaml = { version = "6.0.1", git = "https://github.com/yaml/pyyaml", branch = "main" }
""",
        encoding="utf-8",
    )

    deps = parse_pyproject_toml(pyproject_file)
    dep_names = {d.name for d in deps}
    assert "pydantic" in dep_names
    assert "httpx" in dep_names
    assert "rich" in dep_names
    assert "pyyaml" in dep_names

    pydantic_dep = next(d for d in deps if d.name == "pydantic")
    assert pydantic_dep.version == "2.5.0"
    assert pydantic_dep.is_pinned is True

    pyyaml_dep = next(d for d in deps if d.name == "pyyaml")
    assert pyyaml_dep.source_url == "https://github.com/yaml/pyyaml"


def test_parse_package_json(tmp_path: Path) -> None:
    """Test parsing Node.js package.json dependencies and devDependencies."""
    pkg_file = tmp_path / "package.json"
    data = {
        "name": "my-node-app",
        "dependencies": {
            "express": "4.19.2",
            "lodash": "^4.17.20",
        },
        "devDependencies": {
            "typescript": "5.3.3",
            "jest": "*",
        },
    }
    pkg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    deps = parse_package_json(pkg_file)
    assert len(deps) == 4

    express_dep = next(d for d in deps if d.name == "express")
    assert express_dep.is_dev is False
    assert express_dep.is_pinned is True
    assert express_dep.version == "4.19.2"

    jest_dep = next(d for d in deps if d.name == "jest")
    assert jest_dep.is_dev is True
    assert jest_dep.is_pinned is False


def test_parse_package_lock_json(tmp_path: Path) -> None:
    """Test parsing Node.js package-lock.json with resolved packages and integrity hashes."""
    lock_file = tmp_path / "package-lock.json"
    data = {
        "name": "my-node-app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "my-node-app"},
            "node_modules/axios": {
                "version": "1.6.0",
                "resolved": "https://registry.npmjs.org/axios/-/axios-1.6.0.tgz",
                "integrity": "sha512-abcd1234==",
            },
            "node_modules/mocha": {
                "version": "10.2.0",
                "dev": True,
            },
        },
    }
    lock_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    deps = parse_package_lock_json(lock_file)
    assert len(deps) == 2

    axios_dep = next(d for d in deps if d.name == "axios")
    assert axios_dep.version == "1.6.0"
    assert axios_dep.hashes == ["sha512-abcd1234=="]
    assert axios_dep.transitive is True

    mocha_dep = next(d for d in deps if d.name == "mocha")
    assert mocha_dep.is_dev is True
    assert mocha_dep.hashes == []


def test_parse_dependency_graph_json(tmp_path: Path) -> None:
    """Test parsing generic dependency graph JSON artifact."""
    graph_file = tmp_path / "dependency-graph.json"
    data = {
        "packages": [
            {"name": "root-pkg", "version": "1.0.0"},
            {"name": "child-pkg", "version": "2.0.0"},
        ],
        "dependencies": {
            "root-pkg": ["child-pkg"],
        },
    }
    graph_file.write_text(json.dumps(data), encoding="utf-8")

    deps, edges = parse_dependency_graph_json(graph_file)
    assert len(deps) == 2
    assert "root-pkg" in edges
    assert edges["root-pkg"] == ["child-pkg"]


def test_parsers_invalid_files(tmp_path: Path) -> None:
    """Test parsers handle empty or corrupted files gracefully."""
    bad_file = tmp_path / "corrupted.json"
    bad_file.write_text("{bad-json:", encoding="utf-8")

    assert parse_requirements_txt(tmp_path / "nonexistent.txt") == []
    assert parse_pyproject_toml(bad_file) == []
    assert parse_package_json(bad_file) == []
    assert parse_package_lock_json(bad_file) == []
    deps, edges = parse_dependency_graph_json(bad_file)
    assert deps == []
    assert edges == {}

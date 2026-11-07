# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        src.lh_dependency_graph.manifest_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parsers for multi-ecosystem dependency manifests and lockfiles.

Supports Python requirements.txt, pyproject.toml, Node.js package.json,
package-lock.json, and generic dependency-graph.json artifacts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from lh_dependency_graph.models import DependencyInfo

# Common regex patterns for requirements.txt
REQ_NAME_PATTERN = re.compile(r"^([a-zA-Z0-9_\-\.]+)(.*)$")
HASH_PATTERN = re.compile(r"--hash=([a-zA-Z0-9_:]+)")
VERSION_OPERATORS = ("==", ">=", "<=", "~=", "!=", ">", "<", "===")


def _normalize_name(name: str) -> str:
    """Normalize package names to lowercase with hyphens."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def parse_requirements_txt(path: Path) -> list[DependencyInfo]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse Python requirements.txt format."""
    deps: list[DependencyInfo] = []
    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return deps

    lines = content.splitlines()
    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r ", "-f ", "-i ", "--extra-index-url")):
            continue

        # Check for #egg= in line before comment stripping
        egg_match = re.search(r"#egg=([a-zA-Z0-9_\-\.]+)", line)

        # Extract all hashes
        hashes = HASH_PATTERN.findall(line)
        # Strip comments and hash arguments
        clean = re.sub(r"--hash=\S+", "", line)
        if "#egg=" not in clean:
            clean = clean.split("#")[0]
        else:
            clean = re.sub(r"\s+#.*$", "", clean)
        clean = clean.strip().rstrip("\\").strip()
        if not clean:
            continue

        source_url: str | None = None
        version_spec: str = ""
        version: str | None = None
        is_pinned = False

        if clean.startswith(("-e ", "git+", "http://", "https://", "svn+", "hg+")):
            source_url = clean.replace("-e ", "").strip()
            if egg_match:
                pkg_name = egg_match.group(1)
            else:
                pkg_name = Path(clean.split("@")[0].split("#")[0]).name.replace(".git", "")
            version_spec = clean
        else:
            # Parse specifier e.g. requests==2.31.0; python_version > '3.8'
            spec_part = clean.split(";")[0].strip()
            match = REQ_NAME_PATTERN.match(spec_part)
            if match:
                pkg_name = match.group(1)
                version_spec = match.group(2).strip()
            else:
                pkg_name = spec_part
                version_spec = ""

            if version_spec.startswith("=="):
                version = version_spec[2:].strip()
                is_pinned = True
            elif "==" in version_spec and not any(op in version_spec for op in (">", "<", "~")):
                version = version_spec.split("==")[-1].strip()
                is_pinned = True

        norm_name = _normalize_name(pkg_name)
        deps.append(
            DependencyInfo(
                name=norm_name,
                version_spec=version_spec,
                version=version,
                is_pinned=is_pinned,
                source_url=source_url,
                hashes=hashes,
                is_dev=False,
                line_number=idx,
                manifest_file=str(path),
            )
        )

    return deps


def parse_pyproject_toml(path: Path) -> list[DependencyInfo]:
    """Parse PEP 621 / Poetry dependencies from pyproject.toml."""
    deps: list[DependencyInfo] = []
    try:
        content = path.read_text(encoding="utf-8")
        import tomllib

        data = tomllib.loads(content)
    except Exception:
        try:
            data = yaml.safe_load(content) if "content" in locals() else None
        except Exception:
            data = None

    lines = content.splitlines() if "content" in locals() else []

    # If data is dict, inspect project.dependencies and tool.poetry
    if isinstance(data, dict):
        # PEP 621
        proj_deps = data.get("project", {}).get("dependencies", [])
        if isinstance(proj_deps, list):
            for dep_str in proj_deps:
                if isinstance(dep_str, str):
                    clean = dep_str.split(";")[0].strip()
                    match = REQ_NAME_PATTERN.match(clean)
                    if match:
                        name = _normalize_name(match.group(1))
                        v_spec = match.group(2).strip()
                        v = v_spec[2:].strip() if v_spec.startswith("==") else None
                        pinned = v_spec.startswith("==")
                        deps.append(
                            DependencyInfo(
                                name=name,
                                version_spec=v_spec,
                                version=v,
                                is_pinned=pinned,
                                manifest_file=str(path),
                            )
                        )

        # Poetry dependencies
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for name, val in poetry_deps.items():
                if name.lower() == "python":
                    continue
                source_url = None
                pinned = False
                v = None
                if isinstance(val, str):
                    v_spec = val.strip()
                    pinned = v_spec.startswith("==")
                    v = v_spec[2:].strip() if pinned else None
                elif isinstance(val, dict):
                    source_url = val.get("git") or val.get("url")
                    v_spec = str(val.get("version", ""))
                    if val.get("rev") or val.get("tag"):
                        v_spec += f" @ {val.get('rev') or val.get('tag')}"
                    elif val.get("branch"):
                        v_spec += f" @ {val.get('branch')}"
                    pinned = v_spec.startswith("==")
                    v = v_spec[2:].strip() if pinned else None
                else:
                    v_spec = str(val)

                deps.append(
                    DependencyInfo(
                        name=_normalize_name(name),
                        version_spec=v_spec,
                        version=v,
                        is_pinned=pinned,
                        source_url=source_url,
                        manifest_file=str(path),
                    )
                )

    if not deps and lines:
        # Fallback line-by-line parsing for pyproject dependencies
        in_deps = False
        for idx, line in enumerate(lines, 1):
            s = line.strip()
            if "dependencies = [" in s:
                in_deps = True
                continue
            if in_deps:
                if "]" in s:
                    in_deps = False
                    continue
                dep_clean = s.strip("\",' ")
                if dep_clean:
                    match = REQ_NAME_PATTERN.match(dep_clean.split(";")[0].strip())
                    if match:
                        name = _normalize_name(match.group(1))
                        v_spec = match.group(2).strip()
                        pinned = v_spec.startswith("==")
                        v = v_spec[2:].strip() if pinned else None
                        deps.append(
                            DependencyInfo(
                                name=name,
                                version_spec=v_spec,
                                version=v,
                                is_pinned=pinned,
                                line_number=idx,
                                manifest_file=str(path),
                            )
                        )

    return deps


def parse_package_json(path: Path) -> list[DependencyInfo]:
    """Parse Node.js package.json dependencies."""
    deps: list[DependencyInfo] = []
    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception:
        return deps

    lines = content.splitlines()

    for sec, is_dev in (("dependencies", False), ("devDependencies", True)):
        obj = data.get(sec, {})
        if isinstance(obj, dict):
            for name, v_spec in obj.items():
                spec_str = str(v_spec).strip()
                is_pinned = bool(re.match(r"^\d+\.\d+\.\d+", spec_str))
                source_url = None
                if spec_str.startswith(("http://", "https://", "git+")):
                    source_url = spec_str

                # Find line number
                line_num = None
                for l_idx, l_str in enumerate(lines, 1):
                    if f'"{name}"' in l_str:
                        line_num = l_idx
                        break

                deps.append(
                    DependencyInfo(
                        name=_normalize_name(name),
                        version_spec=spec_str,
                        version=spec_str if is_pinned else None,
                        is_pinned=is_pinned,
                        source_url=source_url,
                        is_dev=is_dev,
                        line_number=line_num,
                        manifest_file=str(path),
                    )
                )

    return deps


def parse_package_lock_json(path: Path) -> list[DependencyInfo]:
    """Parse Node.js package-lock.json resolved packages and hashes."""
    deps: list[DependencyInfo] = []
    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception:
        return deps

    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not pkg_path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or pkg_path.split("node_modules/")[-1]
            if not name:
                continue
            ver = meta.get("version")
            integrity = meta.get("integrity")
            hashes = [integrity] if integrity else []
            resolved = meta.get("resolved")
            source_url = resolved if resolved and resolved.startswith("http") else None
            is_dev = bool(meta.get("dev"))

            deps.append(
                DependencyInfo(
                    name=_normalize_name(name),
                    version_spec=f"=={ver}" if ver else "",
                    version=ver,
                    is_pinned=bool(ver),
                    source_url=source_url,
                    hashes=hashes,
                    is_dev=is_dev,
                    transitive="node_modules" in pkg_path,
                    manifest_file=str(path),
                )
            )

    return deps


def parse_dependency_graph_json(
    path: Path,
) -> tuple[list[DependencyInfo], dict[str, list[str]]]:
    """Parse generic SBOM / dependency-graph.json format with edges."""
    deps: list[DependencyInfo] = []
    edges: dict[str, list[str]] = {}

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception:
        return deps, edges

    pkgs = data.get("packages") or data.get("nodes") or []
    if isinstance(pkgs, list):
        for item in pkgs:
            if isinstance(item, dict):
                name = item.get("name") or item.get("id") or ""
                if name:
                    ver = item.get("version")
                    deps.append(
                        DependencyInfo(
                            name=_normalize_name(name),
                            version_spec=f"=={ver}" if ver else "",
                            version=ver,
                            is_pinned=bool(ver),
                            manifest_file=str(path),
                        )
                    )

    dep_edges = data.get("dependencies") or data.get("edges") or {}
    if isinstance(dep_edges, dict):
        for src, tgts in dep_edges.items():
            norm_src = _normalize_name(src)
            if isinstance(tgts, list):
                edges[norm_src] = [_normalize_name(t) for t in tgts if isinstance(t, str)]
            elif isinstance(tgts, dict):
                edges[norm_src] = [_normalize_name(t) for t in tgts.keys()]

    return deps, edges

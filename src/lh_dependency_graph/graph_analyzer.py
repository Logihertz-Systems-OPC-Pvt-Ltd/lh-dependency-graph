# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        src.lh_dependency_graph.graph_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Dependency graph, reachability correlation, and supply-chain risk analyzer.

Coordinates manifest parsing, AST source code inspection, call-graph reachability,
and supply-chain detection rules (LH-DEP-001 through LH-DEP-010).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from lh_dependency_graph.ast_reachability import analyze_js_file, analyze_python_file
from lh_dependency_graph.manifest_parser import (
    parse_dependency_graph_json,
    parse_package_json,
    parse_package_lock_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from lh_dependency_graph.models import (
    RULES_REGISTRY,
    DependencyInfo,
    Finding,
    ImportReference,
    ReachabilityStatus,
    ScanTargetResult,
    SinkCall,
)

# Python standard library module names
PY_STDLIB: set[str] = (
    set(sys.stdlib_module_names)
    if hasattr(sys, "stdlib_module_names")
    else {
        "abc",
        "argparse",
        "ast",
        "asyncio",
        "base64",
        "builtins",
        "collections",
        "concurrent",
        "contextlib",
        "copy",
        "csv",
        "ctypes",
        "dataclasses",
        "datetime",
        "dis",
        "email",
        "enum",
        "errno",
        "functools",
        "glob",
        "gzip",
        "hashlib",
        "hmac",
        "html",
        "http",
        "importlib",
        "inspect",
        "io",
        "itertools",
        "json",
        "logging",
        "math",
        "mimetypes",
        "multiprocessing",
        "os",
        "pathlib",
        "pickle",
        "platform",
        "queue",
        "random",
        "re",
        "secrets",
        "select",
        "shutil",
        "signal",
        "socket",
        "sqlite3",
        "ssl",
        "stat",
        "string",
        "struct",
        "subprocess",
        "sys",
        "tarfile",
        "tempfile",
        "threading",
        "time",
        "traceback",
        "types",
        "typing",
        "unittest",
        "urllib",
        "uuid",
        "warnings",
        "weakref",
        "xml",
        "zipfile",
        "zlib",
        "__future__",
    }
)

# Node.js built-in module names
NODE_STDLIB: set[str] = {
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
}

# Known vulnerable package versions dictionary for reachability analysis
KNOWN_VULNERABLE_PACKAGES: dict[str, list[dict[str, str]]] = {
    "requests": [
        {
            "max_version": "2.31.0",
            "cve": "CVE-2023-32681",
            "advisory": "Proxy-Authorization header leakage on cross-origin redirects",
        }
    ],
    "urllib3": [
        {
            "max_version": "1.26.18",
            "cve": "CVE-2023-45803",
            "advisory": "Cookie leak on cross-origin redirect",
        }
    ],
    "pillow": [
        {
            "max_version": "10.0.1",
            "cve": "CVE-2023-4863",
            "advisory": "Heap buffer overflow in WebP image parsing",
        }
    ],
    "cryptography": [
        {
            "max_version": "41.0.6",
            "cve": "CVE-2023-49083",
            "advisory": "NULL-dereference when loading PKCS#7 certificates",
        }
    ],
    "aiohttp": [
        {
            "max_version": "3.8.6",
            "cve": "CVE-2023-47627",
            "advisory": "HTTP request smuggling via chunked transfer encoding",
        }
    ],
    "paramiko": [
        {
            "max_version": "2.10.1",
            "cve": "CVE-2022-24302",
            "advisory": "Race condition in keyfile handling",
        }
    ],
    "django": [
        {
            "max_version": "3.2.22",
            "cve": "CVE-2023-43665",
            "advisory": "Denial of service in django.utils.text.Truncator",
        }
    ],
    "flask": [
        {
            "max_version": "2.2.5",
            "cve": "CVE-2023-30861",
            "advisory": "Missing session cookie flags leading to session hijack",
        }
    ],
    "lodash": [
        {
            "max_version": "4.17.21",
            "cve": "CVE-2020-8203",
            "advisory": "Prototype pollution via zipObjectDeep",
        }
    ],
    "jsonwebtoken": [
        {
            "max_version": "9.0.0",
            "cve": "CVE-2022-23529",
            "advisory": "Arbitrary code execution via insecure key validation",
        }
    ],
    "axios": [
        {
            "max_version": "1.6.0",
            "cve": "CVE-2023-45857",
            "advisory": "Cross-site request forgery and SSRF vulnerability",
        }
    ],
}

# Known deprecated or insecure legacy packages
DEPRECATED_PACKAGES: dict[str, str] = {
    "pycrypto": "Deprecated and unmaintained cryptographic library; migrate to cryptography.",
    "imp": "Deprecated Python standard library module removed in 3.12; migrate to importlib.",
    "optparse": "Deprecated legacy CLI parser; migrate to argparse or typer.",
    "request": "Deprecated and unmaintained legacy Node.js HTTP library; migrate to axios/fetch.",
    "event-stream": "Compromised malicious npm package; remove immediately.",
    "nomnom": "Deprecated option parser for Node.js; migrate to commander or yargs.",
    "left-pad": "Deprecated unmaintained micro-package; use native padStart.",
    "colors.js": "Vulnerable/tampered npm package; migrate to chalk or colorette.",
    "crypto": "Deprecated dummy npm package; use built-in node:crypto.",
}

# Package name aliases to import names
PACKAGE_ALIASES: dict[str, set[str]] = {
    "pyyaml": {"yaml", "ruamel.yaml"},
    "pillow": {"pil", "pillow"},
    "beautifulsoup4": {"bs4"},
    "scikit-learn": {"sklearn"},
    "paho-mqtt": {"paho"},
    "google-api-python-client": {"googleapiclient"},
    "protobuf": {"google.protobuf"},
    "opencv-python": {"cv2"},
    "attrs": {"attr", "attrs"},
    "python-dateutil": {"dateutil"},
    "typing-extensions": {"typing_extensions"},
    "psycopg2-binary": {"psycopg2"},
    "mysql-connector-python": {"mysql"},
    "dnspython": {"dns"},
}

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".tox",
    ".eggs",
}


def _parse_semver(v: str) -> tuple[int, ...]:
    """Parse semver string to integer tuple for comparison."""
    parts = re.findall(r"\d+", v)
    if not parts:
        return (0,)
    return tuple(int(p) for p in parts[:3])


def _is_version_vulnerable(declared_ver: str, max_ver: str) -> bool:
    """Check if declared version is strictly less than max patched version."""
    v_decl = _parse_semver(declared_ver)
    v_max = _parse_semver(max_ver)
    return v_decl < v_max


def detect_cycles(edges: dict[str, list[str]]) -> list[list[str]]:
    """Detect circular dependency cycles in directed graph using DFS."""
    visited: set[str] = set()
    rec_stack: list[str] = []
    cycles: list[list[str]] = []

    def dfs(node: str) -> None:
        visited.add(node)
        rec_stack.append(node)

        for neighbor in edges.get(node, []):
            if neighbor not in visited:
                dfs(neighbor)
            elif neighbor in rec_stack:
                cycle_start_idx = rec_stack.index(neighbor)
                cycle = rec_stack[cycle_start_idx:] + [neighbor]
                cycles.append(cycle)

        rec_stack.pop()

    for node in list(edges.keys()):
        if node not in visited:
            dfs(node)

    return cycles


def compute_max_chain_depth(
    edges: dict[str, list[str]],
    roots: list[str],
) -> tuple[int, list[str]]:
    """Compute the maximum transitive dependency chain depth from root nodes."""
    longest_path: list[str] = []

    def dfs(node: str, current_path: list[str], seen: set[str]) -> None:
        nonlocal longest_path
        if len(current_path) > len(longest_path):
            longest_path = list(current_path)

        for nxt in edges.get(node, []):
            if nxt not in seen:
                dfs(nxt, current_path + [nxt], seen | {nxt})

    for r in roots:
        dfs(r, [r], {r})

    depth = max(0, len(longest_path) - 1)
    return depth, longest_path


def _collect_local_modules(target_path: Path) -> set[str]:
    """Identify local package stems and filenames to detect shadowing."""
    local_mods: set[str] = set()
    for item in target_path.rglob("*"):
        if any(part in EXCLUDED_DIRS for part in item.parts):
            continue
        if item.is_file() and item.suffix in (".py", ".js", ".ts"):
            stem = item.stem.lower()
            if stem != "__init__":
                local_mods.add(stem)
        elif item.is_dir() and (item / "__init__.py").exists():
            local_mods.add(item.name.lower())
    return local_mods


def _discover_source_files(target_path: Path) -> list[Path]:
    """Find all Python, JavaScript, and TypeScript source files in project."""
    if target_path.is_file():
        if target_path.suffix in (".py", ".js", ".ts", ".mjs", ".cjs"):
            return [target_path]
        return []

    sources: list[Path] = []
    for item in target_path.rglob("*"):
        if any(part in EXCLUDED_DIRS for part in item.parts):
            continue
        if item.is_file() and item.suffix in (".py", ".js", ".ts", ".mjs", ".cjs"):
            sources.append(item)
    return sorted(sources)


def _discover_manifests(target_path: Path) -> list[Path]:
    """Find all dependency manifests and lockfiles in target directory."""
    if target_path.is_file():
        name = target_path.name.lower()
        if name.endswith((".txt", ".toml", ".json")) or "requirements" in name or "package" in name:
            return [target_path]
        return []

    manifests: list[Path] = []
    for item in target_path.rglob("*"):
        if any(part in EXCLUDED_DIRS for part in item.parts):
            continue
        if not item.is_file():
            continue
        name = item.name.lower()
        if name in (
            "requirements.txt",
            "requirements-dev.txt",
            "requirements.lock",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
            "dependency-graph.json",
        ) or (name.startswith("requirements") and name.endswith(".txt")):
            manifests.append(item)
    return sorted(manifests)


def analyze_project(target: Path | str) -> ScanTargetResult:
    """Analyze a project directory or manifest file for supply-chain risks."""
    target_path = Path(target).resolve()
    result = ScanTargetResult(target=str(target_path))

    if not target_path.exists():
        result.error_message = f"Target path '{target_path}' does not exist"
        return result

    manifest_files = _discover_manifests(target_path)
    source_files = _discover_source_files(target_path)

    result.manifests_scanned = len(manifest_files)
    result.source_files_scanned = len(source_files)

    # Parse all manifests and collect dependencies
    all_deps: list[DependencyInfo] = []
    dep_edges: dict[str, list[str]] = {}

    for m_path in manifest_files:
        m_name = m_path.name.lower()
        if m_name.endswith(".txt") or (m_name.endswith(".lock") and "package-lock" not in m_name):
            deps = parse_requirements_txt(m_path)
            all_deps.extend(deps)
        elif m_name == "pyproject.toml":
            all_deps.extend(parse_pyproject_toml(m_path))
        elif m_name == "package.json":
            all_deps.extend(parse_package_json(m_path))
        elif m_name == "package-lock.json":
            all_deps.extend(parse_package_lock_json(m_path))
        elif m_name == "dependency-graph.json":
            d_list, edges = parse_dependency_graph_json(m_path)
            all_deps.extend(d_list)
            dep_edges.update(edges)

    result.dependencies_count = len(all_deps)

    # Analyze all source files via AST
    all_imports: list[ImportReference] = []
    all_called_symbols: set[str] = set()
    all_sink_calls: list[SinkCall] = []

    for s_path in source_files:
        if s_path.suffix == ".py":
            imports, called, sinks = analyze_python_file(s_path)
        else:
            imports, called, sinks = analyze_js_file(s_path)
        all_imports.extend(imports)
        all_called_symbols.update(called)
        all_sink_calls.extend(sinks)

    local_modules = _collect_local_modules(
        target_path if target_path.is_dir() else target_path.parent
    )

    # Run Detection Rules LH-DEP-001 through LH-DEP-010
    findings: list[Finding] = []

    # 1. LH-DEP-001: Reachable dangerous sink call in module
    rule_001 = RULES_REGISTRY["LH-DEP-001"]
    for sink in all_sink_calls:
        findings.append(
            Finding(
                rule_id=rule_001.rule_id,
                severity=rule_001.severity,
                category=rule_001.category,
                title=rule_001.title,
                message=(
                    f"Dangerous sink '{sink.sink_type}' reached in '{Path(sink.source_file).name}' "
                    f"at line {sink.line_number}: {sink.argument_details}"
                ),
                target=sink.source_file,
                package_or_symbol=sink.sink_type,
                remediation=rule_001.remediation,
                reachability=ReachabilityStatus.REACHABLE,
                line_number=sink.line_number,
                metadata={"call_snippet": sink.call_snippet, "module": sink.caller_module},
            )
        )

    # Map imported modules and confirmed called modules
    imported_module_names: set[str] = set()
    called_module_names: set[str] = set()
    for imp in all_imports:
        m_name = imp.module_name.lower()
        imported_module_names.add(m_name)
        if imp.is_called:
            called_module_names.add(m_name)

    # 2. LH-DEP-002: Vulnerable dependency version with confirmed reachability
    rule_002 = RULES_REGISTRY["LH-DEP-002"]
    for dep in all_deps:
        norm_name = dep.name.lower()
        if norm_name in KNOWN_VULNERABLE_PACKAGES and dep.version:
            for vuln in KNOWN_VULNERABLE_PACKAGES[norm_name]:
                if _is_version_vulnerable(dep.version, vuln["max_version"]):
                    # Check reachability in source code
                    valid_import_names = {norm_name} | PACKAGE_ALIASES.get(norm_name, set())
                    is_imported = any(mod in imported_module_names for mod in valid_import_names)
                    is_called = any(mod in called_module_names for mod in valid_import_names)

                    if is_imported and is_called:
                        reach_status = ReachabilityStatus.REACHABLE
                    elif is_imported:
                        reach_status = ReachabilityStatus.POTENTIAL
                    else:
                        reach_status = ReachabilityStatus.UNREACHABLE

                    # If reachable or potentially reachable in code
                    if reach_status in (ReachabilityStatus.REACHABLE, ReachabilityStatus.POTENTIAL):
                        findings.append(
                            Finding(
                                rule_id=rule_002.rule_id,
                                severity=rule_002.severity,
                                category=rule_002.category,
                                title=rule_002.title,
                                message=(
                                    f"Vulnerable package '{dep.name}' version {dep.version} "
                                    f"({vuln['cve']}: {vuln['advisory']}) is confirmed "
                                    f"{reach_status.value} in source code."
                                ),
                                target=dep.manifest_file or str(target_path),
                                package_or_symbol=dep.name,
                                remediation=(
                                    f"Upgrade '{dep.name}' to >= {vuln['max_version']} "
                                    f"to patch {vuln['cve']}."
                                ),
                                reachability=reach_status,
                                line_number=dep.line_number,
                                metadata={
                                    "cve": vuln["cve"],
                                    "declared_version": dep.version,
                                    "patched_version": vuln["max_version"],
                                },
                            )
                        )

    # 3. LH-DEP-003: Unpinned or wildcard version specifier in production manifest
    rule_003 = RULES_REGISTRY["LH-DEP-003"]
    for dep in all_deps:
        # Ignore dev dependencies or already pinned versions
        if dep.is_dev or dep.is_pinned or dep.transitive:
            continue
        v_spec = dep.version_spec.strip()
        is_unpinned = False
        reason = ""

        if not v_spec or v_spec in ("*", "latest", ""):
            is_unpinned = True
            reason = "unversioned or wildcard '*' specifier"
        elif any(c in v_spec for c in ("*", "latest", "x")):
            is_unpinned = True
            reason = f"wildcard pattern '{v_spec}'"
        elif v_spec.startswith(">=") and not any(op in v_spec for op in ("<", "<=", ",")):
            is_unpinned = True
            reason = f"unbounded open range '{v_spec}'"

        if is_unpinned:
            findings.append(
                Finding(
                    rule_id=rule_003.rule_id,
                    severity=rule_003.severity,
                    category=rule_003.category,
                    title=rule_003.title,
                    message=(f"Package '{dep.name}' uses {reason} in production manifest."),
                    target=dep.manifest_file or str(target_path),
                    package_or_symbol=dep.name,
                    remediation=rule_003.remediation,
                    reachability=ReachabilityStatus.STATIC_DIRECT,
                    line_number=dep.line_number,
                    metadata={"version_spec": dep.version_spec},
                )
            )

    # 4. LH-DEP-004: Insecure URL or mutable VCS branch
    rule_004 = RULES_REGISTRY["LH-DEP-004"]
    for dep in all_deps:
        source_str = f"{dep.source_url or ''} {dep.version_spec}".strip()
        insecure_match = None

        if "http://" in source_str or "git+http://" in source_str:
            insecure_match = "plaintext HTTP repository source"
        elif any(
            branch in source_str.lower()
            for branch in ("@main", "@master", "@head", "@develop", "@trunk")
        ):
            # Check if an explicit 40-character commit hash is also present
            if not re.search(r"[a-f0-9]{40}", source_str):
                insecure_match = "mutable VCS branch without pinned commit SHA"

        if insecure_match:
            findings.append(
                Finding(
                    rule_id=rule_004.rule_id,
                    severity=rule_004.severity,
                    category=rule_004.category,
                    title=rule_004.title,
                    message=f"Package '{dep.name}' uses {insecure_match} ({source_str}).",
                    target=dep.manifest_file or str(target_path),
                    package_or_symbol=dep.name,
                    remediation=rule_004.remediation,
                    reachability=ReachabilityStatus.STATIC_DIRECT,
                    line_number=dep.line_number,
                    metadata={"source_details": source_str},
                )
            )

    # 5. LH-DEP-005: Dependency confusion or module shadowing risk
    rule_005 = RULES_REGISTRY["LH-DEP-005"]
    for dep in all_deps:
        norm_name = dep.name.lower()
        if norm_name in local_modules:
            findings.append(
                Finding(
                    rule_id=rule_005.rule_id,
                    severity=rule_005.severity,
                    category=rule_005.category,
                    title=rule_005.title,
                    message=(
                        f"Local module name '{norm_name}' collides with external declared package "
                        f"'{dep.name}', creating a module shadowing and hijacking risk."
                    ),
                    target=dep.manifest_file or str(target_path),
                    package_or_symbol=dep.name,
                    remediation=rule_005.remediation,
                    reachability=ReachabilityStatus.STATIC_DIRECT,
                    line_number=dep.line_number,
                    metadata={"colliding_module": norm_name},
                )
            )

    # 6. LH-DEP-006: Unused bloated dependency declared in manifest
    rule_006 = RULES_REGISTRY["LH-DEP-006"]
    if source_files:
        for dep in all_deps:
            if dep.is_dev or dep.transitive:
                continue
            norm_name = dep.name.lower()
            valid_names = {norm_name} | PACKAGE_ALIASES.get(norm_name, set())
            is_used = any(name in imported_module_names for name in valid_names)
            if not is_used:
                findings.append(
                    Finding(
                        rule_id=rule_006.rule_id,
                        severity=rule_006.severity,
                        category=rule_006.category,
                        title=rule_006.title,
                        message=(
                            f"Package '{dep.name}' is declared in manifest but never imported "
                            f"in any of the {len(source_files)} scanned source files."
                        ),
                        target=dep.manifest_file or str(target_path),
                        package_or_symbol=dep.name,
                        remediation=rule_006.remediation,
                        reachability=ReachabilityStatus.UNREACHABLE,
                        line_number=dep.line_number,
                    )
                )

    # 7. LH-DEP-007: Phantom or undeclared dependency imported in source code
    rule_007 = RULES_REGISTRY["LH-DEP-007"]
    declared_pkg_names: set[str] = set()
    for dep in all_deps:
        d_name = dep.name.lower()
        declared_pkg_names.add(d_name)
        declared_pkg_names.update(PACKAGE_ALIASES.get(d_name, set()))

    reported_phantoms: set[str] = set()
    for imp in all_imports:
        mod = imp.module_name.lower()
        if (
            mod in PY_STDLIB
            or mod in NODE_STDLIB
            or mod in local_modules
            or mod in declared_pkg_names
            or mod in reported_phantoms
        ):
            continue

        reported_phantoms.add(mod)
        findings.append(
            Finding(
                rule_id=rule_007.rule_id,
                severity=rule_007.severity,
                category=rule_007.category,
                title=rule_007.title,
                message=(
                    f"Third-party module '{mod}' is imported in '{Path(imp.source_file).name}' "
                    f"at line {imp.line_number} but is not declared in direct project manifests."
                ),
                target=imp.source_file,
                package_or_symbol=mod,
                remediation=rule_007.remediation,
                reachability=ReachabilityStatus.REACHABLE
                if imp.is_called
                else ReachabilityStatus.POTENTIAL,
                line_number=imp.line_number,
                metadata={"module": mod},
            )
        )

    # 8. LH-DEP-008: Circular dependency cycle or excessive graph depth (> 5 hops)
    rule_008 = RULES_REGISTRY["LH-DEP-008"]
    if dep_edges:
        cycles = detect_cycles(dep_edges)
        for cycle in cycles:
            cycle_str = " -> ".join(cycle)
            findings.append(
                Finding(
                    rule_id=rule_008.rule_id,
                    severity=rule_008.severity,
                    category=rule_008.category,
                    title=rule_008.title,
                    message=f"Circular dependency cycle detected: {cycle_str}",
                    target=str(target_path),
                    package_or_symbol=cycle[0],
                    remediation=rule_008.remediation,
                    reachability=ReachabilityStatus.STATIC_DIRECT,
                    metadata={"cycle": cycle},
                )
            )

        roots = [dep.name.lower() for dep in all_deps if not dep.transitive] or list(
            dep_edges.keys()
        )
        max_depth, chain = compute_max_chain_depth(dep_edges, roots)
        if max_depth > 5:
            chain_str = " -> ".join(chain)
            findings.append(
                Finding(
                    rule_id=rule_008.rule_id,
                    severity=rule_008.severity,
                    category=rule_008.category,
                    title=rule_008.title,
                    message=(
                        f"Excessive transitive dependency chain depth ({max_depth} hops > 5): "
                        f"{chain_str}"
                    ),
                    target=str(target_path),
                    package_or_symbol=chain[0],
                    remediation=rule_008.remediation,
                    reachability=ReachabilityStatus.STATIC_DIRECT,
                    metadata={"chain_depth": max_depth, "chain": chain},
                )
            )

    # 9. LH-DEP-009: Deprecated, abandoned, or insecure legacy package
    rule_009 = RULES_REGISTRY["LH-DEP-009"]
    for dep in all_deps:
        norm_name = dep.name.lower()
        if norm_name in DEPRECATED_PACKAGES:
            findings.append(
                Finding(
                    rule_id=rule_009.rule_id,
                    severity=rule_009.severity,
                    category=rule_009.category,
                    title=rule_009.title,
                    message=(
                        f"Project depends on legacy/insecure package '{dep.name}': "
                        f"{DEPRECATED_PACKAGES[norm_name]}"
                    ),
                    target=dep.manifest_file or str(target_path),
                    package_or_symbol=dep.name,
                    remediation=rule_009.remediation,
                    reachability=ReachabilityStatus.STATIC_DIRECT,
                    line_number=dep.line_number,
                    metadata={"deprecation_reason": DEPRECATED_PACKAGES[norm_name]},
                )
            )

    # 10. LH-DEP-010: Missing cryptographic integrity hashes in lockfile
    rule_010 = RULES_REGISTRY["LH-DEP-010"]
    for dep in all_deps:
        # Check lockfiles or pinned requirements acting as lockfile
        m_file = dep.manifest_file.lower()
        if ("lock" in m_file or "package-lock" in m_file) and not dep.hashes:
            findings.append(
                Finding(
                    rule_id=rule_010.rule_id,
                    severity=rule_010.severity,
                    category=rule_010.category,
                    title=rule_010.title,
                    message=(
                        f"Dependency '{dep.name}' in lockfile '{Path(dep.manifest_file).name}' "
                        f"is missing cryptographic integrity verification hashes."
                    ),
                    target=dep.manifest_file,
                    package_or_symbol=dep.name,
                    remediation=rule_010.remediation,
                    reachability=ReachabilityStatus.STATIC_DIRECT,
                    line_number=dep.line_number,
                )
            )

    result.findings = findings
    return result

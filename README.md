# lh-dependency-graph

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dependency-graph/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dependency-graph/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise supply chain & reachability analysis developed by **Logihertz Systems (OPC) Private Limited**.

Constructs Python AST import call graphs and cross-references lockfiles (requirements.txt, poetry.lock, uv.lock, package-lock.json) to determine whether vulnerable transitive dependencies are reachable at runtime.

---

## Key Features

- **AST Call-Graph Analysis**: Statically traces imported functions and modules through call graphs to determine whether vulnerable APIs are actually invoked.
- **Multi-Manifest Resolution**: Resolves direct and transitive dependencies across `requirements.txt`, `pyproject.toml`, and lockfiles.
- **Reachability-Based Prioritization**: Differentiates between dead/unreachable vulnerable dependencies and actively reachable exploits.
- **Cyclic & Deep Dependency Detection**: Flags circular dependencies and overly deep dependency chains exceeding maintainability thresholds.
- **Multi-Format Reporting**: Outputs colored terminal tables, dependency graph trees, JSON reports, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-DEP-001` | `CRITICAL` | Reachability Match: Vulnerable third-party function invoked directly in active code path |
| `LH-DEP-002` | `HIGH` | Unpinned transitive dependency with known high-severity vulnerability |
| `LH-DEP-003` | `HIGH` | Cyclic dependency detected between package components risking import deadlocks |
| `LH-DEP-004` | `MEDIUM` | Excessive dependency tree depth (> 7 levels) increasing supply chain attack surface |
| `LH-DEP-005` | `HIGH` | Deprecated or abandoned package dependency with no upstream releases > 24 months |
| `LH-DEP-006` | `MEDIUM` | Shadowed dependency namespace (local module name collides with installed package) |
| `LH-DEP-007` | `HIGH` | Multiple conflicting versions of identical dependency resolved in dependency tree |
| `LH-DEP-008` | `MEDIUM` | Unused direct dependency declared in manifest but never imported across codebase |
| `LH-DEP-009` | `LOW` | Permissive or floating version constraint (e.g., package>=1.0) allowing breaking upgrades |
| `LH-DEP-010` | `LOW` | Missing package metadata or unresolved repository homepage in lockfile |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dependency-graph.git
cd lh-dependency-graph

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-depgraph` (also accessible via `lh-depgraph`, `lh-dependency-graph`).

```bash
# Scan a repository for dependency graph and reachability
lh-depgraph scan ./src/

# Analyze requirements.txt against source code AST
lh-depgraph scan ./src/ --manifest requirements.txt

# Export findings to OASIS SARIF v2.1.0
lh-depgraph scan ./src/ --format sarif --output dep-graph.sarif

# Display all dependency graph rules
lh-depgraph rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).

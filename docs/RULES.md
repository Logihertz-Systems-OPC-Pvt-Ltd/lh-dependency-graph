# Security Rules Reference: lh-dependency-graph

An enterprise ast-driven dependency graph & reachability analyzer developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-dependency-graph`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-DEP-001` | `CRITICAL` | Reachability | Reachability Match: Vulnerable Function Invoked in Code Path |
| `LH-DEP-002` | `HIGH` | Vulnerability | Unpinned Transitive Dependency with Known High-Severity CVE |
| `LH-DEP-003` | `HIGH` | Graph Architecture | Cyclic Dependency Detected Between Package Components |
| `LH-DEP-004` | `MEDIUM` | Graph Architecture | Excessive Dependency Tree Depth Increasing Attack Surface |
| `LH-DEP-005` | `HIGH` | Maintenance | Deprecated or Abandoned Package Dependency |
| `LH-DEP-006` | `MEDIUM` | Namespace Hygiene | Shadowed Dependency Namespace Colliding with Local Module |
| `LH-DEP-007` | `HIGH` | Version Drift | Multiple Conflicting Versions of Identical Dependency |
| `LH-DEP-008` | `MEDIUM` | Dead Code | Unused Direct Dependency Declared in Manifest |
| `LH-DEP-009` | `LOW` | Supply Chain | Permissive or Floating Version Constraint in Direct Manifest |
| `LH-DEP-010` | `LOW` | Governance | Missing Package Metadata or Unresolved Repository Homepage |

---

## Granular Rule Specifications

### `LH-DEP-001`: Reachability Match: Vulnerable Function Invoked in Code Path

- **Severity**: `CRITICAL`
- **Category**: `Reachability`
- **Description**: Vulnerable third-party function or method invoked directly in active codebase call graph.
- **Remediation**: Upgrade dependency immediately to patched version or replace vulnerable function call.

---

### `LH-DEP-002`: Unpinned Transitive Dependency with Known High-Severity CVE

- **Severity**: `HIGH`
- **Category**: `Vulnerability`
- **Description**: Transitive dependency resolved with unpinned version matching active CVE advisory.
- **Remediation**: Pin transitive dependency in lockfile or upgrade direct parent dependency constraint.

---

### `LH-DEP-003`: Cyclic Dependency Detected Between Package Components

- **Severity**: `HIGH`
- **Category**: `Graph Architecture`
- **Description**: Circular dependency detected between package modules risking import deadlocks.
- **Remediation**: Refactor shared interfaces into independent utility module to break circular dependency.

---

### `LH-DEP-004`: Excessive Dependency Tree Depth Increasing Attack Surface

- **Severity**: `MEDIUM`
- **Category**: `Graph Architecture`
- **Description**: Dependency chain depth exceeds 7 transitive hops, increasing supply-chain exposure.
- **Remediation**: Prune redundant wrapper libraries and prefer lightweight direct standard library solutions.

---

### `LH-DEP-005`: Deprecated or Abandoned Package Dependency

- **Severity**: `HIGH`
- **Category**: `Maintenance`
- **Description**: Dependency has had no upstream release in > 24 months or is marked deprecated.
- **Remediation**: Replace abandoned dependency with actively maintained fork or modern alternative.

---

### `LH-DEP-006`: Shadowed Dependency Namespace Colliding with Local Module

- **Severity**: `MEDIUM`
- **Category**: `Namespace Hygiene`
- **Description**: Local module or file name collides with installed third-party package name.
- **Remediation**: Rename local module to avoid namespace collision and accidental package shadowing.

---

### `LH-DEP-007`: Multiple Conflicting Versions of Identical Dependency

- **Severity**: `HIGH`
- **Category**: `Version Drift`
- **Description**: Multiple conflicting versions of identical package resolved in dependency graph.
- **Remediation**: Harmonize version constraints across workspace projects to resolve single deterministic version.

---

### `LH-DEP-008`: Unused Direct Dependency Declared in Manifest

- **Severity**: `MEDIUM`
- **Category**: `Dead Code`
- **Description**: Direct dependency declared in requirements or pyproject but never imported in source.
- **Remediation**: Remove unused dependencies from manifest to reduce attack surface and build times.

---

### `LH-DEP-009`: Permissive or Floating Version Constraint in Direct Manifest

- **Severity**: `LOW`
- **Category**: `Supply Chain`
- **Description**: Version constraint uses floating wildcard (e.g. package>=1.0) allowing breaking changes.
- **Remediation**: Use strict version pinning or tilde/caret constraints with lockfile enforcement.

---

### `LH-DEP-010`: Missing Package Metadata or Unresolved Repository Homepage

- **Severity**: `LOW`
- **Category**: `Governance`
- **Description**: Package entry in lockfile lacks author, license, or verified repository homepage URL.
- **Remediation**: Verify package provenance against PyPI and document upstream repository location.

---

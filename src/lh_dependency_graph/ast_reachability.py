# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        src.lh_dependency_graph.ast_reachability
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""AST call-graph and import reachability analyzer for Python and JavaScript/TypeScript.

Inspects source code for imported third-party modules, confirmed call paths,
and dangerous sinks (e.g. yaml.load without SafeLoader, pickle, subprocess shell=True, eval).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from lh_dependency_graph.models import ImportReference, SinkCall

SAFE_LOADERS = ("safeloader", "csafeloader", "baseloader")


class PythonSourceVisitor(ast.NodeVisitor):
    """AST visitor traversing Python source for imports, function calls, and dangerous sinks."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.imports: list[ImportReference] = []
        # Map alias or imported name to original module/symbol: alias -> (module, symbol)
        self.alias_map: dict[str, tuple[str, str | None]] = {}
        self.called_symbols: set[str] = set()
        self.sink_calls: list[SinkCall] = []

    def visit_Import(self, node: ast.Import) -> None:
        """Handle 'import foo' or 'import foo.bar as fb'."""
        for alias in node.names:
            top_mod = alias.name.split(".")[0]
            name_used = alias.asname or alias.name
            self.alias_map[name_used] = (alias.name, None)
            self.imports.append(
                ImportReference(
                    module_name=top_mod,
                    imported_symbol=None,
                    alias=alias.asname,
                    source_file=self.file_path,
                    line_number=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Handle 'from foo import bar as b'."""
        if not node.module:
            self.generic_visit(node)
            return

        top_mod = node.module.split(".")[0]
        for alias in node.names:
            name_used = alias.asname or alias.name
            self.alias_map[name_used] = (top_mod, alias.name)
            self.imports.append(
                ImportReference(
                    module_name=top_mod,
                    imported_symbol=alias.name,
                    alias=alias.asname,
                    source_file=self.file_path,
                    line_number=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect calls for third-party invocations and dangerous sinks."""
        func_name, full_path = self._resolve_call_target(node.func)

        if func_name:
            self.called_symbols.add(func_name)
        if full_path:
            self.called_symbols.add(full_path)

        # Check for dangerous sinks
        self._check_dangerous_sinks(node, func_name, full_path)
        self.generic_visit(node)

    def _resolve_call_target(self, func_node: ast.expr) -> tuple[str, str]:
        """Resolve func AST node to base name and full attribute path."""
        parts: list[str] = []
        curr: Any = func_node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value

        if isinstance(curr, ast.Name):
            base = curr.id
            parts.append(base)
            parts.reverse()
            full_path = ".".join(parts)

            # Map alias if known
            if base in self.alias_map:
                mod, sym = self.alias_map[base]
                if len(parts) > 1:
                    resolved_path = f"{mod}.{'.'.join(parts[1:])}"
                elif sym:
                    resolved_path = f"{mod}.{sym}"
                else:
                    resolved_path = mod
                return base, resolved_path

            return base, full_path

        return "", ""

    def _check_dangerous_sinks(
        self,
        node: ast.Call,
        base_name: str,
        full_path: str,
    ) -> None:
        """Detect known unsafe deserialization, execution, or injection sinks."""
        snippet = f"{full_path}(...)"

        # 1. yaml.load without SafeLoader
        if full_path in ("yaml.load", "ruamel.yaml.load") or (
            base_name == "load" and "yaml" in self.alias_map.get(base_name, ("", ""))[0]
        ):
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_val = ast.unparse(kw.value).lower()
                    if any(s in loader_val for s in SAFE_LOADERS):
                        has_safe_loader = True
                        break
            if not has_safe_loader:
                self.sink_calls.append(
                    SinkCall(
                        sink_type="yaml.load",
                        caller_module="yaml",
                        source_file=self.file_path,
                        line_number=node.lineno,
                        call_snippet=snippet,
                        argument_details="Missing or unsafe Loader parameter in yaml.load",
                    )
                )

        elif full_path == "yaml.unsafe_load":
            self.sink_calls.append(
                SinkCall(
                    sink_type="yaml.unsafe_load",
                    caller_module="yaml",
                    source_file=self.file_path,
                    line_number=node.lineno,
                    call_snippet=snippet,
                    argument_details="Explicit call to yaml.unsafe_load",
                )
            )

        # 2. pickle.loads / pickle.load
        elif any(
            full_path.startswith(prefix)
            for prefix in ("pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads")
        ):
            self.sink_calls.append(
                SinkCall(
                    sink_type="pickle.loads",
                    caller_module="pickle",
                    source_file=self.file_path,
                    line_number=node.lineno,
                    call_snippet=snippet,
                    argument_details="Unvalidated arbitrary object deserialization via pickle",
                )
            )

        # 3. marshal.loads / marshal.load
        elif any(full_path.startswith(prefix) for prefix in ("marshal.load", "marshal.loads")):
            self.sink_calls.append(
                SinkCall(
                    sink_type="marshal.loads",
                    caller_module="marshal",
                    source_file=self.file_path,
                    line_number=node.lineno,
                    call_snippet=snippet,
                    argument_details="Unsafe code/object deserialization via marshal",
                )
            )

        # 4. subprocess with shell=True
        elif any(
            full_path.startswith(prefix)
            for prefix in (
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
            )
        ):
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.sink_calls.append(
                            SinkCall(
                                sink_type="subprocess.shell",
                                caller_module="subprocess",
                                source_file=self.file_path,
                                line_number=node.lineno,
                                call_snippet=snippet,
                                argument_details="Subprocess spawned with shell=True enabled",
                            )
                        )

        # 5. eval / exec
        elif base_name in ("eval", "exec"):
            self.sink_calls.append(
                SinkCall(
                    sink_type=base_name,
                    caller_module="builtins",
                    source_file=self.file_path,
                    line_number=node.lineno,
                    call_snippet=snippet,
                    argument_details=f"Dynamic evaluation sink '{base_name}' invoked",
                )
            )

        # 6. Unsafe XML parsing (xml.etree, xml.dom.minidom)
        elif (
            any(prefix in full_path for prefix in ("xml.etree", "xml.dom", "xml.sax"))
            and any(fn in full_path for fn in ("parse", "fromstring", "parseString"))
        ) or (
            base_name in ("fromstring", "parse", "parseString")
            and "xml" in self.alias_map.get(base_name, ("", ""))[0]
        ):
            self.sink_calls.append(
                SinkCall(
                    sink_type="xml.unsafe_parse",
                    caller_module="xml",
                    source_file=self.file_path,
                    line_number=node.lineno,
                    call_snippet=snippet,
                    argument_details=(
                        "Standard library XML parser vulnerable to XXE / entity expansion"
                    ),
                )
            )


def analyze_python_file(path: Path) -> tuple[list[ImportReference], set[str], list[SinkCall]]:
    """Parse and inspect a Python file via AST."""
    try:
        content = path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(path))
    except Exception:
        return [], set(), []

    visitor = PythonSourceVisitor(file_path=str(path))
    visitor.visit(tree)

    # Mark imports as called if their module or symbol was invoked
    for imp in visitor.imports:
        mod_name = imp.module_name
        alias = imp.alias or mod_name
        sym = imp.imported_symbol
        if (
            alias in visitor.called_symbols
            or mod_name in visitor.called_symbols
            or (sym and sym in visitor.called_symbols)
        ):
            imp.is_called = True

    return visitor.imports, visitor.called_symbols, visitor.sink_calls


def analyze_js_file(path: Path) -> tuple[list[ImportReference], set[str], list[SinkCall]]:
    """Parse and inspect JavaScript/TypeScript files via regex scanning."""
    imports: list[ImportReference] = []
    called_symbols: set[str] = set()
    sink_calls: list[SinkCall] = []

    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return imports, called_symbols, sink_calls

    lines = content.splitlines()

    # Regex for ES imports: import ... from 'package'
    es_import_re = re.compile(
        r"""import\s+(?:(?:\*\s+as\s+(\w+)|([\w,\s{}]+))\s+from\s+)?['"]([^'"]+)['"]"""
    )
    # Regex for CommonJS: const ... = require('package')
    cjs_require_re = re.compile(
        r"""(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    )

    for idx, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith(("//", "/*", "*")):
            continue

        # ES imports
        es_match = es_import_re.search(s)
        if es_match:
            pkg = es_match.group(3)
            # Ignore relative imports
            if not pkg.startswith("."):
                pkg_clean = (
                    pkg.split("/")[0] if not pkg.startswith("@") else "/".join(pkg.split("/")[:2])
                )
                imports.append(
                    ImportReference(
                        module_name=pkg_clean,
                        source_file=str(path),
                        line_number=idx,
                    )
                )

        # CommonJS require
        cjs_match = cjs_require_re.search(s)
        if cjs_match:
            var_name = cjs_match.group(1)
            pkg = cjs_match.group(2)
            if not pkg.startswith("."):
                pkg_clean = (
                    pkg.split("/")[0] if not pkg.startswith("@") else "/".join(pkg.split("/")[:2])
                )
                imports.append(
                    ImportReference(
                        module_name=pkg_clean,
                        alias=var_name,
                        source_file=str(path),
                        line_number=idx,
                    )
                )

        # Dangerous sinks in JS: eval(...), child_process.exec(...)
        if "eval(" in s:
            sink_calls.append(
                SinkCall(
                    sink_type="eval",
                    caller_module="global",
                    source_file=str(path),
                    line_number=idx,
                    call_snippet=s[:60],
                    argument_details="Dynamic eval() invoked in JavaScript/TypeScript",
                )
            )

        if "exec(" in s and any(k in content for k in ("child_process", "exec")):
            sink_calls.append(
                SinkCall(
                    sink_type="child_process.exec",
                    caller_module="child_process",
                    source_file=str(path),
                    line_number=idx,
                    call_snippet=s[:60],
                    argument_details="Command execution sink child_process.exec invoked",
                )
            )

    return imports, called_symbols, sink_calls

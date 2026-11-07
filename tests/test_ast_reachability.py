# ==============================================================================
# Product:       lh-dependency-graph (lh-depgraph)
# Module:        tests.test_ast_reachability
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for AST call reachability and dangerous sink analyzers.

Validates detection of imported symbols, active call paths, and dangerous sinks
in Python and JavaScript/TypeScript source code.
"""

from __future__ import annotations

from pathlib import Path

from lh_dependency_graph.ast_reachability import analyze_js_file, analyze_python_file


def test_python_ast_imports_and_calls(tmp_path: Path) -> None:
    """Test tracking imports, aliases, and confirmed call reachability in Python."""
    py_file = tmp_path / "script.py"
    py_file.write_text(
        """import requests as req
from os import environ
import json

def fetch():
    data = req.get('https://example.com')
    env_val = environ.get('KEY')
    return data, env_val
""",
        encoding="utf-8",
    )

    imports, called, sinks = analyze_python_file(py_file)
    assert len(imports) == 3
    assert len(sinks) == 0

    req_imp = next(i for i in imports if i.module_name == "requests")
    assert req_imp.alias == "req"
    assert req_imp.is_called is True

    json_imp = next(i for i in imports if i.module_name == "json")
    assert json_imp.is_called is False


def test_python_ast_dangerous_sinks(tmp_path: Path) -> None:
    """Test AST detection of dangerous deserialization, subprocess, and dynamic sinks."""
    py_file = tmp_path / "sinks.py"
    py_file.write_text(
        """import yaml
import pickle
import marshal
import subprocess
import xml.etree.ElementTree as ET

def process(payload, cmd):
    # Unsafe yaml.load
    yaml.load(payload)
    # Safe yaml.load with SafeLoader
    yaml.load(payload, Loader=yaml.SafeLoader)
    # Unsafe pickle
    pickle.loads(payload)
    # Unsafe marshal
    marshal.loads(payload)
    # Subprocess with shell=True
    subprocess.run(cmd, shell=True)
    # Subprocess without shell
    subprocess.run(["echo", "hello"], shell=False)
    # Eval
    eval(cmd)
    # XML parse
    ET.fromstring(payload)
""",
        encoding="utf-8",
    )

    imports, called, sinks = analyze_python_file(py_file)
    sink_types = [s.sink_type for s in sinks]

    assert "yaml.load" in sink_types
    # Safe yaml.load with Loader=SafeLoader must not be added
    assert sink_types.count("yaml.load") == 1
    assert "pickle.loads" in sink_types
    assert "marshal.loads" in sink_types
    assert "subprocess.shell" in sink_types
    assert "eval" in sink_types
    assert "xml.unsafe_parse" in sink_types


def test_js_ast_imports_and_sinks(tmp_path: Path) -> None:
    """Test JavaScript/TypeScript imports and sink analysis."""
    js_file = tmp_path / "index.js"
    js_file.write_text(
        """import express from 'express';
const lodash = require('lodash');
const child_process = require('child_process');

eval("console.log(1)");
child_process.exec("rm -rf /");
""",
        encoding="utf-8",
    )

    imports, called, sinks = analyze_js_file(js_file)
    mod_names = [i.module_name for i in imports]

    assert "express" in mod_names
    assert "lodash" in mod_names
    assert "child_process" in mod_names

    sink_types = [s.sink_type for s in sinks]
    assert "eval" in sink_types
    assert "child_process.exec" in sink_types


def test_ast_syntax_error_handling(tmp_path: Path) -> None:
    """Test graceful handling of files with syntax errors."""
    broken_py = tmp_path / "broken.py"
    broken_py.write_text("def invalid_syntax(:", encoding="utf-8")

    imports, called, sinks = analyze_python_file(broken_py)
    assert imports == []
    assert called == set()
    assert sinks == []

"""
Guards on the test suite itself.

A test module that defines the same test name twice keeps only the last one:
Python rebinds the name, pytest collects one function, and the first test
silently never runs. That happened once (`test_the_finding_cites_every_hop`,
permission management v2's citation test, shadowed by the attack-path one),
and nothing failed -- which is the problem.
"""

import ast
from collections import Counter
from pathlib import Path

TESTS = Path(__file__).parent


def test_no_test_module_defines_a_test_twice():
    duplicates = {}
    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = Counter(
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        )
        repeated = sorted(name for name, n in names.items() if n > 1)
        if repeated:
            duplicates[path.name] = repeated
    assert duplicates == {}


def test_graph_layer_imports_only_downward():
    """
    app/graph/ sits between models and risk, and stays interpretation-free:
    it never imports the risk layer, the normalizer or a connector. Judgements
    about sensitivity, crown jewels and findings live in app/risk/.
    """
    graph = TESTS.parent / "app" / "graph"
    upward = ("app.risk", "app.normalize", "app.connectors")
    offenders = []
    for path in sorted(graph.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(upward):
                offenders.append((path.name, node.module))
            elif isinstance(node, ast.Import):
                offenders += [(path.name, a.name) for a in node.names if a.name.startswith(upward)]
    assert offenders == []

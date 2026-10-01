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

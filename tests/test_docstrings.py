"""Every function and class has a docstring, private and nested ones too.

That holds for the package and for the tests' helpers, fixtures and fakes; a
``test_*`` function is exempt, since its name already reads as a sentence.

pydocstyle (the hook) checks the docstrings' style, but asks for one only on public
names: a ``_helper`` or a function inside another goes unchecked. This test asks
for one everywhere.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "pgsesame"
TESTS = ROOT / "tests"


def _missing(directory, exempt=lambda name: False):
    """Return ``path:line name`` for each function and class without a docstring."""
    missing = []
    for path in sorted(directory.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if ast.get_docstring(node) is None and not exempt(node.name):
                    where = path.relative_to(directory.parent)
                    missing.append(f"{where}:{node.lineno} {node.name}")
    return missing


def test_every_function_and_class_has_a_docstring():
    missing = _missing(SRC)
    assert not missing, "no docstring:\n" + "\n".join(missing)


def test_every_test_helper_has_a_docstring():
    missing = _missing(TESTS, exempt=lambda name: name.startswith("test_"))
    assert not missing, "no docstring:\n" + "\n".join(missing)

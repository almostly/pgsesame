"""Every function and class in the package has a docstring, private and nested ones too.

pydocstyle (the hook) checks the docstrings' style, but asks for one only on public
names: a ``_helper`` or a function inside another goes unchecked. This test asks
for one everywhere.
"""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "pgsesame"


def test_every_function_and_class_has_a_docstring():
    missing = []
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if ast.get_docstring(node) is None:
                    missing.append(
                        f"{path.relative_to(SRC.parent)}:{node.lineno} {node.name}"
                    )
    assert not missing, "no docstring:\n" + "\n".join(missing)

"""Names with a dot in them: quoted where a dot would cut them, and only there."""

import pytest

from pgsesame.state import parent, qualify, schema_of, split


@pytest.mark.parametrize(
    ("name", "parts"),
    [
        ("public.todos", ["public", "todos"]),
        ('userrisk_dwh."roll rates.csv"', ["userrisk_dwh", "roll rates.csv"]),
        ('"a.b".t.c', ["a.b", "t", "c"]),
        ('s."say ""hi""".c', ["s", 'say "hi"', "c"]),
        ("public.f(public.money, int)", ["public", "f(public.money, int)"]),
        ("s.*", ["s", "*"]),
    ],
)
def test_a_name_splits_where_a_dot_is_not_quoted(name, parts):
    assert split(name) == parts
    if "(" not in name:
        assert qualify(*parts) == name


def test_only_a_part_a_dot_or_quote_would_break_is_quoted():
    assert qualify("Public", "Daily Sales") == "Public.Daily Sales"
    assert qualify("s", "roll rates.csv", "month") == 's."roll rates.csv".month'
    assert schema_of('"a.b".t') == "a.b"
    assert parent('s."roll rates.csv".month') == 's."roll rates.csv"'

"""Spec loading and validation (no database)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from pgsesame import spec
from pgsesame.cli import app

EXAMPLE = Path(__file__).parents[1] / "examples" / "redshift.yaml"


def _parse(**overrides):
    raw = {"version": 1, "engine": "postgres", "principals": {}}
    raw.update(overrides)
    return spec.parse(raw)


def _problems(**overrides) -> list[str]:
    with pytest.raises(spec.SpecError) as err:
        _parse(**overrides)
    return err.value.problems


def test_the_example_is_valid():
    loaded = spec.load(EXAMPLE)
    assert loaded.engine == "redshift"
    alice = loaded.principals["alice"]
    assert (alice.type, alice.can_login, alice.groups) == ("user", True, ["analysts"])
    assert loaded.principals["etl"].password == "disabled"
    assert loaded.default_privileges[0].grants() == {"tables": ["select"]}
    assert loaded.default_privileges[0].in_schema == "analytics"


def test_users_log_in_and_roles_do_not_by_default():
    loaded = _parse(principals={"u": {"type": "user"}, "r": {"type": "role"}})
    assert loaded.principals["u"].can_login and not loaded.principals["r"].can_login


def test_every_structural_problem_is_reported_with_its_path():
    problems = _problems(
        engine="mysql",
        colour="blue",
        principals={"a": {"type": "role", "nickname": "x"}, "b": {"type": "admin"}},
    )
    assert "colour: unknown key" in problems
    assert any(p.startswith("engine:") for p in problems)
    assert "principals.a.nickname: unknown key" in problems
    assert any(p.startswith("principals.b.type:") for p in problems)
    assert any(p.startswith("version:") for p in _problems(version=2))


def test_every_reference_problem_is_reported_once_the_structure_is_valid():
    problems = _problems(
        principals={
            "a": {"type": "role", "member_of": ["ghost"]},
            "b": {"type": "user", "member_of": ["phantom"]},
        }
    )
    assert problems == [
        "principals.a.member_of: ghost is not declared",
        "principals.b.member_of: phantom is not declared",
    ]


def test_groups_are_redshift_only():
    problems = _problems(principals={"g": {"type": "group"}})
    assert problems == ["principals.g.type: groups exist on Redshift only"]


def test_privileges_are_checked_per_engine():
    redshift_only = {"type": "role", "privileges": {"tables": {"alter": ["s.t"]}}}
    assert _problems(principals={"r": redshift_only})[0].startswith(
        "principals.r.privileges.tables.alter: not a postgres privilege"
    )
    loaded = _parse(engine="redshift", principals={"r": redshift_only})
    assert loaded.principals["r"].privileges == {"tables": {"alter": ["s.t"]}}


def test_passwords_never_go_in_the_spec():
    problems = _problems(principals={"u": {"type": "user", "password": "hunter2"}})
    assert problems[0].startswith("principals.u.password: input should be 'disabled'")


def test_membership_in_a_group_goes_through_groups():
    problems = _problems(
        engine="redshift",
        principals={"g": {"type": "group"}, "u": {"type": "user", "member_of": ["g"]}},
    )
    assert problems == ["principals.u.member_of: g is a group; use groups"]


def test_default_privileges_name_declared_principals():
    problems = _problems(
        principals={"etl": {"type": "user"}},
        default_privileges=[
            {"owner": "etl", "grantee": "nobody", "tables": ["select"]}
        ],
    )
    assert problems == ["default_privileges[0].grantee: nobody is not declared"]


def test_default_privileges_name_real_privileges():
    problems = _problems(
        principals={"etl": {"type": "user"}},
        default_privileges=[{"owner": "etl", "grantee": "etl", "tables": ["fly"]}],
    )
    assert problems[0].startswith("default_privileges.0.tables.0: input should be")
    # a privilege that exists, but not on this engine, is caught by the second pass
    problems = _problems(
        principals={"etl": {"type": "user"}},
        default_privileges=[{"owner": "etl", "grantee": "etl", "tables": ["alter"]}],
    )
    assert problems == [
        "default_privileges[0].tables: alter is not a postgres privilege on tables"
    ]


@pytest.mark.parametrize(
    ("principal", "where"),
    [
        ({"type": "user", "password_env": "ALICE PW"}, "principals.u.password_env"),
        (
            {"type": "role", "privileges": {"tables": {"select": ["a.b.c.d"]}}},
            "principals.u.privileges.tables.select.0",
        ),
        (
            {"type": "role", "privileges": {"tables": {"fly": ["a.b"]}}},
            "principals.u.privileges.tables.fly",
        ),
        ({"type": "role", "member_of": [""]}, "principals.u.member_of.0"),
    ],
)
def test_malformed_values_are_stopped_at_the_edge(principal, where):
    problems = _problems(principals={"u": principal})
    assert len(problems) == 1 and problems[0].startswith(f"{where}: ")


def test_names_are_held_to_the_engines_limit():
    long_name = "r" * 64
    problems = _problems(principals={long_name: {"type": "role"}})
    assert problems == [f"principals.{long_name}: longer than postgres's 63 bytes"]
    _parse(engine="redshift", principals={long_name: {"type": "role"}})  # fine there


def test_cli_validate():
    runner = CliRunner()
    ok = runner.invoke(app, ["validate", str(EXAMPLE)])
    assert ok.exit_code == 0 and "valid redshift spec" in ok.output


def test_the_json_schema_describes_the_spec():
    schema = spec.json_schema()
    assert schema["title"] == "pgsesame spec"
    principal = schema["$defs"]["Principal"]
    assert principal["additionalProperties"] is False
    assert "schema" in schema["$defs"]["DefaultPrivilege"]["properties"]


def test_masking_is_checked_whole():
    principals = {"support": {"type": "role"}, "analysts": {"type": "group"}}
    problems = _problems(
        engine="redshift",
        principals=principals,
        masking={
            "policies": {
                "sesame_unmasked_x": {"type": "int", "using": "0"},
                "both": {"type": "int", "input": {"a": "int"}, "using": "a"},
                "pair": {"input": {"a": "int", "b": "int"}, "using": "a + b"},
            },
            "columns": {
                "s.t.a": {"unmasked": ["support"]},
                "s.t.b": {"mask": "pair", "roles": {"analysts": "missing"}},
                "s.t.c": {
                    "mask": "pair",
                    "unmasked": ["support"],
                    "roles": {"support": "pair"},
                    "inputs": ["x", "y"],
                },
            },
        },
    )
    assert problems == [
        "masking.policies.sesame_unmasked_x: sesame_unmasked_* names are pgsesame's own",
        "masking.policies.both: give type (one input) or input (several)",
        "masking.columns.s.t.a.unmasked: there's no mask to see past",
        "masking.columns.s.t.b.inputs: pair reads 2 columns; list them in inputs",
        "masking.columns.s.t.b.roles.analysts: missing is not a declared policy",
        "masking.columns.s.t.b.roles: analysts is a group; Redshift masks for users "
        "and roles only",
        "masking.columns.s.t.c: support can't be both unmasked and masked",
    ]


def test_masking_is_redshifts():
    problems = _problems(masking={"policies": {}, "columns": {}})
    assert problems == [
        "masking: dynamic data masking is Redshift's; on PostgreSQL use column privileges"
    ]


def test_a_masking_type_is_a_type_not_sql():
    problems = _problems(
        engine="redshift",
        masking={"policies": {"p": {"type": "int); drop table x; --", "using": "1"}}},
    )
    assert problems[0].startswith("masking.policies.p.type: string should match")


def test_column_privileges_name_columns():
    problems = _problems(
        principals={
            "u": {
                "type": "role",
                "owns": {"columns": ["s.t.c"]},
                "privileges": {
                    "columns": {
                        "select": ["s.t", "s.*", "s.t.c"],
                        "truncate": ["s.t.c"],
                    },
                    "tables": {"select": ["s.t.c"]},
                },
            }
        }
    )
    assert problems == [
        "principals.u.owns.columns: a column is owned with its table",
        "principals.u: s.t: a column is schema.table.column",
        "principals.u: s.*: a column is schema.table.column",
        "principals.u: s.t.c: three parts name a column (use columns)",
        "principals.u.privileges.columns.truncate: not a postgres privilege on columns "
        "(insert, references, select, update)",
    ]


def test_redshift_grants_select_and_update_on_columns():
    problems = _problems(
        engine="redshift",
        principals={
            "u": {"type": "role", "privileges": {"columns": {"insert": ["s.t.c"]}}}
        },
    )
    assert problems == [
        "principals.u.privileges.columns.insert: not a redshift privilege on columns "
        "(select, update)"
    ]


def test_a_policy_for_public_names_no_other_role():
    problems = _problems(
        principals={"r": {"type": "role"}},
        row_level_security={
            "s.t": {"policies": {"p": {"to": ["r", "public"], "using": "true"}}}
        },
    )
    assert problems == [
        "row_level_security.s.t.policies.p.to: public covers every role; list it alone"
    ]

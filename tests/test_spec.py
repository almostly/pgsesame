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


def test_default_privileges_name_declared_principals_and_real_privileges():
    problems = _problems(
        principals={"etl": {"type": "user"}},
        default_privileges=[{"owner": "etl", "grantee": "nobody", "tables": ["fly"]}],
    )
    assert "default_privileges[0].grantee: nobody is not declared" in problems
    assert any("fly is not a postgres privilege" in p for p in problems)


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

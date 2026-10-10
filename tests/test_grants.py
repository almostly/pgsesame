"""sesame grants: the spec's grants as rows, for tools that rebuild tables (no database)."""

import csv
import io
import json

from typer.testing import CliRunner

from pgsesame import grants, spec
from pgsesame.cli import app

SPEC = {
    "version": 1,
    "engine": "redshift",
    "principals": {
        "analysts": {
            "type": "group",
            "privileges": {
                "schemas": {"usage": ["bianalytics"]},
                "tables": {"select": ["bianalytics.*", "funnels.steps"]},
            },
        },
        "lidris": {
            "type": "user",
            "privileges": {
                "tables": {"select": ["bianalytics.loans"]},
                "columns": {"select": ["bianalytics.loans.amount"]},
            },
        },
        "sys:secadmin": {
            "type": "builtin",
            "privileges": {"tables": {"select": ["funnels.steps"]}},
        },
    },
}


def test_every_grant_is_a_row_with_schema_star_kept():
    found = grants.rows(spec.parse(SPEC))
    assert [
        (r.object_type, r.schema, r.object, r.privilege, r.grantee) for r in found
    ] == [
        ("columns", "bianalytics", "loans", "select", "lidris"),
        ("schemas", "bianalytics", "bianalytics", "usage", "analysts"),
        ("tables", "bianalytics", "*", "select", "analysts"),
        ("tables", "bianalytics", "loans", "select", "lidris"),
        ("tables", "funnels", "steps", "select", "analysts"),
        ("tables", "funnels", "steps", "select", "sys:secadmin"),
    ]
    kinds = {r.grantee: r.grantee_type for r in found}
    assert kinds == {"analysts": "group", "lidris": "user", "sys:secadmin": "role"}


def test_one_object_gets_its_own_rows_and_its_schemas_star():
    found = grants.rows(spec.parse(SPEC), "bianalytics.loans")
    assert [(r.object, r.column, r.grantee) for r in found] == [
        ("loans", "amount", "lidris"),
        ("*", "", "analysts"),
        ("loans", "", "lidris"),
    ]
    assert grants.rows(spec.parse(SPEC), "bianalytics.other")[0].object == "*"
    assert grants.rows(spec.parse(SPEC), "nowhere.t") == []


def test_on_postgresql_every_grantee_is_a_role():
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {
                "app": {"type": "user", "privileges": {"tables": {"select": ["s.t"]}}}
            },
        }
    )
    assert [r.grantee_type for r in grants.rows(loaded)] == ["role"]


def test_the_command_writes_json_or_csv(tmp_path):
    import yaml

    path = tmp_path / "spec.yaml"
    path.write_text(yaml.safe_dump(SPEC))
    runner = CliRunner()
    result = runner.invoke(app, ["grants", str(path), "--object", "funnels.steps"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == [
        {
            "object_type": "tables",
            "schema": "funnels",
            "object": "steps",
            "column": "",
            "privilege": "select",
            "grantee": "analysts",
            "grantee_type": "group",
        },
        {
            "object_type": "tables",
            "schema": "funnels",
            "object": "steps",
            "column": "",
            "privilege": "select",
            "grantee": "sys:secadmin",
            "grantee_type": "role",
        },
    ]
    result = runner.invoke(app, ["grants", str(path), "--format", "csv"])
    assert result.exit_code == 0, result.output
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    assert len(rows) == 6 and rows[0]["grantee"] == "lidris"
    bad = runner.invoke(app, ["grants", str(path), "--object", "loans"])
    assert bad.exit_code == 1 and "schema.table" in bad.output


def test_public_is_its_own_grantee_type():
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "redshift",
            "principals": {
                "public": {
                    "type": "builtin",
                    "privileges": {"tables": {"select": ["s.t"]}},
                }
            },
        }
    )
    (row,) = grants.rows(loaded)
    assert (row.grantee, row.grantee_type) == ("public", "public")

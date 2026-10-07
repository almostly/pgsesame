"""plan and apply against Redshift: oblako's redshift-local, or Amazon Redshift.

Set ``PGSESAME_TEST_REDSHIFT_DSN`` to a superuser connection; the tests skip
without it. For oblako's redshift-local:

    PGSESAME_TEST_REDSHIFT_DSN="host=localhost port=5439 user=oblako \\
        password=oblako dbname=oblako sslmode=require"

Every user, group and role the tests make is named ``rs_test_*`` and their objects
live in the schema ``rs_test``; all of it is dropped before and after each test.
"""

import os
import textwrap

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from typer.testing import CliRunner

from pgsesame.cli import app

DSN = os.environ.get("PGSESAME_TEST_REDSHIFT_DSN", "")
P = "rs_test_"
pytestmark = [
    pytest.mark.redshift,
    pytest.mark.skipif(
        not DSN, reason="set PGSESAME_TEST_REDSHIFT_DSN to run against Redshift"
    ),
]

SPEC = f"""
version: 1
engine: redshift
principals:
  {P}reader:
    type: role
    privileges:
      schemas:
        usage: [rs_test]
      tables:
        select: [rs_test.*]
  {P}writer:
    type: role
    member_of: [{P}reader]
    privileges:
      tables:
        insert: [rs_test.events]
  {P}analysts:
    type: group
    privileges:
      schemas:
        usage: [rs_test]
      tables:
        select: [rs_test.daily]
  {P}alice:
    type: user
    password_env: RS_TEST_ALICE_PASSWORD
    member_of: [{P}writer]
    groups: [{P}analysts]
    privileges:
      tables:
        update: [rs_test.daily]
"""


def _cleanup(conn: psycopg.Connection) -> None:
    conn.execute("DROP SCHEMA IF EXISTS rs_test CASCADE")
    users = conn.execute(
        "SELECT usename FROM pg_user WHERE usename LIKE 'rs\\_test\\_%'"
    ).fetchall()
    groups = conn.execute(
        "SELECT groname FROM pg_catalog.pg_group WHERE groname LIKE 'rs\\_test\\_%'"
    ).fetchall()
    roles = conn.execute(
        "SELECT role_name FROM svv_roles WHERE role_name LIKE 'rs\\_test\\_%'"
    ).fetchall()
    for template, rows in (
        ("DROP USER {}", users),
        ("DROP GROUP {}", groups),
        ("DROP ROLE {} FORCE", roles),
    ):
        for (name,) in rows:
            statement = sql.SQL(template).format(sql.Identifier(name))
            try:
                conn.execute(statement)
            except psycopg.Error:  # redshift-local's DROP ROLE has no FORCE
                if template.endswith("FORCE"):
                    conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))
                else:
                    raise


@pytest.fixture
def dsn():
    with psycopg.connect(DSN, autocommit=True) as conn:
        _cleanup(conn)
        conn.execute("CREATE SCHEMA rs_test")
        conn.execute("CREATE TABLE rs_test.events (id int)")
        conn.execute("CREATE TABLE rs_test.daily (day date)")
        yield DSN
        _cleanup(conn)


def _spec(tmp_path, text=SPEC):
    path = tmp_path / "spec.yaml"
    path.write_text(textwrap.dedent(text))
    return str(path)


def _sesame(*args, env=None):
    result = CliRunner().invoke(app, list(args), env={"NO_COLOR": "1", **(env or {})})
    crash = (
        f"\n{result.exception!r}"
        if result.exception and not isinstance(result.exception, SystemExit)
        else ""
    )
    return result.exit_code, result.stdout + result.stderr + crash


ENV = {"RS_TEST_ALICE_PASSWORD": "Alice-pw-123"}  # Redshift's password rules


def test_plan_apply_then_nothing_to_do(dsn, tmp_path):
    spec = _spec(tmp_path)
    code, out = _sesame("plan", spec, "--dsn", dsn, env=ENV)
    assert code == 2, out
    assert f"+ CREATE USER \"{P}alice\" PASSWORD '********'" in out
    assert f'+ CREATE GROUP "{P}analysts"' in out
    assert f'+ CREATE ROLE "{P}reader"' in out
    assert f'+ GRANT ROLE "{P}reader" TO ROLE "{P}writer"' in out
    assert f'+ GRANT ROLE "{P}writer" TO "{P}alice"' in out
    assert f'+ ALTER GROUP "{P}analysts" ADD USER "{P}alice"' in out
    assert f'+ GRANT SELECT ON TABLE "rs_test"."daily" TO GROUP "{P}analysts"' in out
    assert f'+ GRANT SELECT ON TABLE "rs_test"."events" TO ROLE "{P}reader"' in out
    assert f'+ GRANT UPDATE ON TABLE "rs_test"."daily" TO "{P}alice"' in out

    code, out = _sesame("apply", spec, "--dsn", dsn, env=ENV)
    assert code == 0, out
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 0 and "nothing to do" in out, out

    # alice logs in and holds what the user, its group and the role chain grant
    alice = make_conninfo(dsn, user=f"{P}alice", password="Alice-pw-123")
    with psycopg.connect(alice) as conn:
        conn.execute("INSERT INTO rs_test.events VALUES (1)")  # writer
        conn.execute("SELECT count(*) FROM rs_test.events")  # reader, via writer
        conn.execute("SELECT count(*) FROM rs_test.daily")  # the group


def test_drift_is_revoked_only_when_allowed(dsn, tmp_path):
    spec = _spec(tmp_path)
    assert _sesame("apply", spec, "--dsn", dsn, env=ENV)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:  # grants made by hand
        conn.execute(f'GRANT DELETE ON rs_test.events TO ROLE "{P}reader"')
        conn.execute(f'GRANT INSERT ON rs_test.daily TO GROUP "{P}analysts"')
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert f'- REVOKE DELETE ON TABLE "rs_test"."events" FROM ROLE "{P}reader"' in out
    assert f'- REVOKE INSERT ON TABLE "rs_test"."daily" FROM GROUP "{P}analysts"' in out
    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0


def test_memberships_are_removed_only_when_allowed(dsn, tmp_path):
    assert _sesame("apply", _spec(tmp_path), "--dsn", dsn, env=ENV)[0] == 0
    changed = SPEC.replace(
        f"    member_of: [{P}writer]\n    groups: [{P}analysts]\n", ""
    )
    spec = _spec(tmp_path, changed)
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert f'- REVOKE ROLE "{P}writer" FROM "{P}alice"' in out, out
    assert f'- ALTER GROUP "{P}analysts" DROP USER "{P}alice"' in out, out
    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0


def test_a_change_set_round_trip(dsn, tmp_path):
    spec, saved = _spec(tmp_path), str(tmp_path / "changes.json")
    assert _sesame("plan", spec, "--dsn", dsn, "-o", saved, env=ENV)[0] == 2
    assert _sesame("apply", saved, "--dsn", dsn, env=ENV)[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0


def test_a_name_held_by_another_kind_of_identity_stops_the_plan(dsn, tmp_path):
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'CREATE GROUP "{P}reader"')
    code, out = _sesame("plan", _spec(tmp_path), "--dsn", dsn)
    assert code == 1
    assert (
        f"principals.{P}reader: the database has it as a group, the spec declares a role"
        in out
    )


def test_column_privileges(dsn, tmp_path):
    with psycopg.connect(dsn, autocommit=True) as conn:
        found = conn.execute(
            "select count(*) from pg_views where viewname = 'svv_column_privileges'"
        ).fetchone()
        if not (found and found[0]):
            pytest.skip("this Redshift has no svv_column_privileges")
        conn.execute(
            "CREATE TABLE rs_test.people (id int, name varchar(32), ssn char(11))"
        )
    columns = f"""
version: 1
engine: redshift
principals:
  {P}support:
    type: role
    privileges:
      schemas:
        usage: [rs_test]
      columns:
        select: [rs_test.people.id, rs_test.people.name]
        update: [rs_test.people.name]
"""
    spec = _spec(tmp_path, columns)
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert (
        f'+ GRANT SELECT ("name") ON TABLE "rs_test"."people" TO ROLE "{P}support"'
        in out
    )
    assert _sesame("apply", spec, "--dsn", dsn)[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"GRANT SELECT (ssn) ON rs_test.people TO ROLE {P}support")
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert (
        f'- REVOKE SELECT ("ssn") ON TABLE "rs_test"."people" FROM ROLE "{P}support"'
        in out
    ), out
    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0

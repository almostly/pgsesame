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
    # Redshift won't drop a user that has default privileges: revoke them first
    defaults = conn.execute(
        "SELECT owner_name, coalesce(schema_name, ''), object_type, privilege_type, "
        "grantee_name, grantee_type FROM svv_default_privileges "
        "WHERE owner_name LIKE 'rs\\_test\\_%' OR grantee_name LIKE 'rs\\_test\\_%'"
    ).fetchall()
    for owner, schema, kind, privilege, grantee, gtype in defaults:
        conn.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES FOR USER {}{} REVOKE {} ON {} FROM {}{}"
            ).format(
                sql.Identifier(owner),
                sql.SQL(" IN SCHEMA {}").format(sql.Identifier(schema))
                if schema
                else sql.SQL(""),
                sql.SQL(privilege),
                sql.SQL("FUNCTIONS" if kind == "FUNCTION" else "TABLES"),
                sql.SQL(
                    "ROLE " if gtype == "role" else "GROUP " if gtype == "group" else ""
                ),
                sql.Identifier(grantee),
            )
        )
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


def test_a_grant_option_the_spec_doesnt_give_is_drift(dsn, tmp_path):
    # Redshift gives a grant option to users only
    spec = _spec(tmp_path)
    assert _sesame("apply", spec, "--dsn", dsn, env=ENV)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'GRANT UPDATE ON rs_test.daily TO "{P}alice" WITH GRANT OPTION')
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert (
        f'- REVOKE GRANT OPTION FOR UPDATE ON TABLE "rs_test"."daily" FROM "{P}alice"'
        in out
    ), out
    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:  # UPDATE itself stays
        assert conn.execute(
            "SELECT privilege_type, admin_option FROM svv_relation_privileges "
            f"WHERE identity_name = '{P}alice' AND relation_name = 'daily'"
        ).fetchall() == [("UPDATE", False)]


def test_a_disabled_password_is_seen_and_set_again(dsn, tmp_path):
    # Redshift shows no password, disabled or not: plan signs in with password_env
    spec = _spec(tmp_path)
    assert _sesame("apply", spec, "--dsn", dsn, env=ENV)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'ALTER USER "{P}alice" PASSWORD DISABLE')
    code, out = _sesame("plan", spec, "--dsn", dsn, env=ENV)
    assert code == 2, out
    assert f"~ ALTER USER \"{P}alice\" PASSWORD '********'" in out, out
    assert "doesn't sign in with RS_TEST_ALICE_PASSWORD" in out
    assert _sesame("apply", spec, "--dsn", dsn, env=ENV)[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn, env=ENV)[0] == 0
    alice = make_conninfo(dsn, user=f"{P}alice", password=ENV["RS_TEST_ALICE_PASSWORD"])
    psycopg.connect(alice).close()


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


DEFAULTS = f"""
version: 1
engine: redshift
principals:
  {P}etl:
    type: user
    password: disabled
    privileges:
      schemas:
        create: [rs_test]
        usage: [rs_test]
  {P}reader:
    type: role
    privileges:
      schemas:
        usage: [rs_test]
  {P}analysts:
    type: group
default_privileges:
  - owner: {P}etl
    schema: rs_test
    grantee: {P}reader
    tables: [select]
  - owner: {P}etl
    grantee: {P}analysts
    tables: [select]
"""


def test_default_privileges_reach_the_tables_made_later(dsn, tmp_path):
    spec = _spec(tmp_path, DEFAULTS)
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert (
        f'+ ALTER DEFAULT PRIVILEGES FOR USER "{P}etl" IN SCHEMA "rs_test" '
        f'GRANT SELECT ON TABLES TO ROLE "{P}reader"' in out
    ), out
    assert (
        f'+ ALTER DEFAULT PRIVILEGES FOR USER "{P}etl" GRANT SELECT ON TABLES '
        f'TO GROUP "{P}analysts"' in out
    ), out
    assert _sesame("apply", spec, "--dsn", dsn)[0] == 0
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 0, out
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"SET SESSION AUTHORIZATION {P}etl")
        conn.execute("CREATE TABLE rs_test.made_later (x int)")
        conn.execute("RESET SESSION AUTHORIZATION")
        grants = conn.execute(
            "SELECT identity_name, privilege_type FROM svv_relation_privileges "
            "WHERE namespace_name = 'rs_test' AND relation_name = 'made_later' "
            "ORDER BY 1"
        ).fetchall()
    assert grants == [(f"{P}analysts", "SELECT"), (f"{P}reader", "SELECT")]
    # those grants came from the spec's default privileges: not drift
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 0, out


def test_import_writes_a_spec_whose_plan_is_empty(dsn, tmp_path):
    env = {"RS_TEST_ALICE_PASSWORD": "Alice-pw-1"}
    assert _sesame("apply", _spec(tmp_path), "--dsn", dsn, env=env)[0] == 0
    assert _sesame("apply", _spec(tmp_path, DEFAULTS), "--dsn", dsn)[0] == 0
    imported = tmp_path / "imported.yaml"
    code, out = _sesame(
        "import",
        "--dsn",
        dsn,
        "--engine",
        "redshift",
        "--prefix",
        P,
        "-o",
        str(imported),
    )
    assert code == 0, out
    text = imported.read_text()
    assert f"{P}analysts:\n    type: group" in text and "groups:" in text
    assert "default_privileges:" in text and "password" not in text
    code, out = _sesame("plan", str(imported), "--dsn", dsn)
    assert code == 0, out


def test_import_without_engine_finds_redshift(dsn, tmp_path):
    # from --dsn alone: the catalog says Redshift, and groups stay groups
    assert _sesame("apply", _spec(tmp_path), "--dsn", dsn, env=ENV)[0] == 0
    imported = tmp_path / "imported.yaml"
    code, out = _sesame("import", "--dsn", dsn, "--prefix", P, "-o", str(imported))
    assert code == 0, out
    assert "engine: redshift, from the catalog" in out
    text = imported.read_text()
    assert "engine: redshift" in text and f"{P}analysts:\n    type: group" in text


def test_ownership(dsn, tmp_path):
    owners = f"""
version: 1
engine: redshift
principals:
  {P}etl:
    type: user
    password: disabled
    owns:
      schemas: [rs_test]
      tables: [rs_test.*]
"""
    spec = _spec(tmp_path, owners)
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert f'~ ALTER SCHEMA "rs_test" OWNER TO "{P}etl"' in out, out
    assert f'~ ALTER TABLE "rs_test"."events" OWNER TO "{P}etl"' in out, out
    assert _sesame("apply", spec, "--dsn", dsn)[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:  # hand them back for cleanup
        me = sql.Identifier(conn.info.user)
        conn.execute(sql.SQL("ALTER SCHEMA rs_test OWNER TO {}").format(me))
        for (t,) in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'rs_test'"
        ).fetchall():
            conn.execute(
                sql.SQL("ALTER TABLE rs_test.{} OWNER TO {}").format(
                    sql.Identifier(t), me
                )
            )


def test_a_user_that_sees_only_its_own_grants_imports_nothing(dsn, tmp_path):
    # Redshift shows a non-superuser only its own rows in the SVV privilege views
    # (dwhcluster1, 2026-10-07: an IAM user's import lost memberships and column
    # grants, which a superuser's plan of it then revoked)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"CREATE USER {P}limited PASSWORD 'Limited-pw-1'")
        conn.execute(f"GRANT USAGE ON SCHEMA rs_test TO {P}limited")
    limited = make_conninfo(dsn, user=f"{P}limited", password="Limited-pw-1")
    out_file = tmp_path / "partial.yaml"
    code, out = _sesame(
        "import", "--dsn", limited, "--engine", "redshift", "-o", str(out_file)
    )
    assert code == 1, out
    assert "import needs to see every grant" in out
    assert "ACCESS SYSTEM TABLE" in out
    assert not out_file.exists()

    spec = _spec(
        tmp_path,
        f"version: 1\nengine: redshift\nprincipals:\n  {P}limited: {{type: user}}\n",
    )
    code, out = _sesame("plan", spec, "--dsn", limited)
    assert "this user isn't a superuser and doesn't hold ACCESS SYSTEM TABLE" in out, (
        out
    )


def test_access_system_table_through_a_role_sees_everything(dsn, tmp_path):
    # the least-privileged way to read every grant: no superuser needed
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"CREATE USER {P}limited PASSWORD 'Limited-pw-1'")
        conn.execute(f"CREATE ROLE {P}catalog")
        try:
            conn.execute(f"GRANT ACCESS SYSTEM TABLE TO ROLE {P}catalog")
        except psycopg.Error:
            pytest.skip("this Redshift has no ACCESS SYSTEM TABLE permission")
        conn.execute(f"GRANT ROLE {P}catalog TO {P}limited")
    assert _sesame("apply", _spec(tmp_path), "--dsn", dsn, env=ENV)[0] == 0
    limited = make_conninfo(dsn, user=f"{P}limited", password="Limited-pw-1")
    imported = tmp_path / "imported.yaml"
    code, out = _sesame(
        "import",
        "--dsn",
        limited,
        "--prefix",
        P,
        "--schema",
        "rs_test",
        "-o",
        str(imported),
    )
    assert code == 0, out
    text = imported.read_text()
    # what a non-superuser can't see without it: others' memberships and grants
    assert f"member_of:\n    - {P}writer" in text and "groups:" in text, text
    code, out = _sesame("plan", _spec(tmp_path), "--dsn", limited)
    assert "ACCESS SYSTEM TABLE" not in out, out  # no partial-view warning
    assert f'GRANT ROLE "{P}writer" TO "{P}alice"' not in out, out

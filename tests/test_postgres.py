"""plan and apply against a real PostgreSQL server.

Set ``PGSESAME_TEST_DSN`` to a superuser connection (for example a PostgreSQL in
Docker); the tests skip without it. They work in their own database,
``sesame_test``, and every role they make is named ``sesame_test_*``. Roles belong
to the whole server, so both are dropped before and after each test.
"""

import os
import textwrap

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from typer.testing import CliRunner

from pgsesame.cli import app

DSN = os.environ.get("PGSESAME_TEST_DSN", "")
P = "sesame_test_"  # every role the tests make
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        not DSN, reason="set PGSESAME_TEST_DSN to run against PostgreSQL"
    ),
]

SPEC = f"""
version: 1
engine: postgres
principals:
  {P}reader:
    type: role
    privileges:
      schemas:
        usage: [analytics]
      tables:
        select: [analytics.*]
  {P}writer:
    type: role
    member_of: [{P}reader]
    privileges:
      tables:
        insert: [analytics.events]
  {P}alice:
    type: user
    password_env: SESAME_TEST_ALICE_PASSWORD
    member_of: [{P}writer]
"""


def _cleanup(admin: psycopg.Connection) -> None:
    admin.execute("DROP DATABASE IF EXISTS sesame_test WITH (FORCE)")
    roles = admin.execute(
        "SELECT rolname FROM pg_roles WHERE rolname LIKE %s",
        (P.replace("_", "\\_") + "%",),
    ).fetchall()
    for (name,) in roles:
        admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


@pytest.fixture
def dsn():
    admin = psycopg.connect(DSN, autocommit=True)
    _cleanup(admin)
    admin.execute("CREATE DATABASE sesame_test")
    test_dsn = make_conninfo(DSN, dbname="sesame_test")
    with psycopg.connect(test_dsn, autocommit=True) as conn:
        conn.execute(
            """
            CREATE SCHEMA analytics;
            CREATE TABLE analytics.events (id int);
            CREATE TABLE analytics.daily (day date);
            CREATE SCHEMA marts;
            CREATE TABLE marts.sales (amount numeric);
            """
        )
    yield test_dsn
    _cleanup(admin)
    admin.close()


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


def test_plan_apply_then_nothing_to_do(dsn, tmp_path):
    spec = _spec(tmp_path)
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert f'+ CREATE ROLE "{P}reader" NOLOGIN' in out
    assert f'+ GRANT SELECT ON TABLE "analytics"."daily" TO "{P}reader"' in out
    assert f'+ GRANT "{P}reader" TO "{P}writer"' in out
    assert "marts" not in out  # analytics.* is only analytics

    env = {"SESAME_TEST_ALICE_PASSWORD": "alice-pw-1"}
    code, out = _sesame("apply", spec, "--dsn", dsn, env=env)
    assert code == 0, out
    assert "alice-pw-1" not in out  # the password is masked in the output

    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 0, out
    assert "nothing to do" in out

    # alice logs in with her password and reads through the role chain
    alice = make_conninfo(dsn, user=f"{P}alice", password="alice-pw-1")
    with psycopg.connect(alice) as conn:
        conn.execute("INSERT INTO analytics.events VALUES (1)")
        assert conn.execute("SELECT count(*) FROM analytics.daily").fetchone() == (0,)


def test_drift_is_revoked_only_when_allowed(dsn, tmp_path):
    spec = _spec(tmp_path)
    assert _sesame("apply", spec, "--dsn", dsn)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:  # someone grants by hand
        conn.execute(f'GRANT DELETE ON analytics.events TO "{P}reader"')
        conn.execute(f'GRANT USAGE ON SCHEMA marts TO "{P}writer"')

    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert f'- REVOKE DELETE ON TABLE "analytics"."events" FROM "{P}reader"' in out
    assert "needs --allow-revoke" in out

    code, out = _sesame("apply", spec, "--dsn", dsn)
    assert code == 0 and "2 statement(s) skipped" in out, out
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 2  # still drifted

    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0


def test_membership_removal_and_login_change(dsn, tmp_path):
    assert _sesame("apply", _spec(tmp_path), "--dsn", dsn)[0] == 0
    changed = SPEC.replace(f"    member_of: [{P}writer]\n", "    login: false\n")
    spec = _spec(tmp_path, changed)
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert f'~ ALTER ROLE "{P}alice" NOLOGIN' in out
    assert f'- REVOKE "{P}writer" FROM "{P}alice"' in out
    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0


def test_roles_outside_the_spec_are_left_alone(dsn, tmp_path):
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'CREATE ROLE "{P}someone_else"')
        conn.execute(f'GRANT SELECT ON marts.sales TO "{P}someone_else"')
    code, out = _sesame("apply", _spec(tmp_path), "--dsn", dsn, "--allow-revoke")
    assert code == 0 and "someone_else" not in out, out
    with psycopg.connect(dsn) as conn:
        assert conn.execute(
            "SELECT has_table_privilege(%s, 'marts.sales', 'SELECT')",
            (f"{P}someone_else",),
        ).fetchone() == (True,)


def test_a_missing_object_stops_the_plan(dsn, tmp_path):
    spec = _spec(
        tmp_path, SPEC.replace("insert: [analytics.events]", "insert: [analytics.nope]")
    )
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 1
    assert "analytics.nope does not exist" in out


def test_a_change_set_applies_exactly_what_was_planned(dsn, tmp_path):
    spec, saved = _spec(tmp_path), str(tmp_path / "changes.json")
    env = {"SESAME_TEST_ALICE_PASSWORD": "alice-pw-2"}
    code, out = _sesame("plan", spec, "--dsn", dsn, "-o", saved, env=env)
    assert code == 2 and "Saved to" in out, out
    text = (tmp_path / "changes.json").read_text()
    assert "alice-pw-2" not in text and "SESAME_TEST_ALICE_PASSWORD" in text

    code, out = _sesame("show", saved)
    assert code == 0 and f'+ CREATE ROLE "{P}alice" LOGIN' in out, out

    # a change elsewhere in the database doesn't get in the way
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE marts.extra (x int)")
    code, out = _sesame("apply", saved, "--dsn", dsn, env=env)
    assert code == 0, out
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0
    alice = make_conninfo(dsn, user=f"{P}alice", password="alice-pw-2")
    psycopg.connect(alice).close()  # the password came from the environment again


def test_a_change_set_is_refused_when_the_plan_would_differ(dsn, tmp_path):
    spec, saved = _spec(tmp_path), str(tmp_path / "changes.json")
    assert _sesame("plan", spec, "--dsn", dsn, "-o", saved)[0] == 2
    with psycopg.connect(dsn, autocommit=True) as conn:  # analytics.* grows
        conn.execute("CREATE TABLE analytics.late (x int)")
    code, out = _sesame("apply", saved, "--dsn", dsn)
    assert code == 1 and "the database changed since" in out, out
    assert '"analytics"."late"' in out  # the new plan is shown
    with psycopg.connect(dsn) as conn:  # nothing ran
        assert conn.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE %s", (f"{P}%",)
        ).fetchone() == (0,)


def test_an_edited_or_misdirected_change_set_is_refused(dsn, tmp_path):
    import json

    spec, saved = _spec(tmp_path), tmp_path / "changes.json"
    assert _sesame("plan", spec, "--dsn", dsn, "-o", str(saved))[0] == 2
    original = json.loads(saved.read_text())

    edited = {**original, "spec": {**original["spec"], "engine": "redshift"}}
    saved.write_text(json.dumps(edited))
    code, out = _sesame("apply", str(saved), "--dsn", dsn)
    assert code == 1 and "edited after planning" in out, out

    elsewhere = {**original, "target": "someone@prod:warehouse"}
    saved.write_text(json.dumps(elsewhere))
    code, out = _sesame("apply", str(saved), "--dsn", dsn)
    assert code == 1 and "planned against someone@prod:warehouse" in out, out


def test_a_failed_apply_changes_nothing(dsn, tmp_path, monkeypatch):
    from pgsesame import cli
    from pgsesame.ops import Operation

    class Boom(Operation):
        order = 99  # last, after every role and grant ran

        def statement(self):
            return sql.SQL("SELECT 1 / 0")

    make = cli.planner.make

    def make_with_a_failure(*args, **kwargs):
        plan = make(*args, **kwargs)
        plan.operations.append(Boom())
        return plan

    monkeypatch.setattr(cli.planner, "make", make_with_a_failure)
    code, out = _sesame("apply", _spec(tmp_path), "--dsn", dsn)
    assert code == 1 and "apply failed, nothing was changed" in out, out
    with psycopg.connect(dsn) as conn:  # the roles created before it rolled back
        assert conn.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE %s", (f"{P}%",)
        ).fetchone() == (0,)


def test_grant_all_is_read_whatever_the_server_version(dsn, tmp_path):
    # PostgreSQL 17 added MAINTAIN, which GRANT ALL includes: it must neither crash
    # a plan nor be revoked unless the spec manages it
    assert _sesame("apply", _spec(tmp_path), "--dsn", dsn)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'GRANT ALL ON analytics.daily TO "{P}reader"')
    code, out = _sesame("plan", _spec(tmp_path), "--dsn", dsn)
    assert code == 2, out  # the extra grants are drift
    assert f'- REVOKE INSERT ON TABLE "analytics"."daily" FROM "{P}reader"' in out
    assert _sesame("apply", _spec(tmp_path), "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", _spec(tmp_path), "--dsn", dsn)[0] == 0


def test_a_platforms_builtin_role(dsn, tmp_path):
    # a role the platform owns (Supabase's authenticated, say), with grants of its own
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'CREATE ROLE "{P}platform" NOLOGIN')
        conn.execute(f'GRANT USAGE ON SCHEMA marts TO "{P}platform"')
        conn.execute(f'GRANT SELECT ON marts.sales TO "{P}platform"')
    spec = _spec(
        tmp_path,
        f"""
version: 1
engine: postgres
principals:
  {P}platform:
    type: builtin
    privileges:
      schemas:
        usage: [analytics]
      tables:
        select: [analytics.*]
  {P}app:
    type: user
    password: disabled
    member_of: [{P}platform]
""",
    )
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert f'CREATE ROLE "{P}platform"' not in out
    assert f'+ GRANT "{P}platform" TO "{P}app"' in out
    assert "marts" not in out  # the platform's grants are outside the spec's scope
    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0
    with psycopg.connect(dsn) as conn:  # still there
        assert conn.execute(
            "SELECT has_table_privilege(%s, 'marts.sales', 'SELECT')", (f"{P}platform",)
        ).fetchone() == (True,)


RLS = f"""
version: 1
engine: postgres
principals:
  {P}alice:
    type: user
    password_env: SESAME_TEST_ALICE_PASSWORD
    privileges:
      schemas:
        usage: [analytics]
      tables:
        select: [analytics.notes]
row_level_security:
  analytics.notes:
    policies:
      own_rows:
        command: select
        to: [{P}alice]
        using: "owner = current_user"
"""


def test_row_level_security(dsn, tmp_path):
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE analytics.notes (owner text, body text)")
        conn.execute(
            f"INSERT INTO analytics.notes VALUES ('{P}alice', 'mine'), ('bob', 'his')"
        )
    env = {"SESAME_TEST_ALICE_PASSWORD": "alice-pw-3"}
    spec = _spec(tmp_path, RLS)
    code, out = _sesame("plan", spec, "--dsn", dsn, env=env)
    assert code == 2, out
    assert '+ ALTER TABLE "analytics"."notes" ENABLE ROW LEVEL SECURITY' in out
    assert (
        f'+ CREATE POLICY "own_rows" ON "analytics"."notes" AS PERMISSIVE FOR SELECT TO "{P}alice" USING (owner = current_user)'
        in out
    )
    assert _sesame("apply", spec, "--dsn", dsn, env=env)[0] == 0
    # converged although PostgreSQL stores the expression in its own form
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 0, out
    alice = make_conninfo(dsn, user=f"{P}alice", password="alice-pw-3")
    with psycopg.connect(alice) as conn:
        assert conn.execute("SELECT body FROM analytics.notes").fetchall() == [
            ("mine",)
        ]

    # a changed expression is an ALTER; a changed command replaces the policy
    altered = _spec(
        tmp_path, RLS.replace("owner = current_user", "owner = session_user")
    )
    code, out = _sesame("plan", altered, "--dsn", dsn)
    assert '~ ALTER POLICY "own_rows"' in out, out
    assert _sesame("apply", altered, "--dsn", dsn)[0] == 0
    replaced = _spec(tmp_path, RLS.replace("command: select", "command: all"))
    code, out = _sesame("plan", replaced, "--dsn", dsn)
    assert (
        '- DROP POLICY "own_rows" ON "analytics"."notes"  needs --allow-drop' in out
    ), out
    assert _sesame("apply", replaced, "--dsn", dsn, "--allow-drop")[0] == 0
    assert _sesame("plan", replaced, "--dsn", dsn)[0] == 0

    # a policy made by hand on a managed table is drift
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("CREATE POLICY sneaky ON analytics.notes FOR SELECT USING (true)")
    code, out = _sesame("plan", replaced, "--dsn", dsn)
    assert '- DROP POLICY "sneaky" ON "analytics"."notes"' in out, out


COLUMNS = f"""
version: 1
engine: postgres
principals:
  {P}support:
    type: role
    privileges:
      schemas:
        usage: [analytics]
      columns:
        select: [analytics.people.id, analytics.people.name]
        update: [analytics.people.name]
"""


def test_column_privileges(dsn, tmp_path):
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE analytics.people (id int, name text, ssn text)")
        conn.execute("INSERT INTO analytics.people VALUES (1, 'ann', '123')")
    spec = _spec(tmp_path, COLUMNS)
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert code == 2, out
    assert (
        f'+ GRANT SELECT ("name") ON TABLE "analytics"."people" TO "{P}support"' in out
    )
    assert _sesame("apply", spec, "--dsn", dsn)[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"SET ROLE {P}support")
        assert conn.execute("SELECT id, name FROM analytics.people").fetchall() == [
            (1, "ann")
        ]
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT ssn FROM analytics.people")
        conn.execute("RESET ROLE")
        # a column grant made by hand is drift, revoked only when allowed
        conn.execute(f"GRANT SELECT (ssn) ON analytics.people TO {P}support")
    code, out = _sesame("plan", spec, "--dsn", dsn)
    assert (
        f'- REVOKE SELECT ("ssn") ON TABLE "analytics"."people" FROM "{P}support"'
        in out
    ), out
    assert _sesame("apply", spec, "--dsn", dsn, "--allow-revoke")[0] == 0
    assert _sesame("plan", spec, "--dsn", dsn)[0] == 0

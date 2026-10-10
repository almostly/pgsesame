"""plan, apply and import against Amazon Aurora DSQL.

Set ``PGSESAME_TEST_DSQL`` to a cluster's identifier or endpoint, with AWS
credentials that may connect as ``admin`` (dsql:DbConnectAdmin) and as a linked
role (dsql:DbConnect). The tests skip without it.

Every role the tests make is named ``ds_test_*`` and their objects live in the
schema ``ds_test``; all of it is dropped before and after each test.
"""

import os
import textwrap

import pytest
from psycopg import sql
from typer.testing import CliRunner

from pgsesame.cli import app

boto3 = pytest.importorskip("boto3")

CLUSTER = os.environ.get("PGSESAME_TEST_DSQL", "")
P = "ds_test_"
pytestmark = pytest.mark.skipif(
    not CLUSTER, reason="set PGSESAME_TEST_DSQL to an Aurora DSQL cluster"
)


def _arn() -> str:
    """Return the caller's IAM identity, which the tests link to a role."""
    return boto3.client("sts").get_caller_identity()["Arn"]


def _admin():
    from pgsesame.aws import dsql_database

    return dsql_database(CLUSTER)


def _cleanup() -> None:
    db = _admin()
    conn = db.conn
    for role, arn in conn.execute(
        "select pg_role_name, arn from sys.iam_pg_role_mappings "
        "where pg_role_name like 'ds\\_test\\_%'"
    ).fetchall():
        conn.execute(
            sql.SQL("AWS IAM REVOKE {} FROM {}").format(
                sql.Identifier(role), sql.Literal(arn)
            )
        )
    for (grantee,) in conn.execute(
        "select distinct g.rolname from pg_default_acl d, aclexplode(d.defaclacl) a "
        "join pg_roles g on g.oid = a.grantee where g.rolname like 'ds\\_test\\_%'"
    ).fetchall():
        for kind in ("TABLES", "SEQUENCES", "FUNCTIONS"):
            conn.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA ds_test REVOKE ALL ON {} FROM {}"
                ).format(sql.SQL(kind), sql.Identifier(grantee))
            )
    tables = conn.execute(
        "select tablename from pg_tables where schemaname = 'ds_test'"
    ).fetchall()
    for (table,) in tables:
        conn.execute(sql.SQL("DROP TABLE ds_test.{}").format(sql.Identifier(table)))
    conn.execute("DROP SCHEMA IF EXISTS ds_test")
    for (role,) in conn.execute(
        "select rolname from pg_roles where rolname like 'ds\\_test\\_%'"
    ).fetchall():
        conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
    db.close()


@pytest.fixture
def cluster():
    _cleanup()
    db = _admin()
    db.conn.execute("CREATE SCHEMA ds_test")
    db.conn.execute("CREATE TABLE ds_test.events (id int PRIMARY KEY)")
    db.conn.execute("CREATE TABLE ds_test.daily (day date PRIMARY KEY)")
    db.close()
    yield CLUSTER
    _cleanup()


def _spec(tmp_path, text):
    path = tmp_path / "spec.yaml"
    path.write_text(textwrap.dedent(text))
    return str(path)


def _sesame(*args):
    result = CliRunner().invoke(app, list(args), env={"NO_COLOR": "1"})
    crash = (
        f"\n{result.exception!r}"
        if result.exception and not isinstance(result.exception, SystemExit)
        else ""
    )
    return result.exit_code, result.stdout + result.stderr + crash


def _spec_text(arn: str, iam: bool = True) -> str:
    link = f"\n    iam: [{arn}]" if iam else ""
    return f"""
version: 1
engine: dsql
principals:
  {P}reader:
    type: role
    privileges:
      schemas:
        usage: [ds_test]
      tables:
        select: [ds_test.*]
  {P}app:
    type: user
    member_of: [{P}reader]{link}
    privileges:
      tables:
        insert: [ds_test.events]
default_privileges:
  - owner: admin
    schema: ds_test
    grantee: {P}reader
    tables: [select]
"""


def test_plan_apply_then_nothing_to_do(cluster, tmp_path):
    arn = _arn()
    spec = _spec(tmp_path, _spec_text(arn))
    code, out = _sesame("plan", spec, "--dsql", cluster)
    assert code == 2, out
    assert f'+ CREATE ROLE "{P}app" LOGIN' in out
    assert f"+ AWS IAM GRANT \"{P}app\" TO '{arn}'" in out
    assert f'+ GRANT SELECT ON TABLE "ds_test"."daily" TO "{P}reader"' in out
    code, out = _sesame("apply", spec, "--dsql", cluster)
    assert code == 0, out
    code, out = _sesame("plan", spec, "--dsql", cluster)
    assert code == 0 and "nothing to do" in out, out

    # the linked IAM identity signs in as the role, with its own token
    from pgsesame.aws import dsql_database

    app_db = dsql_database(cluster, db_user=f"{P}app")
    app_db.conn.execute("INSERT INTO ds_test.events VALUES (1)")
    assert app_db.conn.execute("SELECT count(*) FROM ds_test.daily").fetchone() == (0,)
    app_db.close()


def test_drift_and_an_iam_link_are_revoked_only_when_allowed(cluster, tmp_path):
    arn = _arn()
    assert _sesame("apply", _spec(tmp_path, _spec_text(arn)), "--dsql", cluster)[0] == 0
    db = _admin()
    db.conn.execute(f'GRANT DELETE ON ds_test.events TO "{P}reader"')
    db.close()
    spec = _spec(tmp_path, _spec_text(arn, iam=False))
    code, out = _sesame("plan", spec, "--dsql", cluster)
    assert code == 2, out
    assert f'- REVOKE DELETE ON TABLE "ds_test"."events" FROM "{P}reader"' in out
    assert f"- AWS IAM REVOKE \"{P}app\" FROM '{arn}'  needs --allow-revoke" in out
    assert _sesame("apply", spec, "--dsql", cluster, "--allow-revoke")[0] == 0
    code, out = _sesame("plan", spec, "--dsql", cluster)
    assert code == 0, out


def test_import_writes_a_spec_whose_plan_is_empty(cluster, tmp_path):
    arn = _arn()
    assert _sesame("apply", _spec(tmp_path, _spec_text(arn)), "--dsql", cluster)[0] == 0
    imported = tmp_path / "imported.yaml"
    code, out = _sesame(
        "import",
        "--dsql",
        cluster,
        "--prefix",
        P,
        "--schema",
        "ds_test",
        "-o",
        str(imported),
    )
    assert code == 0, out
    text = imported.read_text()
    assert "engine: dsql" in text and arn in text, text
    code, out = _sesame("plan", str(imported), "--dsql", cluster)
    assert code == 0, out


def test_a_failed_statement_says_how_many_were_applied(cluster):
    # one DDL statement per transaction: what ran before the failure stays
    from pgsesame.db import PartiallyApplied

    db = _admin()
    statements = [
        sql.SQL("CREATE ROLE {}").format(sql.Identifier(f"{P}first")),
        sql.SQL("GRANT SELECT ON ds_test.missing TO {}").format(
            sql.Identifier(f"{P}first")
        ),
        sql.SQL("CREATE ROLE {}").format(sql.Identifier(f"{P}never")),
    ]
    with pytest.raises(PartiallyApplied) as stopped:
        db.run(statements)
    assert (stopped.value.done, stopped.value.total) == (1, 3)
    roles = {
        r
        for (r,) in db.conn.execute(
            "select rolname from pg_roles where rolname like 'ds\\_test\\_%'"
        ).fetchall()
    }
    assert roles == {f"{P}first"}
    db.close()


def test_what_aurora_dsql_lacks_is_refused_in_the_spec(tmp_path):
    spec = _spec(
        tmp_path,
        f"""
        version: 1
        engine: dsql
        principals:
          {P}app:
            type: user
            password_env: APP_PASSWORD
            owns:
              schemas: [ds_test]
            privileges:
              databases:
                create: [postgres]
        """,
    )
    code, out = _sesame("plan", spec, "--dsql", "unused")
    assert code == 1, out
    assert "IAM only" in out and "no database privileges" in out and "ownership" in out

"""A dbt-rebuilt table keeps the grants pgsesame declares: examples/dbt, run for real.

dbt's table materialization replaces a table on every run, and its grants go with
the old one. The example's post-hook puts back what ``sesame grants`` published.
Set ``PGSESAME_TEST_REDSHIFT_DSN`` (redshift-local or Redshift) and
``PGSESAME_TEST_DBT`` to the dbt command, e.g. ``uvx --from dbt-redshift dbt``;
the test skips without them.
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from typer.testing import CliRunner

from pgsesame.cli import app

DSN = os.environ.get("PGSESAME_TEST_REDSHIFT_DSN", "")
DBT = os.environ.get("PGSESAME_TEST_DBT", "")
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "dbt"
P = "dbt_test_"
pytestmark = pytest.mark.skipif(
    not (DSN and DBT),
    reason="set PGSESAME_TEST_REDSHIFT_DSN and PGSESAME_TEST_DBT (the dbt command)",
)

SPEC = f"""
version: 1
engine: redshift
principals:
  public:
    type: builtin
    privileges:
      tables: {{select: [marts.loans]}}
  {P}analysts:
    type: group
    privileges:
      schemas: {{usage: [marts]}}
      tables: {{select: [marts.*]}}
  {P}lidris:
    type: user
    password: disabled
    privileges:
      schemas: {{usage: [marts]}}
      tables: {{select: [marts.loans]}}
  {P}support:
    type: role
    privileges:
      schemas: {{usage: [marts]}}
      columns: {{select: [marts.loans.id]}}
"""


def _cleanup(conn: psycopg.Connection) -> None:
    conn.execute("DROP SCHEMA IF EXISTS marts CASCADE")
    conn.execute("DROP TABLE IF EXISTS monitoring.declared_grants")
    for template, query in (
        ("DROP USER {}", f"SELECT usename FROM pg_user WHERE usename LIKE '{P}%'"),
        (
            "DROP GROUP {}",
            f"SELECT groname FROM pg_catalog.pg_group WHERE groname LIKE '{P}%'",
        ),
        (
            "DROP ROLE {}",
            f"SELECT role_name FROM svv_roles WHERE role_name LIKE '{P}%'",
        ),
    ):
        for (name,) in conn.execute(query).fetchall():
            conn.execute(sql.SQL(template).format(sql.Identifier(name)))


@pytest.fixture
def admin():
    with psycopg.connect(DSN, autocommit=True) as conn:
        _cleanup(conn)
        yield conn
        _cleanup(conn)


def _dbt(*args: str) -> str:
    parts = conninfo_to_dict(DSN)
    env = {
        **os.environ,
        "DBT_HOST": str(parts.get("host", "localhost")),
        "DBT_PORT": str(parts.get("port", "5439")),
        "DBT_USER": str(parts["user"]),
        "DBT_PASSWORD": str(parts.get("password", "")),
        "DBT_DATABASE": str(parts.get("dbname", "dev")),
        # redshift-local's certificate is self-signed, and the Redshift driver checks
        # it even for require (oblako trust installs it): no TLS on this machine
        "DBT_SSLMODE": os.environ.get(
            "PGSESAME_TEST_DBT_SSLMODE",
            "disable" if parts.get("host") in ("localhost", "127.0.0.1") else "require",
        ),
    }
    result = subprocess.run(
        [
            *shlex.split(DBT),
            *args,
            "--project-dir",
            str(EXAMPLE),
            "--profiles-dir",
            str(EXAMPLE),
        ],
        env=env,
        capture_output=True,
        text=True,
        cwd=EXAMPLE,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def _sesame(*args: str) -> str:
    result = CliRunner().invoke(app, list(args), env={"NO_COLOR": "1"})
    assert result.exit_code in (0, 2), result.output
    return result.stdout


def _grants(conn: psycopg.Connection) -> set[tuple[str, str]]:
    on_table = conn.execute(
        "SELECT identity_name, privilege_type FROM svv_relation_privileges "
        "WHERE namespace_name = 'marts' AND relation_name = 'loans'"
    ).fetchall()
    on_column = conn.execute(
        "SELECT identity_name, privilege_type || ' (' || column_name || ')' "
        "FROM svv_column_privileges "
        "WHERE namespace_name = 'marts' AND relation_name = 'loans'"
    ).fetchall()
    return {
        (who, what)
        for who, what in [*on_table, *on_column]
        if who.startswith(P) or who == "public"
    }


def _table_id(conn: psycopg.Connection) -> int:
    row = conn.execute(
        "SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'marts' AND c.relname = 'loans'"
    ).fetchone()
    assert row is not None, "marts.loans doesn't exist"
    return row[0]


def _publish(spec: Path) -> None:
    rows = _sesame("grants", str(spec), "--format", "csv")
    result = subprocess.run(
        [sys.executable, str(EXAMPLE / "publish_grants.py"), DSN],
        input=rows,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_rebuilt_table_keeps_the_declared_grants(admin, tmp_path):
    expected = {
        ("public", "SELECT"),
        (f"{P}analysts", "SELECT"),
        (f"{P}lidris", "SELECT"),
        (f"{P}support", "SELECT (id)"),
    }
    _dbt("run")  # the first build: marts.loans exists, nothing published yet
    spec = tmp_path / "spec.yaml"
    spec.write_text(SPEC)
    _sesame("apply", str(spec), "--dsn", DSN)
    assert _grants(admin) == expected
    _publish(spec)

    # without the hook, a rebuild loses every grant: the problem
    before = _table_id(admin)
    _dbt("run", "--vars", "{pgsesame_regrant: false}")
    assert _table_id(admin) != before  # a new table
    assert _grants(admin) == set()

    # with it, each rebuild has them again, in the same transaction
    for _ in range(2):
        before = _table_id(admin)
        _dbt("run")
        assert _table_id(admin) != before
        assert _grants(admin) == expected

    # and pgsesame agrees: the database matches the spec
    result = CliRunner().invoke(
        app, ["plan", str(spec), "--dsn", DSN], env={"NO_COLOR": "1"}
    )
    assert result.exit_code == 0, result.output


def test_the_hook_skips_a_grantee_that_doesnt_exist(admin, tmp_path):
    _dbt("run")
    spec = tmp_path / "spec.yaml"
    spec.write_text(SPEC)
    _sesame("apply", str(spec), "--dsn", DSN)
    _publish(spec)
    # gone since the publish (Redshift drops a user only once its grants are)
    admin.execute(f'REVOKE ALL ON marts.loans FROM "{P}lidris"')
    admin.execute(f'REVOKE ALL ON SCHEMA marts FROM "{P}lidris"')
    admin.execute(f'DROP USER "{P}lidris"')
    _dbt("run")
    assert _grants(admin) == {
        ("public", "SELECT"),
        (f"{P}analysts", "SELECT"),
        (f"{P}support", "SELECT (id)"),
    }

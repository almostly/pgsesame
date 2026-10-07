"""pgsesame on Supabase: its built-in roles, and row-level security with auth.uid().

Set ``PGSESAME_TEST_SUPABASE_DSN`` to a project's direct connection, as ``postgres``
(db.<project>.supabase.co:5432); the test skips without it. It works in its own
schema, ``sesame_sb``, which it drops before and after, and creates no roles: it
uses Supabase's ``authenticated``, as an app does.
"""

import os
import textwrap
import uuid

import psycopg
import pytest
from typer.testing import CliRunner

from pgsesame.cli import app

DSN = os.environ.get("PGSESAME_TEST_SUPABASE_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="set PGSESAME_TEST_SUPABASE_DSN")

ANN, BOB = str(uuid.uuid4()), str(uuid.uuid4())
SPEC = """
version: 1
engine: postgres
principals:
  authenticated:
    type: builtin
    privileges:
      schemas:
        usage: [sesame_sb]
      tables:
        select: [sesame_sb.*]
row_level_security:
  sesame_sb.notes:
    policies:
      own_notes:
        command: select
        to: [authenticated]
        using: "auth.uid() = owner"
"""


def _sesame(*args):
    result = CliRunner().invoke(app, list(args), env={"NO_COLOR": "1"})
    return result.exit_code, result.stdout + result.stderr


@pytest.fixture
def project(tmp_path):
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS sesame_sb CASCADE")
        conn.execute("CREATE SCHEMA sesame_sb")
        conn.execute("CREATE TABLE sesame_sb.notes (owner uuid, body text)")
        conn.execute(
            "INSERT INTO sesame_sb.notes VALUES (%s, 'ann''s'), (%s, 'bob''s')",
            (ANN, BOB),
        )
        public_grants = conn.execute(
            "SELECT count(*) FROM information_schema.role_table_grants "
            "WHERE grantee = 'authenticated' AND table_schema = 'public'"
        ).fetchone()
        spec = tmp_path / "spec.yaml"
        spec.write_text(textwrap.dedent(SPEC))
        yield str(spec), public_grants
        conn.execute("DROP SCHEMA IF EXISTS sesame_sb CASCADE")


def _as_user(user_id: str) -> list:
    """Read the table as Supabase's API does for a signed-in user."""
    with psycopg.connect(DSN) as conn:
        conn.execute("SET LOCAL ROLE authenticated")
        conn.execute(
            "SELECT set_config('request.jwt.claims', %s, true)",
            ('{"sub": "%s", "role": "authenticated"}' % user_id,),
        )
        return conn.execute("SELECT body FROM sesame_sb.notes ORDER BY 1").fetchall()


def test_builtin_roles_and_row_level_security_on_supabase(project):
    spec, public_grants = project
    code, out = _sesame("plan", spec, "--dsn", DSN)
    assert code == 2, out
    assert 'CREATE ROLE "authenticated"' not in out  # Supabase's, referred to
    assert '+ GRANT SELECT ON TABLE "sesame_sb"."notes" TO "authenticated"' in out
    assert '+ CREATE POLICY "own_notes"' in out and "auth.uid() = owner" in out
    assert _sesame("apply", spec, "--dsn", DSN)[0] == 0
    code, out = _sesame("plan", spec, "--dsn", DSN)
    assert code == 0, out  # converged: Supabase stores the policy in its own form

    assert _as_user(ANN) == [("ann's",)]
    assert _as_user(BOB) == [("bob's",)]
    assert _as_user(str(uuid.uuid4())) == []

    with psycopg.connect(DSN) as conn:  # Supabase's own grants in public untouched
        assert (
            conn.execute(
                "SELECT count(*) FROM information_schema.role_table_grants "
                "WHERE grantee = 'authenticated' AND table_schema = 'public'"
            ).fetchone()
            == public_grants
        )

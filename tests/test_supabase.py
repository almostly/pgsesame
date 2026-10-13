"""pgsesame on Supabase: its built-in roles, and row-level security with auth.uid().

Set ``PGSESAME_TEST_SUPABASE_DSN`` to a project's direct connection, as ``postgres``
(db.<project>.supabase.co:5432); the test skips without it. It works in its own
schema, ``sesame_sb``, which it drops before and after, and creates no roles: it
uses Supabase's ``authenticated``, as an app does.
"""

import os
import re
import textwrap
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
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


EXAMPLE = Path(__file__).parent.parent / "examples" / "supabase"


def _example(text: str) -> str:
    """The example in a schema and roles of the test's own, never a real app's."""
    text = re.sub(r"\bapp\b", "sesame_example", text)
    text = re.sub(r"\b(reporting|metabase)\b", r"sesame_\1", text)
    return text.replace("REFERENCES auth.users ON DELETE CASCADE", "")  # no sign-ups


def _drop_example(conn):
    conn.execute("DROP SCHEMA IF EXISTS sesame_example CASCADE")
    conn.execute("DROP ROLE IF EXISTS sesame_metabase")
    conn.execute("DROP ROLE IF EXISTS sesame_reporting")


@pytest.fixture
def example(tmp_path, monkeypatch):
    monkeypatch.setenv("METABASE_PASSWORD", uuid.uuid4().hex)
    spec = tmp_path / "permissions.yaml"
    spec.write_text(_example((EXAMPLE / "permissions.yaml").read_text()))
    with psycopg.connect(DSN, autocommit=True) as conn:
        _drop_example(conn)
        conn.execute(_example((EXAMPLE / "schema.sql").read_text()).encode())
        yield str(spec)
        _drop_example(conn)


def _posts_as(role: str, user_id: str = "") -> list:
    with psycopg.connect(DSN) as conn:
        conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
        conn.execute(
            "SELECT set_config('request.jwt.claims', %s, true)",
            ('{"sub": "%s", "role": "%s"}' % (user_id, role),),
        )
        return conn.execute(
            "SELECT title FROM sesame_example.posts ORDER BY 1"
        ).fetchall()


def test_the_supabase_example_applies_and_converges(example):
    code, out = _sesame("plan", example, "--dsn", DSN)
    assert code == 2, out
    assert _sesame("apply", example, "--dsn", DSN)[0] == 0
    code, out = _sesame("plan", example, "--dsn", DSN)
    assert code == 0, out  # policies on (select auth.uid()) compare as stored

    with psycopg.connect(DSN, autocommit=True) as conn:  # as the owner, past RLS
        conn.execute(
            "INSERT INTO sesame_example.profiles (id, username) "
            "VALUES (%s, 'ann'), (%s, 'bob')",
            (ANN, BOB),
        )
        conn.execute(
            "INSERT INTO sesame_example.posts (author, title, published) "
            "VALUES (%s, 'ann public', true), (%s, 'ann draft', false)",
            (ANN, ANN),
        )
    assert _posts_as("anon") == [("ann public",)]
    assert _posts_as("authenticated", ANN) == [("ann draft",), ("ann public",)]
    assert _posts_as("authenticated", BOB) == [("ann public",)]
    assert len(_posts_as("service_role")) == 2


HOOK = """
version: 1
engine: postgres
principals:
  supabase_auth_admin:
    type: builtin
    privileges:
      schemas:
        usage: [sesame_sb]
      functions:
        execute: [sesame_sb.custom_access_token_hook]
"""


@pytest.fixture
def hook(tmp_path):
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS sesame_sb CASCADE")
        conn.execute("CREATE SCHEMA sesame_sb")
        conn.execute(
            "CREATE FUNCTION sesame_sb.custom_access_token_hook(event jsonb) "
            "RETURNS jsonb LANGUAGE sql STABLE RETURN event"
        )
        conn.execute(  # as Supabase's default privileges do in public
            "GRANT EXECUTE ON FUNCTION sesame_sb.custom_access_token_hook "
            "TO anon, authenticated"
        )
        spec = tmp_path / "hook.yaml"
        spec.write_text(textwrap.dedent(HOOK))
        yield str(spec)
        conn.execute("DROP SCHEMA IF EXISTS sesame_sb CASCADE")


def test_an_auth_hook_only_supabase_auth_admin_may_execute(hook):
    code, out = _sesame("plan", hook, "--dsn", DSN)
    assert code == 2, out
    routine = 'ROUTINE "sesame_sb"."custom_access_token_hook"(jsonb)'
    assert f'+ GRANT EXECUTE ON {routine} TO "supabase_auth_admin"' in out
    for grantee in ('"anon"', '"authenticated"', "PUBLIC"):
        assert f"- REVOKE EXECUTE ON {routine} FROM {grantee}" in out, out
    assert _sesame("apply", hook, "--dsn", DSN, "--allow-revoke")[0] == 0
    code, out = _sesame("plan", hook, "--dsn", DSN)
    assert code == 0, out

    with psycopg.connect(DSN) as conn:
        conn.execute("SET LOCAL ROLE authenticated")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT sesame_sb.custom_access_token_hook('{}')")


STORAGE = """
version: 1
engine: postgres
principals:
  authenticated:
    type: builtin
row_level_security:
  storage.objects:
    enabled: {enabled}
    policies:
      sesame_test_own_files:
        command: select
        to: [authenticated]
        using: "bucket_id = 'sesame-test' and (select auth.uid())::text = (storage.foldername(name))[1]"
"""


def _drop_storage_policy():
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute('DROP POLICY IF EXISTS "sesame_test_own_files" ON storage.objects')


@pytest.fixture
def storage(tmp_path):
    _drop_storage_policy()
    yield tmp_path
    _drop_storage_policy()


def test_storage_policies_without_switching_the_platforms_rls(storage):
    # storage.objects is the whole project's: the test drops nothing but its own
    # policy (no --allow-drop), and doesn't assume the project has no others
    spec = storage / "storage.yaml"
    spec.write_text(textwrap.dedent(STORAGE.format(enabled="true")))
    code, out = _sesame("plan", str(spec), "--dsn", DSN)
    assert '+ CREATE POLICY "sesame_test_own_files" ON "storage"."objects"' in out, out
    assert _sesame("apply", str(spec), "--dsn", DSN)[0] == 0
    assert "sesame_test_own_files" not in _sesame("plan", str(spec), "--dsn", DSN)[1]

    # switching its row-level security is the platform's: warned about, skipped
    spec.write_text(textwrap.dedent(STORAGE.format(enabled="false")))
    code, out = _sesame("plan", str(spec), "--dsn", DSN)
    assert "owned by supabase_storage_admin" in out, out
    assert "DISABLE ROW LEVEL SECURITY" not in out

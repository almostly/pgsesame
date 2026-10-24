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
    """Run the CLI; return its exit code and output."""
    result = CliRunner().invoke(app, list(args), env={"NO_COLOR": "1"})
    return result.exit_code, result.stdout + result.stderr


@pytest.fixture
def project(tmp_path):
    """Yield the spec's path and how many grants authenticated has in public."""
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
    """Return the example in the test's own schema and roles, never a real app's."""
    text = re.sub(r"\bapp\b", "sesame_example", text)
    text = re.sub(r"\b(reporting|dashboard)\b", r"sesame_\1", text)
    return text.replace("REFERENCES auth.users ON DELETE CASCADE", "")  # no sign-ups


def _drop_example(conn):
    """Drop the example's schema and roles."""
    conn.execute("DROP SCHEMA IF EXISTS sesame_example CASCADE")
    conn.execute("DROP ROLE IF EXISTS sesame_dashboard")
    conn.execute("DROP ROLE IF EXISTS sesame_reporting")


@pytest.fixture
def example(tmp_path, monkeypatch):
    """Yield the path of the example's spec, with its schema created in the database."""
    monkeypatch.setenv("DASHBOARD_PASSWORD", uuid.uuid4().hex)
    spec = tmp_path / "permissions.yaml"
    spec.write_text(_example((EXAMPLE / "permissions.yaml").read_text()))
    with psycopg.connect(DSN, autocommit=True) as conn:
        _drop_example(conn)
        conn.execute(_example((EXAMPLE / "schema.sql").read_text()).encode())
        yield str(spec)
        _drop_example(conn)


def _posts_as(role: str, user_id: str = "") -> list:
    """Return the titles of the posts ``role`` sees, signed in as ``user_id``."""
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
    """Yield a spec file for an access token hook anon and authenticated may run."""
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
    """Drop the test's policy on storage.objects."""
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute('DROP POLICY IF EXISTS "sesame_test_own_files" ON storage.objects')


@pytest.fixture
def storage(tmp_path):
    """Yield a temporary directory; drop the test's storage policy around it."""
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


JWT_ROLE = """
version: 1
engine: postgres
principals:
  sesame_test_editor:
    type: role
  authenticator:
    type: builtin
    member_of: [sesame_test_editor]
"""


@pytest.fixture
def jwt_role(tmp_path):
    """Yield a spec file that makes authenticator a member of sesame_test_editor."""
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP ROLE IF EXISTS sesame_test_editor")
        spec = tmp_path / "jwt.yaml"
        spec.write_text(textwrap.dedent(JWT_ROLE))
        yield str(spec)
        conn.execute("DROP ROLE IF EXISTS sesame_test_editor")


def test_a_custom_role_a_jwt_can_name(jwt_role):
    code, out = _sesame("plan", jwt_role, "--dsn", DSN)
    assert '+ GRANT "sesame_test_editor" TO "authenticator"' in out, out
    assert _sesame("apply", jwt_role, "--dsn", DSN)[0] == 0
    code, out = _sesame("plan", jwt_role, "--dsn", DSN)
    assert code == 0, out
    with psycopg.connect(DSN) as conn:
        assert conn.execute(
            "SELECT pg_has_role('authenticator', 'sesame_test_editor', 'MEMBER')"
        ).fetchone() == (True,)


EXPOSURE = """
version: 1
engine: postgres
principals:
  anon:
    type: builtin
"""


@pytest.fixture
def leaky(tmp_path):
    """Yield a spec file for a table anon can read with row-level security off."""
    drop = "DROP VIEW IF EXISTS public.sesame_test_view; DROP TABLE IF EXISTS public.sesame_test_leaky"
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(drop)
        conn.execute("CREATE TABLE public.sesame_test_leaky (secret text)")
        conn.execute(
            "CREATE VIEW public.sesame_test_view AS SELECT * FROM public.sesame_test_leaky"
        )
        # Supabase's default privileges in public no longer do it for a new table
        conn.execute(
            "GRANT SELECT ON public.sesame_test_leaky, public.sesame_test_view TO anon"
        )
        spec = tmp_path / "exposure.yaml"
        spec.write_text(textwrap.dedent(EXPOSURE))
        yield str(spec)
        conn.execute(drop)


def test_rows_anon_reaches_past_row_level_security_are_warned_about(leaky):
    code, out = _sesame("plan", leaky, "--dsn", DSN)
    assert "public.sesame_test_leaky: row-level security is off, and anon" in out, out
    assert "public.sesame_test_view: anon" in out and "owner's rights" in out, out
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("ALTER TABLE public.sesame_test_leaky ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER VIEW public.sesame_test_view SET (security_invoker = true)")
    code, out = _sesame("plan", leaky, "--dsn", DSN)
    assert "sesame_test" not in out, out


@pytest.fixture
def giving(tmp_path):
    """Yield a spec file for a schema whose defaults give anon each new table."""
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS sesame_given CASCADE")
        conn.execute("CREATE SCHEMA sesame_given")
        conn.execute("GRANT USAGE ON SCHEMA sesame_given TO anon")
        # what Supabase's defaults in public did before it stopped them
        conn.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA sesame_given "
            "GRANT SELECT ON TABLES TO anon"
        )
        spec = tmp_path / "exposure.yaml"
        spec.write_text(textwrap.dedent(EXPOSURE))
        yield str(spec)
        conn.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA sesame_given "
            "REVOKE SELECT ON TABLES FROM anon"
        )
        conn.execute("DROP SCHEMA sesame_given CASCADE")


def test_default_privileges_that_give_anon_new_tables_are_warned_about(giving):
    code, out = _sesame("plan", giving, "--dsn", DSN)
    assert "creates in sesame_given is given to anon (SELECT)" in out, out


def _drop_imported(conn):
    """Drop the table, function and role app_objects creates."""
    conn.execute("DROP FUNCTION IF EXISTS public.sesame_test_fn")
    conn.execute("DROP TABLE IF EXISTS public.sesame_test_items")
    conn.execute("DROP ROLE IF EXISTS sesame_test_editor")


@pytest.fixture
def app_objects():
    """Create a table, function and role in public as an app's migration does."""
    with psycopg.connect(DSN, autocommit=True) as conn:
        _drop_imported(conn)
        # granted as a migration now must, as Supabase's default privileges in
        # public no longer do; PUBLIC keeps its default EXECUTE on the function
        conn.execute("CREATE TABLE public.sesame_test_items (id int)")
        conn.execute(
            "GRANT SELECT ON public.sesame_test_items TO anon, authenticated, service_role"
        )
        conn.execute("CREATE FUNCTION public.sesame_test_fn() RETURNS int RETURN 1")
        conn.execute("CREATE ROLE sesame_test_editor")
        conn.execute("GRANT SELECT ON public.sesame_test_items TO sesame_test_editor")
        conn.execute("GRANT sesame_test_editor TO authenticator")
        yield
        _drop_imported(conn)


def test_import_leaves_the_platform_to_supabase(app_objects, tmp_path):
    imported = tmp_path / "imported.yaml"
    code, out = _sesame(
        "import", "--dsn", DSN, "--prefix", "sesame_test_", "-o", str(imported)
    )
    assert code == 0, out
    text = imported.read_text()
    assert "auth." not in text and "storage." not in text and "extensions." not in text
    assert "  anon:\n    type: builtin" in text
    assert "public.sesame_test_items" in text and "public.sesame_test_fn()" in text
    assert (
        "  authenticator:\n    type: builtin\n    member_of:\n    - sesame_test_editor"
        in text
    )
    assert "supabase_admin" not in text
    code, out = _sesame("plan", str(imported), "--dsn", DSN)
    assert code == 0, out  # the project as it is: nothing to do


def test_the_example_as_a_migration(example, tmp_path, monkeypatch):
    # no password to set, so the plan can be a committed file
    monkeypatch.delenv("DASHBOARD_PASSWORD")
    migrations = tmp_path / "migrations"
    code, out = _sesame("plan", example, "--dsn", DSN, "--migration", str(migrations))
    assert code == 2, out
    (written,) = migrations.glob("*_pgsesame.sql")
    with psycopg.connect(DSN, autocommit=True) as conn:  # as supabase db push would
        conn.execute(written.read_bytes())
    code, out = _sesame("plan", example, "--dsn", DSN)
    assert code == 0, out


REALTIME = """
version: 1
engine: postgres
principals: {}
publications:
  supabase_realtime:
    tables: [sesame_rt.feed]
"""


@pytest.fixture
def feed(tmp_path):
    """Yield a spec file that publishes sesame_rt.feed to supabase_realtime."""
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS sesame_rt CASCADE")
        conn.execute("CREATE SCHEMA sesame_rt")
        conn.execute("CREATE TABLE sesame_rt.feed (id int PRIMARY KEY)")
        spec = tmp_path / "realtime.yaml"
        spec.write_text(textwrap.dedent(REALTIME))
        yield str(spec)
        conn.execute(
            "DROP SCHEMA IF EXISTS sesame_rt CASCADE"
        )  # and from the publication


def test_realtimes_publication(feed):
    # the project's publication: no --allow-revoke, so no other table leaves it
    code, out = _sesame("plan", feed, "--dsn", DSN)
    added = '+ ALTER PUBLICATION "supabase_realtime" ADD TABLE "sesame_rt"."feed"'
    assert added in out, out
    assert _sesame("apply", feed, "--dsn", DSN)[0] == 0
    assert added not in _sesame("plan", feed, "--dsn", DSN)[1]
    with psycopg.connect(DSN) as conn:
        assert conn.execute(
            "SELECT count(*) FROM pg_publication_tables "
            "WHERE pubname = 'supabase_realtime' AND schemaname = 'sesame_rt'"
        ).fetchone() == (1,)


def test_superusers_are_the_platforms_on_supabase(tmp_path):
    # supabase_admin is the platform's, and postgres isn't a superuser: nothing
    # to warn about, and nothing a plan could change
    spec = tmp_path / "superusers.yaml"
    spec.write_text(
        "version: 1\nengine: postgres\nprincipals: {}\nmanage:\n  superusers: []\n"
    )
    code, out = _sesame("plan", str(spec), "--dsn", DSN)
    assert code == 0, out
    assert "superuser" not in out

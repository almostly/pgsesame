"""Redshift dynamic data masking, planned and applied end to end.

Set ``PGSESAME_TEST_REDSHIFT_DSN`` to a superuser connection on a Redshift with
masking (Amazon Redshift, or oblako's redshift-local from the release with
masking policies); the tests skip without it, and skip on an engine without
svv_masking_policy. They work in their own schema, ``sesame_ddm``, and drop it,
their policies and their identities before and after.
"""

import json
import os
import textwrap

import psycopg
import pytest
from typer.testing import CliRunner

from pgsesame.cli import app

DSN = os.environ.get("PGSESAME_TEST_REDSHIFT_DSN", "")


def _has_masking() -> bool:
    if not DSN:
        return False
    try:
        with psycopg.connect(DSN, connect_timeout=10) as conn:
            conn.execute("select 1 from svv_masking_policy limit 1")
        return True
    except psycopg.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _has_masking(),
    reason="set PGSESAME_TEST_REDSHIFT_DSN to a Redshift with masking",
)

ROLES = ("sesame_ddm_support", "sesame_ddm_pii", "sesame_ddm_fraud")
SPEC = """
version: 1
engine: redshift
principals:
  sesame_ddm_support: {type: role}
  sesame_ddm_pii: {type: role}
  sesame_ddm_fraud: {type: role}
masking:
  policies:
    sesame_redact:
      type: varchar(64)
      using: "'***'::varchar(64)"
    sesame_email_domain:
      type: varchar(64)
      using: "regexp_replace(value, '^[^@]+', '***')"
  columns:
    sesame_ddm.customers.email:
      mask: sesame_redact
      unmasked: [sesame_ddm_pii]
      roles:
        sesame_ddm_support: sesame_email_domain
"""


def _cleanup(conn) -> None:
    conn.execute("DROP SCHEMA IF EXISTS sesame_ddm CASCADE")  # takes the attachments
    policies = conn.execute(
        "select policy_name from svv_masking_policy "
        "where policy_name like 'sesame%' or policy_name like 'pgsesame%'"
    ).fetchall()
    for (name,) in policies:
        # detach first: a policy attached elsewhere (a test's own) can't be dropped
        for table, grantee, gtype, cols in conn.execute(
            "select schema_name || '.' || table_name, grantee, grantee_type, output_columns "
            "from svv_attached_masking_policy where policy_name = %s",
            (name,),
        ).fetchall():
            who = (
                "PUBLIC"
                if gtype == "public"
                else (f'ROLE "{grantee}"' if gtype == "role" else f'"{grantee}"')
            )
            col = cols.strip("[]").replace('"', "")
            conn.execute(f'DETACH MASKING POLICY "{name}" ON {table}({col}) FROM {who}')
        conn.execute(f'DROP MASKING POLICY "{name}"')
    for role in ROLES:
        try:
            conn.execute(f"DROP ROLE {role}")
        except psycopg.Error:
            pass  # not there


@pytest.fixture
def db(tmp_path):
    with psycopg.connect(DSN, autocommit=True) as conn:
        _cleanup(conn)
        conn.execute("CREATE SCHEMA sesame_ddm")
        conn.execute(
            "CREATE TABLE sesame_ddm.customers (id int, email varchar(64), phone varchar(20))"
        )
        yield conn
        _cleanup(conn)


def _spec(tmp_path, text=SPEC):
    path = tmp_path / "spec.yaml"
    path.write_text(textwrap.dedent(text))
    return str(path)


def _sesame(*args):
    result = CliRunner().invoke(app, [*args, "--dsn", DSN], env={"NO_COLOR": "1"})
    return result.exit_code, result.stdout + result.stderr


def _attached(conn) -> set[tuple]:
    return set(
        conn.execute(
            "select policy_name, grantee, grantee_type, priority, output_columns "
            "from svv_attached_masking_policy where schema_name = 'sesame_ddm'"
        ).fetchall()
    )


def test_plan_apply_then_nothing_to_do(db, tmp_path):
    spec = _spec(tmp_path)
    code, out = _sesame("plan", spec)
    assert code == 2, out
    assert 'CREATE MASKING POLICY "sesame_redact" WITH ("value" varchar(64))' in out
    assert 'CREATE MASKING POLICY "sesame_unmasked_varchar_64"' in out
    assert (
        'ATTACH MASKING POLICY "sesame_redact" ON "sesame_ddm"."customers" ("email") '
        "TO PUBLIC PRIORITY 10" in out
    )
    code, out = _sesame("apply", spec)
    assert code == 0, out
    assert _attached(db) == {
        ("sesame_redact", "public", "public", 10, '["email"]'),
        ("sesame_email_domain", "sesame_ddm_support", "role", 20, '["email"]'),
        ("sesame_unmasked_varchar_64", "sesame_ddm_pii", "role", 1000, '["email"]'),
    }
    (expression,) = db.execute(
        "select policy_expression from svv_masking_policy "
        "where policy_name = 'sesame_unmasked_varchar_64'"
    ).fetchone()
    assert json.loads(expression)[0]["type"] == "character varying(64)"
    # converged: Redshift's stored form compared by round trip, not as text
    code, out = _sesame("plan", spec)
    assert code == 0, out
    # the probes were rolled back
    assert db.execute(
        "select count(*) from svv_masking_policy where policy_name like 'pgsesame_probe%'"
    ).fetchone() == (0,)


def test_an_expression_change_is_an_alter(db, tmp_path):
    assert _sesame("apply", _spec(tmp_path))[0] == 0
    changed = SPEC.replace("'***'::varchar(64)", "'#####'::varchar(64)")
    code, out = _sesame("plan", _spec(tmp_path, changed))
    assert code == 2, out
    assert (
        "~ ALTER MASKING POLICY \"sesame_redact\" USING ('#####'::varchar(64))" in out
    )
    assert "ATTACH" not in out and "DETACH" not in out
    assert _sesame("apply", _spec(tmp_path, changed))[0] == 0
    assert _sesame("plan", _spec(tmp_path, changed))[0] == 0


def test_roles_reordered_move_priorities_without_a_revoke(db, tmp_path):
    two = SPEC.replace(
        "        sesame_ddm_support: sesame_email_domain\n",
        "        sesame_ddm_support: sesame_email_domain\n"
        "        sesame_ddm_fraud: sesame_redact\n",
    )
    assert _sesame("apply", _spec(tmp_path, two))[0] == 0
    swapped = SPEC.replace(
        "        sesame_ddm_support: sesame_email_domain\n",
        "        sesame_ddm_fraud: sesame_redact\n"
        "        sesame_ddm_support: sesame_email_domain\n",
    )
    code, out = _sesame("apply", _spec(tmp_path, swapped))  # no --allow-revoke
    assert code == 0, out
    # fraud's policy is the mask's, but it never shares PUBLIC's priority: on
    # Redshift that ATTACH replaces PUBLIC's own, unmasking the column for
    # everyone else. Support, written after it, outranks it
    attached = _attached(db)
    assert ("sesame_redact", "public", "public", 10, '["email"]') in attached
    assert ("sesame_redact", "sesame_ddm_fraud", "role", 20, '["email"]') in attached
    assert (
        "sesame_email_domain",
        "sesame_ddm_support",
        "role",
        30,
        '["email"]',
    ) in attached
    assert _sesame("plan", _spec(tmp_path, swapped))[0] == 0


def test_taking_a_role_off_needs_allow_revoke(db, tmp_path):
    assert _sesame("apply", _spec(tmp_path))[0] == 0
    fewer = SPEC.replace("      unmasked: [sesame_ddm_pii]\n", "")
    code, out = _sesame("apply", _spec(tmp_path, fewer))
    assert "skipped: needs --allow-revoke" in out, out
    assert any(a[1] == "sesame_ddm_pii" for a in _attached(db))
    code, out = _sesame(
        "apply", _spec(tmp_path, fewer), "--allow-revoke", "--allow-drop"
    )
    assert code == 0, out
    assert not any(a[1] == "sesame_ddm_pii" for a in _attached(db))
    # the pass-through policy nothing uses any more is dropped too
    assert db.execute(
        "select count(*) from svv_masking_policy where policy_name like 'sesame_unmasked%'"
    ).fetchone() == (0,)


def test_a_type_change_replaces_the_policy_only_with_allow_drop(db, tmp_path):
    assert _sesame("apply", _spec(tmp_path))[0] == 0
    db.execute(
        "ATTACH MASKING POLICY sesame_redact ON sesame_ddm.customers(phone) TO PUBLIC"
    )  # someone else's column: put back after the replacement
    wider = SPEC.replace(
        "    sesame_redact:\n      type: varchar(64)",
        "    sesame_redact:\n      type: varchar(128)",
    )
    code, out = _sesame("apply", _spec(tmp_path, wider))
    assert "skipped: needs --allow-drop" in out, out
    code, out = _sesame("apply", _spec(tmp_path, wider), "--allow-drop")
    assert code == 0, out
    (inputs,) = db.execute(
        "select input_columns from svv_masking_policy where policy_name = 'sesame_redact'"
    ).fetchone()
    assert json.loads(inputs)[0]["type"] == "character varying(128)"
    assert ("sesame_redact", "public", "public", 0, '["phone"]') in _attached(db)
    assert ("sesame_redact", "public", "public", 10, '["email"]') in _attached(db)
    assert _sesame("plan", _spec(tmp_path, wider))[0] == 0


def test_a_missing_column_stops_the_plan(db, tmp_path):
    spec = SPEC.replace("sesame_ddm.customers.email:", "sesame_ddm.customers.nope:")
    code, out = _sesame("plan", _spec(tmp_path, spec))
    assert code == 1 and "sesame_ddm.customers.nope: the column does not exist" in out


def test_import_writes_masking_in_pgsesames_model_and_the_plan_corrects_it(
    db, tmp_path
):
    # set up by hand, not as pgsesame would: odd priorities and a pass-through
    # policy of its own, as on a cluster masked before pgsesame
    for stmt in [
        "CREATE ROLE sesame_ddm_support",
        "CREATE ROLE sesame_ddm_pii",
        "CREATE MASKING POLICY sesame_redact WITH (email varchar(64)) "
        "USING ('***'::varchar(64))",
        "CREATE MASKING POLICY sesame_domain WITH (email varchar(64)) "
        "USING (regexp_replace(email, '^[^@]+', '***'))",
        "CREATE MASKING POLICY sesame_raw WITH (email varchar(64)) USING (email)",
        "ATTACH MASKING POLICY sesame_redact ON sesame_ddm.customers(email) TO PUBLIC PRIORITY 5",
        "ATTACH MASKING POLICY sesame_domain ON sesame_ddm.customers(email) "
        "TO ROLE sesame_ddm_support PRIORITY 30",
        "ATTACH MASKING POLICY sesame_raw ON sesame_ddm.customers(email) "
        "TO ROLE sesame_ddm_pii PRIORITY 50",
    ]:
        db.execute(stmt)
    imported = tmp_path / "imported.yaml"
    result = CliRunner().invoke(
        app,
        [
            "import",
            "--dsn",
            DSN,
            "--engine",
            "redshift",
            "--prefix",
            "sesame_ddm_",
            "--schema",
            "sesame_ddm",
            "-o",
            str(imported),
        ],
        env={"NO_COLOR": "1"},
    )
    out = result.stdout + result.stderr
    assert result.exit_code == 0, out
    assert "sesame_raw passes values through" in out
    assert "attached another way than pgsesame's model (priorities [5, 30, 50])" in out
    import yaml

    written = yaml.safe_load(imported.read_text())
    assert written["masking"]["columns"] == {
        "sesame_ddm.customers.email": {
            "mask": "sesame_redact",
            "unmasked": ["sesame_ddm_pii"],
            "roles": {"sesame_ddm_support": "sesame_domain"},
        }
    }
    assert set(written["masking"]["policies"]) == {"sesame_redact", "sesame_domain"}

    # the first plan is the correction to pgsesame's model
    code, out = _sesame("plan", str(imported))
    assert code == 2, out
    assert 'CREATE MASKING POLICY "sesame_unmasked_varchar_64"' in out
    assert "TO PUBLIC PRIORITY 10" in out and "PRIORITY 1000" in out
    code, out = _sesame("apply", str(imported), "--allow-revoke")
    assert code == 0, out
    code, out = _sesame("plan", str(imported))
    assert code == 0, out
    assert _attached(db) == {
        ("sesame_redact", "public", "public", 10, '["email"]'),
        ("sesame_domain", "sesame_ddm_support", "role", 20, '["email"]'),
        ("sesame_unmasked_varchar_64", "sesame_ddm_pii", "role", 1000, '["email"]'),
    }


def test_import_of_masking_in_the_right_order_plans_nothing(db, tmp_path):
    # a role's mask at priority 0 with nothing competing (as on dwhcluster1's
    # sensitive_data): the numbers differ from pgsesame's, what anyone reads doesn't
    for stmt in [
        "CREATE ROLE sesame_ddm_support",
        "CREATE MASKING POLICY sesame_domain WITH (email varchar(64)) "
        "USING (regexp_replace(email, '^[^@]+', '***'))",
        "ATTACH MASKING POLICY sesame_domain ON sesame_ddm.customers(email) "
        "TO ROLE sesame_ddm_support PRIORITY 0",
    ]:
        db.execute(stmt)
    imported = tmp_path / "imported.yaml"
    result = CliRunner().invoke(
        app,
        [
            "import",
            "--dsn",
            DSN,
            "--engine",
            "redshift",
            "--prefix",
            "sesame_ddm_",
            "--schema",
            "sesame_ddm",
            "-o",
            str(imported),
        ],
        env={"NO_COLOR": "1"},
    )
    out = result.stdout + result.stderr
    assert result.exit_code == 0, out
    assert "attached another way" not in out  # nothing to correct
    code, out = _sesame("plan", str(imported))
    assert code == 0, out  # import -> plan: nothing to do
    assert ("sesame_domain", "sesame_ddm_support", "role", 0, '["email"]') in _attached(
        db
    )

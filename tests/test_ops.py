"""The SQL each operation renders to (no database)."""

import pytest

from pgsesame.ops import AddMember, AlterLogin, CreateRole, Grant, RemoveMember, Revoke


@pytest.mark.parametrize(
    ("op", "expected"),
    [
        (CreateRole(name="reader", login=False), 'CREATE ROLE "reader" NOLOGIN'),
        (
            CreateRole(name="alice", login=True, password="s3cret"),
            "CREATE ROLE \"alice\" LOGIN PASSWORD 's3cret'",
        ),
        (AlterLogin(name="etl", login=True), 'ALTER ROLE "etl" LOGIN'),
        (AddMember(member="alice", role="reader"), 'GRANT "reader" TO "alice"'),
        (RemoveMember(member="alice", role="reader"), 'REVOKE "reader" FROM "alice"'),
        (
            Grant(
                grantee="r",
                object_type="schemas",
                object_name="analytics",
                privilege="usage",
            ),
            'GRANT USAGE ON SCHEMA "analytics" TO "r"',
        ),
        (
            Grant(
                grantee="r",
                object_type="views",
                object_name="marts.v",
                privilege="select",
            ),
            'GRANT SELECT ON TABLE "marts"."v" TO "r"',
        ),
        (
            Grant(
                grantee="r",
                object_type="databases",
                object_name="dev",
                privilege="connect",
            ),
            'GRANT CONNECT ON DATABASE "dev" TO "r"',
        ),
        (
            Revoke(
                grantee="r",
                object_type="sequences",
                object_name="s.ids",
                privilege="usage",
            ),
            'REVOKE USAGE ON SEQUENCE "s"."ids" FROM "r"',
        ),
    ],
)
def test_rendered_sql(op, expected):
    assert op.statement().as_string() == expected


def test_names_are_quoted_not_pasted():
    op = Grant(
        grantee='IAM:alice"; DROP TABLE x; --',
        object_type="tables",
        object_name='analytics.Daily "Sales"',
        privilege="select",
    )
    assert op.statement().as_string() == (
        'GRANT SELECT ON TABLE "analytics"."Daily ""Sales""" '
        'TO "IAM:alice""; DROP TABLE x; --"'
    )


def test_a_plan_never_shows_a_password():
    op = CreateRole(name="alice", login=True, password="s3cret")
    assert "s3cret" not in op.display().as_string()
    assert "s3cret" not in repr(op) and "s3cret" not in str(op)


def test_removals_are_gated():
    assert Revoke.gate == RemoveMember.gate == "revoke"
    assert Grant.gate is None and CreateRole.gate is None


def test_row_level_security_sql():
    from pgsesame.ops import (
        AlterPolicy,
        CreatePolicy,
        DisableRowSecurity,
        DropPolicy,
        EnableRowSecurity,
        ForceRowSecurity,
    )

    create = CreatePolicy(
        table="app.notes",
        name="own notes",
        command="update",
        permissive=False,
        roles=("authenticated", "public"),
        using="owner = current_user",
        with_check="owner = current_user",
    )
    assert create.statement().as_string() == (
        'CREATE POLICY "own notes" ON "app"."notes" AS RESTRICTIVE FOR UPDATE '
        'TO "authenticated", PUBLIC USING (owner = current_user) '
        "WITH CHECK (owner = current_user)"
    )
    alter = AlterPolicy(table="app.notes", name="p", roles=("public",), using="true")
    assert (
        alter.statement().as_string()
        == 'ALTER POLICY "p" ON "app"."notes" TO PUBLIC USING (true)'
    )
    assert DropPolicy(table="app.notes", name="p").statement().as_string() == (
        'DROP POLICY "p" ON "app"."notes"'
    )
    assert EnableRowSecurity(table="app.notes").statement().as_string() == (
        'ALTER TABLE "app"."notes" ENABLE ROW LEVEL SECURITY'
    )
    assert ForceRowSecurity(table="app.notes", force=False).statement().as_string() == (
        'ALTER TABLE "app"."notes" NO FORCE ROW LEVEL SECURITY'
    )
    assert DisableRowSecurity.gate == DropPolicy.gate == "drop"
    assert DropPolicy.order < CreatePolicy.order  # a replaced policy keeps its name


def test_column_grants_name_the_column_and_its_table():
    from pgsesame.ops import Grant, Revoke

    grant = Grant(
        grantee="bi",
        object_type="columns",
        object_name="crm.c.email",
        privilege="select",
    )
    assert (
        grant.statement().as_string(None)
        == 'GRANT SELECT ("email") ON TABLE "crm"."c" TO "bi"'
    )
    revoke = Revoke(
        grantee="bi",
        object_type="columns",
        object_name="crm.c.email",
        privilege="update",
        grantee_identity="role",
    )
    assert (
        revoke.statement().as_string(None)
        == 'REVOKE UPDATE ("email") ON TABLE "crm"."c" FROM ROLE "bi"'
    )

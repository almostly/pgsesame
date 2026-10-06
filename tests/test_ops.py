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

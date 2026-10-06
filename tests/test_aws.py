"""plan and apply over AWS: IAM credentials and the Redshift Data API.

The same tests run against oblako (its Redshift API and Data API) and against
Amazon Redshift. Set:

* ``PGSESAME_TEST_REDSHIFT_DSN``: an admin connection, to set up and clean up;
* ``PGSESAME_TEST_AWS_WORKGROUP`` (Serverless) or ``PGSESAME_TEST_AWS_CLUSTER``;
* ``PGSESAME_TEST_AWS_DATABASE`` (default ``dev``);
* for the Data API on a cluster, ``PGSESAME_TEST_AWS_DB_USER`` or
  ``PGSESAME_TEST_AWS_SECRET_ARN``;
* AWS credentials and, for oblako, its endpoints (``AWS_ENDPOINT_URL_REDSHIFT``,
  ``AWS_ENDPOINT_URL_REDSHIFT_SERVERLESS``, ``AWS_ENDPOINT_URL_REDSHIFT_DATA``).

The IAM identity's database user is made a superuser for the test (a new IAM
user holds no privileges) and is dropped afterwards.
"""

import os
import secrets
import textwrap

import psycopg
import pytest
from psycopg import sql
from typer.testing import CliRunner

from pgsesame.cli import app

boto3 = pytest.importorskip("boto3")

ADMIN = os.environ.get("PGSESAME_TEST_REDSHIFT_DSN", "")
WORKGROUP = os.environ.get("PGSESAME_TEST_AWS_WORKGROUP", "")
CLUSTER = os.environ.get("PGSESAME_TEST_AWS_CLUSTER", "")
DATABASE = os.environ.get("PGSESAME_TEST_AWS_DATABASE", "dev")
DB_USER = os.environ.get("PGSESAME_TEST_AWS_DB_USER", "")
SECRET_ARN = os.environ.get("PGSESAME_TEST_AWS_SECRET_ARN", "")
P = "aw_test_"
pytestmark = [
    pytest.mark.redshift,
    pytest.mark.skipif(
        not (ADMIN and (WORKGROUP or CLUSTER)),
        reason="set PGSESAME_TEST_REDSHIFT_DSN and an AWS workgroup or cluster",
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
        usage: [aw_test]
      tables:
        select: [aw_test.*]
  {P}group:
    type: group
  {P}user:
    type: user
    password: disabled
    groups: [{P}group]
    member_of: [{P}reader]
"""


def _where() -> list[str]:
    where = ["--database", DATABASE]
    return where + (["--workgroup", WORKGROUP] if WORKGROUP else ["--cluster", CLUSTER])


def _iam_user() -> str:
    """Return the database user AWS maps this IAM identity to, created by a login.

    Redshift creates the user on its first login, not when it issues the
    credentials, so the test logs in once.
    """
    if WORKGROUP:
        api = boto3.client("redshift-serverless")
        creds = api.get_credentials(workgroupName=WORKGROUP, dbName=DATABASE)
        endpoint = api.get_workgroup(workgroupName=WORKGROUP)["workgroup"]["endpoint"]
        user, password = creds["dbUser"], creds["dbPassword"]
    else:
        api = boto3.client("redshift")
        creds = api.get_cluster_credentials_with_iam(
            ClusterIdentifier=CLUSTER, DbName=DATABASE
        )
        found = api.describe_clusters(ClusterIdentifier=CLUSTER)["Clusters"][0]
        endpoint = {
            "address": found["Endpoint"]["Address"],
            "port": found["Endpoint"]["Port"],
        }
        user, password = creds["DbUser"], creds["DbPassword"]
    psycopg.connect(
        host=endpoint["address"],
        port=endpoint["port"],
        dbname=DATABASE,
        user=user,
        password=password,
        sslmode="require",
    ).close()
    return user


def _cleanup(conn: psycopg.Connection) -> None:
    conn.execute("DROP SCHEMA IF EXISTS aw_test CASCADE")
    for template, query in (
        (
            "DROP USER {}",
            "SELECT usename FROM pg_user WHERE usename LIKE 'aw\\_test\\_%'",
        ),
        (
            "DROP GROUP {}",
            "SELECT groname FROM pg_catalog.pg_group WHERE groname LIKE 'aw\\_test\\_%'",
        ),
        (
            "DROP ROLE {}",
            "SELECT role_name FROM svv_roles WHERE role_name LIKE 'aw\\_test\\_%'",
        ),
    ):
        for (name,) in conn.execute(query).fetchall():
            conn.execute(sql.SQL(template).format(sql.Identifier(name)))


@pytest.fixture
def admin():
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        _cleanup(conn)
        conn.execute("CREATE SCHEMA aw_test")
        conn.execute("CREATE TABLE aw_test.events (id int)")
        yield conn
        _cleanup(conn)


def _sesame(*args):
    result = CliRunner().invoke(app, list(args), env={"NO_COLOR": "1"})
    crash = (
        f"\n{result.exception!r}"
        if result.exception and not isinstance(result.exception, SystemExit)
        else ""
    )
    return result.exit_code, result.stdout + result.stderr + crash


def _converge(tmp_path, *how: str) -> None:
    spec = tmp_path / "spec.yaml"
    spec.write_text(textwrap.dedent(SPEC))
    code, out = _sesame("plan", str(spec), *how, *_where())
    assert code == 2, out
    assert f'+ GRANT ROLE "{P}reader" TO "{P}user"' in out
    code, out = _sesame("apply", str(spec), *how, *_where())
    assert code == 0, out
    code, out = _sesame("plan", str(spec), *how, *_where())
    assert code == 0 and "nothing to do" in out, out


@pytest.fixture
def iam_superuser(admin):
    """Make this IAM identity's database user a superuser for the test, then drop it."""
    user = _iam_user()
    # Redshift refuses a superuser without a password ("Superusers cannot have
    # disabled passwords") and an IAM user has none, so it gets one here; it
    # still signs in through IAM
    password = "Aa1" + secrets.token_urlsafe(16)
    admin.execute(
        sql.SQL("ALTER USER {} PASSWORD {} CREATEUSER").format(
            sql.Identifier(user), sql.Literal(password)
        )
    )
    yield user
    # what the user created (the roles) is owned by it on Redshift: drop that first
    _cleanup(admin)
    admin.execute(sql.SQL("DROP USER IF EXISTS {}").format(sql.Identifier(user)))


def test_iam_credentials(iam_superuser, tmp_path):
    _converge(tmp_path, "--iam")


def test_data_api(admin, tmp_path, request):
    how = ["--data-api"]
    if SECRET_ARN:
        how += ["--secret-arn", SECRET_ARN]
    elif DB_USER:
        how += ["--db-user", DB_USER]
    else:  # Serverless without a secret: statements run as the IAM identity
        request.getfixturevalue("iam_superuser")
    _converge(tmp_path, *how)

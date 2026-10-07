"""Aurora PostgreSQL through the RDS Data API, on oblako (or AWS).

Set ``PGSESAME_TEST_RDS_DSN`` to the PostgreSQL the Data API runs statements in
(for set-up and checks), and point boto3 at the RDS and RDS Data APIs; the tests
skip without them. On oblako:

    PGSESAME_TEST_RDS_DSN="host=localhost port=5432 user=oblako password=oblako dbname=oblako" \\
    AWS_ENDPOINT_URL_RDS=http://localhost:8014 AWS_ENDPOINT_URL_RDS_DATA=http://localhost:8006 \\
    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \\
      uv run pytest tests/test_rds.py

The cluster (``PGSESAME_TEST_RDS_CLUSTER``, default ``sesame-aurora``) is created
if the RDS API doesn't have it. pgsesame finds its ARN from the identifier.
"""

import os
import textwrap

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from typer.testing import CliRunner

from pgsesame.cli import app

DSN = os.environ.get("PGSESAME_TEST_RDS_DSN", "")
CLUSTER = os.environ.get("PGSESAME_TEST_RDS_CLUSTER", "sesame-aurora")
SECRET = os.environ.get(
    "PGSESAME_TEST_RDS_SECRET_ARN",
    "arn:aws:secretsmanager:us-east-1:000000000000:secret:sesame-aurora",
)
pytestmark = pytest.mark.skipif(not DSN, reason="set PGSESAME_TEST_RDS_DSN")
P = "sesame_rds_"
SPEC = f"""
version: 1
engine: postgres
principals:
  {P}reader:
    type: role
    privileges:
      schemas:
        usage: [{P}app]
      tables:
        select: [{P}app.notes]
row_level_security:
  {P}app.notes:
    policies:
      readers:
        command: select
        to: [{P}reader]
        using: "true"
"""


def _cleanup(conn) -> None:
    conn.execute(f"DROP SCHEMA IF EXISTS {P}app CASCADE")
    for (name,) in conn.execute(
        "SELECT rolname FROM pg_roles WHERE rolname LIKE %s", (P + "%",)
    ).fetchall():
        conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


@pytest.fixture
def cluster(tmp_path):
    import boto3

    rds = boto3.client("rds")
    try:
        rds.describe_db_clusters(DBClusterIdentifier=CLUSTER)
    except rds.exceptions.DBClusterNotFoundFault:
        rds.create_db_cluster(
            DBClusterIdentifier=CLUSTER,
            Engine="aurora-postgresql",
            MasterUsername="oblako",
            MasterUserPassword="oblako-pw",
            EnableHttpEndpoint=True,
        )
    with psycopg.connect(DSN, autocommit=True) as conn:
        _cleanup(conn)
        conn.execute(f"CREATE SCHEMA {P}app")
        conn.execute(f"CREATE TABLE {P}app.notes (body text)")
        spec = tmp_path / "spec.yaml"
        spec.write_text(textwrap.dedent(SPEC))
        yield str(spec), conn
        _cleanup(conn)


def _sesame(*args):
    database = str(conninfo_to_dict(DSN).get("dbname", "postgres"))
    via = [
        "--data-api",
        "--rds",
        CLUSTER,
        "--secret-arn",
        SECRET,
        "--database",
        database,
    ]
    result = CliRunner().invoke(app, [*args, *via], env={"NO_COLOR": "1"})
    return result.exit_code, result.stdout + result.stderr


def test_plan_and_apply_through_the_rds_data_api(cluster):
    spec, conn = cluster
    code, out = _sesame("plan", spec)
    assert code == 2, out
    assert f"plan · rds-data:{CLUSTER}:" in out
    assert f'+ CREATE ROLE "{P}reader"' in out
    assert f'+ CREATE POLICY "readers" ON "{P}app"."notes"' in out
    code, out = _sesame("apply", spec)
    assert code == 0, out
    # a policy's roles come back over the Data API too, so nothing is left to do
    code, out = _sesame("plan", spec)
    assert code == 0, out
    assert conn.execute(
        "SELECT has_table_privilege(%s, %s, 'SELECT')", (f"{P}reader", f"{P}app.notes")
    ).fetchone() == (True,)

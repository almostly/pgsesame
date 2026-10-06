"""Redshift connections through AWS: IAM credentials, and the Redshift Data API.

Both need ``pip install "pgsesame[redshift]"`` (boto3) and take AWS credentials
from the usual chain (environment, profile, instance role).

* ``iam_database``: ask AWS for temporary database credentials
  (``GetClusterCredentialsWithIAM`` for a provisioned cluster,
  ``redshift-serverless GetCredentials`` for a workgroup), then connect directly.
  No password is stored anywhere; the machine needs a network path to Redshift.
* ``DataApiDatabase``: run statements over the Redshift Data API, AWS's HTTPS
  API, so no network path to the database is needed. The plan runs as one
  ``BatchExecuteStatement``, which Redshift runs as a single transaction.

Each provides what the planner uses from a connection: ``rows``, ``run``,
``render``, ``database`` and ``target``.
"""

from __future__ import annotations

import time
from typing import Any

from psycopg import sql
from pydantic import SecretStr

from pgsesame.db import Database


def _boto3():
    try:
        import boto3
    except ImportError as e:
        raise RuntimeError(
            'connecting through AWS needs boto3: pip install "pgsesame[redshift]"'
        ) from e
    return boto3


def iam_database(
    database: str, cluster: str | None = None, workgroup: str | None = None
) -> Database:
    """Connect to Redshift with temporary credentials AWS issues for this identity."""
    boto3 = _boto3()
    if workgroup:
        serverless = boto3.client("redshift-serverless")
        creds = serverless.get_credentials(workgroupName=workgroup, dbName=database)
        endpoint = serverless.get_workgroup(workgroupName=workgroup)["workgroup"][
            "endpoint"
        ]
        user, password = creds["dbUser"], creds["dbPassword"]
    elif cluster:
        redshift = boto3.client("redshift")
        creds = redshift.get_cluster_credentials_with_iam(
            ClusterIdentifier=cluster, DbName=database
        )
        endpoint = redshift.describe_clusters(ClusterIdentifier=cluster)["Clusters"][0][
            "Endpoint"
        ]
        endpoint = {"address": endpoint["Address"], "port": endpoint["Port"]}
        user, password = creds["DbUser"], creds["DbPassword"]
    else:
        raise ValueError("--iam needs --cluster or --workgroup")
    from psycopg.conninfo import make_conninfo

    dsn = make_conninfo(
        host=endpoint["address"],
        port=endpoint["port"],
        dbname=database,
        user=user,
        password=password,
        sslmode="require",
    )
    return Database(SecretStr(dsn))


class DataApiError(Exception):
    """A statement the Redshift Data API ran failed."""


class DataApiDatabase:
    """A Redshift database reached through the Redshift Data API."""

    def __init__(
        self,
        database: str,
        cluster: str | None = None,
        workgroup: str | None = None,
        secret_arn: str | None = None,
        db_user: str | None = None,
        client: Any = None,
    ):
        """Address a cluster or workgroup; authenticate with a secret, a DB user or IAM."""
        if not (cluster or workgroup):
            raise ValueError("--data-api needs --cluster or --workgroup")
        self.client = client or _boto3().client("redshift-data")
        self._database = database
        self._where: dict[str, str] = {"Database": database}
        if workgroup:
            self._where["WorkgroupName"] = workgroup
        else:
            self._where["ClusterIdentifier"] = str(cluster)
        if secret_arn:
            self._where["SecretArn"] = secret_arn
        elif db_user:
            self._where["DbUser"] = db_user
        self._label = f"data-api:{workgroup or cluster}:{database}"

    @property
    def database(self) -> str:
        """Return the database's name."""
        return self._database

    @property
    def target(self) -> str:
        """Return where the statements go: ``data-api:<cluster or workgroup>:<db>``."""
        return self._label

    def _wait(self, statement_id: str) -> dict[str, Any]:
        delay = 0.1
        while True:
            described = self.client.describe_statement(Id=statement_id)
            status = described["Status"]
            if status == "FINISHED":
                return described
            if status in ("FAILED", "ABORTED"):
                raise DataApiError(described.get("Error") or status)
            time.sleep(delay)
            delay = min(delay * 2, 1.0)

    def rows(self, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        """Run a catalog query and return its rows."""
        if params:
            raise ValueError("the Data API path takes no parameters")
        started = self.client.execute_statement(Sql=query, **self._where)
        described = self._wait(started["Id"])
        if not described.get("HasResultSet"):
            return []
        out: list[tuple[Any, ...]] = []
        token = None
        while True:
            kwargs = {"Id": started["Id"]}
            if token:
                kwargs["NextToken"] = token
            page = self.client.get_statement_result(**kwargs)
            out += [
                tuple(_value(field) for field in record) for record in page["Records"]
            ]
            token = page.get("NextToken")
            if not token:
                return out

    def render(self, statement: sql.Composed) -> str:
        """Return a composed statement as SQL text (quoting needs no connection)."""
        return statement.as_string()

    def run(self, statements: list[sql.Composed]) -> None:
        """Run the statements as one batch, which Redshift runs as one transaction."""
        sqls = [self.render(statement) for statement in statements]
        started = self.client.batch_execute_statement(Sqls=sqls, **self._where)
        self._wait(started["Id"])

    def close(self) -> None:
        """Nothing to close: each call is its own HTTPS request."""


def _value(field: dict[str, Any]) -> Any:
    if field.get("isNull"):
        return None
    for key in ("stringValue", "longValue", "booleanValue", "doubleValue"):
        if key in field:
            return field[key]
    return None

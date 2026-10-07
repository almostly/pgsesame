"""Connections through AWS: Redshift and RDS/Aurora, by IAM or a Data API.

Both need ``pip install "pgsesame[redshift]"`` (boto3) and take AWS credentials
from the usual chain (environment, profile, instance role).

* ``iam_database``: ask AWS for temporary database credentials
  (``GetClusterCredentialsWithIAM`` for a provisioned cluster,
  ``redshift-serverless GetCredentials`` for a workgroup), then connect directly.
  No password is stored anywhere; the machine needs a network path to Redshift.
* ``DataApiDatabase``: run statements over the Redshift Data API, AWS's HTTPS
  API, so no network path to the database is needed. The plan runs as one
  ``BatchExecuteStatement``, which Redshift runs as a single transaction.

For Amazon RDS and Aurora PostgreSQL:

* ``rds_iam_database``: sign an IAM authentication token (``generate_db_auth_token``,
  valid 15 minutes) and connect over TLS with it as the password. The only way
  into an Aurora cluster made with express configuration, whose admin user is set
  up for it.
* ``RdsDataApiDatabase``: the RDS Data API, which unlike Redshift's has
  transactions, so apply runs between BeginTransaction and CommitTransaction.

``describe_rds`` finds an RDS instance or Aurora cluster by its identifier, so
only that needs to be given. Each provides what the planner uses from a
connection: ``rows``, ``run``, ``render``, ``database`` and ``target``.
"""

from __future__ import annotations

import time
from typing import Any

from psycopg import sql
from pydantic import SecretStr

from pgsesame.db import Database


_SESSION: dict[str, str | None] = {"profile": None, "region": None}


def configure(profile: str | None = None, region: str | None = None) -> None:
    """Use this AWS profile and region for the connections made from now on."""
    _SESSION["profile"], _SESSION["region"] = profile, region


def configure_defaults(profile: str | None, region: str | None) -> None:
    """Fill in a profile and region where none was given (a saved target's)."""
    _SESSION["profile"] = _SESSION["profile"] or profile
    _SESSION["region"] = _SESSION["region"] or region


def _boto3():
    try:
        import boto3
    except ImportError as e:
        raise RuntimeError(
            "connecting through AWS needs boto3, which comes with the aws extra: "
            "uv tool install --force 'pgsesame[aws]' (or pip install 'pgsesame[aws]')"
        ) from e
    return boto3


def _client(service: str) -> Any:
    """Return a boto3 client from the configured profile and region.

    The region comes from --region, else AWS_REGION / AWS_DEFAULT_REGION, else the
    profile's ``region`` in ~/.aws/config; without one, say where to set it.
    """
    session = _boto3().session.Session(
        profile_name=_SESSION["profile"], region_name=_SESSION["region"]
    )
    if not session.region_name:
        profile = _SESSION["profile"] or session.profile_name
        raise ValueError(
            "no AWS region: pass --region, set AWS_REGION, or add `region = ...` "
            f"to the [{'profile ' + profile if profile != 'default' else 'default'}] "
            "section of ~/.aws/config"
        )
    return session.client(service)


def iam_database(
    database: str, cluster: str | None = None, workgroup: str | None = None
) -> Database:
    """Connect to Redshift with temporary credentials AWS issues for this identity."""
    if workgroup:
        serverless = _client("redshift-serverless")
        creds = serverless.get_credentials(workgroupName=workgroup, dbName=database)
        endpoint = serverless.get_workgroup(workgroupName=workgroup)["workgroup"][
            "endpoint"
        ]
        user, password = creds["dbUser"], creds["dbPassword"]
    elif cluster:
        redshift = _client("redshift")
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
        self.client = client or _client("redshift-data")
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
        return self.rows_many([query])[0]

    def rows_many(self, queries: list[str]) -> list[list[tuple[Any, ...]]]:
        """Run catalog queries at the same time and return each one's rows.

        Every statement is submitted first, then each is waited for: over the
        Data API a query is an HTTP round trip plus polling, so running them one
        after another costs the sum of those, and together about the slowest.
        ``durations`` keeps each statement's time as Redshift reports it.
        """
        ids = [
            self.client.execute_statement(Sql=query, **self._where)["Id"]
            for query in queries
        ]
        out: list[list[tuple[Any, ...]]] = []
        self.durations: list[float] = []
        for statement_id in ids:
            described = self._wait(statement_id)
            self.durations.append(described.get("Duration", 0) / 1e9)
            out.append(self._result(statement_id, described))
        return out

    def _result(
        self, statement_id: str, described: dict[str, Any]
    ) -> list[tuple[Any, ...]]:
        if not described.get("HasResultSet"):
            return []
        out: list[tuple[Any, ...]] = []
        token = None
        while True:
            kwargs = {"Id": statement_id}
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
        try:
            started = self.client.batch_execute_statement(Sqls=sqls, **self._where)
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code == "AccessDeniedException":
                raise DataApiError(
                    f"{e}\napply runs the plan as one transaction, which needs "
                    "redshift-data:BatchExecuteStatement (plan needs only "
                    "ExecuteStatement, DescribeStatement and GetStatementResult)"
                ) from None
            raise
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


# ---------------------------------------------------------------------------
# Amazon RDS and Aurora PostgreSQL
# ---------------------------------------------------------------------------
class RdsEndpoint:
    """Where an RDS instance or Aurora cluster listens, and who administers it."""

    def __init__(
        self,
        host: str,
        port: int = 5432,
        master_user: str | None = None,
        arn: str | None = None,
        name: str | None = None,
    ):
        """Keep the endpoint; the ARN is the Data API's resource (a cluster's)."""
        self.host, self.port = host, port
        self.master_user, self.arn = master_user, arn
        self.name = name or host.split(".", 1)[0]


def describe_rds(rds: str, client: Any = None) -> RdsEndpoint:
    """Return the endpoint of an Aurora cluster or RDS instance, by identifier.

    A name with a dot is taken as an endpoint host as it is. Otherwise the Aurora
    clusters are asked first, then the RDS instances.
    """
    if "." in rds:
        return RdsEndpoint(rds)
    client = client or _client("rds")
    try:
        cluster = client.describe_db_clusters(DBClusterIdentifier=rds)["DBClusters"][0]
        return RdsEndpoint(
            cluster["Endpoint"],
            cluster.get("Port", 5432),
            cluster.get("MasterUsername"),
            cluster.get("DBClusterArn"),
            rds,
        )
    except client.exceptions.DBClusterNotFoundFault:
        pass
    try:
        found = client.describe_db_instances(DBInstanceIdentifier=rds)["DBInstances"]
    except client.exceptions.DBInstanceNotFoundFault:
        raise ValueError(f"no Aurora cluster or RDS instance named {rds!r}") from None
    instance = found[0]
    return RdsEndpoint(
        instance["Endpoint"]["Address"],
        instance["Endpoint"].get("Port", 5432),
        instance.get("MasterUsername"),
        instance.get("DBInstanceArn"),
        rds,
    )


def rds_iam_database(
    database: str,
    rds: str,
    db_user: str | None = None,
    port: int | None = None,
    client: Any = None,
) -> Database:
    """Connect to RDS or Aurora PostgreSQL with a signed IAM authentication token.

    ``db_user`` defaults to the cluster's or instance's admin user; it must be a
    member of ``rds_iam``, and the caller needs ``rds-db:connect`` for it.
    """
    client = client or _client("rds")
    endpoint = describe_rds(rds, client)
    user = db_user or endpoint.master_user
    if not user:
        raise ValueError("--iam with --rds needs --db-user (the endpoint is a host)")
    token = client.generate_db_auth_token(
        DBHostname=endpoint.host,
        Port=port or endpoint.port,
        DBUsername=user,
        Region=client.meta.region_name,
    )
    from psycopg.conninfo import make_conninfo

    dsn = make_conninfo(
        host=endpoint.host,
        port=port or endpoint.port,
        dbname=database,
        user=user,
        password=token,
        sslmode="require",
    )
    return Database(SecretStr(dsn))


class RdsDataApiDatabase:
    """An Aurora PostgreSQL database reached through the RDS Data API."""

    def __init__(
        self,
        database: str,
        resource_arn: str,
        secret_arn: str,
        name: str | None = None,
        client: Any = None,
    ):
        """Address a cluster by ARN; the Data API signs in with the secret's user."""
        self.client = client or _client("rds-data")
        self._database = database
        self._where = {
            "resourceArn": resource_arn,
            "secretArn": secret_arn,
            "database": database,
        }
        self._label = f"rds-data:{name or resource_arn.rsplit(':', 1)[-1]}:{database}"

    @property
    def database(self) -> str:
        """Return the database's name."""
        return self._database

    @property
    def target(self) -> str:
        """Return where the statements go: ``rds-data:<cluster>:<db>``."""
        return self._label

    def rows(self, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        """Run a catalog query and return its rows."""
        if params:
            raise ValueError("the Data API path takes no parameters")
        result = self.client.execute_statement(sql=query, **self._where)
        return [
            tuple(_rds_value(f) for f in record) for record in result.get("records", [])
        ]

    def render(self, statement: sql.Composed) -> str:
        """Return a composed statement as SQL text (quoting needs no connection)."""
        return statement.as_string()

    def run(self, statements: list[sql.Composed]) -> None:
        """Run statements in one transaction: all of them, or none."""
        tx = self.client.begin_transaction(
            resourceArn=self._where["resourceArn"],
            secretArn=self._where["secretArn"],
            database=self._database,
        )["transactionId"]
        try:
            for statement in statements:
                self.client.execute_statement(
                    sql=self.render(statement), transactionId=tx, **self._where
                )
        except Exception:
            self.client.rollback_transaction(
                resourceArn=self._where["resourceArn"],
                secretArn=self._where["secretArn"],
                transactionId=tx,
            )
            raise
        self.client.commit_transaction(
            resourceArn=self._where["resourceArn"],
            secretArn=self._where["secretArn"],
            transactionId=tx,
        )

    def close(self) -> None:
        """Nothing to close: each call is its own HTTPS request."""


def _rds_value(field: dict[str, Any]) -> Any:
    """Return an RDS Data API field as a Python value (arrays as lists)."""
    if field.get("isNull"):
        return None
    if "arrayValue" in field:
        return _rds_array(field["arrayValue"])
    for key in ("stringValue", "longValue", "booleanValue", "doubleValue"):
        if key in field:
            return field[key]
    return None


def _rds_array(array: dict[str, Any]) -> list[Any]:
    if "arrayValues" in array:
        return [_rds_array(a) for a in array["arrayValues"]]
    for key in ("stringValues", "longValues", "booleanValues", "doubleValues"):
        if key in array:
            return list(array[key])
    return []

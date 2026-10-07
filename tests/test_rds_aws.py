"""RDS and Aurora connections with stand-in AWS clients (no AWS, no database)."""

import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from pgsesame import aws
from pgsesame.aws import RdsDataApiDatabase, describe_rds, rds_iam_database
from pgsesame.postgres import _text_array

CLUSTER_ARN = "arn:aws:rds:eu-west-1:123456789012:cluster:dev"


class NotFound(Exception):
    """A stand-in for botocore's DBClusterNotFoundFault and DBInstanceNotFoundFault."""


class FakeRds:
    """Answers like the RDS API for one cluster and one instance."""

    class exceptions:  # as client.exceptions names them
        DBClusterNotFoundFault = NotFound
        DBInstanceNotFoundFault = NotFound

    class meta:
        region_name = "eu-west-1"

    def __init__(self):
        self.tokens: list[dict] = []

    def describe_db_clusters(self, DBClusterIdentifier):
        if DBClusterIdentifier != "dev":
            raise NotFound()
        return {
            "DBClusters": [
                {
                    "Endpoint": "dev.cluster-abc.eu-west-1.rds.amazonaws.com",
                    "Port": 5432,
                    "MasterUsername": "postgres",
                    "DBClusterArn": CLUSTER_ARN,
                }
            ]
        }

    def describe_db_instances(self, DBInstanceIdentifier):
        if DBInstanceIdentifier != "legacy":
            raise NotFound()
        return {
            "DBInstances": [
                {
                    "Endpoint": {
                        "Address": "legacy.abc.rds.amazonaws.com",
                        "Port": 5433,
                    },
                    "MasterUsername": "admin",
                    "DBInstanceArn": "arn:aws:rds:eu-west-1:1:db:legacy",
                }
            ]
        }

    def generate_db_auth_token(self, **kwargs):
        self.tokens.append(kwargs)
        return "signed-token"


def test_an_aurora_cluster_then_an_instance_then_a_host():
    rds = FakeRds()
    cluster = describe_rds("dev", rds)
    assert (cluster.host, cluster.master_user, cluster.arn) == (
        "dev.cluster-abc.eu-west-1.rds.amazonaws.com",
        "postgres",
        CLUSTER_ARN,
    )
    instance = describe_rds("legacy", rds)
    assert (instance.port, instance.master_user) == (5433, "admin")
    host = describe_rds("db.example.com", rds)
    assert (host.host, host.arn, host.master_user) == ("db.example.com", None, None)
    with pytest.raises(ValueError, match="no Aurora cluster or RDS instance"):
        describe_rds("nope", rds)


def test_iam_signs_a_token_for_the_admin_user_and_requires_tls(monkeypatch):
    opened: list[str] = []
    monkeypatch.setattr(
        aws, "Database", lambda dsn: opened.append(dsn.get_secret_value()) or "db"
    )
    rds = FakeRds()
    assert rds_iam_database("app", "dev", client=rds) == "db"
    assert rds.tokens == [
        {
            "DBHostname": "dev.cluster-abc.eu-west-1.rds.amazonaws.com",
            "Port": 5432,
            "DBUsername": "postgres",
            "Region": "eu-west-1",
        }
    ]
    parts = conninfo_to_dict(opened[0])
    assert parts["password"] == "signed-token" and parts["sslmode"] == "require"
    assert (parts["user"], parts["dbname"]) == ("postgres", "app")
    rds_iam_database("app", "dev", db_user="deployer", client=rds)
    assert rds.tokens[-1]["DBUsername"] == "deployer"
    with pytest.raises(ValueError, match="needs --db-user"):
        rds_iam_database("app", "db.example.com", client=rds)


class FakeRdsData:
    """Answers like the RDS Data API; fails the statement it is told to."""

    def __init__(self, records=None, fail_on=None):
        self.records, self.fail_on = records or [], fail_on
        self.calls: list[tuple[str, dict]] = []

    def execute_statement(self, **kwargs):
        self.calls.append(("execute", kwargs))
        if self.fail_on and self.fail_on in kwargs["sql"]:
            raise RuntimeError("ERROR: permission denied")
        return {"records": self.records}

    def begin_transaction(self, **kwargs):
        self.calls.append(("begin", kwargs))
        return {"transactionId": "tx1"}

    def commit_transaction(self, **kwargs):
        self.calls.append(("commit", kwargs))

    def rollback_transaction(self, **kwargs):
        self.calls.append(("rollback", kwargs))


def _db(client):
    return RdsDataApiDatabase("app", CLUSTER_ARN, "arn:secret", "dev", client=client)


def test_apply_is_one_transaction_committed():
    client = FakeRdsData()
    _db(client).run([sql.SQL("CREATE ROLE a"), sql.SQL("CREATE ROLE b")])
    assert [kind for kind, _ in client.calls] == [
        "begin",
        "execute",
        "execute",
        "commit",
    ]
    assert all(
        c.get("transactionId") == "tx1" for k, c in client.calls if k == "execute"
    )


def test_a_failed_statement_rolls_the_transaction_back():
    client = FakeRdsData(fail_on="CREATE ROLE b")
    with pytest.raises(RuntimeError, match="permission denied"):
        _db(client).run([sql.SQL("CREATE ROLE a"), sql.SQL("CREATE ROLE b")])
    assert [kind for kind, _ in client.calls] == [
        "begin",
        "execute",
        "execute",
        "rollback",
    ]


def test_values_and_arrays_come_back_as_python():
    client = FakeRdsData(
        records=[
            [
                {"stringValue": "app"},
                {"booleanValue": True},
                {"isNull": True},
                {"arrayValue": {"stringValues": ["a", "b c"]}},
                {"longValue": 7},
            ]
        ]
    )
    db = _db(client)
    assert db.rows("select 1") == [("app", True, None, ["a", "b c"], 7)]
    assert db.target == "rds-data:dev:app"


def test_a_text_array_read_either_way():
    assert _text_array(["a", "b"]) == ["a", "b"]
    assert _text_array("{a,b}") == ["a", "b"]
    assert _text_array('{public,"Read Only"}') == ["public", "Read Only"]
    assert _text_array("{}") == []
    assert _text_array(None) == []

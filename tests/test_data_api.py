"""The Data API connection's paths a real service rarely shows: failures, pages."""

import pytest
from psycopg import sql

from pgsesame.aws import DataApiDatabase, DataApiError


class AccessDenied(Exception):
    """An error shaped like botocore's: the AWS error code under ``response``."""

    def __init__(self, message: str):
        super().__init__(message)
        self.response = {"Error": {"Code": "AccessDeniedException"}}


class FakeDataApi:
    """Answers like the Redshift Data API; each statement's fate is set up front."""

    def __init__(self, status="FINISHED", pages=None, deny=False):
        self.status, self.pages, self.deny = status, pages or [], deny
        self.calls: list[tuple[str, dict]] = []

    def execute_statement(self, **kwargs):
        self.calls.append(("execute", kwargs))
        return {"Id": "s1"}

    def batch_execute_statement(self, **kwargs):
        self.calls.append(("batch", kwargs))
        if self.deny:
            raise AccessDenied(
                "User is not authorized to perform BatchExecuteStatement"
            )
        return {"Id": "b1"}

    def describe_statement(self, Id):
        return {
            "Status": self.status,
            "HasResultSet": bool(self.pages),
            "Error": "boom",
        }

    def get_statement_result(self, Id, NextToken=None):
        index = int(NextToken or 0)
        page = {"Records": self.pages[index]}
        if index + 1 < len(self.pages):
            page["NextToken"] = str(index + 1)
        return page


def _db(client, **kwargs):
    return DataApiDatabase("dev", workgroup="wg", client=client, **kwargs)


def test_rows_follow_every_page_and_decode_values():
    client = FakeDataApi(
        pages=[
            [[{"stringValue": "a"}, {"longValue": 1}]],
            [[{"isNull": True}, {"booleanValue": True}]],
        ]
    )
    assert _db(client).rows("select 1") == [("a", 1), (None, True)]
    assert client.calls[0][1]["WorkgroupName"] == "wg"


def test_a_failed_statement_raises():
    with pytest.raises(DataApiError, match="boom"):
        _db(FakeDataApi(status="FAILED")).rows("select 1")


def test_a_plan_runs_as_one_batch_with_the_secret():
    client = FakeDataApi()
    db = _db(client, secret_arn="arn:secret")
    db.run([sql.SQL("GRANT {} TO {}").format(sql.Identifier("r"), sql.Identifier("u"))])
    kind, kwargs = client.calls[0]
    assert kind == "batch" and kwargs["Sqls"] == ['GRANT "r" TO "u"']
    assert kwargs["SecretArn"] == "arn:secret"


def test_a_refused_batch_names_the_missing_permission():
    with pytest.raises(DataApiError, match="redshift-data:BatchExecuteStatement"):
        _db(FakeDataApi(deny=True)).run([sql.SQL("SELECT 1")])


class FakeSession:
    """The Data API's sessions: statements sent with its SessionId share one connection."""

    def __init__(self, fail_on: str | None = None):
        self.fail_on = fail_on
        self.calls: list[tuple[str, dict]] = []
        self.failed: set[str] = set()

    def execute_statement(self, **kwargs):
        self.calls.append(("execute", kwargs))
        statement_id = str(len(self.calls))
        if kwargs["Sql"] == self.fail_on:
            self.failed.add(statement_id)
        if "SessionId" in kwargs:
            return {"Id": statement_id, "SessionId": kwargs["SessionId"]}
        return {"Id": statement_id, "SessionId": "sess-1"}

    def batch_execute_statement(self, **kwargs):
        raise AssertionError("a plan over the batch limit must not go as a batch")

    def describe_statement(self, Id):
        failed = Id in self.failed
        return {"Status": "FAILED" if failed else "FINISHED", "Error": "boom"}

    def sqls(self) -> list[str]:
        return [kwargs["Sql"] for _, kwargs in self.calls]


def _grants(n: int) -> list[sql.Composed]:
    return [
        sql.SQL("GRANT SELECT ON {} TO {}").format(
            sql.Identifier("s", f"t{i}"), sql.Identifier("u")
        )
        for i in range(n)
    ]


def test_forty_statements_still_go_as_one_batch():
    client = FakeDataApi()
    _db(client).run(_grants(40))
    assert [kind for kind, _ in client.calls] == ["batch"]


def test_a_longer_plan_runs_in_one_session_transaction():
    # BatchExecuteStatement refuses more than 40 statements: the plan runs on a
    # session's connection between BEGIN and COMMIT instead
    client = FakeSession()
    _db(client, secret_arn="arn:secret").run(_grants(41))
    sqls = client.sqls()
    assert sqls[0] == "BEGIN" and sqls[-1] == "COMMIT" and len(sqls) == 43
    begin = client.calls[0][1]
    assert begin["SecretArn"] == "arn:secret" and begin["SessionKeepAliveSeconds"] > 0
    # every later call names only the session, which already holds the rest
    for _, kwargs in client.calls[1:]:
        assert set(kwargs) == {"Sql", "SessionId"} and kwargs["SessionId"] == "sess-1"


def test_a_failure_in_a_longer_plan_rolls_it_back():
    statements = _grants(45)
    failing = statements[30].as_string()
    client = FakeSession(fail_on=failing)
    with pytest.raises(DataApiError, match="boom"):
        _db(client).run(statements)
    sqls = client.sqls()
    assert sqls[-1] == "ROLLBACK" and "COMMIT" not in sqls
    assert sqls[-2] == failing  # nothing after the failed statement ran

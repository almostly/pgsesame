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

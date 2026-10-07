"""First-run rough edges: messages, help, AWS region, Data API speed (no services)."""

import pytest
from typer.testing import CliRunner

from pgsesame import aws, redshift
from pgsesame.aws import DataApiDatabase
from pgsesame.cli import app
from pgsesame.console import console, operation


def test_brackets_in_output_are_text_not_markup():
    with console.capture() as captured:
        operation(
            "create", "GRANT SELECT ON t TO x -- see pgsesame[aws] and ARRAY[value]"
        )
    out = captured.get()
    assert "pgsesame[aws]" in out and "ARRAY[value]" in out


def test_help_groups_the_aws_options():
    result = CliRunner().invoke(
        app, ["import", "--help"], env={"NO_COLOR": "1", "COLUMNS": "120"}
    )
    assert "AWS: Redshift, RDS and Aurora" in result.stdout
    assert "--region" in result.stdout and "--profile" in result.stdout


def test_no_region_says_where_to_set_one(tmp_path, monkeypatch):
    pytest.importorskip("boto3")
    config = tmp_path / "config"
    config.write_text("[profile dev]\noutput = json\n")  # a profile without a region
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    aws.configure("dev", None)
    try:
        with pytest.raises(ValueError, match=r"pass --region.*\[profile dev\]"):
            aws._client("redshift-data")
        aws.configure("dev", "eu-west-1")
        assert aws._client("redshift-data").meta.region_name == "eu-west-1"
    finally:
        aws.configure(None, None)


class RecordingDataApi:
    """Answers like the Redshift Data API and records the order of calls."""

    def __init__(self):
        self.calls: list[str] = []
        self.count = 0

    def execute_statement(self, **kwargs):
        self.count += 1
        self.calls.append(f"execute {self.count}")
        return {"Id": str(self.count)}

    def describe_statement(self, Id):
        self.calls.append(f"wait {Id}")
        return {"Status": "FINISHED", "HasResultSet": True, "Duration": 2_000_000_000}

    def get_statement_result(self, Id, NextToken=None):
        return {"Records": [[{"longValue": int(Id)}]]}


def test_catalog_queries_run_together_over_the_data_api(monkeypatch, capsys):
    client = RecordingDataApi()
    db = DataApiDatabase("dev", workgroup="wg", client=client)
    monkeypatch.setenv("SESAME_TIMING", "1")
    rows = redshift.fetch(db, {"a": "select 1", "b": "select 2", "c": "select 3"})
    assert rows == {"a": [(1,)], "b": [(2,)], "c": [(3,)]}
    # every statement is submitted before any is waited for
    assert client.calls[:3] == ["execute 1", "execute 2", "execute 3"]
    err = capsys.readouterr().err
    assert "sesame: a: 1 rows, 2.00s" in err and "catalog read in" in err

"""First-run rough edges: messages, help, AWS region, Data API speed (no services)."""

import re

import pytest
from typer.testing import CliRunner

from pgsesame import aws, redshift
from pgsesame.aws import DataApiDatabase
from pgsesame.cli import app
from pgsesame.console import console, operation


def test_brackets_in_output_are_text_not_markup():
    with console.capture() as captured:
        operation(
            "create",
            "GRANT SELECT ON t TO x -- see pgsesame[redshift] and ARRAY[value]",
        )
    out = captured.get()
    assert "pgsesame[redshift]" in out and "ARRAY[value]" in out


def test_help_groups_the_aws_options():
    result = CliRunner().invoke(
        app, ["import", "--help"], env={"NO_COLOR": "1", "COLUMNS": "120"}
    )
    # on GitHub Actions Rich colours the help even with NO_COLOR: read the text
    text = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    assert "AWS (needs pgsesame[redshift], [rds] or [aurora])" in text
    assert "--region" in text and "--profile" in text


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


@pytest.mark.parametrize(
    ("service", "extra"),
    [
        ("redshift-data", "redshift"),
        ("redshift-serverless", "redshift"),
        ("rds", "rds"),
        ("rds-data", "rds"),
    ],
)
def test_without_boto3_the_hint_names_the_extra(service, extra, monkeypatch):
    import builtins

    real = builtins.__import__

    def no_boto3(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("no boto3")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_boto3)
    with pytest.raises(RuntimeError, match=rf"pgsesame\[{extra}\]"):
        aws._client(service)


class MaskingDataApi(RecordingDataApi):
    """Answers the masking reads: allowed or not, and nothing attached yet."""

    def __init__(self, allowed=True):
        super().__init__()
        self.allowed = allowed

    def get_statement_result(self, Id, NextToken=None):
        if Id == "1":  # can this user see masking policies
            return {"Records": [[{"booleanValue": self.allowed}]]}
        return {"Records": []}


def _masking_spec():
    from pgsesame import spec

    return spec.parse(
        {
            "version": 1,
            "engine": "redshift",
            "principals": {"r": {"type": "role"}},
            "masking": {
                "policies": {"p": {"type": "varchar(9)", "using": "'*'::varchar(9)"}},
                "columns": {"s.t.c": {"mask": "p"}},
            },
        }
    )


def test_masking_reads_run_together_over_the_data_api():
    from pgsesame import masking
    from pgsesame.state import State

    client = MaskingDataApi()
    db = DataApiDatabase("dev", workgroup="wg", client=client)
    masking.read(db, _masking_spec(), State())
    # the permission check, policies, attachments and column types: one round
    assert client.calls[:4] == ["execute 1", "execute 2", "execute 3", "execute 4"]

    refused = DataApiDatabase(
        "dev", workgroup="wg", client=MaskingDataApi(allowed=False)
    )
    with pytest.raises(masking.MaskingError, match="can't see masking policies"):
        masking.read(refused, _masking_spec(), State())

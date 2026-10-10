"""First-run rough edges: messages, help, AWS region, Data API speed (no services)."""

import json
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


class ProbingDataApi:
    """A Data API that keeps masking probes, as Redshift's would for one plan."""

    def __init__(self, deny_batch=False, fail_read=False):
        self.deny_batch, self.fail_read = deny_batch, fail_read
        self.probes: list[str] = []
        self.dropped: list[str] = []
        self.statements: dict[str, str] = {}

    def batch_execute_statement(self, Sqls, **kwargs):
        if self.deny_batch:
            raise RuntimeError("AccessDenied: BatchExecuteStatement")
        for text in Sqls:
            name = text.split('"')[1]
            if text.startswith("CREATE MASKING POLICY"):
                self.probes.append(name)
            elif text.startswith("DROP MASKING POLICY"):
                self.dropped.append(name)
        return {"Id": "batch"}

    def execute_statement(self, Sql, **kwargs):
        self.statements["read"] = Sql
        return {"Id": "read"}

    def describe_statement(self, Id):
        if Id == "read" and self.fail_read:
            return {"Status": "FAILED", "Error": "boom"}
        return {"Status": "FINISHED", "HasResultSet": Id == "read", "Duration": 0}

    def get_statement_result(self, Id, NextToken=None):
        return {
            "Records": [
                [
                    {"stringValue": probe},
                    {
                        "stringValue": '[{"colname":"value","type":"character varying(9)"}]'
                    },
                    {
                        "stringValue": json.dumps(
                            [
                                {
                                    "expr": "CAST('*' AS VARCHAR(9))",
                                    "type": "character varying(9)",
                                }
                            ]
                        )
                    },
                ]
                for probe in self.probes
            ]
        }


def test_masking_expressions_compared_over_the_data_api_with_probes():
    from pgsesame import masking
    from pgsesame.state import State

    client = ProbingDataApi()
    db = DataApiDatabase("dev", workgroup="wg", client=client)
    found = masking.normalize(db, _masking_spec(), State())
    assert found is not None and found["p"].expression == "CAST('*' AS VARCHAR(9))"
    assert client.probes and client.dropped == client.probes  # created, then dropped
    assert all(p.startswith("pgsesame_probe_") for p in client.probes)


def test_masking_probes_are_dropped_even_when_the_read_fails():
    from pgsesame import masking
    from pgsesame.aws import DataApiError
    from pgsesame.state import State

    client = ProbingDataApi(fail_read=True)
    db = DataApiDatabase("dev", workgroup="wg", client=client)
    with pytest.raises(DataApiError):
        masking.normalize(db, _masking_spec(), State())
    assert client.dropped == client.probes


def test_without_batch_rights_expressions_simply_arent_compared():
    from pgsesame import masking
    from pgsesame.state import State

    db = DataApiDatabase("dev", workgroup="wg", client=ProbingDataApi(deny_batch=True))
    assert masking.normalize(db, _masking_spec(), State()) is None


class _NoDatabase:
    """A connection that's never queried: the plan is made up by the test."""

    database = "dev"
    target = "fake:dev"

    def render(self, statement):
        """Return a statement as text, as a real connection would."""
        return statement.as_string(None)

    def close(self):
        """Nothing to close."""


@pytest.mark.parametrize("command", ["plan", "apply"])
def test_notes_are_printed_when_there_is_nothing_to_do(command, tmp_path, monkeypatch):
    # an import followed by an empty plan mustn't hide that PUBLIC can still create
    from pgsesame import cli, planner

    note = "schema public: PUBLIC (every user) can CREATE in it"
    monkeypatch.setattr(cli, "_connect", lambda options: _NoDatabase())
    monkeypatch.setattr(cli, "_plan", lambda loaded, db: planner.Plan([], [note]))
    spec = tmp_path / "spec.yaml"
    spec.write_text("version: 1\nengine: redshift\nprincipals: {}\n")
    result = CliRunner().invoke(
        app, [command, str(spec), "--dsn", "host=x"], env={"NO_COLOR": "1"}
    )
    assert result.exit_code == 0, result.output
    assert f"note: {note}" in result.output
    assert "nothing to" in result.output

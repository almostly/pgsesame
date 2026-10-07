"""The ``sesame`` command: validate, plan and apply a permissions spec."""

from __future__ import annotations

from pathlib import Path

import psycopg
import typer
from pydantic import SecretStr
from typer import rich_utils

from pgsesame import __version__, planner, postgres, redshift, spec
from pgsesame.changeset import ChangeSet, ChangeSetError, is_changeset, same_operations
from pgsesame.console import console, err, header, operation
from pgsesame.db import Connection, Database

# pgcli's green for the help screens, in place of Typer's cyan and yellow
for _name, _style in {
    "STYLE_OPTION": "bold green",
    "STYLE_SWITCH": "bold green",
    "STYLE_USAGE": "green",
    "STYLE_OPTIONS_PANEL_BORDER": "green",
    "STYLE_COMMANDS_PANEL_BORDER": "green",
    "STYLE_COMMANDS_TABLE_FIRST_COLUMN": "bold green",
}.items():
    setattr(rich_utils, _name, _style)

app = typer.Typer(
    name="sesame",
    help="Permissions as code for PostgreSQL and Amazon Redshift.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)

SpecPath = typer.Argument(..., exists=True, dir_okay=False, help="The spec (YAML).")


def _version(value: bool) -> None:
    if value:
        console.print(f"[accent]sesame[/accent] {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show the version."
    ),
) -> None:
    """Declare roles, users, grants and ownership in YAML; plan and apply like Terraform."""


@app.command()
def validate(path: Path = SpecPath) -> None:
    """Check a spec without connecting to a database."""
    header("validate", str(path))
    try:
        loaded = spec.load(path)
    except spec.SpecError as e:
        for problem in e.problems:
            err.print(f"[error]✗[/error] {problem}")
        err.print(f"[error]{len(e.problems)} problem(s)[/error]")
        raise typer.Exit(1) from None
    kinds: dict[str, int] = {}
    for p in loaded.principals.values():
        kinds[p.type] = kinds.get(p.type, 0) + 1
    summary = ", ".join(
        f"{n} {k}{'s' if n != 1 else ''}" for k, n in sorted(kinds.items())
    )
    console.print(
        f"[ok]✓[/ok] valid {loaded.engine} spec: {summary or 'no principals'}, "
        f"{len(loaded.default_privileges)} default privilege rule(s)"
    )


@app.command()
def schema() -> None:
    """Print the spec's JSON Schema, for editor completion and checking."""
    import json

    print(json.dumps(spec.json_schema(), indent=2))


DsnOption = typer.Option(
    "",
    "--dsn",
    envvar="SESAME_DSN",
    help="Connection string; empty uses PGHOST, PGUSER, PGPASSWORD and the rest.",
    show_default=False,
)


def _load(path: Path) -> spec.Spec:
    try:
        return spec.load(path)
    except spec.SpecError as e:
        for problem in e.problems:
            err.print(f"[error]✗[/error] {problem}")
        raise typer.Exit(1) from None


def _plan(loaded: spec.Spec, db: Connection) -> planner.Plan:
    reader = redshift.read if loaded.engine == "redshift" else postgres.read
    try:
        return planner.make(loaded, reader(db))
    except planner.PlanError as e:
        for problem in e.problems:
            err.print(f"[error]✗[/error] {problem}")
        raise typer.Exit(1) from None


class Target:
    """Where to connect, from the command line: a DSN, IAM credentials or the Data API."""

    def __init__(
        self,
        dsn: str,
        cluster: str | None,
        workgroup: str | None,
        database: str,
        iam: bool,
        data_api: bool,
        secret_arn: str | None,
        db_user: str | None,
    ):
        """Keep the options; the DSN as a SecretStr, as it may carry a password."""
        self.dsn = SecretStr(dsn)
        self.cluster, self.workgroup, self.database = cluster, workgroup, database
        self.iam, self.data_api = iam, data_api
        self.secret_arn, self.db_user = secret_arn, db_user

    def connect(self) -> Connection:
        """Open the connection these options describe."""
        if self.iam and self.data_api:
            raise ValueError("choose --iam or --data-api, not both")
        if (self.iam or self.data_api) and not (self.cluster or self.workgroup):
            raise ValueError("--iam and --data-api need --cluster or --workgroup")
        if self.data_api:
            from pgsesame.aws import DataApiDatabase

            return DataApiDatabase(
                self.database,
                cluster=self.cluster,
                workgroup=self.workgroup,
                secret_arn=self.secret_arn,
                db_user=self.db_user,
            )
        if self.iam:
            from pgsesame.aws import iam_database

            return iam_database(self.database, self.cluster, self.workgroup)
        return Database(self.dsn)


ClusterOption = typer.Option(
    None, "--cluster", help="Redshift cluster identifier (for --iam or --data-api)."
)
WorkgroupOption = typer.Option(
    None, "--workgroup", help="Redshift Serverless workgroup (for --iam or --data-api)."
)
DatabaseOption = typer.Option(
    "dev", "--database", help="Database, for --iam or --data-api."
)
IamOption = typer.Option(
    False, "--iam", help="Connect with temporary credentials AWS issues (Redshift)."
)
DataApiOption = typer.Option(
    False,
    "--data-api",
    help="Go through the Redshift Data API (no network path needed).",
)
SecretArnOption = typer.Option(
    None, "--secret-arn", help="Secrets Manager secret, for --data-api."
)
DbUserOption = typer.Option(
    None, "--db-user", help="Database user, for --data-api on a cluster."
)


def _connect(target: Target) -> Connection:
    try:
        return target.connect()
    except (psycopg.OperationalError, ValueError, RuntimeError) as e:
        err.print(f"[error]can't connect:[/error] {str(e).strip()}")
        raise typer.Exit(1) from None
    except Exception as e:  # botocore's errors: no credentials, access denied, ...
        err.print(f"[error]can't connect through AWS:[/error] {e}")
        raise typer.Exit(1) from None


def _show(result: planner.Plan, db: Connection) -> None:
    for note in result.notes:
        console.print(f"[muted]note: {note}[/muted]")
    for op in result.operations:
        gate = f"needs --allow-{op.gate}" if op.gate else ""
        operation(op.kind, db.render(op.display()), gate)


def _summary(result: planner.Plan) -> str:
    counts = {"create": 0, "change": 0, "remove": 0}
    for op in result.operations:
        counts[op.kind] += 1
    return (
        f"[create]{counts['create']} to add[/create], "
        f"[change]{counts['change']} to change[/change], "
        f"[remove]{counts['remove']} to remove[/remove]"
    )


@app.command()
def plan(
    path: Path = SpecPath,
    dsn: str = DsnOption,
    cluster: str | None = ClusterOption,
    workgroup: str | None = WorkgroupOption,
    database: str = DatabaseOption,
    iam: bool = IamOption,
    data_api: bool = DataApiOption,
    secret_arn: str | None = SecretArnOption,
    db_user: str | None = DbUserOption,
    out: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        dir_okay=False,
        help="Save the plan as a change set, for sesame apply to run exactly.",
    ),
) -> None:
    """Show the SQL that would make the database match the spec.

    Exits 0 when the database already matches, 2 when there are changes, 1 on
    errors, like ``terraform plan -detailed-exitcode``.
    """
    loaded = _load(path)
    db = _connect(
        Target(dsn, cluster, workgroup, database, iam, data_api, secret_arn, db_user)
    )
    header("plan", db.target)
    result = _plan(loaded, db)
    if not result.operations:
        console.print("[ok]✓[/ok] the database matches the spec; nothing to do")
        raise typer.Exit(0)
    _show(result, db)
    console.print(f"\n[accent]Plan:[/accent] {_summary(result)}")
    if out is not None:
        ChangeSet.build(loaded, db.target, result.operations).save(out)
        console.print(
            f"[accent]Saved[/accent] to {out}; run it with: sesame apply {out}"
        )
    raise typer.Exit(2)


@app.command()
def show(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="A change set."),
) -> None:
    """Print a saved change set (no database needed)."""
    changeset = _load_changeset(path)
    header("show", changeset.target)
    console.print(
        f"[muted]planned {changeset.created_at:%Y-%m-%d %H:%M} UTC from spec "
        f"{changeset.spec_sha256[:12]} ({changeset.engine})[/muted]"
    )
    result = planner.Plan(list(changeset.operations))
    for op in result.operations:
        gate = f"needs --allow-{op.gate}" if op.gate else ""
        operation(op.kind, op.display().as_string(), gate)
    console.print(f"\n[accent]Plan:[/accent] {_summary(result)}")


def _load_changeset(path: Path) -> ChangeSet:
    try:
        return ChangeSet.load(path)
    except ChangeSetError as e:
        err.print(f"[error]✗[/error] {e}")
        raise typer.Exit(1) from None


@app.command()
def apply(
    path: Path = typer.Argument(
        ..., exists=True, dir_okay=False, help="A spec (YAML) or a saved change set."
    ),
    dsn: str = DsnOption,
    cluster: str | None = ClusterOption,
    workgroup: str | None = WorkgroupOption,
    database: str = DatabaseOption,
    iam: bool = IamOption,
    data_api: bool = DataApiOption,
    secret_arn: str | None = SecretArnOption,
    db_user: str | None = DbUserOption,
    allow_revoke: bool = typer.Option(
        False, "--allow-revoke", help="Also run revokes and membership removals."
    ),
    allow_drop: bool = typer.Option(False, "--allow-drop", help="Also run drops."),
) -> None:
    """Make the database match the spec, in one transaction.

    Given a change set (``sesame plan -o``), runs exactly its statements, and
    refuses if the database changed since in a way that changes the plan.
    """
    saved = _load_changeset(path) if is_changeset(path) else None
    loaded = saved.parsed_spec() if saved else _load(path)
    db = _connect(
        Target(dsn, cluster, workgroup, database, iam, data_api, secret_arn, db_user)
    )
    header("apply", db.target)
    result = _plan(loaded, db)
    if saved is not None:
        if saved.target != db.target:
            err.print(
                f"[error]✗[/error] this change set was planned against {saved.target}, "
                f"not {db.target}"
            )
            raise typer.Exit(1)
        if not same_operations(result.operations, list(saved.operations)):
            err.print(
                "[error]✗[/error] the database changed since this change set was "
                "planned; its plan is now:"
            )
            _show(result, db)
            err.print("plan again (sesame plan -o) and review the new change set")
            raise typer.Exit(1)
        result = planner.Plan(saved.with_secrets(), result.notes)
    runnable = result.allowed(allow_revoke, allow_drop)
    skipped = [op for op in result.operations if op not in runnable]
    if not runnable:
        console.print("[ok]✓[/ok] nothing to apply")
    else:
        _show(planner.Plan(runnable, result.notes), db)
        try:
            db.run([op.statement() for op in runnable])
        except (
            Exception
        ) as e:  # psycopg's or the Data API's: the transaction rolled back
            err.print(f"[error]apply failed, nothing was changed:[/error] {e}")
            raise typer.Exit(1) from None
        console.print(f"\n[ok]✓[/ok] applied {len(runnable)} statement(s)")
    if skipped:
        for op in skipped:
            operation(
                op.kind, db.render(op.display()), f"skipped: needs --allow-{op.gate}"
            )
        console.print(f"[change]{len(skipped)} statement(s) skipped[/change]")

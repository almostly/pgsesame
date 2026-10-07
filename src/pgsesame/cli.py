"""The ``sesame`` command: validate, plan and apply a permissions spec."""

from __future__ import annotations

from pathlib import Path

import os
import sys

import psycopg
import typer
from rich.markup import escape
from psycopg.conninfo import make_conninfo
from pydantic import SecretStr
from typer import rich_utils

from pgsesame import __version__, masking, planner, postgres, redshift, spec, targets
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
            err.print(f"[error]✗[/error] {escape(problem)}")
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
            err.print(f"[error]✗[/error] {escape(problem)}")
        raise typer.Exit(1) from None


def _plan(loaded: spec.Spec, db: Connection) -> planner.Plan:
    reader = redshift.read if loaded.engine == "redshift" else postgres.read
    try:
        normalized = (
            postgres.normalize_policies(db, loaded)
            if loaded.row_level_security and isinstance(db, Database)
            else {}
        )
        # every column only when the spec grants on columns: a large catalog
        # makes it the biggest read
        columns = any("columns" in p.privileges for p in loaded.principals.values())
        current = reader(db, columns)
        masks = None
        if loaded.masking is not None:
            masking.read(db, loaded, current)
            masks = masking.normalize(db, loaded, current)
        return planner.make(loaded, current, normalized, masks)
    except masking.MaskingError as e:
        err.print(f"[error]✗[/error] {escape(str(e))}")
        raise typer.Exit(1) from None
    except planner.PlanError as e:
        for problem in e.problems:
            err.print(f"[error]✗[/error] {escape(problem)}")
        raise typer.Exit(1) from None
    except Exception as e:
        # a Data API's error while reading (access denied, the API not enabled
        # yet ...): said plainly; anything else is a bug and keeps its traceback
        if not type(e).__module__.startswith(("botocore", "pgsesame.aws")):
            raise
        err.print(
            f"[error]✗ reading the database through AWS failed:[/error] {escape(str(e))}"
        )
        raise typer.Exit(1) from None


class ConnectOptions:
    """Where to connect: flags, a saved target, or the standard PG* variables.

    In order: explicit flags (--dsn, --iam, --data-api); a saved target (--target,
    then SESAME_TARGET, then the default set by sesame use); and last libpq's own
    PGHOST, PGUSER, PGPASSWORD, ~/.pgpass and pg_service.conf.
    """

    def __init__(
        self,
        dsn: str,
        cluster: str | None,
        workgroup: str | None,
        database: str | None,
        iam: bool,
        data_api: bool,
        secret_arn: str | None,
        db_user: str | None,
        target: str | None = None,
        rds: str | None = None,
        region: str | None = None,
        profile: str | None = None,
    ):
        """Keep the options; the DSN as a SecretStr, as it may carry a password."""
        self.dsn = SecretStr(dsn)
        self.rds = rds
        self.region, self.profile = region, profile
        # Redshift's default database is dev, PostgreSQL's postgres
        database = database or ("postgres" if rds else "dev")
        self.cluster, self.workgroup, self.database = cluster, workgroup, database
        self.iam, self.data_api = iam, data_api
        self.secret_arn, self.db_user = secret_arn, db_user
        self.target = target
        self.label: str | None = None  # the saved target's name, for the header

    def connect(self) -> Connection:
        """Open the connection these options describe."""
        from pgsesame import aws

        aws.configure(self.profile, self.region)  # AWS paths; harmless for others
        if self.iam and self.data_api:
            raise ValueError("choose --iam or --data-api, not both")
        if self.dsn.get_secret_value() or self.iam or self.data_api:
            return self._from_flags()
        name = self.target or os.environ.get("SESAME_TARGET") or targets.default_name()
        if name:
            self.label = name
            return _from_target(targets.get(name), name)
        return Database(self.dsn)  # libpq's PG* variables, ~/.pgpass, services

    def _from_flags(self) -> Connection:
        if self.rds:
            return _rds(
                self.rds,
                self.database,
                self.iam,
                self.data_api,
                self.db_user,
                self.secret_arn,
            )
        if (self.iam or self.data_api) and not (self.cluster or self.workgroup):
            raise ValueError(
                "--iam and --data-api need --cluster or --workgroup (Redshift) or "
                "--rds (RDS and Aurora)"
            )
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


def _rds(
    rds: str,
    database: str,
    iam: bool,
    data_api: bool,
    db_user: str | None,
    secret_arn: str | None,
) -> Connection:
    """Open an RDS or Aurora connection: IAM token, or the RDS Data API."""
    if iam:
        from pgsesame.aws import rds_iam_database

        return rds_iam_database(database, rds, db_user)
    if data_api:
        from pgsesame.aws import RdsDataApiDatabase, describe_rds

        if not secret_arn:
            raise ValueError("--data-api with --rds needs --secret-arn")
        endpoint = describe_rds(rds)
        if not endpoint.arn:
            raise ValueError(
                "--data-api needs an Aurora cluster identifier, not a host"
            )
        return RdsDataApiDatabase(database, endpoint.arn, secret_arn, endpoint.name)
    raise ValueError("--rds goes with --iam or --data-api")


def _from_target(
    target: targets.Target, name: str, password: SecretStr | None = None
) -> Connection:
    """Open a saved target's connection, its password from the keychain (or given)."""
    from pgsesame import aws

    aws.configure_defaults(target.profile, target.region)
    if target.rds:
        return _rds(
            target.rds,
            target.database,
            target.method == "iam",
            target.method == "data-api",
            target.db_user,
            target.secret_arn,
        )
    if target.method == "data-api":
        from pgsesame.aws import DataApiDatabase

        return DataApiDatabase(
            target.database,
            cluster=target.cluster,
            workgroup=target.workgroup,
            secret_arn=target.secret_arn,
            db_user=target.db_user,
        )
    if target.method == "iam":
        from pgsesame.aws import iam_database

        return iam_database(target.database, target.cluster, target.workgroup)
    secret = password or targets.password(name, target)
    dsn = make_conninfo(
        host=target.host,
        port=target.port,
        dbname=target.database,
        user=target.user,
        sslmode=target.sslmode,
        **({"password": secret.get_secret_value()} if secret else {}),
    )
    return Database(SecretStr(dsn))


# Rich markup: an unescaped [redshift] would be read as a style and dropped
AWS_PANEL = r"AWS (needs pgsesame\[redshift], \[rds] or \[aurora])"
RegionOption = typer.Option(
    None,
    "--region",
    help="AWS region (default: AWS_REGION, then the profile's).",
    rich_help_panel=AWS_PANEL,
)
ProfileOption = typer.Option(
    None,
    "--profile",
    help="AWS profile from ~/.aws/config (default: AWS_PROFILE).",
    rich_help_panel=AWS_PANEL,
)
ClusterOption = typer.Option(
    None,
    "--cluster",
    help="Redshift cluster identifier (for --iam or --data-api).",
    rich_help_panel=AWS_PANEL,
)
WorkgroupOption = typer.Option(
    None,
    "--workgroup",
    help="Redshift Serverless workgroup (for --iam or --data-api).",
    rich_help_panel=AWS_PANEL,
)
DatabaseOption = typer.Option(
    None,
    "--database",
    help="Database, for --iam or --data-api (dev on Redshift, postgres on RDS).",
    rich_help_panel=AWS_PANEL,
)
IamOption = typer.Option(
    False,
    "--iam",
    help="Connect with temporary credentials AWS issues (Redshift, RDS, Aurora).",
    rich_help_panel=AWS_PANEL,
)
RdsOption = typer.Option(
    None,
    "--rds",
    help="Aurora cluster or RDS instance identifier (or endpoint), with --iam or "
    "--data-api.",
    rich_help_panel=AWS_PANEL,
)
DataApiOption = typer.Option(
    False,
    "--data-api",
    help="Go through the Redshift or RDS Data API (no network path needed).",
    rich_help_panel=AWS_PANEL,
)
SecretArnOption = typer.Option(
    None,
    "--secret-arn",
    help="Secrets Manager secret, for --data-api.",
    rich_help_panel=AWS_PANEL,
)
DbUserOption = typer.Option(
    None,
    "--db-user",
    help="Database user: --data-api on a Redshift cluster, or --iam on RDS (default: "
    "the admin user).",
    rich_help_panel=AWS_PANEL,
)


TargetOption = typer.Option(
    None,
    "--target",
    "-t",
    help="A saved target (sesame login); default: SESAME_TARGET, then sesame use.",
    show_default=False,
)


def _where(options: ConnectOptions, db: Connection) -> str:
    """Return the header's target: its name, where it connects, the password's source."""
    if not options.label:
        return db.target
    source = targets.get(options.label).password_source()
    return f"{options.label} ({db.target}, {source})"


def _connect(target: ConnectOptions) -> Connection:
    try:
        return target.connect()
    except (
        psycopg.OperationalError,
        ValueError,
        RuntimeError,
        targets.TargetError,
    ) as e:
        err.print(f"[error]can't connect:[/error] {escape(str(e).strip())}")
        raise typer.Exit(1) from None
    except Exception as e:  # botocore's errors: no credentials, access denied, ...
        err.print(f"[error]can't connect through AWS:[/error] {escape(str(e))}")
        raise typer.Exit(1) from None


PARTIAL = (
    "this user isn't a superuser, and Redshift shows a non-superuser only its own "
    "grants: this plan can't see the rest, so grants it adds may already exist and "
    "drift elsewhere goes unseen. Plan as a superuser to see everything."
)


def _warn_if_partial(result: planner.Plan) -> None:
    if result.partial:
        err.print(f"[change]! {escape(PARTIAL)}[/change]")


def _show(result: planner.Plan, db: Connection) -> None:
    for note in result.notes:
        console.print(f"[muted]note: {escape(note)}[/muted]")
    for op in result.operations:
        gate = f"needs --allow-{op.needs}" if op.needs else ""
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
    target: str | None = TargetOption,
    dsn: str = DsnOption,
    cluster: str | None = ClusterOption,
    workgroup: str | None = WorkgroupOption,
    database: str | None = DatabaseOption,
    iam: bool = IamOption,
    data_api: bool = DataApiOption,
    secret_arn: str | None = SecretArnOption,
    db_user: str | None = DbUserOption,
    rds: str | None = RdsOption,
    region: str | None = RegionOption,
    profile: str | None = ProfileOption,
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
    options = ConnectOptions(
        dsn,
        cluster,
        workgroup,
        database,
        iam,
        data_api,
        secret_arn,
        db_user,
        target,
        rds,
        region=region,
        profile=profile,
    )
    db = _connect(options)
    header("plan", _where(options, db))
    result = _plan(loaded, db)
    _warn_if_partial(result)
    if not result.operations:
        console.print("[ok]✓[/ok] the database matches the spec; nothing to do")
        raise typer.Exit(0)
    _show(result, db)
    console.print(f"\n[accent]Plan:[/accent] {_summary(result)}")
    if out is not None:
        ChangeSet.build(loaded, db.target, result.operations).save(out)
        console.print(
            f"[accent]Saved[/accent] to {escape(str(out))}; run it with: sesame apply {escape(str(out))}"
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
        gate = f"needs --allow-{op.needs}" if op.needs else ""
        operation(op.kind, op.display().as_string(), gate)
    console.print(f"\n[accent]Plan:[/accent] {_summary(result)}")


def _load_changeset(path: Path) -> ChangeSet:
    try:
        return ChangeSet.load(path)
    except ChangeSetError as e:
        err.print(f"[error]✗[/error] {escape(str(e))}")
        raise typer.Exit(1) from None


@app.command()
def apply(
    path: Path = typer.Argument(
        ..., exists=True, dir_okay=False, help="A spec (YAML) or a saved change set."
    ),
    target: str | None = TargetOption,
    dsn: str = DsnOption,
    cluster: str | None = ClusterOption,
    workgroup: str | None = WorkgroupOption,
    database: str | None = DatabaseOption,
    iam: bool = IamOption,
    data_api: bool = DataApiOption,
    secret_arn: str | None = SecretArnOption,
    db_user: str | None = DbUserOption,
    rds: str | None = RdsOption,
    region: str | None = RegionOption,
    profile: str | None = ProfileOption,
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
    options = ConnectOptions(
        dsn,
        cluster,
        workgroup,
        database,
        iam,
        data_api,
        secret_arn,
        db_user,
        target,
        rds,
        region=region,
        profile=profile,
    )
    db = _connect(options)
    header("apply", _where(options, db))
    result = _plan(loaded, db)
    _warn_if_partial(result)
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
            err.print(
                f"[error]apply failed, nothing was changed:[/error] {escape(str(e))}"
            )
            raise typer.Exit(1) from None
        console.print(f"\n[ok]✓[/ok] applied {len(runnable)} statement(s)")
    if skipped:
        for op in skipped:
            operation(
                op.kind, db.render(op.display()), f"skipped: needs --allow-{op.needs}"
            )
        console.print(f"[change]{len(skipped)} statement(s) skipped[/change]")


@app.command(name="import")
def import_spec(
    target: str | None = TargetOption,
    dsn: str = DsnOption,
    cluster: str | None = ClusterOption,
    workgroup: str | None = WorkgroupOption,
    database: str | None = DatabaseOption,
    iam: bool = IamOption,
    data_api: bool = DataApiOption,
    secret_arn: str | None = SecretArnOption,
    db_user: str | None = DbUserOption,
    rds: str | None = RdsOption,
    region: str | None = RegionOption,
    profile: str | None = ProfileOption,
    engine: str | None = typer.Option(
        None,
        "--engine",
        help="postgres or redshift (default: the target's, else postgres).",
    ),
    schema: list[str] = typer.Option(
        [],
        "--schema",
        help="Only grants in this schema (repeat); written as manage.schemas.",
    ),
    prefix: list[str] = typer.Option(
        [], "--prefix", help="Only roles named so (repeat); written as manage.prefixes."
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        dir_okay=False,
        help="Write the spec here (default: stdout).",
    ),
) -> None:
    """Write a spec from what the database grants today, so a first plan is empty."""
    from pgsesame import importer

    options = ConnectOptions(
        dsn,
        cluster,
        workgroup,
        database,
        iam,
        data_api,
        secret_arn,
        db_user,
        target,
        rds,
        region=region,
        profile=profile,
    )
    db = _connect(options)
    if engine is None:
        saved = targets.get(options.label).engine if options.label else None
        engine = saved or ("redshift" if cluster or workgroup else "postgres")
    if engine not in ("postgres", "redshift"):
        err.print("[error]✗[/error] --engine is postgres or redshift")
        raise typer.Exit(1)
    reader = redshift.read if engine == "redshift" else postgres.read
    state = reader(db, False)  # column grants come from their own view
    if not state.sees_everything:
        # what it can't see would be missing from the spec, and a superuser's plan
        # of that spec would revoke it: write nothing
        err.print(
            "[error]✗[/error] import needs a superuser on Redshift: it shows a "
            "non-superuser only its own grants, so the spec would leave out everyone "
            "else's memberships and grants, and a superuser's plan of it would revoke "
            "them. Connect as a superuser (an IAM user is one after ALTER USER "
            "\"IAM:...\" PASSWORD '...' CREATEUSER)."
        )
        raise typer.Exit(1)
    (me,) = db.rows("select current_user")[0]
    visible = masking.read_policies(db, state) if engine == "redshift" else None
    spec_data, notes = importer.build(state, engine, schema, prefix, me, visible)
    text = importer.dump(spec_data, _where(options, db))
    try:
        spec.parse(spec_data)  # what it writes, it can read
    except spec.SpecError as e:
        for problem in e.problems:
            err.print(f"[error]✗[/error] {escape(problem)}")
        raise typer.Exit(1) from None
    for note in notes:
        err.print(f"[muted]note: {escape(note)}[/muted]")
    count = len(spec_data["principals"])
    if out is None:
        sys.stdout.write(text)
    else:
        out.write_text(text)
        err.print(f"[ok]✓[/ok] wrote {count} principal(s) to {escape(str(out))}")


# ---------------------------------------------------------------------------
# Saved targets: sesame login, targets, use, logout
# ---------------------------------------------------------------------------
@app.command()
def login(
    name: str = typer.Argument(
        ..., help="A name for the target: prod, staging, local ..."
    ),
    engine: str = typer.Option("postgres", "--engine", help="postgres or redshift."),
    host: str | None = typer.Option(
        None, "--host", help="Server host (password logins)."
    ),
    port: int | None = typer.Option(
        None, "--port", help="Server port (5432; Redshift 5439)."
    ),
    database: str | None = typer.Option(None, "--database", help="Database to manage."),
    user: str | None = typer.Option(None, "--user", help="Who pgsesame connects as."),
    sslmode: str = typer.Option(
        "prefer", "--sslmode", help="libpq sslmode (require, verify-full ...)."
    ),
    iam: bool = typer.Option(
        False, "--iam", help="Redshift: temporary IAM credentials, no password."
    ),
    data_api: bool = typer.Option(
        False, "--data-api", help="Redshift: through the Data API."
    ),
    cluster: str | None = typer.Option(
        None, "--cluster", help="Redshift cluster (--iam, --data-api)."
    ),
    workgroup: str | None = typer.Option(
        None, "--workgroup", help="Redshift Serverless workgroup."
    ),
    secret_arn: str | None = typer.Option(
        None, "--secret-arn", help="Data API: a Secrets Manager secret."
    ),
    db_user: str | None = typer.Option(
        None, "--db-user", help="Data API on a cluster: the database user."
    ),
    region: str | None = typer.Option(
        None, "--region", help="AWS region (IAM, Data API)."
    ),
    rds: str | None = typer.Option(
        None,
        "--rds",
        help="Aurora cluster or RDS instance (with --iam or --data-api).",
    ),
    profile: str | None = typer.Option(
        None, "--profile", help="AWS profile (IAM, Data API)."
    ),
    password_stdin: bool = typer.Option(
        False, "--password-stdin", help="Read the password from stdin (scripts)."
    ),
    password_env: str | None = typer.Option(
        None,
        "--password-env",
        help="Take the password from this environment variable when connecting "
        "(.env, CI); nothing is stored.",
    ),
    project: bool = typer.Option(
        False,
        "--project",
        help="Save to the project's sesame.toml, to commit (with --password-env).",
    ),
    make_default: bool = typer.Option(
        False, "--default", help="Make it the default target."
    ),
    check: bool = typer.Option(
        True, "--check/--no-check", help="Connect before saving."
    ),
) -> None:
    """Save a target: where to connect and how, the password in the OS keychain."""
    try:
        name = _valid_name(name)
    except ValueError as e:
        err.print(f"[error]✗[/error] {escape(str(e))}")
        raise typer.Exit(1) from None
    if engine not in ("postgres", "redshift"):
        err.print("[error]✗[/error] --engine is postgres or redshift")
        raise typer.Exit(1)
    method = "iam" if iam else "data-api" if data_api else "password"
    if method != "password" and engine != "redshift" and not rds:
        err.print(
            "[error]✗[/error] --iam and --data-api need --rds on PostgreSQL (an RDS "
            "instance or Aurora cluster)"
        )
        raise typer.Exit(1)
    interactive = sys.stdin.isatty() and not password_stdin
    if password_env and password_stdin:
        err.print(
            "[error]✗[/error] choose --password-env or --password-stdin, not both"
        )
        raise typer.Exit(1)
    secret: SecretStr | None = None
    if method == "password":
        host = host or _ask("Host", interactive)
        user = user or _ask("User", interactive)
        database = database or (
            _ask("Database", interactive, "postgres" if engine == "postgres" else "dev")
        )
        port = port or (5439 if engine == "redshift" else 5432)
        if password_env:
            pass  # read from the environment when connecting, never stored
        elif password_stdin:
            secret = SecretStr(sys.stdin.readline().rstrip("\n"))
        elif interactive and not project:
            typed = typer.prompt(
                "Password (empty for none)",
                hide_input=True,
                default="",
                show_default=False,
            )
            secret = SecretStr(typed) if typed else None
    elif rds:
        database = database or "postgres"
    else:
        if not (cluster or workgroup):
            workgroup = _ask(
                "Redshift Serverless workgroup (or pass --cluster)", interactive
            )
        database = database or _ask("Database", interactive, "dev")
    target = targets.Target(
        engine="redshift" if engine == "redshift" else "postgres",
        method=method,
        host=host,
        port=port or 5432,
        database=database or "postgres",
        user=user,
        sslmode=sslmode,
        cluster=cluster,
        workgroup=workgroup,
        secret_arn=secret_arn,
        db_user=db_user,
        region=region,
        password_env=password_env,
        rds=rds,
        profile=profile,
    )
    header("login", name)
    if check:
        _check_target(target, name, secret)
    try:
        path = targets.save(name, target, secret, make_default, project=project)
    except targets.TargetError as e:
        err.print(f"[error]✗[/error] {escape(str(e))}")
        raise typer.Exit(1) from None
    saved = target.model_copy(update={"has_password": secret is not None})
    console.print(
        f"[ok]✓[/ok] saved [accent]{name}[/accent] in {escape(str(path))}; {escape(saved.password_source())}"
    )
    if targets.default_name() == name:
        console.print(
            f"[muted]{name} is the default: sesame plan spec.yaml uses it[/muted]"
        )


def _valid_name(name: str) -> str:
    import re

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", name):
        raise ValueError(
            "a target name is letters, digits, _ . - (prod, staging, eu-1)"
        )
    return name


def _ask(label: str, interactive: bool, default: str | None = None) -> str:
    if not interactive:
        if default is not None:
            return default
        err.print(
            f"[error]✗[/error] missing {label.split(' (')[0].lower()}: pass it as an option"
        )
        raise typer.Exit(1)
    return typer.prompt(label, default=default) if default else typer.prompt(label)


def _check_target(target: targets.Target, name: str, secret: SecretStr | None) -> None:
    """Connect once, show who pgsesame is there, and whether it can manage roles."""
    try:
        db = _from_target(target, name, secret)
        if target.engine == "postgres":
            user, superuser, createrole, version = db.rows(
                "select current_user, rolsuper, rolcreaterole, current_setting('server_version') "
                "from pg_roles where rolname = current_user"
            )[0]
            can_manage = superuser or createrole
            server = f"PostgreSQL {version}"
        else:
            user, superuser = db.rows(
                "select current_user, usesuper from pg_user where usename = current_user"
            )[0]
            can_manage = superuser
            server = "Redshift"
        db.close()
    except Exception as e:  # any failure to connect: say it, save nothing
        err.print(f"[error]✗ can't connect:[/error] {escape(str(e).strip())}")
        err.print("[muted]nothing saved; fix the details, or pass --no-check[/muted]")
        raise typer.Exit(1) from None
    console.print(
        f"[ok]✓[/ok] connected as [accent]{escape(str(user))}[/accent] to {escape(target.describe())} ({escape(server)})"
    )
    if not can_manage:
        console.print(
            "[change]~ this user can't create roles: plan works, apply needs a "
            "superuser or CREATEROLE[/change]"
        )


@app.command(name="targets")
def list_targets() -> None:
    """List the saved targets."""
    saved = targets.all_targets()
    default = targets.default_name()
    project = targets.project_file()
    personal = targets.config_dir() / "targets.toml"
    header("targets", f"{project} + {personal}" if project else str(personal))
    if not saved:
        console.print("[muted]none yet: sesame login <name>[/muted]")
        return
    for name, target in sorted(saved.items()):
        mark = "[accent]*[/accent]" if name == default else " "
        console.print(
            f"{mark} [accent]{name}[/accent]  {target.engine}  {escape(target.describe())}  "
            f"[muted]{target.password_source()}, {targets.origin(name)}[/muted]"
        )


@app.command()
def use(name: str = typer.Argument(..., help="A saved target.")) -> None:
    """Make a saved target the default for plan and apply."""
    try:
        targets.use(name)
    except targets.TargetError as e:
        err.print(f"[error]✗[/error] {escape(str(e))}")
        raise typer.Exit(1) from None
    console.print(f"[ok]✓[/ok] [accent]{name}[/accent] is the default target")


@app.command()
def logout(name: str = typer.Argument(..., help="A saved target.")) -> None:
    """Forget a saved target and its password."""
    try:
        targets.remove(name)
    except targets.TargetError as e:
        err.print(f"[error]✗[/error] {escape(str(e))}")
        raise typer.Exit(1) from None
    console.print(f"[ok]✓[/ok] forgot [accent]{name}[/accent] and its keychain entry")

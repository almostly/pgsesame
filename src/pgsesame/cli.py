"""The ``sesame`` command: validate, plan and apply a permissions spec."""

from __future__ import annotations

from pathlib import Path

import psycopg
import typer
from typer import rich_utils

from pgsesame import __version__, planner, postgres, spec
from pgsesame.console import console, err, header, operation
from pgsesame.db import Database

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


def _plan(loaded: spec.Spec, db: Database) -> planner.Plan:
    if loaded.engine != "postgres":
        err.print("[error]Redshift support comes in a later milestone[/error]")
        raise typer.Exit(1)
    try:
        return planner.make(loaded, postgres.read(db))
    except planner.PlanError as e:
        for problem in e.problems:
            err.print(f"[error]✗[/error] {problem}")
        raise typer.Exit(1) from None


def _connect(dsn: str) -> Database:
    try:
        return Database(dsn)
    except psycopg.OperationalError as e:
        err.print(f"[error]can't connect:[/error] {str(e).strip()}")
        raise typer.Exit(1) from None


def _show(result: planner.Plan, db: Database) -> None:
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
def plan(path: Path = SpecPath, dsn: str = DsnOption) -> None:
    """Show the SQL that would make the database match the spec.

    Exits 0 when the database already matches, 2 when there are changes, 1 on
    errors, like ``terraform plan -detailed-exitcode``.
    """
    loaded = _load(path)
    db = _connect(dsn)
    header("plan", db.target)
    result = _plan(loaded, db)
    if not result.operations:
        console.print("[ok]✓[/ok] the database matches the spec; nothing to do")
        raise typer.Exit(0)
    _show(result, db)
    console.print(f"\n[accent]Plan:[/accent] {_summary(result)}")
    raise typer.Exit(2)


@app.command()
def apply(
    path: Path = SpecPath,
    dsn: str = DsnOption,
    allow_revoke: bool = typer.Option(
        False, "--allow-revoke", help="Also run revokes and membership removals."
    ),
    allow_drop: bool = typer.Option(False, "--allow-drop", help="Also run drops."),
) -> None:
    """Make the database match the spec, in one transaction."""
    loaded = _load(path)
    db = _connect(dsn)
    header("apply", db.target)
    result = _plan(loaded, db)
    runnable = result.allowed(allow_revoke, allow_drop)
    skipped = [op for op in result.operations if op not in runnable]
    if not runnable:
        console.print("[ok]✓[/ok] nothing to apply")
    else:
        _show(planner.Plan(runnable, result.notes), db)
        try:
            db.run([op.statement() for op in runnable])
        except psycopg.Error as e:
            err.print(f"[error]apply failed, nothing was changed:[/error] {e}")
            raise typer.Exit(1) from None
        console.print(f"\n[ok]✓[/ok] applied {len(runnable)} statement(s)")
    if skipped:
        for op in skipped:
            operation(
                op.kind, db.render(op.display()), f"skipped: needs --allow-{op.gate}"
            )
        console.print(f"[change]{len(skipped)} statement(s) skipped[/change]")

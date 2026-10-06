"""The ``sesame`` command: validate, plan and apply a permissions spec."""

from __future__ import annotations

from pathlib import Path

import typer
from typer import rich_utils

from pgsesame import __version__, spec
from pgsesame.console import console, err, header

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
def plan(path: Path = SpecPath) -> None:
    """Show the SQL that would make the database match the spec."""
    header("plan", str(path))
    err.print("[error]plan isn't implemented yet[/error] (milestone 2, see DESIGN.md)")
    raise typer.Exit(1)


@app.command()
def apply(path: Path = SpecPath) -> None:
    """Make the database match the spec."""
    header("apply", str(path))
    err.print("[error]apply isn't implemented yet[/error] (milestone 2, see DESIGN.md)")
    raise typer.Exit(1)

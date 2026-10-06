"""Terminal output in pgcli's style: green accents, Terraform-coloured plans.

Colour is off when output isn't a terminal or ``NO_COLOR`` is set (Rich honours
both), so CI logs stay plain.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

THEME = Theme(
    {
        "accent": "bold green",  # pgcli's green: header, connection, headings
        "muted": "dim",
        "create": "green",  # + create / grant / add member
        "change": "yellow",  # ~ owner / attribute change
        "remove": "red",  # - revoke / drop / remove member
        "error": "bold red",
        "ok": "green",
    }
)
console = Console(theme=THEME, highlight=False)
err = Console(theme=THEME, highlight=False, stderr=True)

SYMBOL = {"create": "+", "change": "~", "remove": "-"}


def header(title: str, target: str | None = None) -> None:
    """Print the green header line, with the pgcli-style ``user@host:db`` target."""
    line = f"[accent]sesame[/accent] [muted]·[/muted] {title}"
    if target:
        line += f" [muted]·[/muted] [accent]{target}[/accent]"
    console.print(line)


def operation(kind: str, sql: str, note: str = "") -> None:
    """Print one planned statement, coloured and marked like Terraform's plan."""
    suffix = f"  [muted]{note}[/muted]" if note else ""
    console.print(f"[{kind}]{SYMBOL[kind]} {sql}[/{kind}]{suffix}")

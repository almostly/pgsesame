"""Terminal output in pgcli's style: green accents, Terraform-coloured plans.

Colour is off when output isn't a terminal or ``NO_COLOR`` is set (Rich honours
both), so CI logs stay plain.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
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
# soft_wrap: long statements and messages stay on one line (logs, grep, copy-paste)
console = Console(theme=THEME, highlight=False, soft_wrap=True)
err = Console(theme=THEME, highlight=False, soft_wrap=True, stderr=True)

SYMBOL = {"create": "+", "change": "~", "remove": "-"}


def header(title: str, target: str | None = None) -> None:
    """Print the green header line, with the pgcli-style ``user@host:db`` target."""
    line = f"[accent]sesame[/accent] [muted]·[/muted] {escape(title)}"
    if target:
        line += f" [muted]·[/muted] [accent]{escape(target)}[/accent]"
    console.print(line)


def operation(kind: str, sql: str, note: str = "") -> None:
    """Print one planned statement, coloured and marked like Terraform's plan."""
    # SQL and notes are data, not markup: ARRAY[x] or a [word] would be eaten
    suffix = f"  [muted]{escape(note)}[/muted]" if note else ""
    console.print(f"[{kind}]{SYMBOL[kind]} {escape(sql)}[/{kind}]{suffix}")

"""Terminal output in pgcli's style: green accents, Terraform-colored plans.

Color is off when output isn't a terminal or ``NO_COLOR`` is set (Rich honors
both), so CI logs stay plain. ``SESAME_THEME=workbench`` highlights each planned
statement's SQL in SQL Workbench/J's colors instead, for a dark terminal; its
``+``/``~``/``-`` marker keeps the plan's color.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from pygments.token import Comment, Keyword, Name, Number, Operator, Punctuation
from pygments.token import String
from rich.console import Console
from rich.markup import escape
from rich.text import Text
from rich.theme import Theme

if TYPE_CHECKING:
    from pygments.token import _TokenType

STYLES = {
    "accent": "bold green",  # pgcli's green: header, connection, headings
    "muted": "dim",
    "create": "green",  # + create / grant / add member
    "change": "yellow",  # ~ owner / attribute change
    "remove": "red",  # - revoke / drop / remove member
    "error": "bold red",
    "ok": "green",
}
# SQL Workbench/J's editor colors, by what a token is
WORKBENCH = {
    "accent": "bold #00FF00",
    "muted": "#808080",  # its comments' gray
    "sql.keyword": "#00FF00",
    "sql.type": "#33CCFF",
    "sql.operator": "#FFFFFF",
    "sql.function": "#FF33FF",
    "sql.literal": "#EEEEEE",  # strings and quoted names
    "sql.comment": "#808080",
}
THEME_NAME = os.environ.get("SESAME_THEME", "")
THEME = Theme(STYLES | WORKBENCH if THEME_NAME == "workbench" else STYLES)
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
    """Print one planned statement, colored and marked like Terraform's plan."""
    if THEME_NAME == "workbench":
        # appended, not added: Text + Text styles the whole line as the first part
        line = Text()
        line.append(f"{SYMBOL[kind]} ", style=kind)
        line.append_text(highlight(sql))
        if note:
            line.append(f"  {note}", style="muted")
        console.print(line)
        return
    # SQL and notes are data, not markup: ARRAY[x] or a [word] would be eaten
    suffix = f"  [muted]{escape(note)}[/muted]" if note else ""
    console.print(f"[{kind}]{SYMBOL[kind]} {escape(sql)}[/{kind}]{suffix}")


def highlight(sql: str) -> Text:
    """Return ``sql`` with each token styled by what it is (the ``sql.*`` styles)."""
    from pygments.lexers.sql import PostgresLexer  # only the workbench theme's

    tokens = list(PostgresLexer().get_tokens(sql.rstrip()))
    # each token's next non-blank value, found walking back from the end
    following: list[str] = []
    after = ""
    for _, value in reversed(tokens):
        following.append(after)
        if value.strip():
            after = value
    following.reverse()
    runs: list[tuple[str, str]] = []  # (text, style): a quoted name is one run
    for (token, value), next_value in zip(tokens, following, strict=True):
        style = _style(token, value, next_value)
        if runs and runs[-1][1] == style:
            runs[-1] = (runs[-1][0] + value, style)
        else:
            runs.append((value, style))
    text = Text.assemble(*runs)
    text.rstrip()  # the lexer ends with a newline
    return text


def _style(token: _TokenType, value: str, following: str) -> str:
    """Return the ``sql.*`` style for one token, given the text after it.

    pgsesame quotes every name it writes, so a bare upper-case word (NOLOGIN,
    PUBLIC) is a keyword the lexer doesn't know, and a name before ``(`` is a
    function.
    """
    if token in Keyword:
        return "sql.keyword"
    if token in Name.Builtin:
        return "sql.type"
    if token in String:
        return "sql.literal"
    if token in Comment:
        return "sql.comment"
    if token in Operator or token in Punctuation or (token in Number and value == "."):
        return "sql.operator"
    if token in Name and following == "(":
        return "sql.function"
    if token in Name and value.isupper():
        return "sql.keyword"
    return ""

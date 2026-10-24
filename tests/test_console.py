"""The workbench theme: each planned statement's SQL highlighted by token."""

from rich.console import Console
from rich.theme import Theme

from pgsesame import console as output


def test_each_token_takes_its_workbench_style():
    text = output.highlight(
        'REVOKE EXECUTE ON ROUTINE "public"."f"(jsonb) FROM PUBLIC; '
        'CREATE POLICY "p" ON "t" USING ((select auth.uid()) = author OR \'x\' = name) -- note'
    )
    styles = {text.plain[s.start : s.end]: str(s.style) for s in text.spans}
    assert styles["REVOKE"] == styles["PUBLIC"] == styles["select"] == "sql.keyword"
    assert styles["jsonb"] == "sql.type"
    assert styles["uid"] == "sql.function"
    assert styles["."] == styles["="] == "sql.operator"
    assert styles["'x'"] == styles['"public"'] == "sql.literal"  # one span each
    assert styles["-- note"] == "sql.comment"
    assert "author" not in styles  # a bare lower-case name keeps the terminal's
    assert not text.plain.endswith("\n")


def test_the_marker_keeps_the_plans_color_and_the_note_is_muted(monkeypatch):
    monkeypatch.setattr(output, "THEME_NAME", "workbench")
    with output.console.capture() as captured:
        output.operation(
            "remove", 'REVOKE SELECT ON "t" FROM "x"', "needs --allow-revoke"
        )
    assert captured.get() == '- REVOKE SELECT ON "t" FROM "x"  needs --allow-revoke\n'
    # only the marker takes the plan's color, not the spaces and names between
    theme = Theme(output.STYLES | output.WORKBENCH)
    colored = Console(theme=theme, force_terminal=True, color_system="standard")
    monkeypatch.setattr(output, "console", colored)
    with colored.capture() as captured:
        output.operation("remove", 'REVOKE SELECT ON "t" FROM x')
    assert captured.get().count("\x1b[31m") == 1

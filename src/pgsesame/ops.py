"""The statements a plan is made of, as typed objects.

Each operation knows its kind (``create``, ``change`` or ``remove``, which the plan
colours green, yellow and red), whether it takes something away (revokes and
membership removals need ``--allow-revoke``, drops ``--allow-drop``), and how to
render itself with ``psycopg.sql``, so names are always quoted and never pasted
into SQL text.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from psycopg import sql
from pydantic import BaseModel, ConfigDict, SecretStr

from pgsesame.spec import PRIVILEGES

Kind = Literal["create", "change", "remove"]
Gate = Literal["revoke", "drop"]

# GRANT's keyword for each object type, and each privilege's keyword, written out
# as constants: psycopg.sql only takes literal strings as SQL
_ON = {
    "databases": sql.SQL("DATABASE"),
    "schemas": sql.SQL("SCHEMA"),
    "tables": sql.SQL("TABLE"),
    "views": sql.SQL("TABLE"),
    "sequences": sql.SQL("SEQUENCE"),
}
_PRIVILEGE = {
    "alter": sql.SQL("ALTER"),
    "connect": sql.SQL("CONNECT"),
    "create": sql.SQL("CREATE"),
    "delete": sql.SQL("DELETE"),
    "drop": sql.SQL("DROP"),
    "execute": sql.SQL("EXECUTE"),
    "insert": sql.SQL("INSERT"),
    "references": sql.SQL("REFERENCES"),
    "select": sql.SQL("SELECT"),
    "temp": sql.SQL("TEMP"),
    "temporary": sql.SQL("TEMPORARY"),
    "trigger": sql.SQL("TRIGGER"),
    "truncate": sql.SQL("TRUNCATE"),
    "update": sql.SQL("UPDATE"),
    "usage": sql.SQL("USAGE"),
}
assert set(_PRIVILEGE) >= set().union(
    *(p for engine in PRIVILEGES.values() for p in engine.values())
), "every privilege the spec accepts needs its keyword here"


def _object(object_type: str, name: str) -> sql.Composed:
    parts = (
        name.split(".", 1)
        if object_type in ("tables", "views", "sequences")
        else [name]
    )
    return sql.SQL("{} {}").format(_ON[object_type], sql.Identifier(*parts))


def _privilege(privilege: str) -> sql.SQL:
    return _PRIVILEGE[privilege]


class Operation(BaseModel):
    """One statement in a plan."""

    model_config = ConfigDict(frozen=True)

    kind: ClassVar[Kind] = "create"
    gate: ClassVar[Gate | None] = None  # the flag apply needs to run it
    order: ClassVar[int] = 0  # position in the plan: dependencies first

    def statement(self) -> sql.Composed:
        """Return the SQL to run."""
        raise NotImplementedError

    def display(self) -> sql.Composed:
        """Return the SQL to show in a plan (secrets masked)."""
        return self.statement()


class CreateRole(Operation):
    """Create a role, user (a role that can log in) or group."""

    order: ClassVar[int] = 10
    name: str
    login: bool
    # SecretStr: the password never shows in a repr, a log or an error; only
    # statement() unwraps it, into a quoted literal
    password: SecretStr | None = None

    def _sql(self, password: sql.Composable | None) -> sql.Composed:
        parts = [
            sql.SQL("CREATE ROLE {}").format(sql.Identifier(self.name)),
            sql.SQL("LOGIN" if self.login else "NOLOGIN"),
        ]
        if password is not None:
            parts.append(sql.SQL("PASSWORD {}").format(password))
        return sql.SQL(" ").join(parts)

    def statement(self) -> sql.Composed:
        """Return CREATE ROLE, with the password when there is one."""
        if self.password is None:
            return self._sql(None)
        return self._sql(sql.Literal(self.password.get_secret_value()))

    def display(self) -> sql.Composed:
        """Return CREATE ROLE with the password masked."""
        return self._sql(None if self.password is None else sql.SQL("'********'"))


class AlterLogin(Operation):
    """Let a role log in, or stop it."""

    kind: ClassVar[Kind] = "change"
    order: ClassVar[int] = 20
    name: str
    login: bool

    def statement(self) -> sql.Composed:
        """Return ALTER ROLE ... LOGIN or NOLOGIN."""
        return sql.SQL("ALTER ROLE {} {}").format(
            sql.Identifier(self.name), sql.SQL("LOGIN" if self.login else "NOLOGIN")
        )


class AddMember(Operation):
    """Make ``member`` a member of ``role``."""

    order: ClassVar[int] = 30
    member: str
    role: str

    def statement(self) -> sql.Composed:
        """Return GRANT role TO member."""
        return sql.SQL("GRANT {} TO {}").format(
            sql.Identifier(self.role), sql.Identifier(self.member)
        )


class Grant(Operation):
    """Grant a privilege on an object."""

    order: ClassVar[int] = 40
    grantee: str
    object_type: str
    object_name: str
    privilege: str

    def statement(self) -> sql.Composed:
        """Return GRANT privilege ON object TO grantee."""
        return sql.SQL("GRANT {} ON {} TO {}").format(
            _privilege(self.privilege),
            _object(self.object_type, self.object_name),
            sql.Identifier(self.grantee),
        )


class Revoke(Operation):
    """Revoke a privilege on an object."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "revoke"
    order: ClassVar[int] = 50
    grantee: str
    object_type: str
    object_name: str
    privilege: str

    def statement(self) -> sql.Composed:
        """Return REVOKE privilege ON object FROM grantee."""
        return sql.SQL("REVOKE {} ON {} FROM {}").format(
            _privilege(self.privilege),
            _object(self.object_type, self.object_name),
            sql.Identifier(self.grantee),
        )


class RemoveMember(Operation):
    """Take ``member`` out of ``role``."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "revoke"
    order: ClassVar[int] = 60
    member: str
    role: str

    def statement(self) -> sql.Composed:
        """Return REVOKE role FROM member."""
        return sql.SQL("REVOKE {} FROM {}").format(
            sql.Identifier(self.role), sql.Identifier(self.member)
        )

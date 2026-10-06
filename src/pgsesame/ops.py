"""The statements a plan is made of, as typed objects.

Each operation knows its kind (``create``, ``change`` or ``remove``, which the plan
colours green, yellow and red), whether it takes something away (revokes and
membership removals need ``--allow-revoke``, drops ``--allow-drop``), and how to
render itself with ``psycopg.sql``, so names are always quoted and never pasted
into SQL text.
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Literal

from psycopg import sql
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from pgsesame.spec import PRIVILEGES
from pgsesame.state import Identity

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


def _grantee(name: str, identity: Identity) -> sql.Composed:
    """Return a grantee as GRANT and REVOKE name it: Redshift says GROUP and ROLE."""
    if identity == "group":
        return sql.SQL("GROUP {}").format(sql.Identifier(name))
    if identity == "role":
        return sql.SQL("ROLE {}").format(sql.Identifier(name))
    return sql.SQL("{}").format(sql.Identifier(name))


class CreateRole(Operation):
    """Create a principal: a PostgreSQL role, or a Redshift user, group or role."""

    order: ClassVar[int] = 10
    op: Literal["create_role"] = "create_role"
    name: str
    identity: Identity = "pg"
    login: bool = False
    # SecretStr: the password never shows in a repr, a log or an error; only
    # statement() unwraps it, into a quoted literal
    password: SecretStr | None = Field(None, exclude=True)  # never saved
    # where apply finds the password again when it runs a saved change set
    password_env: str | None = None
    password_disabled: bool = False

    def _sql(self, password: sql.Composable | None) -> sql.Composed:
        name = sql.Identifier(self.name)
        if self.identity == "group":
            return sql.SQL("CREATE GROUP {}").format(name)
        if self.identity == "role":
            return sql.SQL("CREATE ROLE {}").format(name)
        if self.identity == "user":  # Redshift: a user always has a password clause
            return sql.SQL("CREATE USER {} PASSWORD {}").format(
                name, password if password is not None else sql.SQL("DISABLE")
            )
        parts = [
            sql.SQL("CREATE ROLE {}").format(name),
            sql.SQL("LOGIN" if self.login else "NOLOGIN"),
        ]
        if password is not None:
            parts.append(sql.SQL("PASSWORD {}").format(password))
        return sql.SQL(" ").join(parts)

    def statement(self) -> sql.Composed:
        """Return the CREATE statement, with the password when there is one."""
        if self.password is None or self.password_disabled:
            return self._sql(None)
        return self._sql(sql.Literal(self.password.get_secret_value()))

    def display(self) -> sql.Composed:
        """Return the CREATE statement with the password masked."""
        if self.password is None or self.password_disabled:
            return self._sql(None)
        return self._sql(sql.SQL("'********'"))


class AlterLogin(Operation):
    """Let a PostgreSQL role log in, or stop it."""

    kind: ClassVar[Kind] = "change"
    order: ClassVar[int] = 20
    op: Literal["alter_login"] = "alter_login"
    name: str
    login: bool

    def statement(self) -> sql.Composed:
        """Return ALTER ROLE ... LOGIN or NOLOGIN."""
        return sql.SQL("ALTER ROLE {} {}").format(
            sql.Identifier(self.name), sql.SQL("LOGIN" if self.login else "NOLOGIN")
        )


def _membership(
    verb: Literal["add", "remove"],
    member: str,
    member_identity: Identity,
    role: str,
    role_identity: Identity,
) -> sql.Composed:
    """Render a membership change for the kind of identity ``role`` is."""
    add = verb == "add"
    if role_identity == "group":  # Redshift groups hold users
        return sql.SQL("ALTER GROUP {} {} USER {}").format(
            sql.Identifier(role),
            sql.SQL("ADD" if add else "DROP"),
            sql.Identifier(member),
        )
    if role_identity == "role":  # Redshift roles go to users and other roles
        return sql.SQL("{} ROLE {} {} {}").format(
            sql.SQL("GRANT" if add else "REVOKE"),
            sql.Identifier(role),
            sql.SQL("TO" if add else "FROM"),
            _grantee(member, member_identity),
        )
    return sql.SQL("{} {} {} {}").format(
        sql.SQL("GRANT" if add else "REVOKE"),
        sql.Identifier(role),
        sql.SQL("TO" if add else "FROM"),
        sql.Identifier(member),
    )


class AddMember(Operation):
    """Make ``member`` a member of ``role`` (a group or role on Redshift)."""

    order: ClassVar[int] = 30
    op: Literal["add_member"] = "add_member"
    member: str
    role: str
    member_identity: Identity = "pg"
    role_identity: Identity = "pg"

    def statement(self) -> sql.Composed:
        """Return GRANT role TO member, or Redshift's form for the identity."""
        return _membership(
            "add", self.member, self.member_identity, self.role, self.role_identity
        )


class Grant(Operation):
    """Grant a privilege on an object."""

    order: ClassVar[int] = 40
    op: Literal["grant"] = "grant"
    grantee: str
    object_type: str
    object_name: str
    privilege: str
    grantee_identity: Identity = "pg"

    def statement(self) -> sql.Composed:
        """Return GRANT privilege ON object TO grantee."""
        return sql.SQL("GRANT {} ON {} TO {}").format(
            _privilege(self.privilege),
            _object(self.object_type, self.object_name),
            _grantee(self.grantee, self.grantee_identity),
        )


class Revoke(Operation):
    """Revoke a privilege on an object."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "revoke"
    order: ClassVar[int] = 50
    op: Literal["revoke"] = "revoke"
    grantee: str
    object_type: str
    object_name: str
    privilege: str
    grantee_identity: Identity = "pg"

    def statement(self) -> sql.Composed:
        """Return REVOKE privilege ON object FROM grantee."""
        return sql.SQL("REVOKE {} ON {} FROM {}").format(
            _privilege(self.privilege),
            _object(self.object_type, self.object_name),
            _grantee(self.grantee, self.grantee_identity),
        )


class RemoveMember(Operation):
    """Take ``member`` out of ``role`` (a group or role on Redshift)."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "revoke"
    order: ClassVar[int] = 60
    op: Literal["remove_member"] = "remove_member"
    member: str
    role: str
    member_identity: Identity = "pg"
    role_identity: Identity = "pg"

    def statement(self) -> sql.Composed:
        """Return REVOKE role FROM member, or Redshift's form for the identity."""
        return _membership(
            "remove", self.member, self.member_identity, self.role, self.role_identity
        )


# a plan's operations as one type, told apart by ``op``: what a change set stores
AnyOperation = Annotated[
    CreateRole | AlterLogin | AddMember | Grant | Revoke | RemoveMember,
    Field(discriminator="op"),
]

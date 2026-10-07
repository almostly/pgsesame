"""The statements a plan is made of, as typed objects.

Each operation knows its kind (``create``, ``change`` or ``remove``, which the plan
colours green, yellow and red), whether it takes something away (revokes and
membership removals need ``--allow-revoke``, drops ``--allow-drop``), and how to
render itself with ``psycopg.sql``, so names are always quoted and never pasted
into SQL text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, cast

from psycopg import sql
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from pgsesame.spec import PRIVILEGES
from pgsesame.state import Identity

if TYPE_CHECKING:  # LiteralString is typing's from Python 3.11 on
    from typing_extensions import LiteralString

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
    "columns": sql.SQL("TABLE"),
}
_PRIVILEGE = {
    "alter": sql.SQL("ALTER"),
    "connect": sql.SQL("CONNECT"),
    "create": sql.SQL("CREATE"),
    "delete": sql.SQL("DELETE"),
    "drop": sql.SQL("DROP"),
    "execute": sql.SQL("EXECUTE"),
    "insert": sql.SQL("INSERT"),
    "maintain": sql.SQL("MAINTAIN"),
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
    if object_type == "columns":  # the table a column grant is ON
        name = name.rsplit(".", 1)[0]
    parts = (
        name.split(".", 1)
        if object_type in ("tables", "views", "sequences", "columns")
        else [name]
    )
    return sql.SQL("{} {}").format(_ON[object_type], sql.Identifier(*parts))


def _privilege_on(privilege: str, object_type: str, name: str) -> sql.Composed:
    """Return ``SELECT ON TABLE s.t``, or for a column ``SELECT (c) ON TABLE s.t``."""
    if object_type == "columns":
        column = sql.Identifier(name.rsplit(".", 1)[1])
        return sql.SQL("{} ({}) ON {}").format(
            _privilege(privilege), column, _object(object_type, name)
        )
    return sql.SQL("{} ON {}").format(_privilege(privilege), _object(object_type, name))


def _privilege(privilege: str) -> sql.SQL:
    return _PRIVILEGE[privilege]


class Operation(BaseModel):
    """One statement in a plan."""

    model_config = ConfigDict(frozen=True)

    kind: ClassVar[Kind] = "create"
    gate: ClassVar[Gate | None] = None  # the flag apply needs to run it
    order: ClassVar[int] = 0  # position in the plan: dependencies first

    @property
    def needs(self) -> Gate | None:
        """Return the flag apply needs to run this operation, if any."""
        return self.gate

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
        return sql.SQL("GRANT {} TO {}").format(
            _privilege_on(self.privilege, self.object_type, self.object_name),
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
        return sql.SQL("REVOKE {} FROM {}").format(
            _privilege_on(self.privilege, self.object_type, self.object_name),
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


def _table(name: str) -> sql.Composed:
    schema, table = name.split(".", 1)
    return sql.SQL("{}").format(sql.Identifier(schema, table))


def _roles(roles: tuple[str, ...]) -> sql.Composed:
    return sql.SQL(", ").join(
        sql.SQL("PUBLIC") if r == "public" else sql.Identifier(r) for r in roles
    )


def _expression(text: str) -> sql.SQL:
    # a policy's USING / WITH CHECK is SQL by design: it comes from the reviewed
    # spec, and goes into the statement as written
    return sql.SQL(cast("LiteralString", text))


_COMMAND = {
    "all": sql.SQL("ALL"),
    "select": sql.SQL("SELECT"),
    "insert": sql.SQL("INSERT"),
    "update": sql.SQL("UPDATE"),
    "delete": sql.SQL("DELETE"),
}


def _clauses(using: str | None, with_check: str | None) -> list[sql.Composable]:
    parts: list[sql.Composable] = []
    if using:
        parts.append(sql.SQL("USING ({})").format(_expression(using)))
    if with_check:
        parts.append(sql.SQL("WITH CHECK ({})").format(_expression(with_check)))
    return parts


class CreatePolicy(Operation):
    """Create a row-level security policy."""

    order: ClassVar[int] = 42
    op: Literal["create_policy"] = "create_policy"
    table: str
    name: str
    command: str
    permissive: bool
    roles: tuple[str, ...]
    using: str | None = None
    with_check: str | None = None

    def statement(self) -> sql.Composed:
        """Return CREATE POLICY ... ON table AS ... FOR ... TO ... USING/WITH CHECK."""
        parts: list[sql.Composable] = [
            sql.SQL("CREATE POLICY {} ON {} AS {} FOR {} TO {}").format(
                sql.Identifier(self.name),
                _table(self.table),
                sql.SQL("PERMISSIVE" if self.permissive else "RESTRICTIVE"),
                _COMMAND[self.command],
                _roles(self.roles),
            )
        ]
        return sql.SQL(" ").join(parts + _clauses(self.using, self.with_check))


class AlterPolicy(Operation):
    """Change a policy's roles or expressions (ALTER POLICY)."""

    kind: ClassVar[Kind] = "change"
    order: ClassVar[int] = 43
    op: Literal["alter_policy"] = "alter_policy"
    table: str
    name: str
    roles: tuple[str, ...]
    using: str | None = None
    with_check: str | None = None

    def statement(self) -> sql.Composed:
        """Return ALTER POLICY ... ON table TO ... USING/WITH CHECK."""
        parts: list[sql.Composable] = [
            sql.SQL("ALTER POLICY {} ON {} TO {}").format(
                sql.Identifier(self.name), _table(self.table), _roles(self.roles)
            )
        ]
        return sql.SQL(" ").join(parts + _clauses(self.using, self.with_check))


class DropPolicy(Operation):
    """Drop a policy (also the first half of replacing one ALTER can't change)."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "drop"
    order: ClassVar[int] = 41  # before the creates: a replaced policy keeps its name
    op: Literal["drop_policy"] = "drop_policy"
    table: str
    name: str

    def statement(self) -> sql.Composed:
        """Return DROP POLICY ... ON table."""
        return sql.SQL("DROP POLICY {} ON {}").format(
            sql.Identifier(self.name), _table(self.table)
        )


class EnableRowSecurity(Operation):
    """Turn row-level security on for a table."""

    order: ClassVar[int] = 44
    op: Literal["enable_row_security"] = "enable_row_security"
    table: str

    def statement(self) -> sql.Composed:
        """Return ALTER TABLE ... ENABLE ROW LEVEL SECURITY."""
        return sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(
            _table(self.table)
        )


class ForceRowSecurity(Operation):
    """Apply a table's policies to its owner too (FORCE), or stop (NO FORCE)."""

    kind: ClassVar[Kind] = "change"
    order: ClassVar[int] = 45
    op: Literal["force_row_security"] = "force_row_security"
    table: str
    force: bool

    def statement(self) -> sql.Composed:
        """Return ALTER TABLE ... FORCE / NO FORCE ROW LEVEL SECURITY."""
        return sql.SQL("ALTER TABLE {} {} ROW LEVEL SECURITY").format(
            _table(self.table), sql.SQL("FORCE" if self.force else "NO FORCE")
        )


class DisableRowSecurity(Operation):
    """Turn row-level security off for a table: every row visible again."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "drop"
    order: ClassVar[int] = 46
    op: Literal["disable_row_security"] = "disable_row_security"
    table: str

    def statement(self) -> sql.Composed:
        """Return ALTER TABLE ... DISABLE ROW LEVEL SECURITY."""
        return sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY").format(
            _table(self.table)
        )


# ---------------------------------------------------------------------------
# Redshift dynamic data masking
# ---------------------------------------------------------------------------
def _type(text: str) -> sql.SQL:
    # a policy input's type, from the spec (checked to be words and an optional
    # (n) or (p, s)) or from Redshift's catalog
    return sql.SQL(cast("LiteralString", text))


def _mask_grantee(grantee: str, grantee_type: str) -> sql.Composable:
    if grantee_type == "public":
        return sql.SQL("PUBLIC")
    if grantee_type == "role":
        return sql.SQL("ROLE {}").format(sql.Identifier(grantee))
    return sql.Identifier(grantee)


def _columns(names: tuple[str, ...]) -> sql.Composed:
    return sql.SQL(", ").join(sql.Identifier(n) for n in names)


class _Replaceable(Operation):
    # part of replacing a policy ALTER can't change (detach everywhere, drop,
    # create, attach again): all of it needs --allow-drop, or none of it runs
    replacing: bool = False

    @property
    def needs(self) -> Gate | None:
        """Return drop while replacing a policy, else the operation's own gate."""
        return "drop" if self.replacing else self.gate


class CreateMaskingPolicy(_Replaceable):
    """Create a masking policy."""

    order: ClassVar[int] = 72
    op: Literal["create_masking_policy"] = "create_masking_policy"
    name: str
    inputs: tuple[tuple[str, str], ...]
    using: str

    def statement(self) -> sql.Composed:
        """Return CREATE MASKING POLICY ... WITH (inputs) USING (expression)."""
        inputs = sql.SQL(", ").join(
            sql.SQL("{} {}").format(sql.Identifier(n), _type(t)) for n, t in self.inputs
        )
        return sql.SQL("CREATE MASKING POLICY {} WITH ({}) USING ({})").format(
            sql.Identifier(self.name), inputs, _expression(self.using)
        )


class AlterMaskingPolicy(Operation):
    """Change a masking policy's expression (its output type stays)."""

    kind: ClassVar[Kind] = "change"
    order: ClassVar[int] = 73
    op: Literal["alter_masking_policy"] = "alter_masking_policy"
    name: str
    using: str

    def statement(self) -> sql.Composed:
        """Return ALTER MASKING POLICY ... USING (expression)."""
        return sql.SQL("ALTER MASKING POLICY {} USING ({})").format(
            sql.Identifier(self.name), _expression(self.using)
        )


class DropMaskingPolicy(Operation):
    """Drop a masking policy (also the middle of replacing one ALTER can't change)."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "drop"
    order: ClassVar[int] = 71
    op: Literal["drop_masking_policy"] = "drop_masking_policy"
    name: str

    def statement(self) -> sql.Composed:
        """Return DROP MASKING POLICY."""
        return sql.SQL("DROP MASKING POLICY {}").format(sql.Identifier(self.name))


class _Attachment(_Replaceable):
    policy: str
    table: str
    columns: tuple[str, ...]
    grantee: str
    grantee_type: str


class AttachMaskingPolicy(_Attachment):
    """Attach a masking policy to columns, for a grantee, at a priority."""

    order: ClassVar[int] = 74
    op: Literal["attach_masking_policy"] = "attach_masking_policy"
    inputs: tuple[str, ...]
    priority: int

    def statement(self) -> sql.Composed:
        """Return ATTACH MASKING POLICY ... ON table (cols) [USING (...)] TO ... PRIORITY n."""
        using = (
            sql.SQL(" USING ({})").format(_columns(self.inputs))
            if self.inputs != self.columns
            else sql.SQL("")
        )
        return sql.SQL(
            "ATTACH MASKING POLICY {} ON {} ({}){} TO {} PRIORITY {}"
        ).format(
            sql.Identifier(self.policy),
            _table(self.table),
            _columns(self.columns),
            using,
            _mask_grantee(self.grantee, self.grantee_type),
            sql.Literal(self.priority),
        )


def _detach(op: _Attachment) -> sql.Composed:
    return sql.SQL("DETACH MASKING POLICY {} ON {} ({}) FROM {}").format(
        sql.Identifier(op.policy),
        _table(op.table),
        _columns(op.columns),
        _mask_grantee(op.grantee, op.grantee_type),
    )


class DetachMaskingPolicy(_Attachment):
    """Detach a masking policy from a grantee: the grantee sees the column as before."""

    kind: ClassVar[Kind] = "remove"
    gate: ClassVar[Gate | None] = "revoke"
    order: ClassVar[int] = 70  # first: frees a priority another policy moves into
    op: Literal["detach_masking_policy"] = "detach_masking_policy"

    def statement(self) -> sql.Composed:
        """Return DETACH MASKING POLICY ... ON table (cols) FROM ..."""
        return _detach(self)


class ReattachMaskingPolicy(_Attachment):
    """Detach before attaching again at other priorities: a change, not a revoke.

    One DETACH removes every priority a grantee has for the policy on the column,
    so changing a priority is a detach and the attaches that follow it.
    """

    kind: ClassVar[Kind] = "change"
    order: ClassVar[int] = 70
    op: Literal["reattach_masking_policy"] = "reattach_masking_policy"

    def statement(self) -> sql.Composed:
        """Return DETACH MASKING POLICY ... ON table (cols) FROM ..."""
        return _detach(self)


# a plan's operations as one type, told apart by ``op``: what a change set stores
AnyOperation = Annotated[
    CreateRole
    | AlterLogin
    | AddMember
    | Grant
    | Revoke
    | RemoveMember
    | CreatePolicy
    | AlterPolicy
    | DropPolicy
    | EnableRowSecurity
    | ForceRowSecurity
    | DisableRowSecurity
    | CreateMaskingPolicy
    | AlterMaskingPolicy
    | DropMaskingPolicy
    | AttachMaskingPolicy
    | DetachMaskingPolicy
    | ReattachMaskingPolicy,
    Field(discriminator="op"),
]

"""The state both sides of a diff are expressed in: principals, memberships, grants.

The reader turns a database's catalog into a ``State``; the planner turns a spec
into one. Objects are named the way GRANT names them: a database or schema by its
name, a relation or sequence as ``schema.name``. A part holding a dot or a double
quote is quoted, as SQL quotes it: ``userrisk_dwh."roll rates.csv"``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# what kind of identity a name is: a PostgreSQL role ("pg"), or one of Redshift's
# three, which each have their own DDL and grantee syntax
Identity = Literal["pg", "user", "group", "role"]


def qualify(*parts: str) -> str:
    """Return ``parts`` joined by dots, quoting each that holds a dot or a quote.

    A plain name stays as written (``public.todos``), so names that read before
    read the same; only one a dot would cut in two is quoted.
    """
    return ".".join(
        '"' + part.replace('"', '""') + '"' if "." in part or '"' in part else part
        for part in parts
    )


def part_sql(column: str) -> str:
    """Return SQL writing a catalog name part as qualify() does: quoted if it must be."""
    return (
        f"case when strpos({column}, '.') + strpos({column}, '\"') > 0 "
        f"then '\"' || replace({column}, '\"', '\"\"') || '\"' else {column} end"
    )


def split(name: str) -> list[str]:
    """Return the parts of a dotted name, unquoted; a dot inside quotes is the name's.

    A function's argument types, from ``(`` on, stay with its last part, dots and
    all: ``public.f(public.money)`` is ``public`` and ``f(public.money)``.
    """
    parts = [""]
    quoted = False
    i = 0
    while i < len(name):
        char = name[i]
        if char == '"':
            if quoted and name[i + 1 : i + 2] == '"':  # "" inside quotes is a "
                parts[-1] += char
                i += 1
            else:
                quoted = not quoted
        elif char == "." and not quoted:
            parts.append("")
        elif char == "(" and not quoted:
            parts[-1] += name[i:]
            break
        else:
            parts[-1] += char
        i += 1
    return parts


def schema_of(name: str) -> str:
    """Return the schema of a ``schema.name`` (or a column's), unquoted."""
    return split(name)[0]


def parent(name: str) -> str:
    """Return the table a ``schema.table.column`` belongs to, as ``schema.table``."""
    return qualify(*split(name)[:-1])


@dataclass(frozen=True, order=True)
class Role:
    """A principal as the database sees it."""

    name: str
    login: bool
    superuser: bool = False
    identity: Identity = "pg"
    # PostgreSQL: CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS, as the spec spells them
    attributes: frozenset[str] = frozenset()


@dataclass(frozen=True, order=True)
class Membership:
    """``member`` belongs to ``role``."""

    member: str
    role: str


@dataclass(frozen=True, order=True)
class Privilege:
    """``grantee`` holds ``privilege`` on an object of ``object_type``."""

    grantee: str
    object_type: str  # databases, schemas, tables, views, sequences
    object_name: str
    privilege: str  # lowercase: select, usage, ...


@dataclass(frozen=True, order=True)
class Policy:
    """A row-level security policy, its expressions in the server's own form."""

    table: str
    name: str
    command: str  # all, select, insert, update, delete
    permissive: bool
    roles: tuple[str, ...]  # sorted; ("public",) for PUBLIC
    using: str | None
    with_check: str | None


@dataclass(frozen=True, order=True)
class DefaultGrant:
    """``grantee`` gets ``privilege`` on objects of a type ``owner`` creates."""

    owner: str
    schema: str  # "" for every schema
    object_type: str  # tables, sequences, functions, schemas
    grantee: str
    privilege: str


@dataclass(frozen=True, order=True)
class MaskPolicy:
    """A Redshift masking policy, its expression and types in Redshift's own form."""

    name: str
    inputs: tuple[tuple[str, str], ...]  # (name, type), in order
    expression: str
    output_type: str


@dataclass(frozen=True, order=True)
class Attachment:
    """A masking policy attached to columns of a table, for one grantee."""

    policy: str
    table: str  # schema.table
    columns: tuple[str, ...]  # the masked (output) columns
    inputs: tuple[str, ...]  # the columns the policy reads
    grantee: str  # "public" for PUBLIC
    grantee_type: str  # user, role, public
    priority: int


@dataclass
class State:
    """What the database grants (read) or should grant (from the spec)."""

    roles: dict[str, Role] = field(default_factory=dict)
    # False when the catalog shows this user only part of it: Redshift's SVV
    # privilege views show a non-superuser its own grants only
    sees_everything: bool = True
    memberships: set[Membership] = field(default_factory=set)
    privileges: set[Privilege] = field(default_factory=set)
    # the privileges above held WITH GRANT OPTION: the grantee may grant them on
    # (read for databases, schemas, tables and views; a spec never gives one)
    grant_options: set[Privilege] = field(default_factory=set)
    # every object the database has, by type: lets the planner expand schema.*
    objects: dict[str, set[str]] = field(default_factory=dict)
    # who owns each object: (object type, name) -> owner
    owners: dict[tuple[str, str], str] = field(default_factory=dict)
    # ALTER DEFAULT PRIVILEGES entries: grants on objects not created yet
    default_privileges: set[DefaultGrant] = field(default_factory=set)
    # what PUBLIC (every user) holds on schemas: read to warn about, not managed
    public_privileges: set[Privilege] = field(default_factory=set)
    # row-level security per table: (enabled, forced), and the tables' policies
    rls: dict[str, tuple[bool, bool]] = field(default_factory=dict)
    # publications: name -> (owner, FOR ALL TABLES), and the tables each has
    publications: dict[str, tuple[str, bool]] = field(default_factory=dict)
    publication_tables: set[tuple[str, str]] = field(default_factory=set)
    # views that run with their owner's rights (no security_invoker), of those the
    # connected user may change
    definer_views: set[str] = field(default_factory=set)
    # the tables whose row-level security the connected user may switch (it acts
    # as their owner); None: every table
    rls_switchable: set[str] | None = None
    policies: dict[tuple[str, str], Policy] = field(default_factory=dict)
    # Redshift masking: policies, attachments, and the masked columns' types
    mask_policies: dict[str, MaskPolicy] = field(default_factory=dict)
    attachments: set[Attachment] = field(default_factory=set)
    column_types: dict[str, str] = field(default_factory=dict)
    # users the spec gives a password_env, signed in as with it: None when not
    # tried (over the Data API there's no connection to sign in on), else the
    # ones refused (the password was disabled or changed by hand)
    passwords_refused: set[str] | None = None
    # Aurora DSQL: (role, IAM identity ARN) that signs in as the role
    iam_links: set[tuple[str, str]] = field(default_factory=set)
    # the roles the connected user may alter and grant (ADMIN OPTION on PostgreSQL
    # 16+, any non-superuser with CREATEROLE before); None: every role
    administers: set[str] | None = None
    # the roles the connected user acts as (PostgreSQL); None: every role
    acts_as: set[str] | None = None
    # Redshift system permissions held by roles: (role, permission, lower case);
    # None where the catalog has no svv_system_privileges (older redshift-local)
    system_privileges: set[tuple[str, str]] | None = field(default_factory=set)
    # who is connected, and PostgreSQL's bootstrap superuser (which stays one)
    current_user: str | None = None
    bootstrap: str | None = None
    # the attributes the connected user may give or take; None: every one
    sets_attributes: set[str] | None = None

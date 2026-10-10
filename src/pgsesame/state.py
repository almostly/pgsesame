"""The state both sides of a diff are expressed in: principals, memberships, grants.

The reader turns a database's catalog into a ``State``; the planner turns a spec
into one. Objects are named the way GRANT names them: a database or schema by its
name, a relation or sequence as ``schema.name``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# what kind of identity a name is: a PostgreSQL role ("pg"), or one of Redshift's
# three, which each have their own DDL and grantee syntax
Identity = Literal["pg", "user", "group", "role"]


@dataclass(frozen=True, order=True)
class Role:
    """A principal as the database sees it."""

    name: str
    login: bool
    superuser: bool = False
    identity: Identity = "pg"


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

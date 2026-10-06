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


@dataclass
class State:
    """What the database grants (read) or should grant (from the spec)."""

    roles: dict[str, Role] = field(default_factory=dict)
    memberships: set[Membership] = field(default_factory=set)
    privileges: set[Privilege] = field(default_factory=set)
    # every object the database has, by type: lets the planner expand schema.*
    objects: dict[str, set[str]] = field(default_factory=dict)

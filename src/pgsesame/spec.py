"""The permissions spec: YAML loaded into validated pydantic models.

The spec is principal-centric: each principal (role, user or, on Redshift, group)
declares its memberships, the objects it owns and the privileges it holds. See
DESIGN.md for the format.

Validation runs in two passes and reports every problem, each with its path in the
file: pydantic checks the structure (types, unknown keys, allowed values), then
``_check`` checks what needs the whole spec (engine-specific rules and references
between principals). The second pass runs once the structure is valid, so a spec
with structural problems reports those first. ``json_schema()`` gives editors the
same structure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal, get_args

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

Engine = Literal["postgres", "redshift"]
ObjectType = Literal[
    "databases", "schemas", "tables", "views", "sequences", "functions", "columns"
]
OBJECT_TYPES: tuple[str, ...] = get_args(ObjectType)
# the types a default privilege can cover (a column is never created on its own)
DEFAULT_TYPES = ("databases", "schemas", "tables", "views", "sequences", "functions")
# ... and the ones each engine's ALTER DEFAULT PRIVILEGES takes (views are tables)
DEFAULT_PRIVILEGE_TYPES = {
    "postgres": ("tables", "sequences", "functions", "schemas"),
    "redshift": ("tables", "functions"),
}

# Parse at the edge: a spec that gets past these types holds only well-formed
# names, so nothing past the loader has to check them again.
#
# A role, user, group or schema name: not empty, no NUL byte, at most 127 bytes
# (Redshift's limit; PostgreSQL's 63 is checked per engine in the second pass).
Identifier = Annotated[
    str, StringConstraints(min_length=1, max_length=127, pattern=r"^[^\x00]+$")
]
# an environment variable name, as a shell accepts it
EnvVar = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]
# an object: name, schema.name, schema.* (every object of the type in schema), or
# for columns schema.table.column (which parts a type takes is checked per type)
ObjectPattern = Annotated[
    str,
    StringConstraints(pattern=r"^[^.\x00]+(\.(\*|[^.\x00*]+(\.[^.\x00*]+)?))?$"),
]
# every privilege name any engine knows; which apply to which engine and object
# type is the second pass's job
Privilege = Literal[
    "maintain",
    "alter",
    "connect",
    "create",
    "delete",
    "drop",
    "execute",
    "insert",
    "references",
    "select",
    "temp",
    "temporary",
    "trigger",
    "truncate",
    "update",
    "usage",
]
# PostgreSQL truncates names to NAMEDATALEN - 1 bytes; Redshift allows 127
MAX_NAME_BYTES = {"postgres": 63, "redshift": 127}

# privileges each object type accepts, per engine
_COMMON = {
    "databases": {"connect", "create", "temporary", "temp"},
    "schemas": {"usage", "create"},
    "tables": {"select", "insert", "update", "delete", "references", "truncate"},
    "views": {"select"},
    "sequences": {"usage", "select", "update"},
    "functions": {"execute"},
    "columns": {"select", "insert", "update", "references"},
}
PRIVILEGES: dict[str, dict[str, set[str]]] = {
    # MAINTAIN (VACUUM, ANALYZE, REFRESH ...) exists from PostgreSQL 17 on
    "postgres": {**_COMMON, "tables": _COMMON["tables"] | {"trigger", "maintain"}},
    "redshift": {
        **_COMMON,
        "schemas": _COMMON["schemas"] | {"alter", "drop"},
        "tables": _COMMON["tables"] | {"alter", "drop"},
        "views": _COMMON["views"] | {"alter", "drop"},
        "columns": {"select", "update"},
    },
}


class SpecError(Exception):
    """A spec that can't be used; ``problems`` lists every issue with its path."""

    def __init__(self, problems: list[str]):
        """Keep the problems; the message lists them one per line."""
        super().__init__("\n".join(problems))
        self.problems = problems


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Principal(_Model):
    """A role, user or (Redshift) group, and what it is granted."""

    # builtin: a role the platform owns (Supabase's authenticated, RDS's rds_iam,
    # Redshift's sys:secadmin): referred to and granted to, never created or altered
    type: Literal["role", "user", "group", "builtin"]
    login: bool | None = Field(None, description="Defaults to true for users.")
    member_of: list[Identifier] = Field(
        default_factory=list, description="Roles it belongs to."
    )
    groups: list[Identifier] = Field(
        default_factory=list, description="Redshift groups."
    )
    owns: dict[ObjectType, list[ObjectPattern]] = Field(default_factory=dict)
    privileges: dict[ObjectType, dict[Privilege, list[ObjectPattern]]] = Field(
        default_factory=dict,
        description="Object type -> privilege -> objects (schema.* for all).",
    )
    password_env: EnvVar | None = Field(
        None, description="Environment variable holding the password."
    )
    password: Literal["disabled"] | None = Field(
        None, description="'disabled' for no password; never a password itself."
    )

    @property
    def can_login(self) -> bool:
        """Whether the principal logs in (users do unless ``login: false``)."""
        return self.login if self.login is not None else self.type == "user"


class DefaultPrivilege(_Model):
    """Privileges ``grantee`` gets on objects ``owner`` creates (in ``schema``)."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    owner: Identifier
    grantee: Identifier
    in_schema: Identifier | None = Field(None, alias="schema")
    databases: list[Privilege] | None = None
    schemas: list[Privilege] | None = None
    tables: list[Privilege] | None = None
    views: list[Privilege] | None = None
    sequences: list[Privilege] | None = None
    functions: list[Privilege] | None = None

    def grants(self) -> dict[str, list[str]]:
        """Return object type -> privileges, for the types this rule covers."""
        return {
            kind: sorted(names)
            for kind in DEFAULT_TYPES
            if (names := getattr(self, kind)) is not None
        }


# a table, schema-qualified: schema.table
TableName = Annotated[str, StringConstraints(pattern=r"^[^.\x00]+\.[^.\x00*]+$")]


class RlsPolicy(_Model):
    """One row-level security policy (CREATE POLICY)."""

    command: Literal["all", "select", "insert", "update", "delete"] = "all"
    to: list[Identifier] = Field(
        default_factory=lambda: ["public"], description="Roles, or public (default)."
    )
    using: str | None = Field(None, description="Which existing rows are visible.")
    with_check: str | None = Field(None, description="Which new rows are allowed.")
    permissive: bool = Field(True, description="false for RESTRICTIVE.")


class RlsTable(_Model):
    """Row-level security on one table: on or off, forced or not, its policies."""

    enabled: bool = True
    force: bool = Field(False, description="Apply the policies to the table owner too.")
    policies: dict[Identifier, RlsPolicy] = Field(default_factory=dict)


# a column, schema.table.column
ColumnName = Annotated[
    str, StringConstraints(pattern=r"^[^.\x00]+\.[^.\x00*]+\.[^.\x00*]+$")
]
# a SQL type as a masking policy's input declares it: varchar(256), numeric(12, 2),
# character varying, timestamp ... (words, then an optional (n) or (p, s))
SqlType = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_ ]*(\(\s*\d+\s*(,\s*\d+\s*)?\))?$"),
]
# pgsesame's own pass-through policies, one per column type, are named so
UNMASKED_PREFIX = "sesame_unmasked_"


class MaskingPolicy(_Model):
    """A reusable mask (CREATE MASKING POLICY): its inputs and expression."""

    type: SqlType | None = Field(
        None, description="One input, named value, of this type."
    )
    input: dict[Identifier, SqlType] | None = Field(
        None, description="Several named inputs and their types, in order."
    )
    using: str = Field(..., description="The masked value, over the inputs.")

    def inputs(self) -> list[tuple[str, str]]:
        """Return the policy's inputs as (name, type), in order."""
        if self.type is not None:
            return [("value", self.type)]
        return list((self.input or {}).items())


class MaskedColumn(_Model):
    """What each reader of one column sees."""

    mask: Identifier | None = Field(None, description="The policy everyone sees.")
    unmasked: list[Identifier] = Field(
        default_factory=list, description="Roles that see the raw value."
    )
    roles: dict[Identifier, Identifier] = Field(
        default_factory=dict,
        description="Roles that see their own policy; later entries win.",
    )
    inputs: list[Identifier] | None = Field(
        None, description="The columns a policy with several inputs reads, in order."
    )


class Masking(_Model):
    """Redshift dynamic data masking: the policies, and the columns they mask."""

    policies: dict[Identifier, MaskingPolicy] = Field(default_factory=dict)
    columns: dict[ColumnName, MaskedColumn] = Field(default_factory=dict)


class Spec(_Model):
    """A whole spec: the engine, the principals and default-privilege rules."""

    version: Literal[1]
    engine: Engine
    principals: dict[Identifier, Principal] = Field(default_factory=dict)
    default_privileges: list[DefaultPrivilege] = Field(default_factory=list)
    row_level_security: dict[TableName, RlsTable] = Field(
        default_factory=dict, description="Tables whose row-level security is managed."
    )
    masking: Masking | None = Field(None, description="Redshift dynamic data masking.")


def load(path: str | Path) -> Spec:
    """Read and validate a spec file; raise SpecError listing every problem."""
    try:
        raw = yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as e:
        raise SpecError([f"{path}: not valid YAML: {e}"]) from None
    return parse(raw)


def parse(raw: Any) -> Spec:
    """Validate a spec already loaded from YAML."""
    try:
        spec = Spec.model_validate(raw)
    except ValidationError as e:
        raise SpecError([_describe(err) for err in e.errors()]) from None
    problems = _check(spec)
    if problems:
        raise SpecError(problems)
    return spec


def json_schema() -> dict[str, Any]:
    """Return the spec's JSON Schema, for editor completion and checking."""
    schema = Spec.model_json_schema(by_alias=True)
    schema["title"] = "pgsesame spec"
    return schema


def _describe(err: Any) -> str:
    # pydantic marks a bad mapping key with a "[key]" step; the path names the key
    path = ".".join(str(part) for part in err["loc"] if part != "[key]") or "spec"
    if err["type"] == "extra_forbidden":
        return f"{path}: unknown key"
    if err["type"] == "missing":
        return f"{path}: required"
    return f"{path}: {err['msg'][0].lower()}{err['msg'][1:]}"


def _check(spec: Spec) -> list[str]:
    """Check what pydantic can't: engine rules and references between principals."""
    problems: list[str] = []
    redshift = spec.engine == "redshift"
    principals = spec.principals
    limit = MAX_NAME_BYTES[spec.engine]
    for name, p in principals.items():
        where = f"principals.{name}"
        if len(name.encode()) > limit:
            problems.append(f"{where}: longer than {spec.engine}'s {limit} bytes")
        if p.type == "builtin":
            owned = [
                key
                for key in (
                    "login",
                    "password",
                    "password_env",
                    "groups",
                    "member_of",
                    "owns",
                )
                if getattr(p, key)
            ]
            if owned:
                problems.append(
                    f"{where}: a built-in role is referred to, not managed; only "
                    f"privileges can be declared for it ({', '.join(owned)})"
                )
            continue
        if p.type == "group" and not redshift:
            problems.append(f"{where}.type: groups exist on Redshift only")
        if p.groups and not redshift:
            problems.append(f"{where}.groups: groups exist on Redshift only")
        if p.type == "group" and (p.login or p.member_of):
            problems.append(f"{where}: a group can't log in or be a member of a role")
        elif redshift and p.login is not None and p.login != (p.type == "user"):
            problems.append(
                f"{where}.login: on Redshift a user always logs in and a role never does"
            )
        if "columns" in p.owns:
            problems.append(f"{where}.owns.columns: a column is owned with its table")
        for kind, patterns in [
            *p.owns.items(),
            *(
                (kind, [x for names in grants.values() for x in names])
                for kind, grants in p.privileges.items()
            ),
        ]:
            for pattern in patterns:
                parts = pattern.split(".")
                if kind == "columns" and (len(parts) != 3 or "*" in parts):
                    problems.append(
                        f"{where}: {pattern}: a column is schema.table.column"
                    )
                elif kind != "columns" and len(parts) > 2:
                    problems.append(
                        f"{where}: {pattern}: three parts name a column (use columns)"
                    )
        for kind, grants in p.privileges.items():
            allowed = PRIVILEGES[spec.engine][kind]
            for privilege in grants:
                if privilege not in allowed:
                    problems.append(
                        f"{where}.privileges.{kind}.{privilege}: not a {spec.engine} "
                        f"privilege on {kind} ({', '.join(sorted(allowed))})"
                    )
        for parent in p.member_of:
            target = principals.get(parent)
            if target is None:
                problems.append(f"{where}.member_of: {parent} is not declared")
            elif target.type == "group":
                problems.append(f"{where}.member_of: {parent} is a group; use groups")
        for group in p.groups:
            target = principals.get(group)
            if target is None or target.type != "group":
                problems.append(f"{where}.groups: {group} is not a declared group")
    for i, rule in enumerate(spec.default_privileges):
        where = f"default_privileges[{i}]"
        # the owner need not be declared (often the ETL or admin user that
        # creates the objects); the plan says if it doesn't exist
        if rule.grantee not in principals:
            problems.append(f"{where}.grantee: {rule.grantee} is not declared")
        elif principals[rule.grantee].type == "group" and not redshift:
            problems.append(f"{where}.grantee: groups exist on Redshift only")
        grants = rule.grants()
        if not grants:
            problems.append(f"{where}: grants no privileges")
        allowed_types = DEFAULT_PRIVILEGE_TYPES[spec.engine]
        for kind in grants:
            if kind not in allowed_types:
                problems.append(
                    f"{where}.{kind}: {spec.engine} has no default privileges on {kind} "
                    f"({', '.join(allowed_types)})"
                )
        if "schemas" in grants and rule.in_schema:
            problems.append(
                f"{where}.schemas: default privileges on schemas take no schema"
            )
        for kind, names in grants.items():
            if kind not in allowed_types:
                continue
            allowed = PRIVILEGES[spec.engine][kind]
            for privilege in names:
                if privilege not in allowed:
                    problems.append(
                        f"{where}.{kind}: {privilege} is not a {spec.engine} "
                        f"privilege on {kind}"
                    )
    problems += _check_rls(spec)
    problems += _check_masking(spec)
    return problems


def _check_rls(spec: Spec) -> list[str]:
    """Check the row-level security section: engine, roles and clauses per command."""
    problems: list[str] = []
    if spec.row_level_security and spec.engine == "redshift":
        return ["row_level_security: Redshift's RLS policies come in a later version"]
    for table, rls in spec.row_level_security.items():
        for name, policy in rls.policies.items():
            where = f"row_level_security.{table}.policies.{name}"
            for role in policy.to:
                if role != "public" and role not in spec.principals:
                    problems.append(f"{where}.to: {role} is not declared")
            if "public" in policy.to and len(policy.to) > 1:
                # PostgreSQL keeps only PUBLIC, so the policy would never match
                problems.append(f"{where}.to: public covers every role; list it alone")
            if policy.command in ("select", "delete") and policy.with_check:
                problems.append(
                    f"{where}: {policy.command} policies take no with_check"
                )
            if policy.command == "insert" and policy.using:
                problems.append(f"{where}: insert policies take no using")
            if not (policy.using or policy.with_check):
                problems.append(f"{where}: needs using or with_check")
    return problems


def _check_masking(spec: Spec) -> list[str]:
    """Check the masking section: engine, policies, and who sees what per column."""
    masking = spec.masking
    if masking is None:
        return []
    if spec.engine != "redshift":
        return [
            "masking: dynamic data masking is Redshift's; on PostgreSQL use column "
            "privileges"
        ]
    problems: list[str] = []
    for name, policy in masking.policies.items():
        where = f"masking.policies.{name}"
        if name.startswith(UNMASKED_PREFIX):
            problems.append(f"{where}: {UNMASKED_PREFIX}* names are pgsesame's own")
        if (policy.type is None) == (policy.input is None):
            problems.append(f"{where}: give type (one input) or input (several)")
        elif policy.input is not None and not policy.input:
            problems.append(f"{where}.input: needs at least one input")
    for column, c in masking.columns.items():
        where = f"masking.columns.{column}"
        if c.mask is None and not c.roles and not c.unmasked:
            problems.append(f"{where}: masks nothing (give mask, roles or unmasked)")
        if c.mask is None and c.unmasked:
            problems.append(f"{where}.unmasked: there's no mask to see past")
        used = [("mask", c.mask)] if c.mask else []
        used += [(f"roles.{r}", p) for r, p in c.roles.items()]
        for key, name in used:
            policy = masking.policies.get(name)
            if policy is None:
                problems.append(f"{where}.{key}: {name} is not a declared policy")
            elif len(policy.inputs()) > 1 and len(c.inputs or []) != len(
                policy.inputs()
            ):
                problems.append(
                    f"{where}.inputs: {name} reads {len(policy.inputs())} columns; "
                    "list them in inputs"
                )
        for key, roles in (("unmasked", c.unmasked), ("roles", list(c.roles))):
            for role in roles:
                p = spec.principals.get(role)
                if p is None:
                    problems.append(f"{where}.{key}: {role} is not declared")
                elif p.type == "group":
                    problems.append(
                        f"{where}.{key}: {role} is a group; Redshift masks for users "
                        "and roles only"
                    )
        both = sorted(set(c.unmasked) & set(c.roles))
        if both:
            problems.append(
                f"{where}: {', '.join(both)} can't be both unmasked and masked"
            )
    return problems

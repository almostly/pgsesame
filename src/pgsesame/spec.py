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
from typing import Any, Literal, get_args

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

Engine = Literal["postgres", "redshift"]
ObjectType = Literal[
    "databases", "schemas", "tables", "views", "sequences", "functions"
]
OBJECT_TYPES: tuple[str, ...] = get_args(ObjectType)

# privileges each object type accepts, per engine
_COMMON = {
    "databases": {"connect", "create", "temporary", "temp"},
    "schemas": {"usage", "create"},
    "tables": {"select", "insert", "update", "delete", "references", "truncate"},
    "views": {"select"},
    "sequences": {"usage", "select", "update"},
    "functions": {"execute"},
}
PRIVILEGES: dict[str, dict[str, set[str]]] = {
    "postgres": {**_COMMON, "tables": _COMMON["tables"] | {"trigger"}},
    "redshift": {
        **_COMMON,
        "schemas": _COMMON["schemas"] | {"alter", "drop"},
        "tables": _COMMON["tables"] | {"alter", "drop"},
        "views": _COMMON["views"] | {"alter", "drop"},
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

    type: Literal["role", "user", "group"]
    login: bool | None = Field(None, description="Defaults to true for users.")
    member_of: list[str] = Field(
        default_factory=list, description="Roles it belongs to."
    )
    groups: list[str] = Field(default_factory=list, description="Redshift groups.")
    owns: dict[ObjectType, list[str]] = Field(default_factory=dict)
    privileges: dict[ObjectType, dict[str, list[str]]] = Field(
        default_factory=dict,
        description="Object type -> privilege -> objects (schema.* for all).",
    )
    password_env: str | None = Field(
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

    owner: str
    grantee: str
    in_schema: str | None = Field(None, alias="schema")
    databases: list[str] | None = None
    schemas: list[str] | None = None
    tables: list[str] | None = None
    views: list[str] | None = None
    sequences: list[str] | None = None
    functions: list[str] | None = None

    def grants(self) -> dict[str, list[str]]:
        """Return object type -> privileges, for the types this rule covers."""
        return {
            kind: sorted(names)
            for kind in OBJECT_TYPES
            if (names := getattr(self, kind)) is not None
        }


class Spec(_Model):
    """A whole spec: the engine, the principals and default-privilege rules."""

    version: Literal[1]
    engine: Engine
    principals: dict[str, Principal] = Field(default_factory=dict)
    default_privileges: list[DefaultPrivilege] = Field(default_factory=list)


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
    path = ".".join(str(part) for part in err["loc"]) or "spec"
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
    for name, p in principals.items():
        where = f"principals.{name}"
        if p.type == "group" and not redshift:
            problems.append(f"{where}.type: groups exist on Redshift only")
        if p.groups and not redshift:
            problems.append(f"{where}.groups: groups exist on Redshift only")
        if p.type == "group" and (p.login or p.member_of):
            problems.append(f"{where}: a group can't log in or be a member of a role")
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
        for key in ("owner", "grantee"):
            if getattr(rule, key) not in principals:
                problems.append(f"{where}.{key}: {getattr(rule, key)} is not declared")
        grants = rule.grants()
        if not grants:
            problems.append(f"{where}: grants no privileges")
        for kind, names in grants.items():
            allowed = PRIVILEGES[spec.engine][kind]
            for privilege in names:
                if privilege not in allowed:
                    problems.append(
                        f"{where}.{kind}: {privilege} is not a {spec.engine} "
                        f"privilege on {kind}"
                    )
    return problems

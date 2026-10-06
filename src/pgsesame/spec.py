"""The permissions spec: loading YAML into a validated model.

The spec is principal-centric: each principal (role, user or, on Redshift, group)
declares its memberships, the objects it owns and the privileges it holds. See
DESIGN.md for the format. Validation reports every problem it finds, each with its
path in the file, instead of stopping at the first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ENGINES = ("postgres", "redshift")
PRINCIPAL_TYPES = ("role", "user", "group")
OBJECT_TYPES = ("databases", "schemas", "tables", "views", "sequences", "functions")

# privileges each object type accepts, per engine
_COMMON = {
    "databases": {"connect", "create", "temporary", "temp"},
    "schemas": {"usage", "create"},
    "tables": {"select", "insert", "update", "delete", "references", "truncate"},
    "views": {"select"},
    "sequences": {"usage", "select", "update"},
    "functions": {"execute"},
}
PRIVILEGES = {
    "postgres": {**_COMMON, "tables": _COMMON["tables"] | {"trigger"}},
    "redshift": {
        **_COMMON,
        "schemas": _COMMON["schemas"] | {"alter", "drop"},
        "tables": _COMMON["tables"] | {"alter", "drop"},
        "views": _COMMON["views"] | {"alter", "drop"},
    },
}
_PRINCIPAL_KEYS = {
    "type",
    "login",
    "member_of",
    "groups",
    "owns",
    "privileges",
    "password_env",
    "password",
}
_DEFAULT_KEYS = {"owner", "schema", "grantee", *OBJECT_TYPES}


class SpecError(Exception):
    """A spec that can't be used; ``problems`` lists every issue with its path."""

    def __init__(self, problems: list[str]):
        """Keep the problems; the message lists them one per line."""
        super().__init__("\n".join(problems))
        self.problems = problems


@dataclass
class Principal:
    """A role, user or (Redshift) group, and what it is granted."""

    name: str
    type: str
    login: bool = False
    member_of: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    owns: dict[str, list[str]] = field(default_factory=dict)
    privileges: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    password_env: str | None = None
    password_disabled: bool = False


@dataclass
class DefaultPrivilege:
    """Privileges ``grantee`` gets on objects ``owner`` creates (in ``schema``)."""

    owner: str
    grantee: str
    schema: str | None
    privileges: dict[str, list[str]]


@dataclass
class Spec:
    """A validated spec."""

    engine: str
    principals: dict[str, Principal]
    default_privileges: list[DefaultPrivilege]


def load(path: str | Path) -> Spec:
    """Read and validate a spec file; raise SpecError listing every problem."""
    try:
        raw = yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as e:
        raise SpecError([f"{path}: not valid YAML: {e}"]) from None
    return parse(raw)


def parse(raw: Any) -> Spec:
    """Validate a spec already loaded from YAML."""
    problems: list[str] = []
    if not isinstance(raw, dict):
        raise SpecError(["the spec must be a mapping"])
    unknown = set(raw) - {"version", "engine", "principals", "default_privileges"}
    problems += [f"{k}: unknown key" for k in sorted(unknown)]
    if raw.get("version") != 1:
        problems.append("version: must be 1")
    engine = raw.get("engine")
    if engine not in ENGINES:
        problems.append(f"engine: must be one of {', '.join(ENGINES)}")
        engine = "postgres"  # keep validating the rest

    principals: dict[str, Principal] = {}
    for name, body in (raw.get("principals") or {}).items():
        principal = _principal(str(name), body or {}, engine, problems)
        if principal:
            principals[principal.name] = principal
    _check_references(principals, problems)

    defaults = [
        d
        for i, body in enumerate(raw.get("default_privileges") or [])
        if (d := _default(i, body or {}, engine, principals, problems))
    ]
    if problems:
        raise SpecError(problems)
    return Spec(engine=engine, principals=principals, default_privileges=defaults)


def _principal(
    name: str, body: Any, engine: str, problems: list[str]
) -> Principal | None:
    where = f"principals.{name}"
    if not isinstance(body, dict):
        problems.append(f"{where}: must be a mapping")
        return None
    problems += [
        f"{where}.{k}: unknown key" for k in sorted(set(body) - _PRINCIPAL_KEYS)
    ]
    kind = body.get("type")
    if kind not in PRINCIPAL_TYPES:
        problems.append(f"{where}.type: must be one of {', '.join(PRINCIPAL_TYPES)}")
        return None
    if kind == "group" and engine != "redshift":
        problems.append(f"{where}.type: groups exist on Redshift only")
    if body.get("groups") and engine != "redshift":
        problems.append(f"{where}.groups: groups exist on Redshift only")
    if kind == "group" and (body.get("login") or body.get("member_of")):
        problems.append(f"{where}: a group can't log in or be a member of a role")
    password = body.get("password")
    if password not in (None, "disabled"):
        problems.append(
            f"{where}.password: only 'disabled' is allowed; "
            "name an environment variable with password_env instead"
        )
    privileges = _privileges(
        where + ".privileges", body.get("privileges"), engine, problems
    )
    owns = body.get("owns") or {}
    for kind_owned in set(owns) - set(OBJECT_TYPES):
        problems.append(f"{where}.owns.{kind_owned}: unknown object type")
    return Principal(
        name=name,
        type=kind,
        login=bool(body.get("login", kind == "user")),
        member_of=list(body.get("member_of") or []),
        groups=list(body.get("groups") or []),
        owns={k: list(v or []) for k, v in owns.items() if k in OBJECT_TYPES},
        privileges=privileges,
        password_env=body.get("password_env"),
        password_disabled=password == "disabled",
    )


def _privileges(
    where: str, body: Any, engine: str, problems: list[str]
) -> dict[str, dict[str, list[str]]]:
    out: dict[str, dict[str, list[str]]] = {}
    for kind, grants in (body or {}).items():
        if kind not in OBJECT_TYPES:
            problems.append(f"{where}.{kind}: unknown object type")
            continue
        allowed = PRIVILEGES[engine][kind]
        out[kind] = {}
        for privilege, objects in (grants or {}).items():
            if privilege not in allowed:
                problems.append(
                    f"{where}.{kind}.{privilege}: not a {engine} privilege on {kind} "
                    f"({', '.join(sorted(allowed))})"
                )
                continue
            out[kind][privilege] = list(objects or [])
    return out


def _check_references(principals: dict[str, Principal], problems: list[str]) -> None:
    for p in principals.values():
        for parent in p.member_of:
            target = principals.get(parent)
            if target is None:
                problems.append(
                    f"principals.{p.name}.member_of: {parent} is not declared"
                )
            elif target.type == "group":
                problems.append(
                    f"principals.{p.name}.member_of: {parent} is a group; use groups"
                )
        for group in p.groups:
            target = principals.get(group)
            if target is None or target.type != "group":
                problems.append(
                    f"principals.{p.name}.groups: {group} is not a declared group"
                )


def _default(
    i: int,
    body: Any,
    engine: str,
    principals: dict[str, Principal],
    problems: list[str],
) -> DefaultPrivilege | None:
    where = f"default_privileges[{i}]"
    if not isinstance(body, dict):
        problems.append(f"{where}: must be a mapping")
        return None
    problems += [f"{where}.{k}: unknown key" for k in sorted(set(body) - _DEFAULT_KEYS)]
    for key in ("owner", "grantee"):
        if body.get(key) not in principals:
            problems.append(f"{where}.{key}: {body.get(key)} is not declared")
    privileges: dict[str, list[str]] = {}
    for kind in OBJECT_TYPES:
        if kind not in body:
            continue
        allowed = PRIVILEGES[engine][kind]
        names = list(body[kind] or [])
        for privilege in names:
            if privilege not in allowed:
                problems.append(
                    f"{where}.{kind}: {privilege} is not a {engine} privilege on {kind}"
                )
        privileges[kind] = sorted(p for p in names if p in allowed)
    if not privileges:
        problems.append(f"{where}: grants no privileges")
    return DefaultPrivilege(
        owner=str(body.get("owner")),
        grantee=str(body.get("grantee")),
        schema=body.get("schema"),
        privileges=privileges,
    )

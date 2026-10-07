"""Write a spec from what a database grants today (``sesame import``).

Adopting pgsesame on a database that already has roles and grants would make a
first plan full of drift: every grant the spec doesn't list yet. ``build`` reads
the database and writes the spec that reproduces it, so the first plan is empty
and the spec is edited from there.

Each selected principal gets the objects it owns (``owns``). Which principals:
every role but superusers and the platform's system roles, or,
with ``prefixes``, those named so. A role one of them refers to (a membership)
but that isn't selected is written as ``type: builtin``: referred to, never
managed. With ``schemas``, only grants on objects in those schemas are written,
and the spec says ``manage: {schemas: ...}``, so grants elsewhere stay out of
its plans. Passwords are never written; masking policies and row-level security
are not imported yet.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import yaml

from pgsesame.planner import _system_role
from pgsesame.spec import DEFAULT_PRIVILEGE_TYPES, OWNABLE, PRIVILEGES
from pgsesame.state import Privilege, State


def _in_schemas(p: Privilege, schemas: set[str]) -> bool:
    if not schemas or p.object_type == "databases":
        return True
    schema = (
        p.object_name if p.object_type == "schemas" else p.object_name.split(".", 1)[0]
    )
    return schema in schemas


def build(
    state: State,
    engine: str,
    schemas: list[str] | None = None,
    prefixes: list[str] | None = None,
    me: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return the spec (as data) that reproduces ``state``, and notes on what was left out."""
    redshift = engine == "redshift"
    in_scope = set(schemas or [])
    notes: list[str] = []

    def selectable(name: str) -> bool:
        role = state.roles[name]
        if role.superuser or _system_role(name) or name == me:
            return False
        return not prefixes or name.startswith(tuple(prefixes))

    selected = sorted(name for name in state.roles if selectable(name))
    principals: dict[str, dict[str, Any]] = {}
    referred: set[str] = set()

    for name in selected:
        role = state.roles[name]
        entry: dict[str, Any] = {}
        if redshift:
            entry["type"] = role.identity if role.identity != "pg" else "user"
        else:
            entry["type"] = "user" if role.login else "role"
        member_of = sorted(
            m.role
            for m in state.memberships
            if m.member == name
            and not (
                redshift
                and state.roles.get(m.role)
                and state.roles[m.role].identity == "group"
            )
        )
        groups = sorted(
            m.role
            for m in state.memberships
            if m.member == name
            and redshift
            and state.roles.get(m.role)
            and state.roles[m.role].identity == "group"
        )
        if member_of:
            entry["member_of"] = member_of
        if groups:
            entry["groups"] = groups
        referred |= set(member_of) | set(groups)

        grants: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        known = PRIVILEGES[engine]
        for p in state.privileges:
            if p.grantee != name or not _in_schemas(p, in_scope):
                continue
            if p.privilege not in known.get(p.object_type, ()):
                notes.append(
                    f"{name}: {p.privilege.upper()} on {p.object_name} isn't a privilege "
                    "pgsesame manages; left out"
                )
                continue
            grants[p.object_type][p.privilege].add(p.object_name)
        owned: dict[str, list[str]] = defaultdict(list)
        for (kind, obj), owner in sorted(state.owners.items()):
            if owner != name or kind not in OWNABLE[engine]:
                continue
            schema = obj if kind == "schemas" else obj.split(".", 1)[0]
            if kind == "databases" or not in_scope or schema in in_scope:
                owned[kind].append(obj)
        if owned:
            entry["owns"] = dict(sorted(owned.items()))
        if grants:
            entry["privileges"] = {
                kind: {priv: sorted(objects) for priv, objects in sorted(by.items())}
                for kind, by in sorted(grants.items())
            }
        principals[name] = entry

    for name in sorted(referred - set(principals)):
        principals[name] = {"type": "builtin"}  # referred to, not managed

    defaults: dict[tuple[str, str, str], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    allowed = DEFAULT_PRIVILEGE_TYPES[engine]
    for d in state.default_privileges:
        if d.grantee not in selected or (in_scope and d.schema not in in_scope):
            continue
        if d.object_type not in allowed:
            notes.append(
                f"default privileges of {d.owner} on {d.object_type} for {d.grantee}: "
                "not a type pgsesame manages; left out"
            )
            continue
        # a privilege the spec can't name (Redshift's P in a default ACL, say):
        # noted and left out, as for grants, so the spec stays valid
        if d.privilege not in PRIVILEGES[engine].get(d.object_type, ()):
            notes.append(
                f"{d.grantee}: default {d.privilege.upper()} on {d.object_type} from "
                f"{d.owner} isn't a privilege pgsesame manages; left out"
            )
            continue
        defaults[(d.owner, d.schema, d.grantee)][d.object_type].add(d.privilege)
    default_privileges = []
    for (owner, schema, grantee), kinds in sorted(defaults.items()):
        rule: dict[str, Any] = {"owner": owner}
        if schema:
            rule["schema"] = schema
        rule["grantee"] = grantee
        for kind, privileges in sorted(kinds.items()):
            rule[kind] = sorted(privileges)
        default_privileges.append(rule)

    spec: dict[str, Any] = {"version": 1, "engine": engine}
    manage: dict[str, list[str]] = {}
    if schemas:
        manage["schemas"] = sorted(schemas)
    if prefixes:
        manage["prefixes"] = sorted(prefixes)
    if manage:
        spec["manage"] = manage
    spec["principals"] = principals
    if default_privileges:
        spec["default_privileges"] = default_privileges
    if state.policies or state.attachments:
        notes.append(
            "row-level security and masking aren't imported yet; add them by hand"
        )
    return spec, sorted(set(notes))


def dump(spec: dict[str, Any], source: str) -> str:
    """Return the spec as YAML, with a header saying where it came from."""
    header = (
        f"# Written by sesame import from {source}: what the database grants today.\n"
        "# Edit from here; sesame plan against the same database shows nothing to do.\n"
    )
    return header + yaml.safe_dump(spec, sort_keys=False, default_flow_style=False)

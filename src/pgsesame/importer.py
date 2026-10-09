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
its plans. Passwords are never written. On Redshift masking is written in
pgsesame's model (see ``_masking``); row-level security is not imported yet.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import yaml

from pgsesame.planner import _system_role, public_create_notes
from pgsesame.masking import (
    passes_through,
    role_priorities,
    same_order,
    unmasked_policy,
)
from pgsesame.state import Attachment
from pgsesame.spec import (
    DEFAULT_PRIVILEGE_TYPES,
    OWNABLE,
    PRIVILEGES,
    UNMASKED_PREFIX,
)
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
    masking_visible: bool | None = None,
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
    if masking_visible is False:
        notes.append(
            "masking: this user can't see masking policies (needs superuser or "
            "sys:secadmin), so none were imported; that says nothing about whether "
            "there are any"
        )
    elif masking_visible:
        section = _masking(state, in_scope, notes)
        if section["columns"]:
            spec["masking"] = section
            for column in section["columns"].values():
                for name in [*column.get("unmasked", []), *column.get("roles", {})]:
                    if name not in principals:
                        principals[name] = {"type": "builtin"}  # referred to
    if state.policies:
        notes.append("row-level security isn't imported yet; add it by hand")
    notes += public_create_notes(state, schemas)
    return spec, sorted(set(notes))


def _masking(state: State, in_scope: set[str], notes: list[str]) -> dict[str, Any]:
    """Return the masking section pgsesame's model gives what the database has.

    Per column: the PUBLIC attachment is ``mask``; a role or user whose winning
    attachment passes the value through is ``unmasked``; any other is in
    ``roles``, ordered by its priority so the same one wins. pgsesame's own
    priorities (10, 20 ..., 1000) and pass-through policies replace the
    database's, so where those differ the first plan shows the correction.
    Anything the model can't say is noted, not guessed.
    """
    policies = state.mask_policies

    def raw(name: str) -> bool:
        return name in policies and passes_through(policies[name])

    by_column: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for a in state.attachments:
        if in_scope and a.table.split(".", 1)[0] not in in_scope:
            continue
        if len(a.columns) != 1 or a.inputs != a.columns:
            notes.append(
                f"masking: {a.policy} on {a.table} ({', '.join(a.columns)}) reads "
                "other columns than it masks; not imported"
            )
            continue
        by_column[(a.table, a.columns[0])].append(a)

    columns: dict[str, dict[str, Any]] = {}
    used: set[str] = set()
    for (table, column), attached in sorted(by_column.items()):
        where = f"masking: {table}.{column}"
        public = sorted(
            (a for a in attached if a.grantee_type == "public"),
            key=lambda a: a.priority,
        )
        if len({a.policy for a in public}) > 1:
            notes.append(f"{where}: several policies for PUBLIC; the highest kept")
        entry: dict[str, Any] = {}
        if public:
            if raw(public[-1].policy):
                notes.append(f"{where}: PUBLIC sees the raw value; no mask imported")
            else:
                entry["mask"] = public[-1].policy
                used.add(public[-1].policy)
        # each grantee's highest-priority attachment decides what it sees
        winning: dict[str, Any] = {}
        others = (a for a in attached if a.grantee_type != "public")
        for a in sorted(others, key=lambda a: (a.priority, a.grantee)):
            winning[a.grantee] = a
        unmasked = sorted(g for g, a in winning.items() if raw(a.policy))
        # by priority, then name: a tie is one policy (Redshift refuses two at a
        # priority), so the roles that share it stay together and in one order
        roles = {
            g: a.policy
            for g, a in sorted(winning.items(), key=lambda kv: (kv[1].priority, kv[0]))
            if g not in unmasked
        }
        if unmasked and "mask" not in entry:
            notes.append(
                f"{where}: {', '.join(unmasked)} see the raw value, but there's no "
                "mask to see past; left out"
            )
            unmasked = []
        if unmasked:
            entry["unmasked"] = unmasked
        if roles:
            entry["roles"] = roles
            used |= set(roles.values())
        if not entry:
            continue
        # pgsesame's attachments for this entry; where the database ranks the
        # same attachments the same way, the plan keeps its numbers
        then = []
        if "mask" in entry:
            then.append(
                Attachment(
                    entry["mask"], table, (column,), (column,), "public", "public", 10
                )
            )
        roles = entry.get("roles", {})
        ranks = role_priorities(entry.get("mask"), list(roles.values()))
        for (grantee, policy), priority in zip(roles.items(), ranks):
            gtype = winning[grantee].grantee_type
            then.append(
                Attachment(
                    policy, table, (column,), (column,), grantee, gtype, priority
                )
            )
        for grantee in entry.get("unmasked", []):
            then.append(
                Attachment(
                    unmasked_policy(policies[winning[grantee].policy].inputs[0][1]),
                    table,
                    (column,),
                    (column,),
                    grantee,
                    winning[grantee].grantee_type,
                    1000,
                )
            )
        if not same_order(attached, then):
            notes.append(
                f"{where}: attached another way than pgsesame's model (priorities "
                f"{sorted({a.priority for a in attached})}); the plan re-attaches them"
            )
        columns[f"{table}.{column}"] = entry

    written: dict[str, dict[str, Any]] = {}
    for name in sorted(used):
        policy = policies.get(name)
        if policy is None or name.startswith(UNMASKED_PREFIX):
            continue
        if len(policy.inputs) == 1 and policy.inputs[0][0] == "value":
            written[name] = {"type": policy.inputs[0][1], "using": policy.expression}
        else:
            written[name] = {"input": dict(policy.inputs), "using": policy.expression}
    attached_names = {a.policy for a in state.attachments}
    for name in sorted(policies):
        if (
            raw(name)
            and name in attached_names
            and not name.startswith(UNMASKED_PREFIX)
        ):
            notes.append(
                f"masking: {name} passes values through; its grantees are written as "
                "unmasked, where pgsesame uses its own sesame_unmasked_* policies"
            )
    return {"policies": written, "columns": columns}


def dump(spec: dict[str, Any], source: str) -> str:
    """Return the spec as YAML, with a header saying where it came from."""
    header = (
        f"# Written by sesame import from {source}: what the database grants today.\n"
        "# Edit from here; sesame plan against the same database shows nothing to do.\n"
    )
    return header + yaml.safe_dump(spec, sort_keys=False, default_flow_style=False)

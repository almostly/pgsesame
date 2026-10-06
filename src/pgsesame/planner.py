"""Turn a spec and the database's current state into an ordered plan.

The spec's principals are managed; every other role is left alone. For a managed
principal, its login attribute, its memberships and every privilege it holds on
the object types pgsesame reads are compared with the spec, and each difference
becomes one operation. ``schema.*`` expands to the objects of that type the schema
has now; future objects are for default privileges (a later milestone).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from pgsesame.ops import (
    AddMember,
    AlterLogin,
    CreateRole,
    Grant,
    Operation,
    RemoveMember,
    Revoke,
)
from pgsesame.spec import PRIVILEGES, Spec
from pgsesame.state import Identity, Membership, Privilege, State

# object types this milestone reads and plans
PLANNED_TYPES = ("databases", "schemas", "tables", "views", "sequences")


class PlanError(Exception):
    """The spec names something the database doesn't have."""

    def __init__(self, problems: list[str]):
        """Keep the problems; the message lists them one per line."""
        super().__init__("\n".join(problems))
        self.problems = problems


@dataclass
class Plan:
    """The operations that make the database match the spec, in run order."""

    operations: list[Operation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def allowed(self, allow_revoke: bool, allow_drop: bool) -> list[Operation]:
        """Return the operations apply may run with these flags."""
        gates = {"revoke": allow_revoke, "drop": allow_drop}
        return [op for op in self.operations if op.gate is None or gates[op.gate]]


def desired(spec: Spec, current: State) -> tuple[set[Membership], set[Privilege]]:
    """Return the memberships and privileges the spec asks for, patterns expanded."""
    problems: list[str] = []
    memberships = {
        Membership(name, parent)
        for name, p in spec.principals.items()
        for parent in [*p.member_of, *p.groups]
    }
    privileges: set[Privilege] = set()
    for name, p in spec.principals.items():
        for kind, grants in p.privileges.items():
            if kind not in PLANNED_TYPES:
                continue
            existing = current.objects.get(kind, set())
            for privilege, patterns in grants.items():
                for pattern in patterns:
                    matched = _expand(pattern, existing)
                    if not matched and not pattern.endswith(".*"):
                        problems.append(
                            f"principals.{name}.privileges.{kind}.{privilege}: "
                            f"{pattern} does not exist"
                        )
                    # one spelling for TEMP and TEMPORARY, as the readers report it
                    spelt = "temporary" if privilege == "temp" else privilege
                    privileges |= {Privilege(name, kind, obj, spelt) for obj in matched}
    if problems:
        raise PlanError(problems)
    return memberships, privileges


def _expand(pattern: str, existing: set[str]) -> set[str]:
    if pattern.endswith(".*"):
        schema = pattern[:-2]
        return {obj for obj in existing if obj.split(".", 1)[0] == schema}
    return {pattern} & existing


def make(spec: Spec, current: State) -> Plan:
    """Compare the spec with the current state and return the plan."""
    plan = Plan()
    redshift = spec.engine == "redshift"
    managed = set(spec.principals)
    want_members, want_privileges = desired(spec, current)

    def identity(name: str) -> Identity:
        """Return the kind of identity a name is: the spec's word, else the database's."""
        if not redshift:
            return "pg"
        if name in spec.principals:
            return spec.principals[name].type
        role = current.roles.get(name)
        if role is not None and role.identity != "pg":
            return role.identity
        return "user"

    problems: list[str] = []
    for name, p in sorted(spec.principals.items()):
        role = current.roles.get(name)
        if role is None:
            password = os.environ.get(p.password_env) if p.password_env else None
            if p.password_env and password is None:
                plan.notes.append(
                    f"{name}: {p.password_env} is not set; it is created without a password"
                )
            elif redshift and p.type == "user" and not p.password_env:
                plan.notes.append(
                    f"{name}: created with PASSWORD DISABLE (IAM sign-in)"
                )
            plan.operations.append(
                CreateRole(
                    name=name,
                    identity=identity(name),
                    login=p.can_login,
                    password=password,
                    password_env=p.password_env,
                    password_disabled=p.password == "disabled",
                )
            )
            continue
        if role.superuser:
            plan.notes.append(f"{name} is a superuser; pgsesame leaves it alone")
            managed.discard(name)
            continue
        if redshift and role.identity != p.type:
            problems.append(
                f"principals.{name}: the database has it as a {role.identity}, "
                f"the spec declares a {p.type}"
            )
        elif not redshift and role.login != p.can_login:
            plan.operations.append(AlterLogin(name=name, login=p.can_login))
    if problems:
        raise PlanError(problems)

    want_members = {m for m in want_members if m.member in managed}
    have_members = {m for m in current.memberships if m.member in managed}
    for m in sorted(want_members - have_members):
        plan.operations.append(
            AddMember(
                member=m.member,
                role=m.role,
                member_identity=identity(m.member),
                role_identity=identity(m.role),
            )
        )
    for m in sorted(have_members - want_members):
        plan.operations.append(
            RemoveMember(
                member=m.member,
                role=m.role,
                member_identity=identity(m.member),
                role_identity=identity(m.role),
            )
        )

    held = {
        p
        for p in current.privileges
        if p.grantee in managed and p.object_type in PLANNED_TYPES
    }
    # a privilege pgsesame doesn't model (a newer PostgreSQL's, a Redshift extra)
    # is reported and left in place: never planned, never revoked, never fatal
    known = PRIVILEGES[spec.engine]
    have_privileges = {p for p in held if p.privilege in known.get(p.object_type, ())}
    for p in sorted(held - have_privileges):
        plan.notes.append(
            f"{p.grantee} holds {p.privilege.upper()} on {p.object_name}, which "
            "pgsesame doesn't manage; left as it is"
        )
    want_privileges = {p for p in want_privileges if p.grantee in managed}
    for p in sorted(want_privileges - have_privileges):
        plan.operations.append(
            Grant(
                grantee=p.grantee,
                object_type=p.object_type,
                object_name=p.object_name,
                privilege=p.privilege,
                grantee_identity=identity(p.grantee),
            )
        )
    for p in sorted(have_privileges - want_privileges):
        plan.operations.append(
            Revoke(
                grantee=p.grantee,
                object_type=p.object_type,
                object_name=p.object_name,
                privilege=p.privilege,
                grantee_identity=identity(p.grantee),
            )
        )

    for name, p in spec.principals.items():
        if p.owns:
            plan.notes.append(f"{name}: ownership is planned from a later milestone")
        unplanned = sorted(set(p.privileges) - set(PLANNED_TYPES))
        if unplanned:
            plan.notes.append(
                f"{name}: privileges on {', '.join(unplanned)} are planned from a "
                "later milestone"
            )
    if spec.default_privileges:
        plan.notes.append("default privileges are planned from a later milestone")
    plan.operations.sort(key=lambda op: op.order)  # stable: keeps the sorted order
    return plan

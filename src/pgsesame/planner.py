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
    AlterPolicy,
    CreatePolicy,
    DisableRowSecurity,
    DropPolicy,
    EnableRowSecurity,
    ForceRowSecurity,
    AlterLogin,
    CreateRole,
    Grant,
    Operation,
    RemoveMember,
    Revoke,
)
from pgsesame import masking
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
        return [op for op in self.operations if op.needs is None or gates[op.needs]]


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


Normalized = dict[tuple[str, str], tuple[str | None, str | None]]


def make(
    spec: Spec,
    current: State,
    normalized: Normalized | None = None,
    masks: masking.Normalized | None = None,
) -> Plan:
    """Compare the spec with the current state and return the plan.

    ``normalized`` holds each declared policy's USING / WITH CHECK in the server's
    own form (see ``postgres.normalize_policies``); without it the spec's text is
    compared as written. ``masks`` does the same for Redshift masking policies
    (see ``masking.normalize``); without it their expressions aren't compared.
    """
    plan = Plan()
    redshift = spec.engine == "redshift"
    managed = set(spec.principals)
    want_members, want_privileges = desired(spec, current)

    def identity(name: str) -> Identity:
        """Return the kind of identity a name is: the spec's word, else the database's."""
        if not redshift:
            return "pg"
        declared = spec.principals[name].type if name in spec.principals else None
        if declared == "user" or declared == "group" or declared == "role":
            return declared
        role = current.roles.get(
            name
        )  # undeclared, or built-in: as the database has it
        if role is not None and role.identity != "pg":
            return role.identity
        return "user"

    problems: list[str] = []
    builtins = {name for name, p in spec.principals.items() if p.type == "builtin"}
    for name, p in sorted(spec.principals.items()):
        role = current.roles.get(name)
        if p.type == "builtin":
            if role is None:
                problems.append(
                    f"principals.{name}: the built-in role doesn't exist on this server"
                )
            elif role.superuser:
                plan.notes.append(f"{name} is a superuser; pgsesame leaves it alone")
                managed.discard(name)
            continue
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

    # a built-in role's own memberships are the platform's: never managed
    members = managed - builtins
    want_members = {m for m in want_members if m.member in members}
    have_members = {m for m in current.memberships if m.member in members}
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
    unknown = {p for p in held if p.privilege not in known.get(p.object_type, ())}
    for p in sorted(unknown):
        plan.notes.append(
            f"{p.grantee} holds {p.privilege.upper()} on {p.object_name}, which "
            "pgsesame doesn't manage; left as it is"
        )
    # a built-in role's privileges are managed only where the spec speaks for it:
    # the schemas (and databases) its privileges name. Elsewhere they are the
    # platform's (Supabase grants anon and authenticated a lot in public), and
    # left alone without a word
    scope = {name: _scope(spec.principals[name]) for name in builtins}
    have_privileges = {
        p
        for p in held - unknown
        if p.grantee not in scope or _in_scope(p, scope[p.grantee])
    }
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

    plan.operations += _plan_rls(spec, current, normalized or {}, problems)
    if spec.masking is not None:
        plan.operations += masking.plan(
            spec,
            current,
            masks,
            lambda name: "user" if identity(name) == "user" else "role",
            problems,
            plan.notes,
        )
    if problems:
        raise PlanError(problems)

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


def _scope(principal) -> tuple[set[str], set[str]]:
    """Return the schemas and databases a built-in role's privileges name."""
    schemas: set[str] = set()
    databases: set[str] = set()
    for kind, grants in principal.privileges.items():
        for patterns in grants.values():
            for pattern in patterns:
                if kind == "databases":
                    databases.add(pattern)
                elif kind == "schemas":
                    schemas.add(pattern)
                else:
                    schemas.add(pattern.split(".", 1)[0])
    return schemas, databases


def _in_scope(p: Privilege, scope: tuple[set[str], set[str]]) -> bool:
    schemas, databases = scope
    if p.object_type == "databases":
        return p.object_name in databases
    if p.object_type == "schemas":
        return p.object_name in schemas
    return p.object_name.split(".", 1)[0] in schemas


def _plan_rls(
    spec: Spec, current: State, normalized: Normalized, problems: list[str]
) -> list[Operation]:
    """Plan row-level security for the tables the spec lists; others are left alone."""
    ops: list[Operation] = []
    for table, rls in sorted(spec.row_level_security.items()):
        if table not in current.rls:
            problems.append(f"row_level_security.{table}: the table does not exist")
            continue
        enabled, forced = current.rls[table]
        if rls.enabled and not enabled:
            ops.append(EnableRowSecurity(table=table))
        elif enabled and not rls.enabled:
            ops.append(DisableRowSecurity(table=table))
        if rls.force != forced:
            ops.append(ForceRowSecurity(table=table, force=rls.force))
        for name, p in sorted(rls.policies.items()):
            roles = tuple(sorted(p.to))
            using, check = normalized.get((table, name), (p.using, p.with_check))
            create = CreatePolicy(
                table=table,
                name=name,
                command=p.command,
                permissive=p.permissive,
                roles=roles,
                using=p.using,
                with_check=p.with_check,
            )
            have = current.policies.get((table, name))
            if have is None:
                ops.append(create)
            elif (
                have.command != p.command
                or have.permissive != p.permissive
                or (have.using and not using)
                or (have.with_check and not check)
            ):
                # ALTER POLICY can't change these, or remove a clause: replace it
                ops += [DropPolicy(table=table, name=name), create]
            elif have.roles != roles or have.using != using or have.with_check != check:
                ops.append(
                    AlterPolicy(
                        table=table,
                        name=name,
                        roles=roles,
                        using=p.using,
                        with_check=p.with_check,
                    )
                )
        for (policy_table, name), _ in sorted(current.policies.items()):
            if policy_table == table and name not in rls.policies:
                ops.append(DropPolicy(table=table, name=name))
    return ops

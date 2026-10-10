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
    AlterOwner,
    AlterPolicy,
    CreatePolicy,
    DisableRowSecurity,
    DropPolicy,
    EnableRowSecurity,
    ForceRowSecurity,
    AlterLogin,
    CreateRole,
    Grant,
    GrantDefault,
    Operation,
    AlterPassword,
    LinkIam,
    RemoveMember,
    RevokeGrantOption,
    UnlinkIam,
    Revoke,
    RevokeDefault,
)
from pgsesame import masking
from pgsesame.spec import PRIVILEGES, Spec
from pgsesame.state import DefaultGrant, Identity, Membership, Privilege, State

# object types this milestone reads and plans
PLANNED_TYPES = ("databases", "schemas", "tables", "views", "sequences", "columns")


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
    partial: bool = False  # read by a user the catalog shows only part of
    # objects the spec names that the database doesn't have: their grants are
    # skipped, so a dropped table (a dbt model removed) doesn't block every apply
    warnings: list[str] = field(default_factory=list)

    def allowed(
        self, allow_revoke: bool, allow_drop: bool, allow_owner: bool = False
    ) -> list[Operation]:
        """Return the operations apply may run with these flags."""
        gates = {"revoke": allow_revoke, "drop": allow_drop, "owner": allow_owner}
        return [op for op in self.operations if op.needs is None or gates[op.needs]]


def desired(
    spec: Spec, current: State
) -> tuple[set[Membership], set[Privilege], list[str]]:
    """Return the memberships and privileges the spec asks for, patterns expanded.

    And what it names that doesn't exist, whose grants are left out of the plan.
    """
    missing: list[str] = []
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
                        missing.append(
                            f"principals.{name}.privileges.{kind}.{privilege}: "
                            f"{pattern} does not exist; skipped"
                        )
                    # one spelling for TEMP and TEMPORARY, as the readers report it
                    spelt = "temporary" if privilege == "temp" else privilege
                    privileges |= {Privilege(name, kind, obj, spelt) for obj in matched}
    return memberships, privileges, missing


def _expand(pattern: str, existing: set[str]) -> set[str]:
    """Return the objects a pattern names: ``schema.*`` or one name, if it exists."""
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
    plan = Plan(partial=not current.sees_everything)
    redshift = spec.engine == "redshift"
    managed = set(spec.principals)
    want_members, want_privileges, missing = desired(spec, current)
    plan.warnings += missing

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
    for name, p in sorted(spec.principals.items()):
        joined = [g for g in p.member_of if spec.principals[g].type == "group"]
        if joined:
            plan.notes.append(
                f"principals.{name}.member_of: {', '.join(joined)} is a group; "
                "planned as groups (groups: [...] says so in the spec)"
            )
    plan.notes += public_create_notes(current, spec.manage.schemas)
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
        if p.password_env and name in (current.passwords_refused or ()):
            # the password in the environment doesn't sign it in: disabled or
            # changed by hand since; set it again
            plan.notes.append(
                f"{name}: doesn't sign in with {p.password_env} (its password was "
                "disabled or changed); setting it again"
            )
            password = os.environ.get(p.password_env)
            plan.operations.append(
                AlterPassword(
                    name=name,
                    identity=identity(name),
                    password=password,
                    password_env=p.password_env,
                )
            )
    if current.passwords_refused is None and any(
        p.password_env and name in current.roles for name, p in spec.principals.items()
    ):
        plan.notes.append(
            "passwords aren't checked over the Data API (no connection to sign in "
            "on): one disabled or changed by hand isn't seen"
        )
    if problems:
        raise PlanError(problems)

    # manage.prefixes: undeclared roles named so are managed as if declared with
    # nothing, so what they hold is drift (revoked only with --allow-revoke);
    # never dropped, and never a superuser or a platform's system role
    for name, role in sorted(current.roles.items()):
        if (
            name not in spec.principals
            and any(name.startswith(prefix) for prefix in spec.manage.prefixes)
            and not role.superuser
            and not _system_role(name)
        ):
            managed.add(name)
            plan.notes.append(
                f"{name}: not in the spec, managed by manage.prefixes; what it holds "
                "is revoked with --allow-revoke"
            )

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
    plan.notes += unmanaged_notes(unknown, "left as they are")
    # a built-in role's privileges are managed only where the spec speaks for it:
    # the schemas (and databases) its privileges name. Elsewhere they are the
    # platform's (Supabase grants anon and authenticated a lot in public), and
    # left alone without a word
    scope = {name: _scope(spec.principals[name]) for name in builtins}
    have_privileges = {
        p
        for p in held - unknown
        if (p.grantee not in scope or _in_scope(p, scope[p.grantee]))
        and _in_managed_schemas(p, spec)
    }
    want_privileges = {p for p in want_privileges if p.grantee in managed}

    # ownership: each object a principal owns goes to it; an owner's privileges
    # on its own object are implied, so they are neither granted nor revoked
    owner_of = dict(current.owners)
    for name, p in sorted(spec.principals.items()):
        if p.type == "builtin" or name not in managed:
            continue
        for kind, patterns in sorted(p.owns.items()):
            existing = current.objects.get(kind, set())
            for pattern in patterns:
                matched = _expand(pattern, existing)
                if not matched and not pattern.endswith(".*"):
                    plan.warnings.append(
                        f"principals.{name}.owns.{kind}: {pattern} does not exist; "
                        "skipped"
                    )
                for obj in sorted(matched):
                    owner_of[(kind, obj)] = name
                    if current.owners.get((kind, obj)) != name:
                        plan.operations.append(
                            AlterOwner(
                                object_type=kind,
                                object_name=obj,
                                owner=name,
                                owner_identity=identity(name),
                            )
                        )

    def implied(p: Privilege) -> bool:
        """Return whether the grantee holds this by owning the object."""
        if p.object_type == "columns":
            table = p.object_name.rsplit(".", 1)[0]
            return p.grantee in (
                owner_of.get(("tables", table)),
                owner_of.get(("views", table)),
            )
        return owner_of.get((p.object_type, p.object_name)) == p.grantee

    # what the spec's own default privileges give an object its owner made later
    # (owner, schema, grantee, privilege): granted by the database, so not drift
    defaulted: set[tuple[str, str, str, str, str]] = set()
    for rule in spec.default_privileges:
        for kind, names in rule.grants().items():
            for privilege in names:
                defaulted.add(
                    (kind, rule.owner, rule.in_schema or "", rule.grantee, privilege)
                )

    def explained(p: Privilege) -> bool:
        """Return whether one of the spec's default privileges gave this grant."""
        # ON TABLES covers views too
        kind = "tables" if p.object_type == "views" else p.object_type
        if kind not in ("tables", "sequences", "schemas"):
            return False
        schema = p.object_name.split(".", 1)[0]
        owner = owner_of.get((p.object_type, p.object_name))
        if owner is None:
            return False
        anywhere = (kind, owner, "", p.grantee, p.privilege) in defaulted
        here = kind != "schemas" and (
            (kind, owner, schema, p.grantee, p.privilege) in defaulted
        )
        return anywhere or here

    want_privileges = {p for p in want_privileges if not implied(p)}
    have_privileges = {p for p in have_privileges if not implied(p)}
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
    # explained grants only escape a revoke: one the spec also names is still
    # compared, or it would look missing and be granted again
    for p in sorted(p for p in have_privileges - want_privileges if not explained(p)):
        plan.operations.append(
            Revoke(
                grantee=p.grantee,
                object_type=p.object_type,
                object_name=p.object_name,
                privilege=p.privilege,
                grantee_identity=identity(p.grantee),
            )
        )
    # a spec never gives the right to grant on: where a privilege it keeps is held
    # WITH GRANT OPTION, the option is drift (a privilege revoked takes it along)
    for p in sorted(current.grant_options & have_privileges & want_privileges):
        plan.operations.append(
            RevokeGrantOption(
                grantee=p.grantee,
                object_type=p.object_type,
                object_name=p.object_name,
                privilege=p.privilege,
                grantee_identity=identity(p.grantee),
            )
        )

    if spec.engine == "dsql":
        plan.operations += _plan_iam(spec, current, managed - builtins)
    plan.operations += _plan_defaults(
        spec, current, identity, problems, managed - builtins, plan.notes
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
        unplanned = sorted(set(p.privileges) - set(PLANNED_TYPES))
        if unplanned:
            plan.notes.append(
                f"{name}: privileges on {', '.join(unplanned)} are planned from a "
                "later milestone"
            )
    plan.operations = _within_reach(plan, current)
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
    """Return whether a grant is on an object the spec's scope covers."""
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


def _within_reach(plan: Plan, current: State) -> list[Operation]:
    """Drop the role changes the connected user can't make; note each one.

    An RDS or Aurora admin user (or Supabase's postgres) is not a superuser: from
    PostgreSQL 16 on it alters and grants only the roles it has ADMIN OPTION on,
    so a role someone else created is reported rather than failing the apply.
    A role the plan creates is the user's own.
    """
    administers = current.administers
    if administers is None:
        return plan.operations
    created = {op.name for op in plan.operations if isinstance(op, CreateRole)}

    def reachable(role: str) -> bool:
        """Return whether the plan may alter this role: it creates or administers it."""
        return role in created or role in administers

    kept: list[Operation] = []
    for op in plan.operations:
        if isinstance(op, AlterLogin) and not reachable(op.name):
            plan.notes.append(
                f"{op.name}: can't change its login as this user: needs ADMIN "
                "OPTION on it (or a superuser)"
            )
        elif isinstance(op, (AddMember, RemoveMember)) and not reachable(op.role):
            verb = "grant" if isinstance(op, AddMember) else "revoke"
            plan.notes.append(
                f"{op.member}: can't {verb} {op.role} as this user: needs ADMIN "
                f"OPTION on {op.role} (or a superuser)"
            )
        else:
            kept.append(op)
    return kept


def _plan_defaults(
    spec: Spec,
    current: State,
    identity,
    problems: list[str],
    managed: set[str],
    notes: list[str],
) -> list[Operation]:
    """Plan default privileges: what the spec's principals get on future objects.

    Managed: every entry whose grantee the spec declares, whoever the owner is.
    An entry for another grantee is someone else's and left alone.
    """
    want: set[DefaultGrant] = set()
    for i, rule in enumerate(spec.default_privileges):
        if rule.owner not in current.roles and rule.owner not in spec.principals:
            problems.append(
                f"default_privileges[{i}].owner: {rule.owner} does not exist"
            )
            continue
        for kind, privileges in rule.grants().items():
            for privilege in privileges:
                spelt = "temporary" if privilege == "temp" else privilege
                want.add(
                    DefaultGrant(
                        rule.owner, rule.in_schema or "", kind, rule.grantee, spelt
                    )
                )
    schemas = set(spec.manage.schemas)
    have = {
        d
        for d in current.default_privileges
        if d.grantee in managed and (not schemas or d.schema in schemas)
    }
    have = {
        d
        for d in have
        if d.object_type in ("tables", "sequences", "functions", "schemas")
    }
    # a default privilege pgsesame doesn't model is reported and left in place,
    # never revoked (there's no keyword for it), as for grants
    known = PRIVILEGES[spec.engine]
    for d in sorted(d for d in have if d.privilege not in known.get(d.object_type, ())):
        notes.append(
            f"{d.grantee} gets {d.privilege.upper()} on {d.object_type} {d.owner} "
            "creates, which pgsesame doesn't manage; left as it is"
        )
    have = {d for d in have if d.privilege in known.get(d.object_type, ())}

    def op(cls, d: DefaultGrant) -> Operation:
        """Return the operation (``cls``) for a default privilege."""
        return cls(
            owner=d.owner,
            in_schema=d.schema,
            object_type=d.object_type,
            privilege=d.privilege,
            grantee=d.grantee,
            grantee_identity=identity(d.grantee),
            owner_identity=identity(d.owner),
        )

    return [op(GrantDefault, d) for d in sorted(want - have)] + [
        op(RevokeDefault, d) for d in sorted(have - want)
    ]


def public_create_notes(state: State, schemas: list[str] | None) -> list[str]:
    """Return a warning per schema in scope where PUBLIC (every user) may CREATE.

    pgsesame doesn't manage PUBLIC's grants yet, so this is said, not revoked:
    any user can create objects there (and on PostgreSQL before 15, functions
    that shadow ones other users call).
    """
    return [
        f"schema {p.object_name}: PUBLIC (every user) can CREATE in it, which "
        "pgsesame doesn't manage yet; REVOKE CREATE ON SCHEMA "
        f"{p.object_name} FROM PUBLIC closes it"
        for p in sorted(state.public_privileges)
        if p.object_type == "schemas"
        and p.privilege == "create"
        and (not schemas or p.object_name in schemas)
    ]


def _plan_iam(spec: Spec, current: State, managed: set[str]) -> list[Operation]:
    """Return the AWS IAM GRANT and REVOKE that link the spec's IAM identities."""
    want = {(name, arn) for name, p in spec.principals.items() for arn in p.iam}
    have = {(role, arn) for role, arn in current.iam_links if role in managed}
    return [LinkIam(role=r, arn=a) for r, a in sorted(want - have)] + [
        UnlinkIam(role=r, arn=a) for r, a in sorted(have - want)
    ]


def unmanaged_notes(privileges: set[Privilege], outcome: str) -> list[str]:
    """Return one note per privilege and object type pgsesame doesn't manage.

    A warehouse can hold thousands (GRANT ALL on views gives Redshift's INSERT,
    DELETE ... on each): a count and a few examples, not a line each.
    """
    by_kind: dict[tuple[str, str], list[Privilege]] = {}
    for p in sorted(privileges):
        by_kind.setdefault((p.privilege, p.object_type), []).append(p)
    notes = []
    for (privilege, kind), held in sorted(by_kind.items()):
        examples = ", ".join(f"{p.grantee} on {p.object_name}" for p in held[:3])
        more = f", and {len(held) - 3} more" if len(held) > 3 else ""
        if len(held) == 1:
            count, said = "1 grant", outcome.replace("they are", "it is")
        else:
            count, said = f"{len(held)} grants", outcome
        notes.append(
            f"{privilege.upper()} on {kind} isn't a privilege pgsesame manages: "
            f"{count} {said} ({examples}{more})"
        )
    return notes


def _system_role(name: str) -> bool:
    """Return whether a role is the platform's own (never adopted by prefix)."""
    return name.startswith(
        ("pg_", "rds", "sys:", "cloudsql", "alloydb", "supabase")
    ) or name in ("postgres", "PUBLIC", "dbowner")  # dbowner: Aurora DSQL's


def _in_managed_schemas(p: Privilege, spec: Spec) -> bool:
    """Return whether manage.schemas (if any) covers the privilege's object."""
    schemas = spec.manage.schemas
    if not schemas or p.object_type == "databases":
        return True
    schema = (
        p.object_name if p.object_type == "schemas" else p.object_name.split(".", 1)[0]
    )
    return schema in schemas

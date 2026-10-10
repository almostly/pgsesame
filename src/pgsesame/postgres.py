"""Read a PostgreSQL database's roles, memberships and privileges.

Privileges come from the ACLs in the catalog, expanded with ``aclexplode()``.
Grants an object's owner holds on it are implied by ownership, so they are left
out; so are grants to PUBLIC, which pgsesame does not manage yet (its schema
grants are read to warn about, CREATE above all). System schemas
(``pg_*``, ``information_schema``) are never read.
"""

from __future__ import annotations

from pgsesame.db import Connection, Database
from pgsesame.spec import Spec
from pgsesame.state import DefaultGrant, Membership, Policy, Privilege, Role, State

ROLES = """
select rolname, rolcanlogin, rolsuper from pg_roles
"""

MEMBERSHIPS = """
select m.rolname, r.rolname
from pg_auth_members a
join pg_roles r on r.oid = a.roleid
join pg_roles m on m.oid = a.member
"""

_USER_SCHEMA = "n.nspname not like 'pg\\_%' and n.nspname <> 'information_schema'"

SCHEMAS = f"""
select n.nspname from pg_namespace n where {_USER_SCHEMA}
"""

RELATIONS = f"""
select n.nspname || '.' || c.relname,
       case c.relkind when 'S' then 'sequences'
                      when 'v' then 'views' when 'm' then 'views'
                      else 'tables' end
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'S') and {_USER_SCHEMA}
"""

DATABASE_PRIVILEGES = """
select g.rolname, d.datname, lower(a.privilege_type), a.is_grantable
from pg_database d, aclexplode(d.datacl) a
join pg_roles g on g.oid = a.grantee
where d.datname = current_database() and a.grantee <> d.datdba
"""

SCHEMA_PRIVILEGES = f"""
select g.rolname, n.nspname, lower(a.privilege_type), a.is_grantable
from pg_namespace n, aclexplode(n.nspacl) a
join pg_roles g on g.oid = a.grantee
where {_USER_SCHEMA} and a.grantee <> n.nspowner
"""

# grantee 0 is PUBLIC: not a role, so the join above leaves it out
PUBLIC_SCHEMA_PRIVILEGES = f"""
select n.nspname, lower(a.privilege_type)
from pg_namespace n, aclexplode(n.nspacl) a
where {_USER_SCHEMA} and a.grantee = 0
"""

RELATION_PRIVILEGES = f"""
select g.rolname,
       case c.relkind when 'S' then 'sequences'
                      when 'v' then 'views' when 'm' then 'views'
                      else 'tables' end,
       n.nspname || '.' || c.relname,
       lower(a.privilege_type), a.is_grantable
from pg_class c
join pg_namespace n on n.oid = c.relnamespace,
     aclexplode(c.relacl) a
join pg_roles g on g.oid = a.grantee
where c.relkind in ('r', 'p', 'v', 'm', 'S') and {_USER_SCHEMA}
  and a.grantee <> c.relowner
"""


# columns of tables and views (what column grants can name) and their grants
COLUMNS = f"""
select n.nspname || '.' || c.relname || '.' || a.attname
from pg_attribute a
join pg_class c on c.oid = a.attrelid
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'f') and a.attnum > 0 and not a.attisdropped
  and {_USER_SCHEMA}
"""

COLUMN_PRIVILEGES = f"""
select g.rolname, n.nspname || '.' || c.relname || '.' || a.attname,
       lower(x.privilege_type)
from pg_attribute a
join pg_class c on c.oid = a.attrelid
join pg_namespace n on n.oid = c.relnamespace,
     aclexplode(a.attacl) x
join pg_roles g on g.oid = x.grantee
where a.attnum > 0 and not a.attisdropped and {_USER_SCHEMA}
  and x.grantee <> c.relowner
"""

# owners: the current database, the user schemas, and their relations and sequences
OWNERS = f"""
select 'databases', d.datname, r.rolname
from pg_database d join pg_roles r on r.oid = d.datdba
where d.datname = current_database()
union all
select 'schemas', n.nspname, r.rolname
from pg_namespace n join pg_roles r on r.oid = n.nspowner
where {_USER_SCHEMA}
union all
select case c.relkind when 'S' then 'sequences'
                      when 'v' then 'views' when 'm' then 'views' else 'tables' end,
       n.nspname || '.' || c.relname, r.rolname
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
join pg_roles r on r.oid = c.relowner
where c.relkind in ('r', 'p', 'v', 'm', 'S') and {_USER_SCHEMA}
"""

# default privileges: a global entry (no schema) holds the whole default ACL, the
# owner's own privileges and PUBLIC's included, which are left out as implied
DEFAULT_PRIVILEGES = """
select o.rolname, coalesce(n.nspname, ''),
       case d.defaclobjtype when 'r' then 'tables' when 'S' then 'sequences'
                            when 'f' then 'functions' when 'n' then 'schemas'
                            else 'types' end,
       g.rolname, lower(a.privilege_type)
from pg_default_acl d
join pg_roles o on o.oid = d.defaclrole
left join pg_namespace n on n.oid = d.defaclnamespace,
     aclexplode(d.defaclacl) a
join pg_roles g on g.oid = a.grantee
where a.grantee <> d.defaclrole
"""

RLS_TABLES = f"""
select n.nspname || '.' || c.relname, c.relrowsecurity, c.relforcerowsecurity
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and {_USER_SCHEMA}
"""

POLICIES = """
select schemaname || '.' || tablename, policyname, lower(cmd), permissive = 'PERMISSIVE',
       roles::text[], qual, with_check
from pg_policies
where schemaname !~ '^pg_' and schemaname <> 'information_schema'
"""


# whether the connected user may alter a role and grant it: a superuser always;
# from PostgreSQL 16 on, only with ADMIN OPTION on it (the role's creator has it),
# which is what an RDS or Aurora admin user, a member of rds_superuser, works with;
# before 16, CREATEROLE covers every role but a superuser
ADMINISTERS = """
select r.rolname,
       case when me.rolsuper then true
            when current_setting('server_version_num')::int < 160000
                 then me.rolcreaterole and not r.rolsuper
            else pg_has_role(current_user, r.oid, 'MEMBER WITH ADMIN OPTION')
                 and not r.rolsuper
       end
from pg_roles r, pg_roles me
where me.rolname = current_user
"""


def _text_array(value: object) -> list[str]:
    """Return a text[] column: a list over a driver, ``{a,"b c"}`` text over a Data API."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if not isinstance(value, str):
        return []
    import csv

    inner = value.strip()[1:-1]
    if not inner:
        return []
    return next(csv.reader([inner], quotechar='"', escapechar="\\"))


def read(db: Connection, columns: bool = True) -> State:
    """Return the current state of the database ``db`` is connected to.

    ``columns`` reads every column (to check the ones a spec grants on); without
    it, column grants are still read.
    """
    state = State()
    for name, login, superuser in db.rows(ROLES):
        state.roles[name] = Role(name, login, superuser)
    state.memberships = {Membership(m, r) for m, r in db.rows(MEMBERSHIPS)}
    state.administers = {name for name, can in db.rows(ADMINISTERS) if can}

    state.objects = {"databases": {db.database}, "schemas": set()}
    state.objects["schemas"] = {name for (name,) in db.rows(SCHEMAS)}
    for name, kind in db.rows(RELATIONS):
        state.objects.setdefault(kind, set()).add(name)

    def held(p: Privilege, grantable: bool) -> None:
        """Record a privilege, and its grant option when it has one."""
        state.privileges.add(p)
        if grantable:
            state.grant_options.add(p)

    for grantee, name, privilege, grantable in db.rows(DATABASE_PRIVILEGES):
        held(Privilege(grantee, "databases", name, privilege), grantable)
    for grantee, name, privilege, grantable in db.rows(SCHEMA_PRIVILEGES):
        held(Privilege(grantee, "schemas", name, privilege), grantable)
    for name, privilege in db.rows(PUBLIC_SCHEMA_PRIVILEGES):
        state.public_privileges.add(Privilege("public", "schemas", name, privilege))
    for grantee, kind, name, privilege, grantable in db.rows(RELATION_PRIVILEGES):
        held(Privilege(grantee, kind, name, privilege), grantable)
    if columns:
        state.objects["columns"] = {name for (name,) in db.rows(COLUMNS)}
    for grantee, name, privilege in db.rows(COLUMN_PRIVILEGES):
        state.privileges.add(Privilege(grantee, "columns", name, privilege))
    for kind, name, owner in db.rows(OWNERS):
        state.owners[(kind, name)] = owner
    for owner, schema, kind, grantee, privilege in db.rows(DEFAULT_PRIVILEGES):
        state.default_privileges.add(
            DefaultGrant(owner, schema, kind, grantee, privilege)
        )
    for table, enabled, forced in db.rows(RLS_TABLES):
        state.rls[table] = (enabled, forced)
    for table, name, command, permissive, roles, using, check in db.rows(POLICIES):
        state.policies[(table, name)] = Policy(
            table,
            name,
            command,
            permissive,
            tuple(sorted(_text_array(roles))),
            using,
            check,
        )
    return state


def normalize_policies(
    db: Database, spec: Spec
) -> dict[tuple[str, str], tuple[str | None, str | None]]:
    """Return each declared policy's expressions in the server's own form.

    PostgreSQL stores a policy's USING and WITH CHECK rewritten (casts spelt out,
    names qualified as needed), so the spec's text can't be compared with the
    catalog's. Each declared policy is created as a probe inside a transaction
    that is always rolled back, and its stored form read back. A table the spec
    names but the database doesn't have is skipped: the planner reports it.
    """
    from pgsesame.ops import CreatePolicy

    out: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    with db.conn.transaction(force_rollback=True), db.conn.cursor() as cur:
        for table, rls in spec.row_level_security.items():
            exists = cur.execute(
                "select to_regclass(%s) is not null", (table,)
            ).fetchone()
            if not (exists and exists[0]):
                continue
            for name, p in rls.policies.items():
                probe = f"pgsesame_probe_{len(out)}"
                cur.execute(
                    CreatePolicy(
                        table=table,
                        name=probe,
                        command=p.command,
                        permissive=p.permissive,
                        roles=("public",),  # the roles may not exist yet
                        using=p.using,
                        with_check=p.with_check,
                    ).statement()
                )
                schema, relname = table.split(".", 1)
                row = cur.execute(
                    "select qual, with_check from pg_policies "
                    "where schemaname = %s and tablename = %s and policyname = %s",
                    (schema, relname, probe),
                ).fetchone()
                out[(table, name)] = (row[0], row[1]) if row else (None, None)
    return out

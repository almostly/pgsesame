"""Read a PostgreSQL database's roles, memberships and privileges.

Privileges come from the ACLs in the catalog, expanded with ``aclexplode()``.
Grants an object's owner holds on it are implied by ownership, so they are left
out; so are grants to PUBLIC, which pgsesame does not manage yet (its schema
grants are read to warn about, CREATE above all). System schemas
(``pg_*``, ``information_schema``) are never read.
"""

from __future__ import annotations

from dataclasses import replace

from pgsesame.db import Connection, Database
from pgsesame.spec import ATTRIBUTES, Spec
from pgsesame.state import DefaultGrant, Membership, Policy, Privilege, Role, State
from pgsesame.state import part_sql, split

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


# a relation and a column, named as State names them (schema.name, schema.name.column)
_RELATION = f"{part_sql('n.nspname')} || '.' || {part_sql('c.relname')}"
_COLUMN = f"{_RELATION} || '.' || {part_sql('a.attname')}"
_TABLE = f"{part_sql('schemaname')} || '.' || {part_sql('tablename')}"

SCHEMAS = f"""
select n.nspname from pg_namespace n where {_USER_SCHEMA}
"""

RELATIONS = f"""
select {_RELATION},
       case c.relkind when 'S' then 'sequences'
                      when 'v' then 'views' when 'm' then 'views'
                      else 'tables' end
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'S') and {_USER_SCHEMA}
"""

DATABASE_PRIVILEGES = """
select coalesce(g.rolname, 'public'), d.datname, lower(a.privilege_type), a.is_grantable
from pg_database d, aclexplode(d.datacl) a
left join pg_roles g on g.oid = a.grantee
where d.datname = current_database() and a.grantee <> d.datdba
"""

SCHEMA_PRIVILEGES = f"""
select coalesce(g.rolname, 'public'), n.nspname, lower(a.privilege_type), a.is_grantable
from pg_namespace n, aclexplode(n.nspacl) a
left join pg_roles g on g.oid = a.grantee
where {_USER_SCHEMA} and a.grantee <> n.nspowner
"""

# grantee 0 is PUBLIC (the queries above name it public): its schema grants
# again on their own, for the CREATE warning where the spec doesn't manage them
PUBLIC_SCHEMA_PRIVILEGES = f"""
select n.nspname, lower(a.privilege_type)
from pg_namespace n, aclexplode(n.nspacl) a
where {_USER_SCHEMA} and a.grantee = 0
"""

RELATION_PRIVILEGES = f"""
select coalesce(g.rolname, 'public'),
       case c.relkind when 'S' then 'sequences'
                      when 'v' then 'views' when 'm' then 'views'
                      else 'tables' end,
       {_RELATION},
       lower(a.privilege_type), a.is_grantable
from pg_class c
join pg_namespace n on n.oid = c.relnamespace,
     aclexplode(c.relacl) a
left join pg_roles g on g.oid = a.grantee
where c.relkind in ('r', 'p', 'v', 'm', 'S') and {_USER_SCHEMA}
  and a.grantee <> c.relowner
"""


# columns of tables and views (what column grants can name) and their grants
COLUMNS = f"""
select {_COLUMN}
from pg_attribute a
join pg_class c on c.oid = a.attrelid
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'f') and a.attnum > 0 and not a.attisdropped
  and {_USER_SCHEMA}
"""

COLUMN_PRIVILEGES = f"""
select coalesce(g.rolname, 'public'), {_COLUMN},
       lower(x.privilege_type)
from pg_attribute a
join pg_class c on c.oid = a.attrelid
join pg_namespace n on n.oid = c.relnamespace,
     aclexplode(a.attacl) x
left join pg_roles g on g.oid = x.grantee
where a.attnum > 0 and not a.attisdropped and {_USER_SCHEMA}
  and x.grantee <> c.relowner
"""

# functions and procedures, named as GRANT names them: schema.name(argument types),
# the types as PostgreSQL writes them; an extension's own are left out
_FUNCTION_NAME = (
    "n.nspname || '.' || p.proname || '(' || oidvectortypes(p.proargtypes) || ')'"
)
_USER_FUNCTION = f"""p.prokind in ('f', 'p') and {_USER_SCHEMA}
  and not exists (select from pg_depend d
                  where d.classid = 'pg_proc'::regclass and d.objid = p.oid
                    and d.deptype = 'e')"""

FUNCTIONS = f"""
select {_FUNCTION_NAME}
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where {_USER_FUNCTION}
"""

# a function without an ACL has PostgreSQL's default, EXECUTE for PUBLIC, which
# acldefault spells out so a spec can take it away
FUNCTION_PRIVILEGES = f"""
select coalesce(g.rolname, 'public'), {_FUNCTION_NAME}, lower(a.privilege_type),
       a.is_grantable
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace,
     aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
left join pg_roles g on g.oid = a.grantee
where {_USER_FUNCTION} and a.grantee <> p.proowner
"""

FUNCTION_OWNERS = f"""
select 'functions', {_FUNCTION_NAME}, r.rolname
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
join pg_roles r on r.oid = p.proowner
where {_USER_FUNCTION}
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
       {_RELATION}, r.rolname
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

# views that run with their owner's rights, past the row-level security of what
# they read (all of them before PostgreSQL 15, and since, those without
# security_invoker), among those the connected user may change, as their owner;
# an extension's own are left out
DEFINER_VIEWS = f"""
select {_RELATION}
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'v' and {_USER_SCHEMA} and pg_has_role(c.relowner, 'USAGE')
  and not exists (select from pg_depend d
                  where d.classid = 'pg_class'::regclass and d.objid = c.oid
                    and d.deptype = 'e')
  and not exists (select from unnest(c.reloptions) o
                  where lower(o) in ('security_invoker=true', 'security_invoker=on',
                                     'security_invoker=yes', 'security_invoker=1'))
"""

RLS_TABLES = f"""
select {_RELATION}, c.relrowsecurity, c.relforcerowsecurity
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and {_USER_SCHEMA}
"""

# the tables whose row-level security the connected user may switch: only as their
# owner, which a platform's tables (Supabase's storage.objects) aren't
RLS_SWITCHABLE = f"""
select {_RELATION}
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and {_USER_SCHEMA} and pg_has_role(c.relowner, 'USAGE')
"""

# the role PostgreSQL made at initdb: it can't stop being a superuser
BOOTSTRAP = """
select rolname from pg_roles where oid = 10
"""

# each role's attributes, but LOGIN and SUPERUSER, which are read on their own
ROLE_ATTRIBUTES = """
select rolname, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
from pg_roles
"""

# what the connected user may set those to: a superuser, any; from PostgreSQL 16
# on, a CREATEROLE user those it holds itself; before, CREATEDB and CREATEROLE
# (REPLICATION and BYPASSRLS were a superuser's)
SETS_ATTRIBUTES = """
select rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls,
       current_setting('server_version_num')::int >= 160000
from pg_roles where rolname = current_user
"""

POLICIES = f"""
select {_TABLE}, policyname, lower(cmd), permissive = 'PERMISSIVE',
       roles::text[], qual, with_check
from pg_policies
where schemaname !~ '^pg_' and schemaname <> 'information_schema'
"""


# the roles the connected user acts as (itself, those it inherits, or every one
# for a superuser): only for them can it change default privileges
ACTS_AS = """
select rolname from pg_roles where pg_has_role(oid, 'USAGE')
"""

# publications, and the tables each sends the changes of (Supabase Realtime's)
PUBLICATIONS = """
select p.pubname, r.rolname, p.puballtables
from pg_publication p join pg_roles r on r.oid = p.pubowner
"""

PUBLICATION_TABLES = f"""
select pubname, {_TABLE} from pg_publication_tables
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


def _sets_attributes(rows: list) -> set[str]:
    """Return the attributes the connected user may set, from SETS_ATTRIBUTES."""
    if not rows:
        return set()
    superuser, createrole, createdb, replication, bypassrls, sixteen = rows[0]
    if superuser:
        return set(ATTRIBUTES)
    if not createrole:
        return set()
    if not sixteen:
        return {"createdb", "createrole"}
    held = {"createdb": createdb, "replication": replication, "bypassrls": bypassrls}
    return {"createrole"} | {name for name, on in held.items() if on}


def read(db: Connection, columns: bool = True, full: bool = True) -> State:
    """Return the current state of the database ``db`` is connected to.

    ``columns`` reads every column (to check the ones a spec grants on); without
    it, column grants are still read. ``full`` also reads what only PostgreSQL's
    plans use: functions, publications, views that run with their owner's rights,
    and whom the connected user acts as (Aurora DSQL is read without).
    """
    state = State()
    for name, login, superuser in db.rows(ROLES):
        state.roles[name] = Role(name, login, superuser)
    state.memberships = {Membership(m, r) for m, r in db.rows(MEMBERSHIPS)}
    state.administers = {name for name, can in db.rows(ADMINISTERS) if can}
    state.current_user = next(
        (name for (name,) in db.rows("select current_user")), None
    )

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
    if full:
        state.objects["functions"] = {name for (name,) in db.rows(FUNCTIONS)}
        for grantee, name, privilege, grantable in db.rows(FUNCTION_PRIVILEGES):
            held(Privilege(grantee, "functions", name, privilege), grantable)
        for kind, name, owner in db.rows(FUNCTION_OWNERS):
            state.owners[(kind, name)] = owner
    for owner, schema, kind, grantee, privilege in db.rows(DEFAULT_PRIVILEGES):
        state.default_privileges.add(
            DefaultGrant(owner, schema, kind, grantee, privilege)
        )
    for table, enabled, forced in db.rows(RLS_TABLES):
        state.rls[table] = (enabled, forced)
    if full:
        state.acts_as = {name for (name,) in db.rows(ACTS_AS)}
        state.rls_switchable = {name for (name,) in db.rows(RLS_SWITCHABLE)}
        for name, *flags in db.rows(ROLE_ATTRIBUTES):
            has = frozenset(a for a, on in zip(ATTRIBUTES, flags) if on)
            state.roles[name] = replace(state.roles[name], attributes=has)
        state.sets_attributes = _sets_attributes(db.rows(SETS_ATTRIBUTES))
        state.bootstrap = next((name for (name,) in db.rows(BOOTSTRAP)), None)
        state.definer_views = {name for (name,) in db.rows(DEFINER_VIEWS)}
        for name, owner, all_tables in db.rows(PUBLICATIONS):
            state.publications[name] = (owner, all_tables)
        state.publication_tables = {
            (name, table) for name, table in db.rows(PUBLICATION_TABLES)
        }
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
                schema, relname = split(table)
                row = cur.execute(
                    "select qual, with_check from pg_policies "
                    "where schemaname = %s and tablename = %s and policyname = %s",
                    (schema, relname, probe),
                ).fetchone()
                out[(table, name)] = (row[0], row[1]) if row else (None, None)
    return out

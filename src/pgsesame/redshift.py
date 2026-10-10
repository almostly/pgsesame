"""Read a Redshift database's users, groups, roles and privileges.

Redshift reports privileges through its SVV views, which spell each privilege out
with the kind of identity holding it, so there is no ACL string to parse (the
letters Redshift adds to PostgreSQL's are what crashed earlier tools). The same
queries run on Amazon Redshift and on oblako's redshift-local, which provides the
same views. Only explicit grants are read: what an owner holds on its own object
is implied by ownership. Superusers are never managed.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

from pgsesame.db import Connection
from pgsesame.state import DefaultGrant, Membership, Privilege, Role, State

USERS = "select usesysid, usename, usesuper from pg_user"
# pg_catalog.pg_group, qualified: on redshift-local the proxy then leaves out
# PostgreSQL's own pg_* roles and Redshift roles, as Redshift's pg_group does
GROUPS = "select groname, grolist from pg_catalog.pg_group"
ROLES = "select role_name from svv_roles"
USER_ROLES = "select user_name, role_name from svv_user_grants"
ROLE_ROLES = "select role_name, granted_role_name from svv_role_grants"

_USER_SCHEMA = (
    "{col} not like 'pg\\_%' and {col} not in ('information_schema', 'catalog_history')"
)
SCHEMAS = "select nspname from pg_namespace where " + _USER_SCHEMA.format(col="nspname")
# local tables and views from the catalog: svv_tables also lists external
# (Spectrum, Glue) tables, which on a real cluster makes it slow to read
RELATIONS = (
    "select n.nspname, c.relname, case c.relkind when 'v' then 'VIEW' else 'TABLE' end "
    "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
    "where c.relkind in ('r', 'v') and " + _USER_SCHEMA.format(col="n.nspname")
)
DATABASE_PRIVILEGES = """
select identity_name, identity_type, database_name, lower(privilege_type),
       admin_option
from svv_database_privileges
where database_name = current_database() and privilege_scope = 'DATABASE'
"""
SCHEMA_PRIVILEGES = """
select identity_name, identity_type, namespace_name, lower(privilege_type),
       admin_option
from svv_schema_privileges
where privilege_scope = 'SCHEMA'
"""
RELATION_PRIVILEGES = """
select identity_name, identity_type, namespace_name, relation_name,
       lower(privilege_type), admin_option
from svv_relation_privileges
"""
# every column, needed only when a spec grants on columns (svv_columns, like
# svv_tables, reaches into external schemas: the catalog stays local)
COLUMNS = (
    "select n.nspname, c.relname, a.attname from pg_attribute a "
    "join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace "
    "where a.attnum > 0 and not a.attisdropped and c.relkind in ('r', 'v') and "
    + _USER_SCHEMA.format(col="n.nspname")
)
# owners: Redshift's objects are owned by users (pg_user, not pg_roles)
OWNERS = (
    "select 'schemas', n.nspname, u.usename from pg_namespace n "
    "join pg_user u on u.usesysid = n.nspowner where "
    + _USER_SCHEMA.format(col="n.nspname")
    + " union all select case c.relkind when 'v' then 'views' else 'tables' end, "
    "n.nspname || '.' || c.relname, u.usename from pg_class c "
    "join pg_namespace n on n.oid = c.relnamespace "
    "join pg_user u on u.usesysid = c.relowner where c.relkind in ('r', 'v') and "
    + _USER_SCHEMA.format(col="n.nspname")
)
DEFAULT_PRIVILEGES = """
select owner_name, coalesce(schema_name, ''), object_type, grantee_name, grantee_type,
       lower(privilege_type)
from svv_default_privileges
"""
_DEFAULT_TYPES = {
    "RELATION": "tables",
    "FUNCTION": "functions",
    "PROCEDURE": "procedures",
}
COLUMN_PRIVILEGES = """
select identity_name, identity_type, namespace_name, relation_name, column_name,
       lower(privilege_type)
from svv_column_privileges
"""


def is_redshift(db: Connection) -> bool:
    """Return whether the database has Redshift's SVV views (Redshift or redshift-local).

    version() doesn't tell: redshift-local reports PostgreSQL's. pg_views lists
    the SVV views on both, and none on PostgreSQL.
    """
    rows = db.rows(
        "select count(*) from pg_views where viewname in ('svv_roles', 'svv_user_grants')"
    )
    return bool(rows and rows[0][0])


def _true(value: Any) -> bool:
    """Return a boolean column: a bool over a driver, maybe 't'/'true' as text."""
    if isinstance(value, str):
        return value.lower() in ("t", "true")
    return bool(value)


def _int_array(value: Any) -> list[int]:
    """Return an int[] column: a list over a driver, ``{1,2}`` text over the Data API."""
    if value is None:
        return []
    if isinstance(value, str):
        inner = value.strip("{}")
        return [int(v) for v in inner.split(",") if v.strip()]
    return list(value)


def read(db: Connection, columns: bool = True) -> State:
    """Return the current state of the Redshift database ``db`` is connected to.

    ``columns`` reads every column (to check the ones a spec grants on); without
    it, column grants are still read. The queries are fetched together: over the
    Data API they run at the same time, each an HTTP round trip.
    """
    queries = {
        "me": "select usesuper from pg_user where usename = current_user",
        "users": USERS,
        "groups": GROUPS,
        "roles": ROLES,
        "user_roles": USER_ROLES,
        "role_roles": ROLE_ROLES,
        "schemas": SCHEMAS,
        "relations": RELATIONS,
        "database_privileges": DATABASE_PRIVILEGES,
        "schema_privileges": SCHEMA_PRIVILEGES,
        "relation_privileges": RELATION_PRIVILEGES,
        "owners": OWNERS,
        "default_privileges": DEFAULT_PRIVILEGES,
        "column_privileges": COLUMN_PRIVILEGES,
    }
    if columns:
        queries["columns"] = COLUMNS
    rows = fetch(db, queries)

    state = State()
    me = rows["me"]
    # a non-superuser sees only its own grants in the SVV views (and no masking)
    state.sees_everything = bool(me and me[0][0])
    users: dict[int, str] = {}
    for sysid, name, superuser in rows["users"]:
        users[sysid] = name
        state.roles[name] = Role(name, True, superuser, "user")
    for name, members in rows["groups"]:
        state.roles[name] = Role(name, False, False, "group")
        for sysid in _int_array(members):
            if sysid in users:
                state.memberships.add(Membership(users[sysid], name))
    for (name,) in rows["roles"]:
        state.roles[name] = Role(name, False, False, "role")
    state.memberships |= {Membership(u, r) for u, r in rows["user_roles"]}
    state.memberships |= {Membership(r, g) for r, g in rows["role_roles"]}

    state.objects = {"databases": {db.database}, "tables": set(), "views": set()}
    state.objects["schemas"] = {name for (name,) in rows["schemas"]}
    kinds: dict[str, str] = {}
    for schema, name, table_type in rows["relations"]:
        kind = "views" if table_type == "VIEW" else "tables"
        kinds[f"{schema}.{name}"] = kind
        state.objects[kind].add(f"{schema}.{name}")

    def privilege(
        grantee: str, identity: str, kind: str, name: str, priv: str, option=False
    ) -> None:
        """Record one SVV privilege row; PUBLIC's only as a schema grant to warn about."""
        if identity == "public":  # PUBLIC isn't managed yet; its schema grants are
            if kind == "schemas":  # read to warn about
                state.public_privileges.add(Privilege("public", kind, name, priv))
            return
        if priv == "temp":  # one spelling, as the planner writes it
            priv = "temporary"
        state.privileges.add(Privilege(grantee, kind, name, priv))
        if _true(option):
            state.grant_options.add(Privilege(grantee, kind, name, priv))

    for grantee, identity, name, priv, option in rows["database_privileges"]:
        privilege(grantee, identity, "databases", name, priv, option)
    for grantee, identity, name, priv, option in rows["schema_privileges"]:
        privilege(grantee, identity, "schemas", name, priv, option)
    for grantee, identity, schema, relation, priv, option in rows[
        "relation_privileges"
    ]:
        full = f"{schema}.{relation}"
        privilege(grantee, identity, kinds.get(full, "tables"), full, priv, option)
    for kind, name, owner in rows["owners"]:
        state.owners[(kind, name)] = owner
    for owner, schema, kind, grantee, gtype, priv in rows["default_privileges"]:
        if gtype != "public":  # PUBLIC isn't managed yet
            state.default_privileges.add(
                DefaultGrant(
                    owner, schema, _DEFAULT_TYPES.get(kind, kind.lower()), grantee, priv
                )
            )
    if columns:
        state.objects["columns"] = {f"{s}.{t}.{c}" for s, t, c in rows["columns"]}
    for grantee, identity, schema, relation, column, priv in rows["column_privileges"]:
        privilege(grantee, identity, "columns", f"{schema}.{relation}.{column}", priv)
    return state


def fetch(db: Connection, queries: dict[str, str]) -> dict[str, list[tuple[Any, ...]]]:
    """Run catalog queries, together where the connection can; time them on request.

    A Data API connection runs them all at once (``rows_many``); a direct one in
    turn. ``SESAME_TIMING=1`` prints each query's time and row count to stderr.
    """
    started = time.monotonic()
    many = getattr(db, "rows_many", None)
    if many is not None:
        results = dict(zip(queries, many(list(queries.values()))))
        durations = getattr(db, "durations", [None] * len(queries))
        timings = dict(zip(queries, durations))
    else:
        results, timings = {}, {}
        for name, query in queries.items():
            t = time.monotonic()
            results[name] = db.rows(query)
            timings[name] = time.monotonic() - t
    if os.environ.get("SESAME_TIMING"):
        for name, rows in results.items():
            took = f"{timings[name]:.2f}s" if timings[name] is not None else "together"
            print(f"sesame: {name}: {len(rows)} rows, {took}", file=sys.stderr)
        print(
            f"sesame: catalog read in {time.monotonic() - started:.2f}s",
            file=sys.stderr,
        )
    return results

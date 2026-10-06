"""Read a Redshift database's users, groups, roles and privileges.

Redshift reports privileges through its SVV views, which spell each privilege out
with the kind of identity holding it, so there is no ACL string to parse (the
letters Redshift adds to PostgreSQL's are what crashed earlier tools). The same
queries run on Amazon Redshift and on oblako's redshift-local, which provides the
same views. Only explicit grants are read: what an owner holds on its own object
is implied by ownership. Superusers are never managed.
"""

from __future__ import annotations

from typing import Any

from pgsesame.db import Connection
from pgsesame.state import Membership, Privilege, Role, State

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
RELATIONS = (
    "select table_schema, table_name, table_type from svv_tables where "
    + _USER_SCHEMA.format(col="table_schema")
)
DATABASE_PRIVILEGES = """
select identity_name, identity_type, database_name, lower(privilege_type)
from svv_database_privileges
where database_name = current_database() and privilege_scope = 'DATABASE'
"""
SCHEMA_PRIVILEGES = """
select identity_name, identity_type, namespace_name, lower(privilege_type)
from svv_schema_privileges
where privilege_scope = 'SCHEMA'
"""
RELATION_PRIVILEGES = """
select identity_name, identity_type, namespace_name, relation_name,
       lower(privilege_type)
from svv_relation_privileges
"""


def _int_array(value: Any) -> list[int]:
    """Return an int[] column: a list over a driver, ``{1,2}`` text over the Data API."""
    if value is None:
        return []
    if isinstance(value, str):
        inner = value.strip("{}")
        return [int(v) for v in inner.split(",") if v.strip()]
    return list(value)


def read(db: Connection) -> State:
    """Return the current state of the Redshift database ``db`` is connected to."""
    state = State()
    users: dict[int, str] = {}
    for sysid, name, superuser in db.rows(USERS):
        users[sysid] = name
        state.roles[name] = Role(name, True, superuser, "user")
    for name, members in db.rows(GROUPS):
        state.roles[name] = Role(name, False, False, "group")
        for sysid in _int_array(members):
            if sysid in users:
                state.memberships.add(Membership(users[sysid], name))
    for (name,) in db.rows(ROLES):
        state.roles[name] = Role(name, False, False, "role")
    state.memberships |= {Membership(u, r) for u, r in db.rows(USER_ROLES)}
    state.memberships |= {Membership(r, g) for r, g in db.rows(ROLE_ROLES)}

    state.objects = {"databases": {db.database}, "tables": set(), "views": set()}
    state.objects["schemas"] = {name for (name,) in db.rows(SCHEMAS)}
    kinds: dict[str, str] = {}
    for schema, name, table_type in db.rows(RELATIONS):
        kind = "views" if table_type == "VIEW" else "tables"
        kinds[f"{schema}.{name}"] = kind
        state.objects[kind].add(f"{schema}.{name}")

    def privilege(grantee: str, identity: str, kind: str, name: str, priv: str) -> None:
        if identity == "public":  # PUBLIC isn't managed yet
            return
        if priv == "temp":  # one spelling, as the planner writes it
            priv = "temporary"
        state.privileges.add(Privilege(grantee, kind, name, priv))

    for grantee, identity, name, priv in db.rows(DATABASE_PRIVILEGES):
        privilege(grantee, identity, "databases", name, priv)
    for grantee, identity, name, priv in db.rows(SCHEMA_PRIVILEGES):
        privilege(grantee, identity, "schemas", name, priv)
    for grantee, identity, schema, relation, priv in db.rows(RELATION_PRIVILEGES):
        full = f"{schema}.{relation}"
        privilege(grantee, identity, kinds.get(full, "tables"), full, priv)
    return state

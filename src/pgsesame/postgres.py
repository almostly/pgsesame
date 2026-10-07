"""Read a PostgreSQL database's roles, memberships and privileges.

Privileges come from the ACLs in the catalog, expanded with ``aclexplode()``.
Grants an object's owner holds on it are implied by ownership, so they are left
out; so are grants to PUBLIC, which pgsesame does not manage yet. System schemas
(``pg_*``, ``information_schema``) are never read.
"""

from __future__ import annotations

from pgsesame.db import Connection
from pgsesame.state import Membership, Privilege, Role, State

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
select g.rolname, d.datname, lower(a.privilege_type)
from pg_database d, aclexplode(d.datacl) a
join pg_roles g on g.oid = a.grantee
where d.datname = current_database() and a.grantee <> d.datdba
"""

SCHEMA_PRIVILEGES = f"""
select g.rolname, n.nspname, lower(a.privilege_type)
from pg_namespace n, aclexplode(n.nspacl) a
join pg_roles g on g.oid = a.grantee
where {_USER_SCHEMA} and a.grantee <> n.nspowner
"""

RELATION_PRIVILEGES = f"""
select g.rolname,
       case c.relkind when 'S' then 'sequences'
                      when 'v' then 'views' when 'm' then 'views'
                      else 'tables' end,
       n.nspname || '.' || c.relname,
       lower(a.privilege_type)
from pg_class c
join pg_namespace n on n.oid = c.relnamespace,
     aclexplode(c.relacl) a
join pg_roles g on g.oid = a.grantee
where c.relkind in ('r', 'p', 'v', 'm', 'S') and {_USER_SCHEMA}
  and a.grantee <> c.relowner
"""


def read(db: Connection) -> State:
    """Return the current state of the database ``db`` is connected to."""
    state = State()
    for name, login, superuser in db.rows(ROLES):
        state.roles[name] = Role(name, login, superuser)
    state.memberships = {Membership(m, r) for m, r in db.rows(MEMBERSHIPS)}

    state.objects = {"databases": {db.database}, "schemas": set()}
    state.objects["schemas"] = {name for (name,) in db.rows(SCHEMAS)}
    for name, kind in db.rows(RELATIONS):
        state.objects.setdefault(kind, set()).add(name)

    for grantee, name, privilege in db.rows(DATABASE_PRIVILEGES):
        state.privileges.add(Privilege(grantee, "databases", name, privilege))
    for grantee, name, privilege in db.rows(SCHEMA_PRIVILEGES):
        state.privileges.add(Privilege(grantee, "schemas", name, privilege))
    for grantee, kind, name, privilege in db.rows(RELATION_PRIVILEGES):
        state.privileges.add(Privilege(grantee, kind, name, privilege))
    return state

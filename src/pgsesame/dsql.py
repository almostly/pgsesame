"""Read an Amazon Aurora DSQL database: PostgreSQL's catalog, and its IAM links.

Aurora DSQL speaks PostgreSQL 16 for roles, memberships and grants, so the
PostgreSQL reader reads it unchanged. What it adds is how IAM identities sign in
as roles (AWS IAM GRANT role TO 'arn'), kept in sys.iam_pg_role_mappings.
"""

from __future__ import annotations

from pgsesame import postgres
from pgsesame.db import Connection
from pgsesame.state import State

IAM_LINKS = "select pg_role_name, arn from sys.iam_pg_role_mappings"


def read(db: Connection, columns: bool = True) -> State:
    """Return the database's state, IAM links included."""
    state = postgres.read(db, columns)
    state.iam_links = {(role, arn) for role, arn in db.rows(IAM_LINKS)}
    return state


def is_dsql(db: Connection) -> bool:
    """Return whether the database is Aurora DSQL: it has sys.iam_pg_role_mappings."""
    rows = db.rows(
        "select count(*) from information_schema.tables "
        "where table_schema = 'sys' and table_name = 'iam_pg_role_mappings'"
    )
    return bool(rows and rows[0][0])

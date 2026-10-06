"""A connection to the database being managed.

A thin layer over psycopg: read rows, and run a list of statements in one
transaction. The planner and the readers only see this interface, so the Redshift
IAM and Data API connections can provide the same one later.
"""

from __future__ import annotations

from typing import Any, Protocol

import psycopg
from psycopg import sql
from pydantic import SecretStr


class Connection(Protocol):
    """What the readers and the CLI use from a connection, whichever kind it is."""

    @property
    def database(self) -> str:
        """Return the database's name."""
        ...

    @property
    def target(self) -> str:
        """Return where the connection goes, for headers and change sets."""
        ...

    def rows(self, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        """Run a catalog query and return its rows."""
        ...

    def render(self, statement: sql.Composed) -> str:
        """Return a statement as SQL text."""
        ...

    def run(self, statements: list[sql.Composed]) -> None:
        """Run statements in one transaction."""
        ...

    def close(self) -> None:
        """Release the connection."""
        ...


class Database:
    """A psycopg connection, from a DSN or the standard ``PG*`` variables."""

    def __init__(self, dsn: SecretStr | None = None):
        """Connect; no DSN uses PGHOST, PGUSER, PGPASSWORD and the rest.

        The DSN can carry a password, so it stays a SecretStr until the moment it
        is handed to libpq; ``target`` shows the connection without it.
        """
        secret = dsn.get_secret_value() if dsn is not None else ""
        self.conn = psycopg.connect(secret, autocommit=True)

    @property
    def database(self) -> str:
        """Return the name of the connected database."""
        return self.conn.info.dbname

    @property
    def target(self) -> str:
        """Return the connection as pgcli shows it: ``user@host:database``."""
        info = self.conn.info
        return f"{info.user}@{info.host}:{info.dbname}"

    def rows(self, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        """Run a catalog query and return its rows."""
        with self.conn.cursor() as cur:
            # constant SQL from the readers; no parameters means no placeholders,
            # so a LIKE pattern's % stays a %
            cur.execute(query.encode(), params or None)
            return cur.fetchall()

    def render(self, statement: sql.Composed) -> str:
        """Return a composed statement as the SQL text the server will run."""
        return statement.as_string(self.conn)

    def run(self, statements: list[sql.Composed]) -> None:
        """Run statements in one transaction: all of them, or none."""
        with self.conn.transaction(), self.conn.cursor() as cur:
            for statement in statements:
                cur.execute(statement)

    def close(self) -> None:
        """Close the connection."""
        self.conn.close()

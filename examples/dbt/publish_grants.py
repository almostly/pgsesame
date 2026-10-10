"""Publish the grants a spec declares to monitoring.declared_grants, for the dbt hook.

    sesame grants permissions.yaml --format csv | python publish_grants.py "$DSN"

Run it after each successful apply. The table's rows are replaced in one
transaction, so the hook never sees half of them.
"""

import csv
import sys

import psycopg

COLUMNS = (
    "object_type",
    "schema",
    "object",
    "column",
    "privilege",
    "grantee",
    "grantee_type",
)


def main() -> None:
    """Replace the table's rows with the CSV on stdin."""
    rows = [tuple(r[c] for c in COLUMNS) for r in csv.DictReader(sys.stdin)]
    with psycopg.connect(sys.argv[1]) as conn, conn.transaction():
        conn.execute("create schema if not exists monitoring")
        conn.execute(
            "create table if not exists monitoring.declared_grants ("
            "object_type varchar(16), schema varchar(127), object varchar(127), "
            '"column" varchar(127), privilege varchar(32), grantee varchar(127), '
            "grantee_type varchar(8))"
        )
        conn.execute("delete from monitoring.declared_grants")
        with conn.cursor() as cur:
            cur.executemany(
                "insert into monitoring.declared_grants values (%s, %s, %s, %s, %s, %s, %s)",
                rows,
            )
    print(f"published {len(rows)} grant(s)")


if __name__ == "__main__":
    main()

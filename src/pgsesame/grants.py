"""The grants a spec declares, as rows: for tools that rebuild tables to put back.

dbt's table materialization (and Glue, stored procedures ...) replaces a table on
each run, and its grants go with the old one. ``sesame grants`` lists what the spec
grants, from the spec alone (no database), so such a tool re-grants from
pgsesame's reading of the spec instead of parsing the YAML itself.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass

from pgsesame.planner import PLANNED_TYPES
from pgsesame.spec import Spec

COLUMNS = (
    "object_type",
    "schema",
    "object",
    "column",
    "privilege",
    "grantee",
    "grantee_type",
)


@dataclass(frozen=True, order=True)
class GrantRow:
    """One privilege the spec gives a grantee on an object (or a schema's ``*``)."""

    object_type: str  # databases, schemas, tables, views, sequences, columns
    schema: str  # the schema; for a database grant, empty
    object: str  # the object's name, * for schema.*, the name itself for a schema
    column: str  # for a column grant, else empty
    privilege: str
    grantee: str
    grantee_type: str  # Redshift: user, group or role; PostgreSQL: role; public


def rows(spec: Spec, only: str | None = None) -> list[GrantRow]:
    """Return the spec's grants, patterns as written; ``only`` keeps one object's.

    ``only`` is ``schema.table``: its own rows, column ones included, and those its
    schema's ``*`` gives it.
    """
    out: set[GrantRow] = set()
    for name, p in spec.principals.items():
        if name == "public":
            kind = "public"  # GRANT ... TO PUBLIC
        elif spec.engine == "redshift":
            kind = "role" if p.type == "builtin" else p.type
        else:
            kind = "role"
        for object_type, grants in p.privileges.items():
            if object_type not in PLANNED_TYPES:
                continue
            for privilege, patterns in grants.items():
                spelt = "temporary" if privilege == "temp" else privilege
                for pattern in patterns:
                    parts = pattern.split(".")
                    if object_type == "databases":
                        schema, obj, column = "", pattern, ""
                    elif object_type == "schemas":
                        schema, obj, column = pattern, pattern, ""
                    elif object_type == "columns":
                        schema, obj, column = parts
                    else:
                        schema, obj, column = parts[0], parts[1], ""
                    out.add(
                        GrantRow(object_type, schema, obj, column, spelt, name, kind)
                    )
    if only is not None:
        schema, _, obj = only.partition(".")
        out = {
            r
            for r in out
            if r.object_type in ("tables", "views", "sequences", "columns")
            and r.schema == schema
            and r.object in (obj, "*")
        }
    return sorted(out)


def dump(found: list[GrantRow], fmt: str) -> str:
    """Return rows as JSON (a list of objects) or CSV (with a header row)."""
    if fmt == "json":
        return json.dumps([asdict(r) for r in found], indent=2) + "\n"
    text = io.StringIO()
    writer = csv.DictWriter(text, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(asdict(r) for r in found)
    return text.getvalue()

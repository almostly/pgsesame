"""Redshift dynamic data masking: read the policies and plan who sees what.

The spec says, per column, what everyone sees (``mask``), which roles see their
own mask (``roles``) and which see the raw value (``unmasked``). On Redshift that
is a policy per mask and an attachment per column and grantee, the highest
priority winning:

* ``mask``: the policy, TO PUBLIC, priority 10;
* ``roles``: each role's policy, TO ROLE, priority 20, 30, ... in the order
  written, so a later entry wins for a user in two of the roles;
* ``unmasked``: a pass-through policy (``USING (value)``), TO ROLE, priority 1000.

The pass-through policies are pgsesame's own, one per column type
(``sesame_unmasked_varchar_256``), so a raw value keeps its column's type.

Redshift stores a policy's expression and types in its own form (``'***'``
becomes ``CAST(CAST('***' AS VARCHAR) AS VARCHAR(256))``), so the spec's text
can't be compared with the catalog's. ``normalize`` creates each policy as a
probe inside a transaction that is always rolled back and reads Redshift's form
back. See DESIGN.md, "Masking".
"""

from __future__ import annotations

import json
import re
from typing import Any

from psycopg import sql

from pgsesame import redshift
from pgsesame.db import Connection, Database
from pgsesame.ops import (
    AlterMaskingPolicy,
    AttachMaskingPolicy,
    CreateMaskingPolicy,
    DetachMaskingPolicy,
    DropMaskingPolicy,
    Operation,
    ReattachMaskingPolicy,
)
from pgsesame.spec import UNMASKED_PREFIX, Spec
from pgsesame.state import Attachment, MaskPolicy, State

MASK_PRIORITY = 10
ROLE_PRIORITY = 20  # then 30, 40 ... in the order the spec lists the roles
UNMASKED_PRIORITY = 1000
PASS_THROUGH = "value"

CAN_MANAGE = """
select (select usesuper from pg_user where usename = current_user)
    or exists (select 1 from svv_user_grants
               where user_name = current_user and role_name = 'sys:secadmin')
"""
POLICIES = (
    "select policy_name, input_columns, policy_expression from svv_masking_policy"
)
ATTACHED = """
select policy_name, schema_name, table_name, grantee, grantee_type, priority,
       input_columns, output_columns
from svv_attached_masking_policy
"""
COLUMNS = """
select n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod)
from pg_attribute a
join pg_class c on c.oid = a.attrelid
join pg_namespace n on n.oid = c.relnamespace
where a.attnum > 0 and not a.attisdropped and ({})
"""

Normalized = dict[str, MaskPolicy]


class MaskingError(Exception):
    """The connection can't see masking policies, so it can't plan them."""


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _policy(name: str, inputs: Any, expression: Any) -> MaskPolicy:
    columns = _json(inputs) or []
    (expr,) = _json(expression) or [{"expr": "", "type": ""}]
    return MaskPolicy(
        name=name,
        inputs=tuple((c["colname"], c["type"]) for c in columns),
        expression=expr["expr"],
        output_type=expr["type"],
    )


def read(db: Connection, spec: Spec, state: State) -> None:
    """Add the masking policies, attachments and masked columns' types to ``state``.

    Without superuser or ``sys:secadmin`` Redshift's masking views return no rows,
    which would read as "nothing is masked", so that is checked (on the same
    round as the reads: over the Data API they run together).
    """
    assert spec.masking is not None
    queries = {"can_manage": CAN_MANAGE, "policies": POLICIES, "attached": ATTACHED}
    tables = sorted({c.rsplit(".", 1)[0] for c in spec.masking.columns})
    if tables:
        where = sql.SQL(" or ").join(
            sql.SQL("(n.nspname = {} and c.relname = {})").format(
                sql.Literal(t.split(".", 1)[0]), sql.Literal(t.split(".", 1)[1])
            )
            for t in tables
        )
        queries["columns"] = db.render(sql.SQL(COLUMNS).format(where))
    rows = redshift.fetch(db, queries)

    allowed = rows["can_manage"]
    if not (allowed and allowed[0][0]):
        raise MaskingError(
            "masking: this user can't see masking policies (Redshift shows them to "
            "superusers and the sys:secadmin role only), so it can't plan them"
        )
    for name, inputs, expression in rows["policies"]:
        state.mask_policies[name] = _policy(name, inputs, expression)
    for policy, schema, table, grantee, gtype, priority, inputs, outputs in rows[
        "attached"
    ]:
        state.attachments.add(
            Attachment(
                policy=policy,
                table=f"{schema}.{table}",
                columns=tuple(_json(outputs)),
                inputs=tuple(_json(inputs)),
                grantee=grantee,
                grantee_type=gtype,
                priority=int(priority),
            )
        )
    for schema, table, column, type_name in rows.get("columns", []):
        state.column_types[f"{schema}.{table}.{column}"] = type_name


def unmasked_policy(type_name: str) -> str:
    """Return the pass-through policy's name for a column type."""
    short = re.sub(r"^character varying", "varchar", type_name)
    short = re.sub(r"^character\b", "char", short)
    short = re.sub(r" with(out)? time zone$", lambda m: "tz" if not m[1] else "", short)
    return UNMASKED_PREFIX + re.sub(r"[^a-z0-9]+", "_", short.lower()).strip("_")


def wanted_policies(spec: Spec, state: State) -> dict[str, CreateMaskingPolicy]:
    """Return every policy the spec needs: its own and the pass-throughs."""
    assert spec.masking is not None
    out = {
        name: CreateMaskingPolicy(name=name, inputs=tuple(p.inputs()), using=p.using)
        for name, p in spec.masking.policies.items()
    }
    for column, c in spec.masking.columns.items():
        type_name = state.column_types.get(column)
        if c.unmasked and type_name:
            name = unmasked_policy(type_name)
            out[name] = CreateMaskingPolicy(
                name=name, inputs=((PASS_THROUGH, type_name),), using=PASS_THROUGH
            )
    return out


def normalize(db: Connection, spec: Spec, state: State) -> Normalized | None:
    """Return each wanted policy as Redshift stores it, or None if it can't be had.

    Each policy is created under a probe name in a transaction that is always
    rolled back, and read back from svv_masking_policy. The Data API has no
    transaction to roll back, so there the spec's text is compared as written.
    """
    if not isinstance(db, Database):
        return None
    out: Normalized = {}
    with db.conn.transaction(force_rollback=True), db.conn.cursor() as cur:
        for i, (name, create) in enumerate(
            sorted(wanted_policies(spec, state).items())
        ):
            probe = f"pgsesame_probe_{i}"
            cur.execute(create.model_copy(update={"name": probe}).statement())
            row = cur.execute(
                "select input_columns, policy_expression from svv_masking_policy "
                "where policy_name = %s",
                (probe,),
            ).fetchone()
            if row:
                out[name] = _policy(name, row[0], row[1])
    return out


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------
def _wanted_attachments(
    spec: Spec, state: State, grantee_type, problems: list[str]
) -> set[Attachment]:
    assert spec.masking is not None
    out: set[Attachment] = set()
    for column, c in sorted(spec.masking.columns.items()):
        table, name = column.rsplit(".", 1)
        type_name = state.column_types.get(column)
        if type_name is None:
            problems.append(f"masking.columns.{column}: the column does not exist")
            continue
        for extra in c.inputs or []:
            if f"{table}.{extra}" not in state.column_types:
                problems.append(
                    f"masking.columns.{column}.inputs: {table}.{extra} does not exist"
                )

        def attach(policy: str, grantee: str, gtype: str, priority: int) -> None:
            reads = spec.masking.policies.get(policy) if spec.masking else None
            several = reads is not None and len(reads.inputs()) > 1
            out.add(
                Attachment(
                    policy=policy,
                    table=table,
                    columns=(name,),
                    inputs=tuple(c.inputs or ()) if several else (name,),
                    grantee=grantee,
                    grantee_type=gtype,
                    priority=priority,
                )
            )

        if c.mask:
            attach(c.mask, "public", "public", MASK_PRIORITY)
        for i, (role, policy) in enumerate(c.roles.items()):
            attach(policy, role, grantee_type(role), ROLE_PRIORITY + 10 * i)
        for role in c.unmasked:
            attach(
                unmasked_policy(type_name), role, grantee_type(role), UNMASKED_PRIORITY
            )
    return out


def plan(
    spec: Spec,
    state: State,
    normalized: Normalized | None,
    grantee_type,
    problems: list[str],
    notes: list[str],
) -> list[Operation]:
    """Return the operations that make the masked columns read as the spec says.

    Managed: the policies the spec declares, pgsesame's pass-through policies, and
    every attachment on the columns the spec lists. Other policies, and
    attachments on other columns, are left alone.
    """
    assert spec.masking is not None
    ops: list[Operation] = []
    want = _wanted_attachments(spec, state, grantee_type, problems)
    if problems:
        return []
    managed_columns = {tuple(c.rsplit(".", 1)) for c in spec.masking.columns}

    def managed(a: Attachment) -> bool:
        return any((a.table, col) in managed_columns for col in a.columns)

    have = {a for a in state.attachments if managed(a)}
    wanted = wanted_policies(spec, state)
    replaced: set[str] = set()
    for name, create in sorted(wanted.items()):
        current = state.mask_policies.get(name)
        if current is None:
            ops.append(create)
            continue
        if normalized is None:
            continue
        target = normalized.get(name)
        if target is None:
            continue
        if current.inputs != target.inputs or current.output_type != target.output_type:
            # ALTER can't change these: detach everywhere, drop, create, attach again
            replaced.add(name)
            ops += [
                DropMaskingPolicy(name=name),
                create.model_copy(update={"replacing": True}),
            ]
        elif current.expression != target.expression:
            ops.append(AlterMaskingPolicy(name=name, using=create.using))
    if normalized is None and any(n in state.mask_policies for n in wanted):
        notes.append(
            "masking: over the Data API policy expressions aren't compared (Redshift "
            "stores its own form, read by a rolled-back probe); connect with a "
            "password or IAM to plan changes to them"
        )

    # per policy, column and grantee: one DETACH removes every priority, so a
    # change of priorities is a detach and the attaches that follow it
    def key(a: Attachment) -> tuple:
        return (a.policy, a.table, a.columns, a.grantee, a.grantee_type)

    detached: set[tuple] = set()
    for a in sorted(a for a in state.attachments if a.policy in replaced):
        if key(a) not in detached:
            detached.add(key(a))
            ops.append(_detach(a, ReattachMaskingPolicy, replacing=True))
        if not managed(a):  # someone else's column: put it back as it was
            ops.append(_attach(a, replacing=True))

    groups = {key(a) for a in have | want}
    for k in sorted(groups):
        now = {a for a in have if key(a) == k}
        then = {a for a in want if key(a) == k}
        if k[0] in replaced:
            ops += [_attach(a, replacing=True) for a in sorted(then)]
            continue
        if {(a.priority, a.inputs) for a in now} == {
            (a.priority, a.inputs) for a in then
        }:
            continue
        if now:
            kind = ReattachMaskingPolicy if then else DetachMaskingPolicy
            ops.append(_detach(min(now), kind))
        ops += [_attach(a) for a in sorted(then)]

    for name in sorted(set(state.mask_policies) - set(wanted)):
        if not name.startswith(UNMASKED_PREFIX):
            notes.append(f"masking: policy {name} isn't in the spec; left alone")
            continue
        still = {a for a in state.attachments if a.policy == name} - have
        if not still and not any(a.policy == name for a in want):
            ops.append(DropMaskingPolicy(name=name))
    return ops


def _attach(a: Attachment, replacing: bool = False) -> AttachMaskingPolicy:
    return AttachMaskingPolicy(
        policy=a.policy,
        table=a.table,
        columns=a.columns,
        inputs=a.inputs,
        grantee=a.grantee,
        grantee_type=a.grantee_type,
        priority=a.priority,
        replacing=replacing,
    )


def _detach(a: Attachment, kind, replacing: bool = False) -> Operation:
    return kind(
        policy=a.policy,
        table=a.table,
        columns=a.columns,
        grantee=a.grantee,
        grantee_type=a.grantee_type,
        replacing=replacing,
    )

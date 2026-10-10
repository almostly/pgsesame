"""Change sets: a plan saved to a file, to apply exactly as it was reviewed.

``sesame plan spec.yaml -o changes.json`` writes one; ``sesame apply
changes.json`` runs it. A change set embeds the spec it was planned from, so apply
plans again from that same spec against the database as it is now, and runs the
saved statements only if the new plan is identical. If the database changed in a
way that matters (a grant made by hand, a new table under ``schema.*``), the plans
differ and apply refuses; changes elsewhere in the database don't get in the way.

No secret is ever written: a new role's password is left out, and apply reads it
again from the environment variable the spec names.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PastDatetime,
    SecretStr,
    StringConstraints,
)

from pgsesame import spec as spec_module
from pgsesame.ops import AnyOperation, CreateRole, Operation

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class ChangeSetError(Exception):
    """A change set that can't be read, or can't be applied any more."""


class ChangeSet(BaseModel):
    """A saved plan: what to run, against what, planned from which spec."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal[1] = 1
    created_at: PastDatetime
    target: str = Field(description="user@host:database the plan was made against")
    engine: spec_module.Engine
    spec_sha256: Sha256
    spec: dict[str, Any] = Field(description="The spec, as validated")
    operations: list[AnyOperation]

    @classmethod
    def build(
        cls, spec: spec_module.Spec, target: str, operations: list[Operation]
    ) -> ChangeSet:
        """Make a change set from a validated spec and its plan."""
        raw = spec.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        return cls.model_validate(
            {
                "created_at": datetime.now(timezone.utc),
                "target": target,
                "engine": spec.engine,
                "spec_sha256": _sha256(raw),
                "spec": raw,
                "operations": [op.model_dump(mode="json") for op in operations],
            }
        )

    def save(self, path: str | Path) -> None:
        """Write the change set as JSON."""
        Path(path).write_text(self.model_dump_json(indent=2) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> ChangeSet:
        """Read and validate a change set, the embedded spec included."""
        try:
            changeset = cls.model_validate_json(Path(path).read_text())
        except ValueError as e:
            raise ChangeSetError(f"{path}: not a valid change set: {e}") from None
        if _sha256(changeset.spec) != changeset.spec_sha256:
            raise ChangeSetError(f"{path}: the embedded spec was edited after planning")
        return changeset

    def parsed_spec(self) -> spec_module.Spec:
        """Return the embedded spec, validated again."""
        return spec_module.parse(self.spec)

    def with_secrets(self) -> list[Operation]:
        """Return the operations with passwords read again from the environment."""
        out: list[Operation] = []
        for op in self.operations:
            if isinstance(op, CreateRole) and op.password_env:
                password = os.environ.get(op.password_env)
                secret = SecretStr(password) if password is not None else None
                op = op.model_copy(update={"password": secret})
            out.append(op)
        return out


def same_operations(a: list[Operation], b: list[Operation]) -> bool:
    """Whether two plans run the same statements (passwords aside)."""
    return [op.model_dump(mode="json") for op in a] == [
        op.model_dump(mode="json") for op in b
    ]


def is_changeset(path: str | Path) -> bool:
    """Whether ``path`` holds a change set rather than a spec."""
    try:
        head = json.loads(Path(path).read_text())
    except ValueError:
        return False
    return isinstance(head, dict) and "operations" in head and "spec" in head


def _sha256(raw: dict[str, Any]) -> str:
    """Return the SHA-256 of ``raw`` as canonical JSON (sorted keys, no spaces)."""
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()

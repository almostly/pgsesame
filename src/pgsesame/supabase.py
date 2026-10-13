"""Where a Supabase project's database is, for ``sesame login --supabase``.

The direct connection, ``db.<ref>.supabase.co``, is IPv6 only on Supabase's own
plans; the session pooler takes IPv4 too, at an address that depends on the
project's region. With a personal access token in ``SUPABASE_ACCESS_TOKEN`` (the
Supabase CLI's), the Management API says which; without one, the direct
connection is used.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass

API = "https://api.supabase.com/v1"
TOKEN = "SUPABASE_ACCESS_TOKEN"
# the session pooler's port; 6543, which the API reports, is transaction mode
SESSION_PORT = 5432


@dataclass(frozen=True)
class Endpoint:
    """How to reach a project's database as postgres."""

    host: str
    port: int
    user: str
    pooled: bool


def endpoint(ref: str) -> Endpoint:
    """Return where project ``ref``'s database is: the session pooler if it can say."""
    if not re.fullmatch(r"[a-z]{20}", ref):
        raise ValueError(f"{ref}: a Supabase project ref is 20 lowercase letters")
    token = os.environ.get(TOKEN)
    if not token:
        return Endpoint(f"db.{ref}.supabase.co", 5432, "postgres", pooled=False)
    request = urllib.request.Request(
        f"{API}/projects/{ref}/config/database/pooler",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        primary = next(
            pool
            for pool in json.load(response)
            if pool.get("database_type", "PRIMARY") == "PRIMARY"
        )
    return Endpoint(primary["db_host"], SESSION_PORT, primary["db_user"], pooled=True)

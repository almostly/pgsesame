"""The planner on hand-built states (no database)."""

import pytest

from pgsesame import planner, spec
from pgsesame.masking import unmasked_policy
from pgsesame.ops import (
    AlterMaskingPolicy,
    AttachMaskingPolicy,
    CreateMaskingPolicy,
    CreateRole,
    DetachMaskingPolicy,
    DropMaskingPolicy,
    Grant,
    ReattachMaskingPolicy,
    RemoveMember,
    Revoke,
)
from pgsesame.state import (
    Attachment,
    DefaultGrant,
    Membership,
    MaskPolicy,
    Privilege,
    Role,
    State,
)


def _spec(engine="postgres", **principals):
    """Return a spec for ``engine`` with these principals."""
    return spec.parse({"version": 1, "engine": engine, "principals": principals})


def _state(*roles: Role, objects=None, **extra) -> State:
    """Return a state with these roles and objects."""
    state = State(roles={r.name: r for r in roles}, objects=objects or {}, **extra)
    return state


def test_a_function_that_does_not_exist_is_warned_about_not_dropped_silently():
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {
                "etl": {"type": "user", "owns": {"schemas": ["analytics"]}},
                "fn": {
                    "type": "role",
                    "privileges": {"functions": {"execute": ["s.f"]}},
                },
            },
            "default_privileges": [
                {"owner": "etl", "grantee": "fn", "tables": ["select"]}
            ],
        }
    )
    plan = planner.make(loaded, _state(objects={"schemas": {"analytics"}}))
    assert (
        "principals.fn.privileges.functions.execute: s.f does not exist; skipped"
        in plan.warnings
    )
    # the default privilege is planned, for an owner the same plan creates
    assert [type(op).__name__ for op in plan.operations] == [
        "CreateRole",
        "CreateRole",
        "AlterOwner",  # etl owns analytics: after etl exists, before grants
        "GrantDefault",
    ]


def test_a_superuser_in_the_spec_is_left_alone():
    loaded = _spec(
        admin={"type": "role", "privileges": {"schemas": {"usage": ["s"]}}},
    )
    current = _state(
        Role("admin", True, superuser=True),
        objects={"schemas": {"s"}},
        memberships={Membership("admin", "someone")},
        privileges={Privilege("admin", "schemas", "s", "create")},
    )
    plan = planner.make(loaded, current)
    assert plan.operations == []  # no login change, no grant, no revoke
    assert "admin is a superuser; pgsesame leaves it alone" in plan.notes


def test_what_a_superuser_owns_is_planned_though_it_is_left_alone_otherwise():
    from pgsesame.ops import AlterOwner

    loaded = _spec(
        "redshift",
        dpu_redshift={
            "type": "user",
            "owns": {"schemas": ["mart"], "tables": ["mart.loans", "mart.missing"]},
            "privileges": {"schemas": {"usage": ["mart"]}},
        },
    )
    current = _state(
        Role("dpu_redshift", True, superuser=True, identity="user"),
        Role("etl_owner", True, identity="user"),
        objects={"schemas": {"mart"}, "tables": {"mart.loans"}},
        owners={
            ("schemas", "mart"): "etl_owner",
            ("tables", "mart.loans"): "etl_owner",
        },
    )
    plan = planner.make(loaded, current)
    assert [op.statement().as_string(None) for op in plan.operations] == [
        'ALTER SCHEMA "mart" OWNER TO "dpu_redshift"',
        'ALTER TABLE "mart"."loans" OWNER TO "dpu_redshift"',
    ]
    assert all(isinstance(op, AlterOwner) for op in plan.operations)  # no grant
    assert plan.allowed(False, False) == []  # behind --allow-owner, as any owner
    assert any("mart.missing does not exist" in w for w in plan.warnings)
    assert "dpu_redshift is a superuser; pgsesame manages only what it owns" in (
        plan.notes
    )

    # once it owns them, nothing to do
    current.owners = {
        ("schemas", "mart"): "dpu_redshift",
        ("tables", "mart.loans"): "dpu_redshift",
    }
    assert planner.make(loaded, current).operations == []


def test_unmanaged_roles_keep_their_redshift_identity_in_a_removal():
    loaded = _spec("redshift", alice={"type": "user"})
    current = _state(
        Role("alice", True, identity="user"),
        Role("ops", False, identity="group"),
        memberships={Membership("alice", "ops")},
    )
    (op,) = planner.make(loaded, current).operations
    assert isinstance(op, RemoveMember) and op.role_identity == "group"
    assert op.statement().as_string() == 'ALTER GROUP "ops" DROP USER "alice"'


def test_temp_and_temporary_are_one_privilege():
    loaded = _spec(r={"type": "role", "privileges": {"databases": {"temp": ["dev"]}}})
    current = _state(
        Role("r", False),
        objects={"databases": {"dev"}},
        privileges={Privilege("r", "databases", "dev", "temporary")},
    )
    assert planner.make(loaded, current).operations == []
    fresh = planner.make(
        loaded, _state(Role("r", False), objects={"databases": {"dev"}})
    )
    assert fresh.operations == [
        Grant(
            grantee="r",
            object_type="databases",
            object_name="dev",
            privilege="temporary",
        )
    ]


def test_a_privilege_pgsesame_does_not_model_is_noted_and_left_alone():
    loaded = _spec(r={"type": "role", "privileges": {"tables": {"select": ["s.t"]}}})
    current = _state(
        Role("r", False),
        objects={"tables": {"s.t"}},
        privileges={
            Privilege("r", "tables", "s.t", "select"),
            Privilege("r", "tables", "s.t", "rule"),  # a privilege from elsewhere
        },
    )
    plan = planner.make(loaded, current)
    assert plan.operations == []
    assert plan.notes == [
        "RULE on tables isn't a privilege pgsesame manages: 1 grant left as it is "
        "(r on s.t)"
    ]


def test_a_builtin_role_is_referred_to_never_created():
    loaded = _spec(
        platform={"type": "builtin"}, app={"type": "user", "member_of": ["platform"]}
    )
    with pytest.raises(planner.PlanError) as err:
        planner.make(loaded, _state())
    assert err.value.problems == [
        "principals.platform: the built-in role doesn't exist on this server"
    ]
    plan = planner.make(loaded, _state(Role("platform", False)))
    assert [type(op).__name__ for op in plan.operations] == ["CreateRole", "AddMember"]
    created = plan.operations[0]
    assert isinstance(created, CreateRole) and created.name == "app"  # only the user


def test_a_builtin_roles_privileges_are_managed_only_where_the_spec_speaks():
    loaded = _spec(
        authenticated={
            "type": "builtin",
            "privileges": {
                "schemas": {"usage": ["app"]},
                "tables": {"select": ["app.*"]},
            },
        }
    )
    current = _state(
        Role("authenticated", False),
        objects={"schemas": {"app", "public"}, "tables": {"app.t", "public.x"}},
        memberships={Membership("authenticated", "something_else")},
        privileges={
            Privilege("authenticated", "tables", "app.t", "delete"),  # in scope: drift
            Privilege(
                "authenticated", "tables", "public.x", "select"
            ),  # the platform's
            Privilege("authenticated", "schemas", "public", "usage"),  # the platform's
        },
    )
    plan = planner.make(loaded, current)
    rendered = sorted(op.statement().as_string() for op in plan.operations)
    assert rendered == [
        'GRANT SELECT ON TABLE "app"."t" TO "authenticated"',
        'GRANT USAGE ON SCHEMA "app" TO "authenticated"',
        'REVOKE DELETE ON TABLE "app"."t" FROM "authenticated"',
    ]  # nothing in public, and its own membership is left alone


def test_a_builtin_role_joins_the_specs_own_roles():
    # Supabase's authenticator switches to the role a request's JWT names
    loaded = _spec(
        editor={"type": "role"},
        authenticator={"type": "builtin", "member_of": ["editor"]},
    )
    current = _state(
        Role("editor", False),
        Role("auditor", False),
        Role("authenticator", True),
        Role("anon", False),
        memberships={
            Membership("authenticator", "anon"),  # the platform's: left alone
            Membership("authenticator", "auditor"),  # not the spec's: left alone
        },
    )
    (op,) = planner.make(loaded, current).operations
    assert op.statement().as_string(None) == 'GRANT "editor" TO "authenticator"'

    # leaving one of the spec's roles is drift
    current.memberships.add(Membership("authenticator", "editor"))
    unjoined = _spec(editor={"type": "role"}, authenticator={"type": "builtin"})
    (op,) = planner.make(unjoined, current).operations
    assert isinstance(op, RemoveMember) and op.needs == "revoke"


def test_a_builtin_role_joins_only_the_specs_own_roles():
    with pytest.raises(spec.SpecError) as err:
        _spec(
            anon={"type": "builtin"},
            authenticator={"type": "builtin", "member_of": ["anon", "ghost"]},
            public={"type": "builtin", "member_of": ["anon"]},
        )
    assert sorted(err.value.problems) == [
        "principals.authenticator.member_of: anon is not one of the spec's own "
        "roles; a built-in role joins only those",
        "principals.authenticator.member_of: ghost is not one of the spec's own "
        "roles; a built-in role joins only those",
        "principals.public.member_of: PUBLIC joins no role",
    ]


def test_a_builtin_role_takes_only_privileges():
    with pytest.raises(spec.SpecError) as err:
        _spec(platform={"type": "builtin", "login": True, "member_of": []})
    assert err.value.problems[0].startswith(
        "principals.platform: a built-in role is referred to, not managed"
    )


def _rls_spec(**policy):
    """Return a spec with one row-level security policy on app.notes, for reader."""
    return spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {"reader": {"type": "role"}},
            "row_level_security": {
                "app.notes": {
                    "policies": {"own": {"to": ["reader"], "using": "true", **policy}}
                }
            },
        }
    )


def test_row_level_security_is_planned_per_table():
    from pgsesame.state import Policy

    loaded = _rls_spec()
    fresh = planner.make(
        loaded, _state(Role("reader", False), rls={"app.notes": (False, False)})
    )
    assert [type(op).__name__ for op in fresh.operations] == [
        "CreatePolicy",
        "EnableRowSecurity",
    ]

    have = Policy("app.notes", "own", "all", True, ("reader",), "true", None)
    current = _state(Role("reader", False), rls={"app.notes": (True, False)})
    current.policies = {("app.notes", "own"): have}
    assert planner.make(loaded, current).operations == []  # converged

    current.policies[("app.notes", "old")] = Policy(
        "app.notes", "old", "all", True, ("public",), "true", None
    )
    (drop,) = planner.make(
        loaded, current
    ).operations  # undeclared policy on a managed table
    assert type(drop).__name__ == "DropPolicy" and drop.gate == "drop"
    del current.policies[("app.notes", "old")]

    replaced = planner.make(_rls_spec(command="select"), current).operations
    assert [type(op).__name__ for op in replaced] == ["DropPolicy", "CreatePolicy"]
    altered = planner.make(_rls_spec(using="false"), current).operations
    assert [type(op).__name__ for op in altered] == ["AlterPolicy"]


def test_row_level_security_on_a_table_the_user_cant_own_plans_only_policies():
    # Supabase's storage.objects: postgres may create policies on it, not switch
    # its row-level security
    current = _state(
        Role("reader", False),
        rls={"app.notes": (False, False)},
        rls_switchable=set(),
        owners={("tables", "app.notes"): "supabase_storage_admin"},
    )
    plan = planner.make(_rls_spec(), current)
    assert [type(op).__name__ for op in plan.operations] == ["CreatePolicy"]
    (warning,) = plan.warnings
    assert warning.startswith(
        "row_level_security.app.notes: owned by supabase_storage_admin"
    )


def test_row_level_security_problems():
    with pytest.raises(planner.PlanError) as err:
        planner.make(_rls_spec(), _state(Role("reader", False)))
    assert err.value.problems == [
        "row_level_security.app.notes: the table does not exist"
    ]
    with pytest.raises(spec.SpecError) as bad:
        _rls_spec(command="select", with_check="true")
    assert bad.value.problems == [
        "row_level_security.app.notes.policies.own: select policies take no with_check"
    ]


# ---------------------------------------------------------------------------
# Redshift masking
# ---------------------------------------------------------------------------
MASKING = {
    "policies": {
        "redact": {"type": "varchar(64)", "using": "'***'::varchar(64)"},
        "domain": {"type": "varchar(64)", "using": "regexp_replace(value, '@.*', '')"},
    },
    "columns": {
        "crm.c.email": {
            "mask": "redact",
            "unmasked": ["pii"],
            "roles": {"support": "domain", "fraud": "redact"},
        }
    },
}


def _masking_spec(masking=MASKING):
    """Return a Redshift spec with ``masking`` and the roles it names."""
    principals = {r: {"type": "role"} for r in ("pii", "support", "fraud")}
    return spec.parse(
        {
            "version": 1,
            "engine": "redshift",
            "principals": principals,
            "masking": masking,
        }
    )


def _masked_state(attachments=(), policies=()):
    """Return a state with crm.c.email, its roles, these attachments and policies."""
    roles = [Role(r, False, False, "role") for r in ("pii", "support", "fraud")]
    return _state(
        *roles,
        column_types={"crm.c.email": "character varying(64)"},
        attachments=set(attachments),
        mask_policies={p.name: p for p in policies},
    )


def _attachment(policy, grantee, priority, gtype="role"):
    """Return an attachment of ``policy`` on crm.c.email for ``grantee``."""
    return Attachment(policy, "crm.c", ("email",), ("email",), grantee, gtype, priority)


def _policy(name, expression="x", type_name="character varying(64)"):
    """Return a masking policy that takes one ``value`` of ``type_name``."""
    return MaskPolicy(name, (("value", type_name),), expression, type_name)


def test_masking_priorities_follow_the_spec():
    plan = planner.make(_masking_spec(), _masked_state(), masks={})
    attaches = {
        (op.policy, op.grantee, op.grantee_type, op.priority)
        for op in plan.operations
        if isinstance(op, AttachMaskingPolicy)
    }
    assert attaches == {
        ("redact", "public", "public", 10),
        ("domain", "support", "role", 20),
        ("redact", "fraud", "role", 30),  # later entries win
        ("sesame_unmasked_varchar_64", "pii", "role", 1000),
    }
    creates = [op.name for op in plan.operations if isinstance(op, CreateMaskingPolicy)]
    assert creates == ["domain", "redact", "sesame_unmasked_varchar_64"]


def test_pass_through_policy_names():
    assert unmasked_policy("character varying(256)") == "sesame_unmasked_varchar_256"
    assert unmasked_policy("numeric(12,2)") == "sesame_unmasked_numeric_12_2"
    assert unmasked_policy("character(11)") == "sesame_unmasked_char_11"
    assert unmasked_policy("timestamp without time zone") == "sesame_unmasked_timestamp"
    assert unmasked_policy("timestamp with time zone") == "sesame_unmasked_timestamptz"


def _converged():
    """Return the policies and attachments of a database that matches MASKING."""
    policies = [
        _policy("redact"),
        _policy("domain"),
        _policy("sesame_unmasked_varchar_64"),
    ]
    attachments = [
        _attachment("redact", "public", 10, "public"),
        _attachment("domain", "support", 20),
        _attachment("redact", "fraud", 30),
        _attachment("sesame_unmasked_varchar_64", "pii", 1000),
    ]
    return policies, attachments


def test_masking_converges_and_compares_normalized_expressions():
    policies, attachments = _converged()
    state = _masked_state(attachments, policies)
    same = {p.name: p for p in policies}
    assert planner.make(_masking_spec(), state, masks=same).operations == []
    changed = {**same, "redact": _policy("redact", "y")}
    ops = planner.make(_masking_spec(), state, masks=changed).operations
    assert ops == [AlterMaskingPolicy(name="redact", using="'***'::varchar(64)")]


def test_priorities_are_compared_by_order_not_number():
    policies, attachments = _converged()
    # fraud from 30 to 40: still above support (20), below unmasked (1000)
    attachments[2] = _attachment("redact", "fraud", 40)
    state = _masked_state(attachments, policies)
    assert planner.make(_masking_spec(), state, masks={}).operations == []
    # every number different, the same order: what each user reads is the same
    renumbered = [
        _attachment("redact", "public", 0, "public"),
        _attachment("domain", "support", 5),
        _attachment("redact", "fraud", 6),
        _attachment("sesame_unmasked_varchar_64", "pii", 50),
    ]
    state = _masked_state(renumbered, policies)
    assert planner.make(_masking_spec(), state, masks={}).operations == []


def test_a_changed_order_is_a_reattach_not_a_revoke():
    policies, attachments = _converged()
    # fraud below support: support would win for a user in both, the spec says fraud
    attachments[2] = _attachment("redact", "fraud", 15)
    state = _masked_state(attachments, policies)
    ops = planner.make(_masking_spec(), state, masks={}).operations
    assert ReattachMaskingPolicy in [type(op) for op in ops]
    assert all(op.needs is None for op in ops)  # a change, not a revoke


def test_attachments_the_spec_drops_are_revokes():
    policies, attachments = _converged()
    attachments.append(_attachment("redact", "support", 50))
    state = _masked_state(attachments, policies)
    ops = planner.make(_masking_spec(), state, masks={}).operations
    assert [(type(op), op.needs) for op in ops] == [(DetachMaskingPolicy, "revoke")]


def test_a_type_change_replaces_the_policy_behind_allow_drop():
    policies, attachments = _converged()
    state = _masked_state(attachments, policies)
    masks = {p.name: p for p in policies}
    masks["redact"] = _policy("redact", "x", "character varying(128)")
    plan = planner.make(_masking_spec(), state, masks=masks)
    kinds = [type(op).__name__ for op in plan.operations]
    assert kinds == [
        "ReattachMaskingPolicy",  # fraud's, then PUBLIC's: every attachment of it
        "ReattachMaskingPolicy",
        "DropMaskingPolicy",
        "CreateMaskingPolicy",
        "AttachMaskingPolicy",
        "AttachMaskingPolicy",
    ]
    assert all(op.needs == "drop" for op in plan.operations)
    assert plan.allowed(allow_revoke=True, allow_drop=False) == []


def test_roles_with_one_policy_share_a_priority():
    from pgsesame.masking import role_priorities

    assert role_priorities(["a", "b"]) == [20, 30]  # each outranks the last
    assert role_priorities(["a", "a"]) == [20, 20]  # one policy: one priority
    assert role_priorities(["a", "a", "b", "a"]) == [20, 20, 30, 40]
    assert role_priorities([]) == []


def test_a_role_with_the_masks_policy_never_shares_publics_priority():
    # on Redshift, attaching a policy to a role at the priority PUBLIC holds it
    # at replaces PUBLIC's attachment: everyone else would read the raw value
    from pgsesame.masking import MASK_PRIORITY, role_priorities

    assert role_priorities(["m", "b"]) == [20, 30]
    assert MASK_PRIORITY not in role_priorities(["m", "m", "b", "m"])


def test_import_of_one_policy_on_two_roles_at_priority_0_plans_nothing():
    # provision.sh's way: ATTACH ... TO ROLE x, TO ROLE y, no PRIORITY (0 each)
    from pgsesame import importer

    policies = [_policy("domain", "regexp_replace(value, '@.*', '')")]
    attachments = [
        _attachment("domain", "support", 0),
        _attachment("domain", "fraud", 0),
    ]
    state = _masked_state(attachments, policies)
    written, notes = importer.build(state, "redshift", masking_visible=True)
    assert written["masking"]["columns"]["crm.c.email"] == {
        "roles": {
            "fraud": "domain",
            "support": "domain",
        }  # by name: a tie is one policy
    }
    assert not any("attached another way" in n for n in notes)
    loaded = spec.parse(written)
    plan = planner.make(loaded, state, masks={p.name: p for p in policies})
    assert plan.operations == []


def test_a_policy_already_in_redshifts_form_is_not_altered():
    # sesame import writes the stored expression; creating it again can give a
    # different text back, which isn't a change
    stored = "CAST(CAST('***' AS VARCHAR) AS VARCHAR(64))"
    masking = {**MASKING, "policies": {**MASKING["policies"]}}
    masking["policies"]["redact"] = {"type": "varchar(64)", "using": stored}
    policies, attachments = _converged()
    policies[0] = _policy("redact", stored)
    state = _masked_state(attachments, policies)
    masks = {p.name: p for p in policies}
    masks["redact"] = _policy("redact", f"CAST({stored} AS VARCHAR(64))")
    assert planner.make(_masking_spec(masking), state, masks=masks).operations == []


def test_policies_outside_the_spec_are_left_alone():
    policies, attachments = _converged()
    policies.append(_policy("someone_elses"))
    policies.append(_policy("sesame_unmasked_int"))
    state = _masked_state(attachments, policies)
    plan = planner.make(_masking_spec(), state, masks={})
    assert "masking: policy someone_elses isn't in the spec; left alone" in plan.notes
    assert plan.operations == [DropMaskingPolicy(name="sesame_unmasked_int")]


FUNCTIONS = {"functions": {"app.hook(jsonb)", "app.f(integer)", "app.f(text)"}}


def _statements(plan) -> list[str]:
    """Return the plan's statements as SQL text."""
    return [op.statement().as_string(None) for op in plan.operations]


def test_a_function_name_covers_its_overloads_and_types_name_one():
    plan = planner.make(
        _spec(
            a={"type": "role", "privileges": {"functions": {"execute": ["app.f"]}}},
            b={
                "type": "role",
                "privileges": {"functions": {"execute": ["app.f( text )"]}},
            },
        ),
        _state(Role("a", False), Role("b", False), objects=FUNCTIONS),
    )
    assert _statements(plan) == [
        'GRANT EXECUTE ON ROUTINE "app"."f"(integer) TO "a"',
        'GRANT EXECUTE ON ROUTINE "app"."f"(text) TO "a"',
        'GRANT EXECUTE ON ROUTINE "app"."f"(text) TO "b"',
    ]


def test_a_function_the_spec_names_is_declared_in_full():
    # Supabase's Auth hook: only supabase_auth_admin may execute it; PUBLIC's
    # default EXECUTE and anon's (Supabase's default privileges) are drift, though
    # the spec declares neither
    s = _spec(
        supabase_auth_admin={
            "type": "builtin",
            "privileges": {"functions": {"execute": ["app.hook"]}},
        },
    )
    state = _state(
        Role("supabase_auth_admin", False),
        Role("anon", False),
        objects=FUNCTIONS,
        privileges={
            Privilege("public", "functions", "app.hook(jsonb)", "execute"),
            Privilege("anon", "functions", "app.hook(jsonb)", "execute"),
            Privilege("anon", "functions", "app.f(integer)", "execute"),  # not named
            Privilege("public", "functions", "app.f(text)", "execute"),  # not named
        },
    )
    plan = planner.make(s, state)
    assert _statements(plan) == [
        'GRANT EXECUTE ON ROUTINE "app"."hook"(jsonb) TO "supabase_auth_admin"',
        'REVOKE EXECUTE ON ROUTINE "app"."hook"(jsonb) FROM "anon"',
        'REVOKE EXECUTE ON ROUTINE "app"."hook"(jsonb) FROM PUBLIC',
    ]
    assert {op.needs for op in plan.operations[1:]} == {"revoke"}


def test_functions_on_dsql_are_refused():
    with pytest.raises(spec.SpecError, match="functions aren't planned on Aurora"):
        _spec(
            "dsql",
            a={"type": "role", "privileges": {"functions": {"execute": ["s.f"]}}},
        )


# ---------------------------------------------------------------------------
# Default privileges
# ---------------------------------------------------------------------------
def _defaults_spec(engine="postgres", rules=None):
    """Return a spec with these default privileges (by default: reader's in s)."""
    return spec.parse(
        {
            "version": 1,
            "engine": engine,
            "principals": {"reader": {"type": "role"}},
            "default_privileges": rules
            or [
                {
                    "owner": "etl",
                    "schema": "s",
                    "grantee": "reader",
                    "tables": ["select"],
                }
            ],
        }
    )


def _defaults_state(*grants, engine="pg"):
    """Return a state with etl, reader and these default privileges."""
    roles = [
        Role("etl", True, False, engine),
        Role("reader", False, False, "role" if engine != "pg" else "pg"),
    ]
    return _state(*roles, default_privileges=set(grants))


def test_a_default_privilege_is_granted_for_an_owner_outside_the_spec():
    from pgsesame.ops import GrantDefault

    plan = planner.make(_defaults_spec(), _defaults_state())
    (op,) = plan.operations
    assert isinstance(op, GrantDefault)
    assert op.statement().as_string(None) == (
        'ALTER DEFAULT PRIVILEGES FOR ROLE "etl" IN SCHEMA "s" GRANT SELECT ON TABLES TO "reader"'
    )


def test_redshift_names_the_owner_as_a_user_and_the_grantee_by_kind():
    from pgsesame.state import DefaultGrant

    plan = planner.make(
        _defaults_spec(
            "redshift", [{"owner": "etl", "grantee": "reader", "tables": ["select"]}]
        ),
        _defaults_state(
            DefaultGrant("etl", "", "tables", "reader", "insert"), engine="user"
        ),
    )
    assert [op.statement().as_string(None) for op in plan.operations] == [
        'ALTER DEFAULT PRIVILEGES FOR USER "etl" GRANT SELECT ON TABLES TO ROLE "reader"',
        'ALTER DEFAULT PRIVILEGES FOR USER "etl" REVOKE INSERT ON TABLES FROM ROLE "reader"',
    ]
    assert plan.operations[1].needs == "revoke"


def test_default_privileges_of_other_grantees_are_left_alone():
    from pgsesame.state import DefaultGrant

    other = DefaultGrant("etl", "s", "tables", "someone_else", "select")
    mine = DefaultGrant("etl", "s", "tables", "reader", "select")
    assert planner.make(_defaults_spec(), _defaults_state(other, mine)).operations == []


def test_a_default_privilege_for_a_superuser_is_left_alone():
    from pgsesame.state import DefaultGrant

    current = _defaults_state(DefaultGrant("etl", "s", "tables", "reader", "select"))
    current.roles["reader"] = Role("reader", True, superuser=True)
    plan = planner.make(_defaults_spec(), current)
    # the spec's grant exists but isn't compared for a superuser: not planned again
    assert plan.operations == []
    assert "default_privileges[0]: reader is a superuser; left alone" in plan.notes

    # and one it lacks isn't granted, as it gives a superuser nothing
    current.default_privileges = set()
    assert planner.make(_defaults_spec(), current).operations == []


def test_a_builtin_roles_default_privileges_are_managed_where_the_spec_names_it():
    from pgsesame.state import DefaultGrant

    s = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {"service_role": {"type": "builtin"}},
            "default_privileges": [
                {
                    "owner": "etl",
                    "schema": "app",
                    "grantee": "service_role",
                    "tables": ["select"],
                }
            ],
        }
    )
    state = _state(
        Role("etl", True, False, "pg"),
        Role("service_role", False, False, "pg"),
        default_privileges={
            DefaultGrant("etl", "app", "tables", "service_role", "select"),
            DefaultGrant("etl", "app", "tables", "service_role", "delete"),
            DefaultGrant("etl", "public", "tables", "service_role", "select"),
        },
    )
    # converged in app (no endless re-grant), drift there revoked; the
    # platform's entries in public are left alone
    assert [
        op.statement().as_string(None) for op in planner.make(s, state).operations
    ] == [
        'ALTER DEFAULT PRIVILEGES FOR ROLE "etl" IN SCHEMA "app" REVOKE DELETE ON TABLES FROM "service_role"'
    ]


def test_an_owner_that_does_not_exist_stops_the_plan():
    with pytest.raises(planner.PlanError, match="owner: ghost does not exist"):
        planner.make(
            _defaults_spec(
                rules=[{"owner": "ghost", "grantee": "reader", "tables": ["select"]}]
            ),
            _defaults_state(),
        )


# ---------------------------------------------------------------------------
# manage: schemas and prefixes
# ---------------------------------------------------------------------------
def _held(*privileges, roles=("reader",), extra_roles=()):
    """Return a state where ``roles`` hold ``privileges`` in collections and risk."""
    state = _state(
        *[Role(r, False) for r in (*roles, *extra_roles)],
        objects={
            "schemas": {"collections", "risk"},
            "tables": {"collections.t", "risk.t"},
        },
    )
    state.privileges = set(privileges)
    return state


def test_manage_schemas_leaves_grants_elsewhere_alone():
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "manage": {"schemas": ["collections"]},
            "principals": {
                "reader": {
                    "type": "role",
                    "privileges": {"tables": {"select": ["collections.t"]}},
                }
            },
        }
    )
    state = _held(
        Privilege("reader", "tables", "risk.t", "select"),  # outside: not drift
        Privilege("reader", "tables", "collections.t", "insert"),  # inside: drift
    )
    ops = planner.make(loaded, state).operations
    assert ops == [
        Grant(
            grantee="reader",
            object_type="tables",
            object_name="collections.t",
            privilege="select",
        ),
        Revoke(
            grantee="reader",
            object_type="tables",
            object_name="collections.t",
            privilege="insert",
        ),
    ]


def test_manage_schemas_refuses_a_grant_outside_them():
    with pytest.raises(spec.SpecError) as e:
        spec.parse(
            {
                "version": 1,
                "engine": "postgres",
                "manage": {"schemas": ["collections"]},
                "principals": {
                    "reader": {
                        "type": "role",
                        "privileges": {"tables": {"select": ["risk.t"]}},
                    }
                },
                "default_privileges": [
                    {"owner": "etl", "grantee": "reader", "tables": ["select"]}
                ],
            }
        )
    assert e.value.problems == [
        "principals.reader.privileges.tables: risk.t is outside manage.schemas (collections)",
        "default_privileges[0]: every schema is outside manage.schemas (collections)",
    ]


def test_manage_prefixes_adopts_undeclared_roles_but_never_drops_them():
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "manage": {"prefixes": ["svc_"]},
            "principals": {"reader": {"type": "role"}},
        }
    )
    state = _held(
        Privilege("svc_old", "tables", "risk.t", "select"),
        Privilege("other", "tables", "risk.t", "select"),
        roles=("reader",),
        extra_roles=("svc_old", "other"),
    )
    state.roles["svc_admin"] = Role("svc_admin", True, superuser=True)
    state.memberships = {Membership("svc_old", "reader")}
    plan = planner.make(loaded, state)
    assert [
        (type(op).__name__, getattr(op, "grantee", getattr(op, "member", "")))
        for op in plan.operations
    ] == [
        ("Revoke", "svc_old"),
        ("RemoveMember", "svc_old"),
    ]
    assert all(op.needs == "revoke" for op in plan.operations)
    assert any(
        "svc_old: not in the spec, managed by manage.prefixes" in n for n in plan.notes
    )
    assert not any("svc_admin" in n for n in plan.notes)  # a superuser: never adopted


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------
def _owners_spec(owns, privileges=None):
    """Return a spec where etl owns ``owns``, with ``privileges`` if given."""
    principals = {"etl": {"type": "role", "owns": owns}}
    if privileges:
        principals["etl"]["privileges"] = privileges
    return spec.parse({"version": 1, "engine": "postgres", "principals": principals})


def _owned_state(**owners):
    """Return a state with etl, admin and schema a; ``owners`` maps ``type:name``."""
    state = _state(
        Role("etl", False),
        Role("admin", True),
        objects={"schemas": {"a"}, "tables": {"a.t", "a.u"}},
    )
    state.owners = {
        (k.split(":", 1)[0], k.split(":", 1)[1]): v for k, v in owners.items()
    }
    return state


def test_ownership_moves_only_what_isnt_the_owners_yet():
    from pgsesame.ops import AlterOwner

    state = _owned_state(
        **{"schemas:a": "admin", "tables:a.t": "etl", "tables:a.u": "admin"}
    )
    ops = planner.make(
        _owners_spec({"schemas": ["a"], "tables": ["a.*"]}), state
    ).operations
    assert [
        op.statement().as_string(None) for op in ops if isinstance(op, AlterOwner)
    ] == [
        'ALTER SCHEMA "a" OWNER TO "etl"',
        'ALTER TABLE "a"."u" OWNER TO "etl"',
    ]


def test_an_owners_privileges_on_its_objects_are_implied():
    state = _owned_state(**{"tables:a.t": "admin", "tables:a.u": "etl"})
    # explicit grants the new owner already holds: implied once it owns the table
    state.privileges = {Privilege("etl", "tables", "a.t", "select")}
    loaded = _owners_spec({"tables": ["a.t"]}, {"tables": {"select": ["a.*"]}})
    ops = planner.make(loaded, state).operations
    assert [type(op).__name__ for op in ops] == ["AlterOwner"]  # no grant, no revoke


def test_an_object_has_one_owner_and_must_exist():
    with pytest.raises(spec.SpecError, match="a.t is owned by etl too"):
        spec.parse(
            {
                "version": 1,
                "engine": "postgres",
                "principals": {
                    "etl": {"type": "role", "owns": {"tables": ["a.t"]}},
                    "app": {"type": "role", "owns": {"tables": ["a.t"]}},
                },
            }
        )
    # a missing object is warned about and skipped, not fatal
    plan = planner.make(_owners_spec({"tables": ["a.missing"]}), _owned_state())
    assert any("owns.tables: a.missing does not exist" in w for w in plan.warnings)
    with pytest.raises(spec.SpecError, match="on Redshift only a user owns objects"):
        spec.parse(
            {
                "version": 1,
                "engine": "redshift",
                "principals": {"r": {"type": "role", "owns": {"schemas": ["a"]}}},
            }
        )


def test_a_default_privilege_pgsesame_doesnt_model_is_noted_not_revoked():
    from pgsesame.state import DefaultGrant

    # Redshift's default ACLs can carry letters past the SQL privileges (a P)
    odd = DefaultGrant("etl", "s", "tables", "reader", "p")
    plan = planner.make(_defaults_spec(), _defaults_state(odd))
    assert [type(op).__name__ for op in plan.operations] == ["GrantDefault"]
    assert any("P on tables etl creates" in n for n in plan.notes)


def test_import_leaves_out_a_default_privilege_the_spec_cant_name():
    from pgsesame import importer
    from pgsesame.state import DefaultGrant

    state = _state(
        Role("etl", True, False, "user"),
        Role("reader", False, False, "role"),
        default_privileges={
            DefaultGrant("etl", "s", "tables", "reader", "select"),
            DefaultGrant("etl", "s", "tables", "reader", "p"),
        },
    )
    written, notes = importer.build(state, "redshift")
    assert written["default_privileges"] == [
        {"owner": "etl", "schema": "s", "grantee": "reader", "tables": ["select"]}
    ]
    assert any("default P on tables from etl" in n for n in notes)
    spec.parse(written)  # what import writes, the spec accepts


def test_import_says_when_masking_couldnt_be_seen():
    from pgsesame import importer

    state = _state(Role("reader", False, False, "role"))
    written, notes = importer.build(state, "redshift", masking_visible=False)
    assert "masking" not in written
    assert any(
        "can't see masking policies" in n and "says nothing about whether" in n
        for n in notes
    )


def test_a_group_in_member_of_is_planned_as_groups_with_a_note():
    loaded = _spec(
        "redshift",
        analysts={"type": "group"},
        u={"type": "user", "member_of": ["analysts"]},
    )
    state = _state(
        Role("analysts", False, False, "group"), Role("u", True, False, "user")
    )
    plan = planner.make(loaded, state)
    statements = [str(op.statement().as_string(None)) for op in plan.operations]
    assert statements == ['ALTER GROUP "analysts" ADD USER "u"']
    assert any(
        "member_of: analysts is a group; planned as groups" in n for n in plan.notes
    )


def test_create_for_public_on_a_schema_in_scope_is_warned_about():
    from pgsesame import importer

    state = _state(
        Role("reader", False, False),
        objects={"schemas": {"public", "app"}},
        public_privileges={
            Privilege("public", "schemas", "public", "create"),
            Privilege("public", "schemas", "public", "usage"),
            Privilege("public", "schemas", "app", "create"),
        },
    )
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {"reader": {"type": "role"}},
            "manage": {"schemas": ["public"]},
        }
    )
    notes = [n for n in planner.make(loaded, state).notes if "PUBLIC" in n]
    assert notes == [
        "schema public: PUBLIC (every user) can CREATE in it, which the spec doesn't "
        "manage; REVOKE CREATE ON SCHEMA public FROM PUBLIC closes it (or declare "
        "public: {type: builtin} with its grants)"
    ]  # app is outside manage.schemas; USAGE isn't warned about
    _, notes = importer.build(state, "postgres", schemas=["public"])
    assert sum("PUBLIC (every user) can CREATE" in n for n in notes) == 1


def test_grants_the_specs_default_privileges_gave_are_not_drift():
    # a table etl made after the apply got SELECT for reader from the default
    # privilege: the next plan mustn't revoke it; the same grant on a table
    # someone else owns is still drift
    from pgsesame.ops import Revoke
    from pgsesame.state import DefaultGrant, Privilege

    state = _defaults_state(DefaultGrant("etl", "s", "tables", "reader", "select"))
    state.objects = {
        "schemas": {"s"},
        "tables": {"s.made_later", "s.by_admin"},
        "views": {"s.v_later"},
    }
    state.owners = {
        ("schemas", "s"): "admin",
        ("tables", "s.made_later"): "etl",
        ("views", "s.v_later"): "etl",
        ("tables", "s.by_admin"): "admin",
    }
    state.privileges = {
        Privilege("reader", "tables", "s.made_later", "select"),
        Privilege("reader", "views", "s.v_later", "select"),  # ON TABLES covers views
        Privilege("reader", "tables", "s.by_admin", "select"),
        Privilege("reader", "tables", "s.made_later", "insert"),  # not defaulted
    }
    plan = planner.make(_defaults_spec(), state)
    revoked = sorted(
        (op.object_name, op.privilege)
        for op in plan.operations
        if isinstance(op, Revoke)
    )
    assert revoked == [("s.by_admin", "select"), ("s.made_later", "insert")]


def test_a_grant_option_on_a_kept_privilege_is_revoked_alone():
    from pgsesame.ops import Revoke, RevokeGrantOption
    from pgsesame.state import Privilege

    loaded = _spec(
        reader={"type": "role", "privileges": {"tables": {"select": ["s.t"]}}}
    )
    held = Privilege("reader", "tables", "s.t", "select")
    extra = Privilege("reader", "tables", "s.t", "insert")
    state = _state(Role("reader", False), objects={"tables": {"s.t"}, "schemas": {"s"}})
    state.privileges = {held, extra}
    state.grant_options = {held, extra}  # INSERT goes whole, its option with it
    plan = planner.make(loaded, state)
    assert [type(op) for op in plan.operations] == [Revoke, RevokeGrantOption]
    (option,) = [op for op in plan.operations if isinstance(op, RevokeGrantOption)]
    assert option.needs == "revoke"
    assert option.statement().as_string(None) == (
        'REVOKE GRANT OPTION FOR SELECT ON TABLE "s"."t" FROM "reader"'
    )


def test_a_refused_password_is_set_again_from_its_variable(monkeypatch):
    from pgsesame.ops import AlterPassword

    monkeypatch.setenv("ALICE_PW", "Alice-pw-1")
    loaded = _spec("redshift", alice={"type": "user", "password_env": "ALICE_PW"})
    state = _state(Role("alice", True, False, "user"))
    state.passwords_refused = {"alice"}
    plan = planner.make(loaded, state)
    (op,) = plan.operations
    assert isinstance(op, AlterPassword)
    assert op.display().as_string(None) == "ALTER USER \"alice\" PASSWORD '********'"
    assert (
        op.statement().as_string(None) == "ALTER USER \"alice\" PASSWORD 'Alice-pw-1'"
    )
    assert any("doesn't sign in with ALICE_PW" in n for n in plan.notes)


def test_over_the_data_api_passwords_are_said_to_be_unchecked():
    loaded = _spec("redshift", alice={"type": "user", "password_env": "ALICE_PW"})
    state = _state(Role("alice", True, False, "user"))  # passwords_refused: None
    plan = planner.make(loaded, state)
    assert plan.operations == []
    assert any("passwords aren't checked over the Data API" in n for n in plan.notes)


def test_a_defaulted_grant_the_spec_also_names_is_not_granted_again():
    # sesame import writes both: the grant on the table and the default privilege
    from pgsesame.state import DefaultGrant, Privilege

    loaded = _defaults_spec()
    loaded = spec.parse(
        {
            **loaded.model_dump(by_alias=True, exclude_none=True),
            "principals": {
                "reader": {
                    "type": "role",
                    "privileges": {"tables": {"select": ["s.t"]}},
                }
            },
        }
    )
    state = _defaults_state(DefaultGrant("etl", "s", "tables", "reader", "select"))
    state.objects = {"schemas": {"s"}, "tables": {"s.t"}}
    state.owners = {("tables", "s.t"): "etl"}
    state.privileges = {Privilege("reader", "tables", "s.t", "select")}
    assert planner.make(loaded, state).operations == []


def test_iam_links_are_granted_and_revoked_only_when_allowed():
    from pgsesame.ops import LinkIam, UnlinkIam

    keep, new = (
        "arn:aws:iam::123456789012:role/keep",
        "arn:aws:iam::123456789012:role/new",
    )
    gone = "arn:aws:iam::123456789012:role/gone"
    loaded = _spec("dsql", app={"type": "user", "iam": [keep, new]})
    state = _state(Role("app", True))
    state.iam_links = {
        ("app", keep),
        ("app", gone),
        ("other", gone),
    }  # other: unmanaged
    plan = planner.make(loaded, state)
    link, unlink = plan.operations
    assert isinstance(link, LinkIam) and isinstance(unlink, UnlinkIam)
    assert (link.arn, unlink.arn) == (new, gone)
    assert link.statement().as_string(None) == f"AWS IAM GRANT \"app\" TO '{new}'"
    assert unlink.needs == "revoke"


def test_a_grant_on_a_missing_table_is_skipped_with_a_warning():
    loaded = _spec(
        reader={"type": "role", "privileges": {"tables": {"select": ["s.t", "s.gone"]}}}
    )
    state = _state(Role("reader", False), objects={"tables": {"s.t"}, "schemas": {"s"}})
    plan = planner.make(loaded, state)
    assert [op.object_name for op in plan.operations if hasattr(op, "object_name")] == [
        "s.t"
    ]
    assert plan.warnings == [
        "principals.reader.privileges.tables.select: s.gone does not exist; skipped"
    ]


def test_privileges_pgsesame_doesnt_manage_are_one_note_per_kind():
    # GRANT ALL on Redshift views gives INSERT, DELETE ... on each: thousands of
    # lines in a CI log, now one per privilege and object type
    from pgsesame.state import Privilege

    loaded = _spec("redshift", reader={"type": "role"})
    state = _state(Role("reader", False, False, "role"))
    views = [f"s.v{i}" for i in range(50)]
    state.objects = {"schemas": {"s"}, "views": set(views)}
    state.privileges = {
        Privilege("reader", "views", v, priv)
        for v in views
        for priv in ("insert", "delete")
    }
    plan = planner.make(loaded, state)
    unmanaged = [n for n in plan.notes if "isn't a privilege pgsesame manages" in n]
    assert unmanaged == [
        "DELETE on views isn't a privilege pgsesame manages: 50 grants left as they "
        "are (reader on s.v0, reader on s.v1, reader on s.v10, and 47 more)",
        "INSERT on views isn't a privilege pgsesame manages: 50 grants left as they "
        "are (reader on s.v0, reader on s.v1, reader on s.v10, and 47 more)",
    ]


def test_owner_changes_need_allow_owner_and_password_resets_allow_revoke(monkeypatch):
    # nothing that takes rights away runs without its flag: an owner change takes
    # from the old owner what owning gave it; a reset overrides a password
    from pgsesame.ops import AlterOwner, AlterPassword

    monkeypatch.setenv("ETL_PW", "Etl-pw-12345")
    loaded = _spec(
        "postgres",
        etl={"type": "user", "password_env": "ETL_PW", "owns": {"tables": ["s.t"]}},
    )
    state = _state(Role("etl", True), objects={"tables": {"s.t"}, "schemas": {"s"}})
    state.owners = {("tables", "s.t"): "admin"}
    state.passwords_refused = {"etl"}
    plan = planner.make(loaded, state)
    assert {type(op) for op in plan.operations} == {AlterOwner, AlterPassword}
    assert plan.allowed(allow_revoke=False, allow_drop=False) == []
    assert [type(op) for op in plan.allowed(False, False, allow_owner=True)] == [
        AlterOwner
    ]
    assert [type(op) for op in plan.allowed(True, False)] == [AlterPassword]


def test_public_is_granted_and_its_drift_revoked_only_where_the_spec_speaks():
    # PUBLIC's defaults elsewhere (CONNECT on the database, other schemas) stay
    from pgsesame.ops import Grant, Revoke
    from pgsesame.state import Privilege

    loaded = _spec(
        public={"type": "builtin", "privileges": {"tables": {"select": ["s.t"]}}}
    )
    state = _state(objects={"tables": {"s.t", "s.u", "other.x"}, "schemas": {"s"}})
    state.privileges = {
        Privilege("public", "tables", "s.u", "insert"),  # in s: drift
        Privilege("public", "tables", "other.x", "select"),  # outside: left alone
        Privilege("public", "databases", "app", "connect"),  # PostgreSQL's default
    }
    plan = planner.make(loaded, state)
    statements = [op.statement().as_string(None) for op in plan.operations]
    assert statements == [
        'GRANT SELECT ON TABLE "s"."t" TO PUBLIC',
        'REVOKE INSERT ON TABLE "s"."u" FROM PUBLIC',
    ]
    assert isinstance(plan.operations[0], Grant) and isinstance(
        plan.operations[1], Revoke
    )
    assert plan.operations[1].needs == "revoke"


def test_public_is_declared_only_as_a_builtin():
    def problems(principals, **more):
        """Return the problems the spec parser finds with these principals."""
        with pytest.raises(spec.SpecError) as err:
            spec.parse(
                {"version": 1, "engine": "postgres", "principals": principals, **more}
            )
        return err.value.problems

    assert problems({"public": {"type": "role"}})[0].startswith(
        "principals.public: PUBLIC"
    )
    assert problems({"PUBLIC": {"type": "builtin"}})[0].startswith(
        "principals.PUBLIC: PUBLIC"
    )
    assert (
        problems(
            {
                "public": {"type": "builtin"},
                "app": {"type": "user", "member_of": ["public"]},
            }
        )[0]
        == "principals.app: every user is in PUBLIC already"
    )
    assert problems(
        {"public": {"type": "builtin"}},
        default_privileges=[
            {"owner": "etl", "grantee": "public", "tables": ["select"]}
        ],
    ) == [
        "default_privileges[0].grantee: default privileges for PUBLIC aren't planned yet"
    ]


def _creator_spec(*rules, **principals):
    """Return a Redshift spec with a reader group and these default privileges."""
    return spec.parse(
        {
            "version": 1,
            "engine": "redshift",
            "principals": {"reader": {"type": "group"}, **principals},
            "default_privileges": list(rules),
        }
    )


def _creator_rule(owner, schema="ds_reporting"):
    """Return a rule: reader may select the tables ``owner`` creates in ``schema``."""
    return {"owner": owner, "schema": schema, "grantee": "reader", "tables": ["select"]}


def _creator_state(*extra_roles, **kw):
    """Return a state with the reader group, these roles and two schemas."""
    return _state(
        Role("reader", False, identity="group"),
        *extra_roles,
        objects={"schemas": {"ds_reporting", "other"}},
        **kw,
    )


def test_a_default_privilege_whose_owner_cant_create_there_is_skipped_on_redshift():
    # Redshift refuses ALTER DEFAULT PRIVILEGES FOR USER x IN SCHEMA s unless x
    # may create in s, superuser or not: one such entry failed the whole apply
    loaded = _creator_spec(_creator_rule("iiashchuk"), _creator_rule("etl"))
    current = _creator_state(
        Role("iiashchuk", True, identity="user"),
        Role("etl", True, identity="user"),
        privileges={Privilege("etl", "schemas", "ds_reporting", "create")},
    )
    plan = planner.make(loaded, current)
    assert [op.statement().as_string(None) for op in plan.operations] == [
        'ALTER DEFAULT PRIVILEGES FOR USER "etl" IN SCHEMA "ds_reporting" '
        'GRANT SELECT ON TABLES TO GROUP "reader"'
    ]
    (warning,) = plan.warnings
    assert warning.startswith(
        "default_privileges: iiashchuk can't create in ds_reporting"
    ) and warning.endswith(")")
    assert "skipped" in warning

    # a revoke there is refused too: skipped, not run
    current.default_privileges = {
        DefaultGrant("iiashchuk", "ds_reporting", "tables", "reader", "select"),
        DefaultGrant("iiashchuk", "ds_reporting", "tables", "reader", "insert"),
    }
    plan = planner.make(loaded, current)
    assert not any(
        "iiashchuk" in op.statement().as_string(None) for op in plan.operations
    )
    assert any("iiashchuk can't create in ds_reporting" in w for w in plan.warnings)


@pytest.mark.parametrize(
    "how",
    [
        "group",
        "role chain",
        "public",
        "planned grant",
        "owner",
        "superuser",
        "all schemas",
    ],
)
def test_every_way_to_create_counts_for_a_default_privileges_owner(how):
    # as Redshift Serverless takes them: CREATE directly, through a group, a role
    # (and a role's role), PUBLIC, owning the schema, a superuser; and a rule for
    # every schema isn't checked at all
    principals = {}
    privileges, memberships, owners = set(), set(), {}
    roles = [Role("x", True, identity="user")]
    rule = _creator_rule("x")
    if how == "group":
        roles.append(Role("g", False, identity="group"))
        memberships = {Membership("x", "g")}
        privileges = {Privilege("g", "schemas", "ds_reporting", "create")}
    elif how == "role chain":
        roles += [
            Role("r1", False, identity="role"),
            Role("r2", False, identity="role"),
        ]
        memberships = {Membership("x", "r2"), Membership("r2", "r1")}
        privileges = {Privilege("r1", "schemas", "ds_reporting", "create")}
    elif how == "public":
        privileges = {Privilege("public", "schemas", "ds_reporting", "create")}
    elif how == "planned grant":  # the same apply grants it first
        principals = {
            "x": {
                "type": "user",
                "privileges": {"schemas": {"create": ["ds_reporting"]}},
            }
        }
    elif how == "owner":
        owners = {("schemas", "ds_reporting"): "x"}
    elif how == "superuser":
        roles = [Role("x", True, superuser=True, identity="user")]
    else:
        rule = {"owner": "x", "grantee": "reader", "tables": ["select"]}
    loaded = _creator_spec(rule, **principals)
    current = _creator_state(
        *roles, privileges=privileges, memberships=memberships, owners=owners
    )
    plan = planner.make(loaded, current)
    assert plan.warnings == []
    assert any(type(op).__name__ == "GrantDefault" for op in plan.operations)


def test_a_schema_owner_change_still_pending_doesnt_count_for_default_privileges():
    # the change runs only with --allow-owner: without it the entry would fail
    loaded = _creator_spec(
        _creator_rule("x"), x={"type": "user", "owns": {"schemas": ["ds_reporting"]}}
    )
    current = _creator_state(
        Role("x", True, identity="user"),
        Role("etl", True, identity="user"),
        owners={("schemas", "ds_reporting"): "etl"},
    )
    plan = planner.make(loaded, current)
    assert any("x can't create in ds_reporting" in w for w in plan.warnings)


def test_postgresql_doesnt_check_a_default_privileges_owner():
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {"reader": {"type": "role"}},
            "default_privileges": [_creator_rule("x")],
        }
    )
    current = _state(
        Role("reader", False), Role("x", True), objects={"schemas": {"ds_reporting"}}
    )
    plan = planner.make(loaded, current)
    assert plan.warnings == [] and len(plan.operations) == 1


def test_default_privileges_are_revoked_before_any_privilege_is():
    from pgsesame.ops import Revoke, RevokeDefault

    assert RevokeDefault.order < Revoke.order


def _exposure_state(*privileges: Privilege, api=("anon",), **extra) -> State:
    """Return a Supabase state with public.todos, its row-level security off.

    Supabase's Data API signs in as authenticator and switches to its roles, ``api``.
    """
    return _state(
        Role("anon", False),
        Role("service_role", False, attributes=frozenset({"bypassrls"})),
        Role("authenticator", True),
        objects={"schemas": {"public"}, "tables": {"public.todos"}},
        rls={"public.todos": (False, False)},
        memberships={Membership("authenticator", role) for role in api},
        privileges=set(privileges),
        **extra,
    )


USAGE = Privilege("anon", "schemas", "public", "usage")
SELECT = Privilege("anon", "tables", "public.todos", "select")
NO_SPEC = _spec()


def test_a_table_the_data_api_reaches_without_row_level_security_is_warned_about():
    (warning,) = planner.make(NO_SPEC, _exposure_state(USAGE, SELECT)).warnings
    assert warning == (
        "public.todos: row-level security is off, and anon (SELECT) can reach it: "
        "every row is open to them"
    )
    # row-level security on (by the plan, here) closes it
    rls = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {},
            "row_level_security": {"public.todos": {}},
        }
    )
    assert planner.make(rls, _exposure_state(USAGE, SELECT)).warnings == []


def test_what_public_holds_the_data_api_holds():
    state = _exposure_state(
        USAGE, Privilege("public", "tables", "public.todos", "select")
    )
    (warning,) = planner.make(NO_SPEC, state).warnings
    assert "PUBLIC (SELECT) can reach it" in warning
    # without the Data API, a table for everyone is nobody's business here
    assert planner.make(NO_SPEC, _exposure_state(USAGE, SELECT, api=())).warnings == []


def test_reach_needs_the_schema_rls_that_applies_and_a_table_the_user_can_change():
    assert planner.make(NO_SPEC, _exposure_state(SELECT)).warnings == []
    bypasses = _exposure_state(
        Privilege("service_role", "schemas", "public", "usage"),
        Privilege("service_role", "tables", "public.todos", "select"),
        api=("service_role",),
    )
    assert planner.make(NO_SPEC, bypasses).warnings == []
    platforms = _exposure_state(USAGE, SELECT, rls_switchable=set())
    assert planner.make(NO_SPEC, platforms).warnings == []
    # nor a table in a schema the platform owns, though the user can act as the
    # table's owner (Supabase's supabase_functions, owned by supabase_admin)
    theirs = _exposure_state(
        USAGE,
        SELECT,
        acts_as={"postgres", "supabase_functions_admin"},
        owners={("schemas", "public"): "supabase_admin"},
    )
    assert planner.make(NO_SPEC, theirs).warnings == []
    ours = _exposure_state(
        USAGE,
        SELECT,
        acts_as={"postgres", "pg_database_owner"},
        owners={("schemas", "public"): "pg_database_owner"},
    )
    assert len(planner.make(NO_SPEC, ours).warnings) == 1
    # a schema another role owns (postgres's public before PostgreSQL 15), or one
    # the catalog doesn't show yet, is still the user's
    migrator = _exposure_state(
        USAGE,
        SELECT,
        acts_as={"migrator"},
        owners={("schemas", "public"): "postgres"},
    )
    assert len(planner.make(NO_SPEC, migrator).warnings) == 1
    unknown = _exposure_state(USAGE, SELECT, acts_as={"migrator"})
    assert len(planner.make(NO_SPEC, unknown).warnings) == 1


def _given(*privileges: str, owner="postgres") -> set[DefaultGrant]:
    """Return default privileges that give anon ``privileges`` on new tables."""
    return {DefaultGrant(owner, "public", "tables", "anon", p) for p in privileges}


def test_default_privileges_that_give_the_data_api_new_tables_are_warned_about():
    state = _exposure_state(USAGE, default_privileges=_given("select", "insert"))
    (warning,) = planner.make(NO_SPEC, state).warnings
    assert warning == (
        "each table postgres creates in public is given to anon (INSERT, SELECT) by "
        "default privileges: its rows are open to them until its row-level security "
        "is turned on"
    )
    # another's defaults (Supabase's supabase_admin) aren't the user's to change
    theirs = _exposure_state(
        USAGE,
        default_privileges=_given("select", owner="supabase_admin"),
        acts_as={"postgres"},
    )
    assert planner.make(NO_SPEC, theirs).warnings == []
    # nor are the defaults in a schema the platform owns (Supabase's storage)
    platforms = _exposure_state(
        USAGE,
        default_privileges=_given("select"),
        acts_as={"postgres"},
        owners={("schemas", "public"): "supabase_admin"},
    )
    assert planner.make(NO_SPEC, platforms).warnings == []
    ours = _exposure_state(
        USAGE,
        default_privileges=_given("select"),
        acts_as={"postgres", "pg_database_owner"},
        owners={("schemas", "public"): "pg_database_owner"},
    )
    assert len(planner.make(NO_SPEC, ours).warnings) == 1
    # nor is a schema anon can't use any of its business
    assert (
        planner.make(
            NO_SPEC, _exposure_state(default_privileges=_given("select"))
        ).warnings
        == []
    )


def test_revoking_the_default_privileges_closes_it():
    loaded = spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {
                "anon": {
                    "type": "builtin",
                    "privileges": {"schemas": {"usage": ["public"]}},
                }
            },
            "default_privileges": [],
        }
    )
    state = _exposure_state(USAGE, default_privileges=_given("select"))
    plan = planner.make(loaded, state)
    assert any("REVOKE SELECT ON TABLES FROM" in s for s in _statements(plan)), (
        _statements(plan)
    )
    assert plan.warnings == []


def test_a_view_that_runs_with_its_owners_rights_is_warned_about():
    state = _exposure_state(
        USAGE,
        Privilege("anon", "views", "public.open_todos", "select"),
        definer_views={"public.open_todos"},
    )
    (warning,) = planner.make(NO_SPEC, state).warnings
    assert warning.startswith(
        "public.open_todos: anon (SELECT) can reach this view, which runs with its "
        "owner's rights"
    )


def _publication_spec(*tables):
    """Return a spec where supabase_realtime publishes these tables."""
    return spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {},
            "publications": {"supabase_realtime": {"tables": list(tables)}},
        }
    )


def _publication_state(owner="postgres", all_tables=False, **extra) -> State:
    """Return a state with three app tables; supabase_realtime has app.users."""
    return _state(
        objects={"tables": {"app.posts", "app.drafts", "app.users"}},
        publications={"supabase_realtime": (owner, all_tables)},
        publication_tables={("supabase_realtime", "app.users")},
        **extra,
    )


def test_a_publication_sends_the_tables_the_spec_lists():
    plan = planner.make(_publication_spec("app.posts"), _publication_state())
    assert _statements(plan) == [
        'ALTER PUBLICATION "supabase_realtime" DROP TABLE "app"."users"',
        'ALTER PUBLICATION "supabase_realtime" ADD TABLE "app"."posts"',
    ]
    assert plan.operations[0].needs == "revoke"
    every = planner.make(_publication_spec("app.*"), _publication_state())
    assert len(every.operations) == 2  # drafts and posts added, users kept


def test_a_publication_another_role_owns_or_for_all_tables_is_not_changed():
    plan = planner.make(
        _publication_spec("app.posts"),
        _publication_state(owner="supabase_admin", acts_as={"postgres"}),
    )
    assert plan.operations == []
    assert plan.warnings[0].startswith(
        "publications.supabase_realtime: owned by supabase_admin"
    )
    with pytest.raises(planner.PlanError, match="FOR ALL TABLES"):
        planner.make(
            _publication_spec("app.posts"), _publication_state(all_tables=True)
        )
    with pytest.raises(spec.SpecError, match="publications: PostgreSQL's"):
        spec.parse(
            {
                "version": 1,
                "engine": "redshift",
                "principals": {},
                "publications": {"p": {"tables": ["a.b"]}},
            }
        )


def test_aurora_dsql_is_read_without_what_only_postgresql_plans():
    # the catalog Aurora DSQL may not have: only PostgreSQL's plans read it
    from typing import cast

    from pgsesame import dsql, postgres
    from pgsesame.db import Connection

    class Recorder:
        """A connection that records each query and finds no rows."""

        database = "postgres"

        def __init__(self):
            """Start with no queries run."""
            self.queries = []

        def rows(self, query):
            """Record the query; return no rows."""
            self.queries.append(query)
            return []

    full_only = {
        postgres.ACTS_AS,
        postgres.ROLE_ATTRIBUTES,
        postgres.SETS_ATTRIBUTES,
        postgres.DEFINER_VIEWS,
        postgres.FUNCTIONS,
        postgres.FUNCTION_OWNERS,
        postgres.FUNCTION_PRIVILEGES,
        postgres.PUBLICATIONS,
        postgres.PUBLICATION_TABLES,
        postgres.RLS_SWITCHABLE,
    }
    on_dsql = Recorder()
    state = dsql.read(cast(Connection, on_dsql))
    assert full_only.isdisjoint(on_dsql.queries)
    assert (state.acts_as, state.rls_switchable, state.sets_attributes) == (
        None,
        None,
        None,
    )  # no limit known
    on_postgres = Recorder()
    postgres.read(cast(Connection, on_postgres))
    assert full_only <= set(on_postgres.queries)


def test_role_attributes_are_what_the_spec_says_once_it_says_them():
    created = planner.make(
        _spec(migrator={"type": "user", "attributes": ["createrole", "createdb"]}),
        _state(),
    )
    assert _statements(created)[1:] == [
        'ALTER ROLE "migrator" CREATEDB',
        'ALTER ROLE "migrator" CREATEROLE',
    ]
    holder = Role("migrator", True, attributes=frozenset({"createdb", "replication"}))
    changed = planner.make(
        _spec(migrator={"type": "user", "attributes": ["createdb", "createrole"]}),
        _state(holder),
    )
    assert _statements(changed) == [
        'ALTER ROLE "migrator" CREATEROLE',
        'ALTER ROLE "migrator" NOREPLICATION',
    ]
    assert [op.needs for op in changed.operations] == [None, "revoke"]
    # no attributes key: whatever the role has is left alone
    assert (
        planner.make(_spec(migrator={"type": "user"}), _state(holder)).operations == []
    )


def test_an_attribute_the_connected_user_cant_set_is_noted_not_attempted():
    holder = Role("migrator", True)
    plan = planner.make(
        _spec(migrator={"type": "user", "attributes": ["createdb", "replication"]}),
        _state(holder, sets_attributes={"createdb", "createrole"}),
    )
    assert _statements(plan) == ['ALTER ROLE "migrator" CREATEDB']
    assert any("can't change its REPLICATION" in note for note in plan.notes)


def test_role_attributes_are_postgresqls_and_not_a_builtins():
    with pytest.raises(spec.SpecError) as err:
        _spec("redshift", etl={"type": "user", "attributes": ["createdb"]})
    assert "planned on PostgreSQL only" in err.value.problems[0]
    with pytest.raises(spec.SpecError, match="referred to, not managed"):
        _spec(anon={"type": "builtin", "attributes": ["createdb"]})


def test_redshift_system_permissions_once_a_role_lists_them():
    auditor = Role("auditor", False, identity="role")
    s = _spec(
        "redshift",
        auditor={"type": "role", "system": ["access system table", "create user"]},
    )
    state = _state(
        auditor,
        system_privileges={("auditor", "create user"), ("auditor", "drop user")},
    )
    plan = planner.make(s, state)
    assert _statements(plan) == [
        'GRANT ACCESS SYSTEM TABLE TO ROLE "auditor"',
        'REVOKE DROP USER FROM ROLE "auditor"',
    ]
    assert [op.needs for op in plan.operations] == [None, "revoke"]
    # not listed: left as they are; an older catalog can't say
    assert (
        planner.make(_spec("redshift", auditor={"type": "role"}), state).operations
        == []
    )
    with pytest.raises(planner.PlanError, match="no svv_system_privileges"):
        planner.make(s, _state(auditor, system_privileges=None))


def test_system_permissions_are_words_for_redshift_roles():
    with pytest.raises(spec.SpecError) as err:
        _spec("redshift", etl={"type": "user", "system": ["create user"]})
    assert err.value.problems == [
        "principals.etl.system: Redshift grants system permissions to roles only"
    ]
    with pytest.raises(spec.SpecError, match="should match pattern"):
        _spec("redshift", odd={"type": "role", "system": ["create user; drop table t"]})


def _superusers(current_user="admin") -> State:
    """Return a state with four superusers, one the bootstrap user, and dba."""
    return _state(
        Role("admin", True, superuser=True),
        Role("intern", True, superuser=True),
        Role("rdsadmin", True, superuser=True),
        Role("boot", True, superuser=True),
        Role("dba", True),
        current_user=current_user,
        bootstrap="boot",
    )


def _listing(*names):
    """Return a spec where manage.superusers lists these names."""
    return spec.parse(
        {
            "version": 1,
            "engine": "postgres",
            "principals": {},
            "manage": {"superusers": list(names)},
        }
    )


def test_superusers_are_who_manage_superusers_lists():
    plan = planner.make(_listing("admin", "dba"), _superusers())
    assert _statements(plan) == [
        'ALTER ROLE "intern" NOSUPERUSER',
        'ALTER ROLE "dba" SUPERUSER',
    ]
    assert {op.needs for op in plan.operations} == {"superuser"}
    assert plan.warnings == [
        "intern is a superuser, which manage.superusers doesn't list"
    ]
    assert plan.allowed(True, True, True) == []  # --allow-revoke and the rest: no
    # the platform's (rdsadmin) and the bootstrap one are never in question
    assert "rdsadmin" not in " ".join(plan.warnings + plan.notes)
    # not given: superusers aren't compared
    assert planner.make(_spec(), _superusers()).operations == []


def test_the_connected_user_stays_a_superuser_and_others_only_audit():
    plan = planner.make(_listing("intern"), _superusers())
    assert _statements(plan) == []
    assert plan.warnings == [
        "admin is a superuser, which manage.superusers doesn't list; it's the "
        "connected user, so it stays one"
    ]
    # an admin that isn't a superuser (RDS, Supabase): warned, not attempted
    audit = planner.make(_listing("admin"), _superusers(current_user="dba"))
    assert audit.operations == []
    assert audit.warnings == [
        "intern is a superuser, which manage.superusers doesn't list"
    ]
    assert "this plan is an audit" in audit.notes[-1]


def test_a_redshift_superuser_needs_a_password():
    with pytest.raises(spec.SpecError, match="refuses a superuser without a password"):
        spec.parse(
            {
                "version": 1,
                "engine": "redshift",
                "principals": {"etl": {"type": "user", "password": "disabled"}},
                "manage": {"superusers": ["etl"]},
            }
        )


def test_redshift_superusers_are_createuser():
    state = _state(
        Role("admin", True, True, "user"),
        Role("etl", True, True, "user"),
        current_user="admin",
    )
    plan = planner.make(
        spec.parse(
            {
                "version": 1,
                "engine": "redshift",
                "principals": {},
                "manage": {"superusers": ["admin"]},
            }
        ),
        state,
    )
    assert _statements(plan) == ['ALTER USER "etl" NOCREATEUSER']


def test_making_a_redshift_superuser_notes_it_needs_a_password(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("DBA_PW", "secret")
    state = _state(
        Role("admin", True, True, "user"),
        Role("IAM:etl", True, False, "user"),
        Role("dba", True, False, "user"),
        current_user="admin",
    )
    listing = {
        "version": 1,
        "engine": "redshift",
        "principals": {"dba": {"type": "user", "password_env": "DBA_PW"}},
        "manage": {"superusers": ["admin", "IAM:etl", "dba"]},
    }
    plan = planner.make(spec.parse(listing), state)
    assert _statements(plan) == [
        'ALTER USER "IAM:etl" CREATEUSER',
        'ALTER USER "dba" CREATEUSER',
    ]
    # Redshift doesn't show whose password is disabled: said where it may be
    note = (
        ": Redshift refuses a superuser without a password; if its password is "
        "disabled (an IAM user's), give it a password_env that is set, or apply "
        "fails and changes nothing"
    )
    assert [n for n in plan.notes if "refuses a superuser" in n] == ["IAM:etl" + note]
    # a password_env that isn't set gives no password either
    monkeypatch.delenv("DBA_PW")
    plan = planner.make(spec.parse(listing), state)
    assert [n for n in plan.notes if "refuses a superuser" in n] == [
        "IAM:etl" + note,
        "dba" + note,
    ]

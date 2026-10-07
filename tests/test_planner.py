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
    Membership,
    MaskPolicy,
    Privilege,
    Role,
    State,
)


def _spec(engine="postgres", **principals):
    return spec.parse({"version": 1, "engine": engine, "principals": principals})


def _state(*roles: Role, objects=None, **extra) -> State:
    state = State(roles={r.name: r for r in roles}, objects=objects or {}, **extra)
    return state


def test_parts_not_planned_yet_are_noted_not_dropped_silently():
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
        "fn: privileges on functions are planned from a later milestone" in plan.notes
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
        "r holds RULE on s.t, which pgsesame doesn't manage; left as it is"
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


def test_a_builtin_role_takes_only_privileges():
    with pytest.raises(spec.SpecError) as err:
        _spec(platform={"type": "builtin", "login": True, "member_of": []})
    assert err.value.problems[0].startswith(
        "principals.platform: a built-in role is referred to, not managed"
    )


def _rls_spec(**policy):
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
    roles = [Role(r, False, False, "role") for r in ("pii", "support", "fraud")]
    return _state(
        *roles,
        column_types={"crm.c.email": "character varying(64)"},
        attachments=set(attachments),
        mask_policies={p.name: p for p in policies},
    )


def _attachment(policy, grantee, priority, gtype="role"):
    return Attachment(policy, "crm.c", ("email",), ("email",), grantee, gtype, priority)


def _policy(name, expression="x", type_name="character varying(64)"):
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


def test_a_moved_priority_is_a_reattach_not_a_revoke():
    policies, attachments = _converged()
    attachments[2] = _attachment("redact", "fraud", 40)
    state = _masked_state(attachments, policies)
    ops = planner.make(_masking_spec(), state, masks={}).operations
    assert [type(op) for op in ops] == [ReattachMaskingPolicy, AttachMaskingPolicy]
    detach, attach = ops
    assert detach.needs is None
    assert isinstance(attach, AttachMaskingPolicy) and attach.priority == 30


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


def test_policies_outside_the_spec_are_left_alone():
    policies, attachments = _converged()
    policies.append(_policy("someone_elses"))
    policies.append(_policy("sesame_unmasked_int"))
    state = _masked_state(attachments, policies)
    plan = planner.make(_masking_spec(), state, masks={})
    assert "masking: policy someone_elses isn't in the spec; left alone" in plan.notes
    assert plan.operations == [DropMaskingPolicy(name="sesame_unmasked_int")]


# ---------------------------------------------------------------------------
# Default privileges
# ---------------------------------------------------------------------------
def _defaults_spec(engine="postgres", rules=None):
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
    principals = {"etl": {"type": "role", "owns": owns}}
    if privileges:
        principals["etl"]["privileges"] = privileges
    return spec.parse({"version": 1, "engine": "postgres", "principals": principals})


def _owned_state(**owners):
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
    with pytest.raises(
        planner.PlanError, match="owns.tables: a.missing does not exist"
    ):
        planner.make(_owners_spec({"tables": ["a.missing"]}), _owned_state())
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

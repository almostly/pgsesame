"""The planner on hand-built states (no database)."""

import pytest

from pgsesame import planner, spec
from pgsesame.ops import CreateRole, Grant, RemoveMember
from pgsesame.state import Membership, Privilege, Role, State


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
    plan = planner.make(loaded, _state())
    assert "etl: ownership is planned from a later milestone" in plan.notes
    assert (
        "fn: privileges on functions are planned from a later milestone" in plan.notes
    )
    assert "default privileges are planned from a later milestone" in plan.notes
    assert all(isinstance(op, CreateRole) for op in plan.operations)  # nothing else


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

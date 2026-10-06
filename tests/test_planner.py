"""The planner on hand-built states (no database)."""

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

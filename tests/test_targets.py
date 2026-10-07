"""Saved targets: sesame login, targets, use, logout, and --target.

The keychain is an in-memory stand-in (the real one is never touched) and the
config directory a temporary one. The login tests connect to the PostgreSQL in
``PGSESAME_TEST_DSN`` and skip without it.
"""

import os

import keyring
import pytest
from keyring.backend import KeyringBackend
from psycopg.conninfo import conninfo_to_dict
from pydantic import SecretStr
from typer.testing import CliRunner

from pgsesame import targets
from pgsesame.cli import app


class MemoryKeyring(KeyringBackend):
    """A keychain that lives for one test."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.items.get((service, username))

    def set_password(self, service, username, password):
        self.items[(service, username)] = password

    def delete_password(self, service, username):
        self.items.pop((service, username), None)


@pytest.fixture
def keychain(tmp_path, monkeypatch):
    monkeypatch.setenv("SESAME_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.delenv("SESAME_TARGET", raising=False)
    memory = MemoryKeyring()
    previous = keyring.get_keyring()
    keyring.set_keyring(memory)
    yield memory
    keyring.set_keyring(previous)


def _sesame(*args, input=None, env=None):
    result = CliRunner().invoke(
        app, list(args), input=input, env={"NO_COLOR": "1", **(env or {})}
    )
    return result.exit_code, result.stdout + result.stderr


def test_a_password_goes_to_the_keychain_never_the_file(keychain):
    target = targets.Target(host="db.example", user="admin", database="app")
    targets.save("prod", target, SecretStr("s3cret-pw"), make_default=False)
    text = (targets.config_dir() / "targets.toml").read_text()
    assert "s3cret-pw" not in text and 'host = "db.example"' in text
    assert keychain.items[("pgsesame", "prod")] == "s3cret-pw"
    assert targets.default_name() == "prod"  # the first target becomes the default
    assert targets.get("prod").has_password

    targets.save("staging", target, None, make_default=False)
    assert targets.default_name() == "prod"
    targets.use("staging")
    assert targets.default_name() == "staging"

    targets.remove("prod")
    assert ("pgsesame", "prod") not in keychain.items
    with pytest.raises(targets.TargetError, match="saved: staging"):
        targets.get("prod")


def test_a_machine_without_a_keychain_keeps_no_password(keychain, monkeypatch):
    from keyring.backends.fail import Keyring as NoKeyring

    keyring.set_keyring(NoKeyring())
    with pytest.raises(targets.TargetError, match="no keychain"):
        targets.save("prod", targets.Target(host="h", user="u"), SecretStr("pw"), False)
    assert not (targets.config_dir() / "targets.toml").exists()


LOCAL = os.environ.get("PGSESAME_TEST_DSN", "")
needs_postgres = pytest.mark.skipif(not LOCAL, reason="set PGSESAME_TEST_DSN")


def _login_args(name="local"):
    parts = conninfo_to_dict(LOCAL)
    return [
        "login",
        name,
        "--host",
        str(parts.get("host", "localhost")),
        "--port",
        str(parts.get("port", 5432)),
        "--user",
        str(parts["user"]),
        "--database",
        str(parts.get("dbname", "postgres")),
        "--password-stdin",
    ], str(parts.get("password", ""))


@needs_postgres
def test_login_then_plan_by_name(keychain, tmp_path):
    args, password = _login_args()
    code, out = _sesame(*args, input=password + "\n")
    assert code == 0, out
    assert (
        "✓ connected as" in out and "saved local; password kept in the keychain" in out
    )
    assert password not in (targets.config_dir() / "targets.toml").read_text()

    code, out = _sesame("targets")
    assert code == 0 and "* local  postgres" in out, out

    spec = tmp_path / "spec.yaml"
    spec.write_text("version: 1\nengine: postgres\nprincipals: {}\n")
    for extra, env in (
        ([], None),
        (["--target", "local"], None),
        ([], {"SESAME_TARGET": "local"}),
    ):
        code, out = _sesame("plan", str(spec), *extra, env=env)
        assert code == 0, out
        assert "plan · local (" in out  # the header names the target

    code, out = _sesame("logout", "local")
    assert code == 0 and ("pgsesame", "local") not in keychain.items, out


@needs_postgres
def test_a_failed_login_saves_nothing(keychain):
    args, _ = _login_args("broken")
    code, out = _sesame(*args, input="not-the-password\n")
    assert code == 1 and "can't connect" in out and "nothing saved" in out, out
    assert targets.all_targets() == {}
    assert keychain.items == {}


def test_plan_names_an_unknown_target(keychain, tmp_path):
    spec = tmp_path / "spec.yaml"
    spec.write_text("version: 1\nengine: postgres\nprincipals: {}\n")
    code, out = _sesame("plan", str(spec), "--target", "nope")
    assert code == 1 and "no target named 'nope'" in out, out

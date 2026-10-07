"""Saved targets: where sesame connects, by name (``sesame login``).

A target is a database and the way to reach it: a PostgreSQL or Redshift server
with a password, Redshift through IAM credentials, or through the Data API. Its
settings live in ``targets.toml`` in pgsesame's config directory (``SESAME_CONFIG_DIR``,
else ``$XDG_CONFIG_HOME/pgsesame``, else ``~/.config/pgsesame``) and hold no
secret. A password goes to the operating system's keychain (macOS Keychain,
Windows Credential Manager, the Secret Service on Linux) under the service
``pgsesame`` and the target's name; IAM and Data API targets have none to keep.

The file names a default target (``sesame use``), which plan and apply use when
no other connection is given.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Literal

import tomli_w
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

KEYCHAIN_SERVICE = "pgsesame"
TargetName = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
]


class TargetError(Exception):
    """A target that doesn't exist, or a password that can't be kept."""


class Target(BaseModel):
    """How to reach one database."""

    model_config = ConfigDict(extra="forbid")

    engine: Literal["postgres", "redshift"] = "postgres"
    method: Literal["password", "iam", "data-api"] = "password"
    # password: a server
    host: str | None = None
    port: int = 5432
    database: str = "postgres"
    user: str | None = None
    sslmode: str = "prefer"
    # iam / data-api: Redshift
    cluster: str | None = None
    workgroup: str | None = None
    secret_arn: str | None = None
    db_user: str | None = None
    region: str | None = None
    has_password: bool = Field(False, description="A password is in the keychain")

    def describe(self) -> str:
        """Return where the target goes, the way the plan header shows it."""
        if self.method == "password":
            return f"{self.user}@{self.host}:{self.port}/{self.database}"
        place = (
            f"workgroup {self.workgroup}"
            if self.workgroup
            else f"cluster {self.cluster}"
        )
        return f"{self.method} {place}/{self.database}"


def config_dir() -> Path:
    """Return pgsesame's config directory."""
    if os.environ.get("SESAME_CONFIG_DIR"):
        return Path(os.environ["SESAME_CONFIG_DIR"])
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "pgsesame"


def _path() -> Path:
    return config_dir() / "targets.toml"


def _read() -> dict:
    path = _path()
    if not path.exists():
        return {"targets": {}}
    data = tomllib.loads(path.read_text())
    data.setdefault("targets", {})
    return data


def _write(data: dict) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        "# pgsesame's saved targets (sesame login). No secrets here: passwords are in\n"
        "# the operating system's keychain.\n" + tomli_w.dumps(data)
    )
    tmp.replace(path)


def all_targets() -> dict[str, Target]:
    """Return every saved target by name."""
    return {
        name: Target.model_validate(body) for name, body in _read()["targets"].items()
    }


def default_name() -> str | None:
    """Return the default target's name, if one is set."""
    return _read().get("default")


def get(name: str) -> Target:
    """Return a saved target, or raise TargetError naming the saved ones."""
    targets = all_targets()
    if name not in targets:
        known = ", ".join(sorted(targets)) or "none yet"
        raise TargetError(
            f"no target named {name!r} (saved: {known}); see sesame login"
        )
    return targets[name]


def save(
    name: str, target: Target, password: SecretStr | None, make_default: bool
) -> None:
    """Save a target, its password in the keychain; never the password in the file."""
    if password is not None:
        _keychain_set(name, password.get_secret_value())
    data = _read()
    data["targets"][name] = target.model_copy(
        update={"has_password": password is not None}
    ).model_dump(exclude_none=True)
    if make_default or not data.get("default"):
        data["default"] = name
    _write(data)


def remove(name: str) -> None:
    """Forget a target and its keychain entry."""
    data = _read()
    if name not in data["targets"]:
        raise TargetError(f"no target named {name!r}")
    del data["targets"][name]
    if data.get("default") == name:
        data.pop("default")
    _write(data)
    try:
        import keyring

        keyring.delete_password(KEYCHAIN_SERVICE, name)
    except Exception:  # nothing stored, or no keychain: nothing to forget
        pass


def use(name: str) -> None:
    """Make a saved target the default."""
    get(name)
    data = _read()
    data["default"] = name
    _write(data)


def password(name: str) -> SecretStr | None:
    """Return a target's password from the keychain, if one is stored."""
    try:
        import keyring

        value = keyring.get_password(KEYCHAIN_SERVICE, name)
    except Exception as e:
        raise TargetError(f"can't read the keychain: {e}") from None
    return SecretStr(value) if value is not None else None


def _keychain_set(name: str, value: str) -> None:
    try:
        import keyring
        from keyring.backends.fail import Keyring as NoKeyring

        if isinstance(keyring.get_keyring(), NoKeyring):
            raise TargetError(
                "this machine has no keychain to keep the password in; set SESAME_DSN "
                "or the PG* variables instead (a password is never written to a file)"
            )
        keyring.set_password(KEYCHAIN_SERVICE, name, value)
    except TargetError:
        raise
    except Exception as e:
        raise TargetError(f"can't store the password in the keychain: {e}") from None

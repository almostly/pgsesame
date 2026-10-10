"""Targets: where sesame connects, by name.

A target is a database and the way to reach it: a PostgreSQL or Redshift server
with a password, Redshift through IAM credentials, or through the Data API. Its
settings hold no secret. They live in one of two places, nearest first:

* the project's ``sesame.toml``, or ``[tool.sesame]`` in ``pyproject.toml``
  (found by walking up from the current directory to the repository root), to be
  committed and shared; ``sesame login --project`` writes there;
* your own ``targets.toml`` in pgsesame's config directory (``SESAME_CONFIG_DIR``,
  else ``$XDG_CONFIG_HOME/pgsesame``, else ``~/.config/pgsesame``), which
  ``sesame login`` writes.

A project target of the same name wins over your own. The default target is the
one ``sesame use`` chose, else the project's ``default``.

A password is never in either file. It comes from, in order: the environment
variable the target names (``password_env``, so ``.env`` loaded by uv or direnv,
or a CI secret, supplies it), or the operating system's keychain (macOS Keychain,
Windows Credential Manager, the Secret Service on Linux) under the service
``pgsesame`` and the target's name. IAM and Data API targets have none.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

import tomli_w
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

KEYCHAIN_SERVICE = "pgsesame"
EnvVar = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]


class TargetError(Exception):
    """A target that doesn't exist, or a password that can't be had or kept."""


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
    password_env: EnvVar | None = Field(
        None,
        description="Environment variable with the password (wins over the keychain)",
    )
    # iam / data-api: an RDS instance or Aurora cluster, or Redshift's
    rds: str | None = None
    cluster: str | None = None
    workgroup: str | None = None
    secret_arn: str | None = None
    db_user: str | None = None
    region: str | None = None
    profile: str | None = None  # AWS profile for IAM and the Data APIs
    has_password: bool = Field(False, description="A password is in the keychain")

    def describe(self) -> str:
        """Return where the target goes, the way the plan header shows it."""
        if self.method == "password":
            return f"{self.user}@{self.host}:{self.port}/{self.database}"
        if self.rds:
            return f"{self.method} rds {self.rds}/{self.database}"
        place = (
            f"workgroup {self.workgroup}"
            if self.workgroup
            else f"cluster {self.cluster}"
        )
        return f"{self.method} {place}/{self.database}"

    def password_source(self) -> str:
        """Return where the password comes from, for the header and sesame targets."""
        if self.password_env:
            return f"password from ${self.password_env}"
        if self.has_password:
            return "password from the keychain"
        return "no password" if self.method == "password" else self.method


# ---------------------------------------------------------------------------
# Where targets live
# ---------------------------------------------------------------------------
def config_dir() -> Path:
    """Return pgsesame's config directory, for your own targets."""
    if os.environ.get("SESAME_CONFIG_DIR"):
        return Path(os.environ["SESAME_CONFIG_DIR"])
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "pgsesame"


def _personal_path() -> Path:
    """Return where the personal targets file lives."""
    return config_dir() / "targets.toml"


def project_file(start: Path | None = None) -> Path | None:
    """Return the project's sesame.toml, or a pyproject.toml with [tool.sesame].

    Looks in the current directory and its parents, up to the repository root
    (the directory with .git) or the filesystem's root.
    """
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / "sesame.toml"
        if candidate.is_file():
            return candidate
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file() and "sesame" in tomllib.loads(pyproject.read_text()).get(
            "tool", {}
        ):
            return pyproject
        if (directory / ".git").exists():
            return None
    return None


def _load(path: Path) -> dict[str, Any]:
    """Return a targets file's contents (pyproject.toml's [tool.sesame])."""
    data = tomllib.loads(path.read_text())
    if path.name == "pyproject.toml":
        data = data.get("tool", {}).get("sesame", {})
    data.setdefault("targets", {})
    return data


def _personal() -> dict[str, Any]:
    """Return the personal targets, empty when there's no file yet."""
    path = _personal_path()
    return _load(path) if path.exists() else {"targets": {}}


def _project() -> tuple[Path | None, dict[str, Any]]:
    """Return the project's targets file and its contents, if there is one."""
    path = project_file()
    return (path, _load(path)) if path else (None, {"targets": {}})


def _write_personal(data: dict[str, Any]) -> None:
    """Write the personal targets file, replacing it in one step."""
    path = _personal_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        "# Your pgsesame targets (sesame login). No secrets here: passwords are in\n"
        "# the operating system's keychain or the environment.\n" + tomli_w.dumps(data)
    )
    tmp.replace(path)


def _write_project(path: Path, data: dict[str, Any]) -> None:
    """Write the project's targets file; pyproject.toml is edited by hand."""
    if path.name == "pyproject.toml":
        raise TargetError(
            "the project's targets are in pyproject.toml [tool.sesame]: edit it there"
        )
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        "# pgsesame targets for this project (sesame login --project). Committed: no\n"
        "# secrets here, passwords come from the environment (password_env).\n"
        + tomli_w.dumps(data)
    )
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def all_targets() -> dict[str, Target]:
    """Return every target by name, a project's over your own of the same name."""
    _, project = _project()
    merged = {name: body for name, body in _personal()["targets"].items()}
    merged.update(project["targets"])
    return {name: Target.model_validate(body) for name, body in merged.items()}


def origin(name: str) -> str:
    """Return where a target is defined: the project file's name, or 'personal'."""
    path, project = _project()
    if path is not None and name in project["targets"]:
        return path.name
    return "personal"


def default_name() -> str | None:
    """Return the default target: your sesame use, else the project's default."""
    _, project = _project()
    return _personal().get("default") or project.get("default")


def get(name: str) -> Target:
    """Return a target, or raise TargetError naming the known ones."""
    found = all_targets()
    if name not in found:
        known = ", ".join(sorted(found)) or "none yet"
        raise TargetError(
            f"no target named {name!r} (known: {known}); see sesame login"
        )
    return found[name]


def password(name: str, target: Target) -> SecretStr | None:
    """Return a target's password: its environment variable, else the keychain."""
    if target.password_env:
        value = os.environ.get(target.password_env)
        if value is None:
            raise TargetError(
                f"{target.password_env} is not set (the password for {name!r}); "
                f"export it, or load .env with: uv run --env-file .env sesame ..."
            )
        return SecretStr(value)
    if not target.has_password:
        return None
    try:
        import keyring

        value = keyring.get_password(KEYCHAIN_SERVICE, name)
    except Exception as e:
        raise TargetError(f"can't read the keychain: {e}") from None
    if value is None:
        raise TargetError(
            f"the keychain has no password for {name!r}; run sesame login {name} again"
        )
    return SecretStr(value)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def save(
    name: str,
    target: Target,
    secret: SecretStr | None,
    make_default: bool,
    project: bool = False,
) -> Path:
    """Save a target; a typed password to the keychain, never to a file.

    ``project`` writes the project's sesame.toml (created next to the current
    directory when there is none), which takes no keychain password: it's for
    committing, so its password comes from ``password_env``.
    """
    stored = target.model_copy(update={"has_password": secret is not None})
    if project:
        if secret is not None:
            raise TargetError(
                "a project target is committed: give it --password-env, not a typed password"
            )
        path, data = _project()
        path = path or Path.cwd() / "sesame.toml"
        data["targets"][name] = stored.model_dump(exclude_none=True)
        if make_default or not data.get("default"):
            data["default"] = name
        _write_project(path, data)
        return path
    if secret is not None:
        _keychain_set(name, secret.get_secret_value())
    data = _personal()
    data["targets"][name] = stored.model_dump(exclude_none=True)
    if make_default or not data.get("default"):
        data["default"] = name
    _write_personal(data)
    return _personal_path()


def remove(name: str) -> None:
    """Forget one of your targets and its keychain entry."""
    if origin(name) != "personal":
        raise TargetError(
            f"{name!r} is defined in the project's {origin(name)}: edit or remove it there"
        )
    data = _personal()
    if name not in data["targets"]:
        raise TargetError(f"no target named {name!r}")
    del data["targets"][name]
    if data.get("default") == name:
        data.pop("default")
    _write_personal(data)
    try:
        import keyring

        keyring.delete_password(KEYCHAIN_SERVICE, name)
    except Exception:  # nothing stored, or no keychain: nothing to forget
        pass


def use(name: str) -> None:
    """Make a target your default (over the project's default)."""
    get(name)
    data = _personal()
    data["default"] = name
    _write_personal(data)


def _keychain_set(name: str, value: str) -> None:
    """Keep a target's password in the system keychain, or say there is none."""
    try:
        import keyring
        from keyring.backends.fail import Keyring as NoKeyring

        if isinstance(keyring.get_keyring(), NoKeyring):
            raise TargetError(
                "this machine has no keychain to keep the password in; use "
                "--password-env (or SESAME_DSN) instead: a password is never written "
                "to a file"
            )
        keyring.set_password(KEYCHAIN_SERVICE, name, value)
    except TargetError:
        raise
    except Exception as e:
        raise TargetError(f"can't store the password in the keychain: {e}") from None

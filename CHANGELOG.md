# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Commits follow `Area(<+|~|->): description`, where `+` = **Added**, `~` =
**Changed**, `-` = **Removed**. Running `cz bump` turns those commits into the
versioned entries below.

## Unreleased

### Added

- **Spec**: built-in roles (`type: builtin`): a platform's own roles (Supabase's `authenticated`, `anon`, `service_role`; RDS's `rds_iam`) can be granted to and joined, are never created or altered, and have their privileges managed only in the schemas the spec names for them
- **Postgres**: row-level security per table: enabled and forced, and its policies (command, roles, USING, WITH CHECK, permissive or restrictive); expressions compared in PostgreSQL's stored form by a rolled-back round trip; dropping a policy or disabling RLS needs `--allow-drop`
- **CLI**: `sesame login <name>` saves a target (where to connect and how), its password in the OS keychain, after connecting once to show who pgsesame is there and whether it can manage roles; `sesame targets`, `sesame use`, `sesame logout`; plan and apply take `--target`, `SESAME_TARGET`, or the default target, so no DSN is needed. CI keeps `SESAME_DSN` and the `PG*` variables
- **CLI**: a target can take its password from an environment variable (`sesame login --password-env`), for `.env` files and CI secrets; project targets in `sesame.toml` or `[tool.sesame]` in `pyproject.toml`, committed with the spec (`sesame login --project`), found up to the repository root, ahead of your own; the plan header and `sesame targets` show where each password comes from
- **Redshift**: dynamic data masking by column and role (`masking:`): what everyone sees (`mask`), roles with their own mask in priority order (`roles`), roles that see the raw value through pass-through policies of pgsesame's own (`unmasked`); expressions compared in Redshift's stored form by a rolled-back round trip; a priority move is a change, a detach needs `--allow-revoke`, replacing a policy whose type changed needs `--allow-drop`; tested on oblako's redshift-local
- **Spec**: column privileges (`columns: {select: [schema.table.column]}`): `select`, `insert`, `update` and `references` on PostgreSQL (read from column ACLs), `select` and `update` on Redshift (read from `svv_column_privileges`); drift is revoked with `--allow-revoke`
- **Tests**: on Supabase (`PGSESAME_TEST_SUPABASE_DSN`): built-in roles and an `auth.uid()` policy, read as Supabase's API does

### Changed

- **Docs**: the README's first line and the repository description promise what pgsesame does today: roles, users, groups and grants
- **Repo**: `.env` files are ignored, so local secrets are never committed or packaged

## v0.1.1 (2026-10-06)

### Added

- **Action**: a GitHub Action, `uses: almostly/pgsesame@v0.1.1`: `command: plan` posts the plan on the pull request as one comment, updated on each push, and keeps the change set; `command: apply` runs that change set (revokes with `allow-revoke: true`). Outputs `has-changes`, `to-add`, `to-change`, `to-remove`
- **Docs**: the icon, screenshots of a plan, drift and a change set, and how to run pgsesame in GitHub Actions

### Changed

- **Postgres**: `MAINTAIN` (PostgreSQL 17+) is a privilege the spec can declare; a privilege pgsesame doesn't model is noted in the plan instead of failing it
- **Plan**: privileges on `functions` are noted as not planned yet, instead of being skipped silently

## v0.1.0 (2026-10-06)

The first release.

### Added

- **CLI**: the `sesame` command (also installed as `pgsesame`, so `uvx pgsesame` works): `sesame validate`, `sesame plan` (Terraform's exit codes: 0 nothing to do, 2 changes, 1 error), `sesame apply`, `sesame show` and `sesame schema`, in pgcli's green
- **Spec**: principal-centric YAML for roles, users, Redshift groups, memberships, privileges on databases, schemas, tables, views and sequences, ownership and default privileges; parsed into pydantic models with constrained types, every problem reported with its YAML path; a JSON Schema for editors
- **Plan**: only the spec's principals are managed; `schema.*` expands to the schema's objects; revokes and membership removals are planned but applied only with `--allow-revoke`
- **Plan**: change sets: `sesame plan -o` saves the plan, `sesame apply changes.json` runs exactly it, or refuses when the database changed in a way that changes the plan, when it was planned against another database, or when its spec was edited
- **Postgres**: read through the catalog's ACLs; plan and apply in one transaction
- **Redshift**: users, groups and RBAC roles, read through Redshift's SVV views (no ACL parsing); Redshift's DDL and `GROUP` / `ROLE` grantees
- **Redshift**: connect with a password, with temporary IAM credentials (`--iam`, a cluster or a Serverless workgroup), or through the Data API (`--data-api`, one transaction per apply)
- **Release**: on PyPI, and as a container image for CI without Python: `ghcr.io/almostly/pgsesame` (amd64, arm64; tags `0.1.0`, `0.1`, `latest`)
- **Security**: passwords never go in the spec, a plan, a change set or a log: SecretStr from the environment variable the spec names; the DSN is a SecretStr

Ownership and default privileges are validated but not yet planned.

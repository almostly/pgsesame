# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Commits follow `Area(<+|~|->): description`, where `+` = **Added**, `~` =
**Changed**, `-` = **Removed**. Running `cz bump` turns those commits into the
versioned entries below.

## Unreleased

### Changed

- **Redshift**: masking priorities are compared by order, not number: where a column's attachments already rank everyone as the spec does, the plan keeps the database's numbers, so `sesame import` then `plan` is empty for masking set up in the right order; an order that differs is still corrected, and import notes only the columns the plan will change
- **Redshift**: over the Data API, masking expressions are compared too: probe policies are created, read back and dropped in the same plan (never attached); without `BatchExecuteStatement` the plan says it couldn't compare them
- **Docs**: upgrading with `uv tool install --force --refresh`, as uv can otherwise reuse a cached version

## v0.2.2 (2026-10-07)

Fixes from a first run against a production Redshift cluster over the Data API,
and masking in `sesame import`.

### Added

- **CLI**: `--region` and `--profile` on plan, apply and import (and `--profile` on `sesame login`, kept with the target); without a region anywhere, the message says where to set one
- **CLI**: `SESAME_TIMING=1` prints each catalog query's time and row count

### Changed

- **Install**: the `rds` and `aurora` extras, beside `redshift`: each brings boto3, for IAM sign-in and the Data APIs; the message without it names the extra for the path used
- **CLI**: the AWS options are grouped in `--help` under "AWS (needs pgsesame[redshift], [rds] or [aurora])"
- **Redshift**: masking's reads (who may see policies, the policies, attachments, column types) run together over the Data API
- **Redshift**: reading the catalog is faster: over the Data API the queries run at the same time, tables and columns come from the catalog rather than svv_tables and svv_columns (which also reach external schemas), and every column is read only when the spec grants on columns

### Fixed

- **Redshift**: a default privilege pgsesame doesn't model (a `P` in Redshift's default ACLs) made `sesame import` write a spec that failed its own validation, and a plan revoke it: it is now noted and left alone, as for grants
- **CLI**: text in square brackets was dropped from messages and plans (`pgsesame[redshift]` printed as `pgsesame`, `ARRAY[x]` lost its index): output now prints data as text, not markup

## v0.2.1 (2026-10-07)

Adoption: ownership and default privileges applied, and a way onto a database
that already has roles and grants (`sesame import`, `manage:`).

### Added

- **Spec**: ownership planned and applied (`owns`: `ALTER ... OWNER TO` for the objects a principal lists; databases, schemas, tables, views and sequences on PostgreSQL, schemas, tables and views on Redshift, where the owner is a user); objects the spec doesn't list keep their owner, an object has one owner, and an owner's privileges on its own objects are implied, never granted or revoked; `sesame import` writes `owns`
- **Spec**: default privileges planned and applied (`ALTER DEFAULT PRIVILEGES`, `FOR ROLE` on PostgreSQL, `FOR USER` on Redshift) for the spec's grantees; the owner needn't be declared (often the ETL or admin user); a default privilege the spec doesn't list is drift, revoked with `--allow-revoke`
- **CLI**: `sesame import` writes the spec that reproduces what a database grants today (roles, memberships, grants, column grants, default privileges; no passwords), so a first plan is empty; `--schema` and `--prefix` narrow it and become the spec's `manage:`
- **Spec**: `manage.schemas` compares grants only in the named schemas, so a team adopts pgsesame one area at a time; `manage.prefixes` also manages undeclared roles by name (their grants become drift; never dropped, never a superuser)

### Changed

- **Spec**: a Redshift principal's `groups` may name a `builtin` principal (a group the spec refers to, not manages)
- **CI**: the Redshift job runs on oblako 0.2.0's redshift-local

## v0.2.0 (2026-10-07)

Platforms' own roles and row-level security, a login instead of a DSN, Redshift
masking and column privileges, and Amazon RDS and Aurora.

### Added

- **Spec**: built-in roles (`type: builtin`): a platform's own roles (Supabase's `authenticated`, `anon`, `service_role`; RDS's `rds_iam`) can be granted to and joined, are never created or altered, and have their privileges managed only in the schemas the spec names for them
- **Postgres**: row-level security per table: enabled and forced, and its policies (command, roles, USING, WITH CHECK, permissive or restrictive); expressions compared in PostgreSQL's stored form by a rolled-back round trip; dropping a policy or disabling RLS needs `--allow-drop`
- **CLI**: `sesame login <name>` saves a target (where to connect and how), its password in the OS keychain, after connecting once to show who pgsesame is there and whether it can manage roles; `sesame targets`, `sesame use`, `sesame logout`; plan and apply take `--target`, `SESAME_TARGET`, or the default target, so no DSN is needed. CI keeps `SESAME_DSN` and the `PG*` variables
- **CLI**: a target can take its password from an environment variable (`sesame login --password-env`), for `.env` files and CI secrets; project targets in `sesame.toml` or `[tool.sesame]` in `pyproject.toml`, committed with the spec (`sesame login --project`), found up to the repository root, ahead of your own; the plan header and `sesame targets` show where each password comes from
- **Redshift**: dynamic data masking by column and role (`masking:`): what everyone sees (`mask`), roles with their own mask in priority order (`roles`), roles that see the raw value through pass-through policies of pgsesame's own (`unmasked`); expressions compared in Redshift's stored form by a rolled-back round trip; a priority move is a change, a detach needs `--allow-revoke`, replacing a policy whose type changed needs `--allow-drop`; tested on oblako's redshift-local and Redshift Serverless
- **Spec**: column privileges (`columns: {select: [schema.table.column]}`): `select`, `insert`, `update` and `references` on PostgreSQL (read from column ACLs), `select` and `update` on Redshift (read from `svv_column_privileges`); drift is revoked with `--allow-revoke`
- **RDS**: Amazon RDS and Aurora PostgreSQL by `--rds <instance or cluster>`: `--iam` signs an IAM authentication token (the admin user by default; the way into an Aurora cluster made with express configuration), `--data-api` goes through the RDS Data API with apply in one transaction; `sesame login --rds` saves either
- **Postgres**: the roles a user can't change (without ADMIN OPTION on them, PostgreSQL 16+, as an RDS admin user or Supabase's `postgres`) are noted in the plan, not attempted
- **Spec**: a row-level security policy for `public` names no other role (PostgreSQL keeps only PUBLIC, so the plan would never settle)
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

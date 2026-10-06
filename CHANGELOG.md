# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Commits follow `Area(<+|~|->): description`, where `+` = **Added**, `~` =
**Changed**, `-` = **Removed**. Running `cz bump` turns those commits into the
versioned entries below.

## Unreleased

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
- **Security**: passwords never go in the spec, a plan, a change set or a log: SecretStr from the environment variable the spec names; the DSN is a SecretStr

Ownership and default privileges are validated but not yet planned.

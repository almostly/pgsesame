# pgsesame

Declarative permission management for PostgreSQL and Amazon Redshift. Define
roles, users, grants and ownership in YAML, then plan and apply changes like
Terraform.

> **Status: early development.** `sesame validate` works; `plan` and `apply` are
> being built (see [DESIGN.md](DESIGN.md) for the milestones).

## Why

Granting access by hand leaves a trail of `GRANT` statements nobody can review.
pgsesame keeps the intended state in one file: changes go through pull requests,
`sesame plan` shows exactly which statements a change needs, and `sesame apply`
runs them. A second plan after apply is empty.

It is built on what went wrong with earlier tools (redtape for Redshift, pgbedrock
for PostgreSQL): it reads the real catalog without crashing on what it doesn't
model, issues only the difference instead of every grant on every run, and plans
revokes and drops but applies them only when you ask.

## Install

```bash
pip install pgsesame               # PostgreSQL and Redshift over a direct connection
pip install "pgsesame[redshift]"   # adds the Redshift Data API
```

## A spec

```yaml
version: 1
engine: redshift            # or postgres

principals:
  reader:
    type: role
    privileges:
      schemas:
        usage: [analytics]
      tables:
        select: [analytics.*]

  alice:
    type: user
    password_env: ALICE_PASSWORD
    member_of: [reader]
```

```bash
sesame validate permissions.yaml
sesame plan permissions.yaml       # exit code 2 when there are changes
sesame apply permissions.yaml      # revokes and drops need --allow-revoke / --allow-drop
```

Passwords never go in the spec: name an environment variable with `password_env`,
use IAM, or set `password: disabled`.

## Testing locally

The integration tests run against PostgreSQL in Docker and against
[oblako](https://github.com/almostly/oblako)'s local Redshift, so a spec can be
planned and applied in CI before it touches a real cluster.

## License

Apache-2.0

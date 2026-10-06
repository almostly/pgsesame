<p align="center">
  <img src="https://oblako-public.s3.amazonaws.com/pgsesame_icon.png" width="128" alt="pgsesame">
</p>

# pgsesame

Declarative permission management for PostgreSQL and Amazon Redshift. Define
roles, users, grants and ownership in YAML, then plan and apply changes like
Terraform.

> **Status: 0.1, alpha.** `validate`, `plan`, `apply` and change sets work for
> roles, users, groups, memberships and privileges on PostgreSQL and Redshift,
> tested against PostgreSQL 14 to 18, oblako's redshift-local and Redshift
> Serverless, on Python 3.10 to 3.13.
> Ownership (`owns`) and default privileges are validated but not yet planned; see
> the [roadmap](DESIGN.md#roadmap).

## Why

Granting access by hand leaves a trail of `GRANT` statements nobody can review.
pgsesame keeps the intended state in one file: changes go through pull requests,
`sesame plan` shows exactly which statements a change needs, and `sesame apply`
runs them. A second plan after apply is empty.

It is built on what went wrong with earlier tools (redtape for Redshift, pgbedrock
for PostgreSQL): it reads the real catalog without crashing on what it doesn't
model, issues only the difference instead of every grant on every run, and plans
revokes and drops but applies them only when you ask.

## Where it runs

PostgreSQL 14 to 18 and Amazon Redshift (provisioned or Serverless). PostgreSQL
services work through the same connection: Supabase, Google's AlloyDB, Amazon RDS
and Aurora, Cloud SQL, Neon; connect as the platform's admin role. Referring to a
platform's built-in roles (`authenticated`, `alloydbsuperuser`, ...) without
managing them, and Supabase's row-level security policies, are on the
[roadmap](DESIGN.md#roadmap).

## Install

```bash
uv tool install pgsesame               # installs the `sesame` command
uv tool install "pgsesame[redshift]"   # adds IAM credentials and the Data API for Redshift
uvx pgsesame --help                    # or try it without installing
pip install pgsesame                   # or into an environment
```

In CI without Python, use the image (amd64 and arm64):

```bash
docker run --rm -v "$PWD:/work" -e SESAME_DSN ghcr.io/almostly/pgsesame plan permissions.yaml
```

pgsesame connects the way you already do: a DSN or the standard `PG*` variables
with a password (PostgreSQL and Redshift), temporary credentials from IAM for a
Redshift cluster or Serverless workgroup, or the Redshift Data API when the
database isn't reachable over the network.

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

sesame plan permissions.yaml -o changes.json   # save the plan as a change set
sesame show changes.json                       # review it, no database needed
sesame apply changes.json                      # run exactly that, or refuse if it's stale
```

Passwords never go in the spec: name an environment variable with `password_env`,
use IAM, or set `password: disabled`.

A first plan creates the roles and grants the spec declares:

![sesame plan: the roles and grants a spec needs](https://raw.githubusercontent.com/almostly/pgsesame/main/docs/images/plan.png)

Later, two grants someone made by hand show up as drift; they are revoked only
with `--allow-revoke`:

![sesame plan: drift, planned as revokes](https://raw.githubusercontent.com/almostly/pgsesame/main/docs/images/drift.png)

A saved change set can be reviewed without a database, then applied exactly:

![sesame show: a saved change set](https://raw.githubusercontent.com/almostly/pgsesame/main/docs/images/change-set.png)

## In GitHub Actions

Review a plan on the pull request, then apply on merge exactly the change set a
reviewer approves. Keep the spec in the repository and the connection in a
secret (`SESAME_DSN`).

````yaml
# .github/workflows/permissions.yml
name: permissions

on:
  pull_request:
    paths: [permissions.yaml]
  push:
    branches: [main]
    paths: [permissions.yaml]

jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # to post the plan on the pull request
    env:
      SESAME_DSN: ${{ secrets.SESAME_DSN }}
      NO_COLOR: "1"
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5

      # exit code 2 means "changes planned": a result here, not a failure
      - name: Plan
        run: uvx pgsesame plan permissions.yaml -o changes.json > plan.txt || [ $? -eq 2 ]

      - name: Post the plan on the pull request
        if: github.event_name == 'pull_request'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          { echo '### sesame plan'; echo '```diff'; cat plan.txt; echo '```'; } > comment.md
          gh pr comment ${{ github.event.pull_request.number }} --body-file comment.md

      - uses: actions/upload-artifact@v4
        if: github.event_name == 'push'
        with:
          name: changes
          path: changes.json
          if-no-files-found: ignore  # nothing to apply

  apply:
    if: github.event_name == 'push'
    needs: plan
    runs-on: ubuntu-latest
    # a protected environment: a reviewer approves before anything runs
    environment: production
    env:
      SESAME_DSN: ${{ secrets.SESAME_DSN }}
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: changes
        continue-on-error: true  # no change set: the database already matches
      - uses: astral-sh/setup-uv@v5
      - name: Apply the reviewed change set
        run: |
          if [ -f changes.json ]; then uvx pgsesame apply changes.json; fi
````

A plan's `+`, `~` and `-` lines render as a diff in the comment. `apply`
refuses the change set if the database changed since it was planned; revokes run
only with `--allow-revoke`, so add that flag once you trust the spec to remove
access too. A new user's password comes from the variable its spec names
(`password_env`), so pass that secret to the `apply` job as well.

For Redshift with IAM instead of a stored password, sign the jobs in to AWS with
OIDC and connect through `--iam` (or `--data-api` when the runner can't reach the
cluster's network):

```yaml
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/sesame
          aws-region: us-east-1
      - run: uvx --from "pgsesame[redshift]" sesame plan permissions.yaml --iam --workgroup analytics -o changes.json || [ $? -eq 2 ]
```

Outside GitHub, the container image does the same without Python:
`docker run --rm -v "$PWD:/work" -e SESAME_DSN ghcr.io/almostly/pgsesame plan permissions.yaml`.

## Testing locally

The integration tests run against PostgreSQL in Docker and against
[oblako](https://github.com/almostly/oblako)'s local Redshift, so a spec can be
planned and applied in CI before it touches a real cluster.

## License

Apache-2.0

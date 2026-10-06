# pgsesame design

pgsesame manages database permissions from a YAML file. You declare roles, users,
groups, memberships, privileges and ownership; `sesame plan` reads what the
database currently grants, compares it with the file, and prints the SQL that
would close the difference; `sesame apply` runs it. The workflow follows Terraform:
the file is reviewed in a pull request, the plan is reviewed before anything runs,
and a second plan after apply should be empty.

It targets PostgreSQL and Amazon Redshift. They share most of the GRANT
vocabulary but differ in principals (Redshift has groups next to users and roles),
in privileges (Redshift adds ALTER, TRUNCATE, DROP and ASSUMEROLE) and in how the
catalog exposes them, so each engine has its own reader and SQL renderer behind a
common model.

## Lessons this design starts from

redtape (Redshift) and pgbedrock (PostgreSQL) both did this job and are both
unmaintained. Running redtape 0.4.2 against a production Redshift cluster showed
what an access manager has to get right:

- **Read the real catalog without crashing.** redtape's ACL parser rejects
  privilege letters it does not know (Redshift's `A` and `P`) and the extra columns
  newer Redshift functions return. pgsesame reads Redshift through its `SVV_*`
  privilege views, which spell privileges out, and treats anything it does not
  model as "unmanaged", reported but never fatal.
- **Diff, do not re-emit.** redtape re-issued every declared grant on every run.
  pgsesame compares desired and current state as sets keyed by name, so a run
  issues only the change, and a converged database plans nothing.
- **Revoke, but only when asked.** A tool that cannot revoke cannot converge; a
  tool that revokes by default is dangerous. redtape's unfiltered plan contained 46
  DROP USER/GROUP statements. pgsesame plans revokes and drops but applies them only
  with explicit flags, and never touches principals outside its scope.
- **Cover what people actually declare.** Default privileges, ownership and
  Redshift roles are first-class, not afterthoughts.

## Workflow

```
spec.yaml ──load + validate──▶ desired state ─┐
                                              ├─ diff ─▶ plan (ordered SQL) ─▶ apply
database ──read catalog──────▶ current state ─┘
```

- `sesame validate spec.yaml`: parse and check the file; no database needed.
- `sesame plan spec.yaml`: connect, read, diff, print the plan. The exit code
  follows `terraform plan -detailed-exitcode`: 0 nothing to do, 2 changes planned,
  1 error, so CI can tell "drift" from "failure".
- `sesame apply spec.yaml`: plan, then run the plan. `--plan-file` applies a
  plan saved earlier, refusing it if the database changed since it was made.

## The CLI's look

The command is `sesame`, styled after pgcli: green is the accent colour (the
header, the `user@host:db` connection line, help headings), and the plan colours
its operations the way Terraform does: green `+` for creates and grants, red `-`
for revokes and drops, yellow `~` for changes such as ownership. Colour turns off
when the output is not a terminal or `NO_COLOR` is set, so CI logs stay plain. An
interactive `sesame shell` in pgcli's style (prompt_toolkit, completion of
principal and object names) is a possible later addition, not part of the first
milestones.

## The spec

Principal-centric, so a reviewer reads one block to see everything a role can do.

```yaml
version: 1
engine: redshift            # or postgres

principals:
  etl:
    type: user
    login: true
    owns:
      schemas: [analytics]

  analyst:
    type: role
    member_of: [reader]
    privileges:
      schemas:
        usage: [analytics, marts]
      tables:
        select: [analytics.*, marts.daily_sales]

  reader:
    type: role

  alice:
    type: user
    login: true
    groups: [analysts]       # Redshift only
    member_of: [analyst]

  analysts:
    type: group              # Redshift only

default_privileges:
  - owner: etl               # objects etl creates ...
    schema: analytics        # ... in this schema ...
    grantee: analyst         # ... are readable by analyst
    tables: [select]
```

Rules:

- **Principal types**: `role` and `user` on both engines (a PostgreSQL user is a
  role that can log in); `group` on Redshift only.
- **Privileges by object type**: `databases`, `schemas`, `tables`, `views`,
  `sequences` (PostgreSQL), `functions`; each maps privilege names to object
  patterns. `schema.*` means every existing object of that type in the schema,
  expanded when the plan is made; future objects are covered by
  `default_privileges`, as in the database itself.
- **Ownership** (`owns`) is declared on the owner. Changing it plans
  `ALTER ... OWNER TO`.
- **No secrets.** Passwords never appear in the spec. A login user either gets its
  password from an environment variable named in the spec
  (`password_env: ALICE_PASSWORD`), authenticates through IAM (Redshift
  `IAM:` users), or has `password: disabled`.
- Unknown keys, unknown principals in references and engine-specific keys on the
  wrong engine are validation errors, reported with the YAML path.

## Scope: what pgsesame manages

The spec's principals are managed. Everything else in the database is **observed
but untouched**: reported in the plan as unmanaged, never altered. A spec can widen
its scope with `manage: {prefixes: [app_, svc_]}` to take over principals by name,
so a team can adopt pgsesame one area at a time. Built-in principals (`PUBLIC`
aside), superusers, the connecting user and Redshift's `rdsdb` are never managed.

## Reading the current state

**PostgreSQL**: `pg_roles` and `pg_auth_members` for principals and memberships;
`aclexplode()` over `pg_database`, `pg_namespace`, `pg_class` and `pg_proc` ACLs
for privileges; `pg_default_acl` for default privileges; object owners from the
same catalogs.

**Redshift**: `SVV_USER_INFO` and `pg_group` for users and groups,
`SVV_ROLES`, `SVV_USER_GRANTS` and `SVV_ROLE_GRANTS` for roles and role membership,
`SVV_RELATION_PRIVILEGES`, `SVV_SCHEMA_PRIVILEGES`, `SVV_DATABASE_PRIVILEGES`,
`SVV_FUNCTION_PRIVILEGES` and `SVV_DEFAULT_PRIVILEGES` for privileges. These views
name each privilege, so there is no ACL string to parse. Where a view is missing,
the reader falls back to ACL strings with a parser that keeps letters it does not
know as unmanaged privileges.

Both readers return the same model: principals, memberships, a set of
`(grantee, privilege, object)` triples, owners and default-privilege entries.

## Diff and plan

Desired and current state are compared as sets. Each difference becomes one
operation (create principal, grant, revoke, add member, change owner, ...), and
the plan orders them so every statement can succeed: create principals first,
then ownership, then grants and memberships, then revokes, then drops last.
Operations render to engine-specific SQL with identifiers quoted on both sides
(including `IAM:` user names), `PUBLIC` kept as a keyword.

Revokes and drops are always planned and shown, but marked; `apply` runs them only
with `--allow-revoke` and `--allow-drop`. Without the flags, apply runs the
additive part and reports what it skipped.

## Applying

PostgreSQL runs the plan in one transaction: all of it or none. Redshift runs it in
one transaction where its statements allow, and otherwise statement by statement,
stopping at the first error and reporting what ran. After apply, `sesame plan`
should be empty; the integration tests assert exactly that.

## Connecting

Connection settings are not part of the spec: the same spec is planned against
development, staging and production, so where to connect comes from the command
line or the environment. Redshift speaks PostgreSQL's wire protocol, so a direct
connection is the same psycopg connection for both engines; only how the
credentials are obtained differs.

- **Credentials**: `--dsn`, or the standard libpq variables (`PGHOST`, `PGPORT`,
  `PGDATABASE`, `PGUSER`, `PGPASSWORD`) and `~/.pgpass`. Works for PostgreSQL and
  for Redshift with a database user's password.
- **Redshift with IAM** (`pip install "pgsesame[redshift]"`): `--cluster ID` or
  `--workgroup NAME` with `--iam`. pgsesame asks AWS for temporary database
  credentials (`GetClusterCredentialsWithIAM` or `GetClusterCredentials` for a
  provisioned cluster, `redshift-serverless GetCredentials` for a workgroup) with
  the usual AWS credential chain, then connects directly with them. No password is
  stored anywhere; the machine still needs a network path to the database.
- **Redshift Data API** (same extra): `--data-api` with `--cluster ID` or
  `--workgroup NAME`, authenticated with `--secret-arn` or IAM. Statements go over
  AWS's HTTPS API, so no network path to the database is needed, which suits CI
  runners outside the VPC. The Data API runs one statement (or one batch) per call,
  so apply sends the plan as a batch where Redshift allows it.

All three produce the same connection interface inside pgsesame (run a query,
run statements), so the reader, planner and applier do not know which one is in
use, and the integration tests can run the same scenarios over each.

## Implementation choices

- **The spec is pydantic models.** Pydantic checks the structure (types, unknown
  keys, allowed values); a second pass checks what needs the whole spec
  (engine-specific privileges, references between principals). Both report every
  problem with its YAML path. `sesame schema` prints the spec's JSON Schema, so
  editors can complete and check the YAML as it's written.
- **Statements are typed objects, not strings.** The planner produces frozen
  pydantic models (`CreateRole`, `Grant`, `Revoke`, `AddMember`, `AlterOwner`,
  ...); each renders itself for PostgreSQL or Redshift in one place, and golden
  tests pin the SQL for both engines.
- **SQL is composed with `psycopg.sql`** (`SQL`, `Identifier`, `Literal`), so
  names from the spec are always quoted correctly (`IAM:alice`, mixed case,
  reserved words) and never concatenated into SQL. The Data API path renders the
  same objects to text with the same quoting rules.
- **Catalog queries are named constants**, one module per engine, each covered by
  the integration tests against a real server.
- **No SQLAlchemy.** Its Core has no constructs for GRANT, REVOKE, roles, default
  privileges or ownership, its reflection does not cover roles or ACLs, and it
  needs a DBAPI driver, which the Data API does not have. It would add weight
  without removing any SQL. An adapter that accepts a SQLAlchemy engine as a
  connection can come later if users ask for it.

## Testing

- Unit tests: spec validation, diff and plan ordering, SQL rendering, the ACL
  fallback parser.
- Integration tests: `plan`, `apply`, then an empty `plan`, against PostgreSQL in
  Docker and against oblako's redshift-local. redshift-local does not yet provide the
  `SVV_*` privilege views; adding them to oblako is a prerequisite for the Redshift
  integration tests, and also a parity gain for oblako.

## Milestones

1. Spec model and `sesame validate`.
2. PostgreSQL: read, diff, plan and apply for roles, users, memberships, schema and
   table privileges.
3. Ownership and default privileges.
4. Redshift reader and renderer: users, groups, roles; tested on redshift-local.
5. Redshift IAM credentials and the Data API backend; saved plans; `manage.prefixes`.

# Testing against Amazon Redshift Serverless

`serverless.yaml` is a short-lived workgroup for the integration tests. Deploy,
test, delete:

```bash
sam deploy --template-file tests/aws/serverless.yaml --stack-name pgsesame-test \
  --resolve-s3 --parameter-overrides AllowedCidr=$(curl -s https://checkip.amazonaws.com)/32
# the admin password is in Secrets Manager:
#   aws redshift-serverless get-namespace --namespace-name pgsesame-test \
#     --query namespace.adminPasswordSecretArn
PGSESAME_TEST_REDSHIFT_DSN="postgresql://sesame_admin:<password>@<host>:5439/dev?sslmode=require" \
PGSESAME_TEST_AWS_WORKGROUP=pgsesame-test PGSESAME_TEST_AWS_DATABASE=dev \
PGSESAME_TEST_AWS_SECRET_ARN=<secret arn> \
  uv run pytest tests/test_redshift.py tests/test_aws.py tests/test_masking.py
sam delete --stack-name pgsesame-test
```

What to expect:

- The workgroup's public endpoint can take a while after the stack reports it
  available before it accepts connections: minutes on 2026-10-06, about 25 on
  2026-10-07. The Data API works at once, so it tells a slow endpoint from a
  broken one.
- `--iam`: the database user an IAM identity maps to (`IAM:<user>`) is created at
  its first login, without a password and without privileges. Redshift refuses a
  superuser without a password, so the tests grant one with
  `ALTER USER "IAM:x" PASSWORD '...' CREATEUSER`; IAM sign-in keeps working.
- `--data-api`: `plan` needs `redshift-data:ExecuteStatement`,
  `DescribeStatement` and `GetStatementResult`; `apply` also needs
  `BatchExecuteStatement`, as it runs the whole plan as one transaction.

Last run, 2026-10-06 (us-east-1): every test in `test_redshift.py` and
`test_aws.py` passed against Serverless, unchanged from redshift-local.

2026-10-07 (us-east-1): every test in `test_masking.py` passed against
Serverless, once the tests cast their constant (`'***'::varchar(64)`), which
Redshift requires.

## Aurora PostgreSQL, express configuration

A cluster made with express configuration needs no VPC or template: it is
reachable over the internet through its gateway, with IAM authentication only.

```bash
aws rds create-db-cluster --db-cluster-identifier pgsesame-express \
  --engine aurora-postgresql --with-express-configuration      # available in ~20 s
sesame plan spec.yaml --iam --rds pgsesame-express             # as its admin, postgres
```

- The caller needs `rds-db:connect` on the cluster's database users; the free-tier
  `admin` user has `AmazonRDSFullAccess`, which doesn't include it, so the run used
  a temporary role with only that (and the Data API's actions), deleted afterwards.
- The gateway accepts IAM tokens only: a test that signs in as one of its own users
  with a password is refused (`PAM authentication failed`). The rest of
  `test_postgres.py` passes.
- The Data API is off on an express cluster and can't use the admin user: enable it
  (`aws rds enable-http-endpoint`, ready about 20 s later) and give it a user with a
  password in Secrets Manager. It returns arrays as `arrayValue` lists.

Last run, 2026-10-07 (us-east-1, Aurora PostgreSQL 17.9): `test_rds.py` passed
through the Data API; 18 of `test_postgres.py` passed and the 4 that sign in with a
password were refused by the gateway, as above; a spec granting `rds_iam` was
applied as `postgres` (not a superuser: ADMIN OPTION on the `rds_*` roles, none
on `rdsadmin`, which the plan left alone) and the user it made then signed in with
its own token. Then the cluster, the secret and the role were deleted.


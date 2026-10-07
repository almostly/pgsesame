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

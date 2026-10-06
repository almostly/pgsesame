# pgsesame for CI systems without Python: docker run ghcr.io/almostly/pgsesame plan ...
# Published by .github/workflows/release.yml with each version tag (amd64, arm64).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /usr/local/bin/uv

WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
# the Redshift extra too (IAM credentials, the Data API): the image is for any target
RUN uv pip install --system --no-cache ".[redshift]" && rm -rf /src /usr/local/bin/uv

# no root: pgsesame only reads a spec and talks to a database
RUN useradd --create-home --uid 10001 sesame
USER sesame
WORKDIR /work

ENTRYPOINT ["sesame"]
CMD ["--help"]

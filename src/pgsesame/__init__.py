"""pgsesame: permissions as code for PostgreSQL and Amazon Redshift."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pgsesame")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"

"""Explicit unit-test configuration; PostgreSQL integration tests use P03_TEST_DATABASE_URL."""

import os

os.environ.setdefault("APP_ENV", "unit-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./dlp-unit-test.db")

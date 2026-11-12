#!/bin/sh
# Applies platform (P2) database migrations when the platform is enabled, then starts the API.
set -e
if [ -n "${PLATFORM_DATABASE_URL:-}" ]; then
  echo "Applying platform migrations..."
  DATABASE_URL="$PLATFORM_DATABASE_URL" alembic upgrade head
fi
exec uvicorn main:app --host 0.0.0.0 --port 8000

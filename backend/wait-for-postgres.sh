#!/bin/sh
# wait-for-postgres.sh (debug version)

set -e

host="$1"
shift

echo "========================================"
echo "🕒 [$(date)] Starting wait-for-postgres.sh"
echo "Target host: $host"
echo "Remaining command: $@"
echo "----------------------------------------"

# Check if psql exists
if ! command -v psql >/dev/null 2>&1; then
  echo "❌ psql command not found in container! Make sure PostgreSQL client is installed."
  exit 1
fi

# Wait loop
echo "Waiting for PostgreSQL at host: $host..."
retries=0
max_retries=30

until PGPASSWORD="$POSTGRES_PASSWORD" \
  psql -h "$host" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c '\q' 2>/tmp/pg_error.log; do
  retries=$((retries+1))
  echo "Attempt #$retries: Postgres is unavailable - sleeping"
  if [ $retries -ge $max_retries ]; then
    echo "❌ Reached max retries ($max_retries)."
    echo "Last psql error output:"
    cat /tmp/pg_error.log
    exit 1
  fi
  sleep 2
done

echo "✅ PostgreSQL is up - executing command"
echo "----------------------------------------"
exec "$@"

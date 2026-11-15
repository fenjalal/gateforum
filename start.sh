#!/bin/bash
# GateForum: production start
cd "$(dirname "$0")"
if [ ! -f ".env" ]; then
  echo "ERROR: .env not found. Run: python3 setup_password.py"
  exit 1
fi
set -a; source .env 2>/dev/null || export $(grep -v '^#' .env | xargs); set +a
HOST="${GATEFORUM_HOST:-127.0.0.1}"
PORT="${GATEFORUM_PORT:-5000}"
VERSION="$(cat VERSION 2>/dev/null)"
echo "Starting GateForum ${VERSION} on $HOST:$PORT"
echo "Admin: http://$HOST:$PORT/${GATEFORUM_ADMIN_PREFIX}/${GATEFORUM_ADMIN_SUFFIX}"
exec python3 -m gunicorn \
  --bind "$HOST:$PORT" \
  --workers 2 \
  --threads 2 \
  --timeout 900 \
  --keep-alive 5 \
  --limit-request-line 8190 \
  --limit-request-fields 100 \
  --limit-request-field_size 16384 \
  --access-logfile - \
  --error-logfile - \
  "app:app"

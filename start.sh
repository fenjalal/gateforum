#!/bin/bash
# DNet v9 — production start
cd "$(dirname "$0")"
if [ ! -f ".env" ]; then
  echo "ERROR: .env not found. Run: python3 setup_password.py"
  exit 1
fi
set -a; source .env 2>/dev/null || export $(grep -v '^#' .env | xargs); set +a
HOST="${DNet_HOST:-127.0.0.1}"
PORT="${DNet_PORT:-5000}"
echo "Starting DNet on $HOST:$PORT"
echo "Admin: http://$HOST:$PORT/${DNet_ADMIN_PREFIX}/${DNet_ADMIN_SUFFIX}"
exec python3 -m gunicorn \
  --bind "$HOST:$PORT" \
  --workers 2 \
  --threads 2 \
  --timeout 120 \
  --keep-alive 5 \
  --limit-request-line 8190 \
  --limit-request-fields 100 \
  --limit-request-field_size 16384 \
  --access-logfile - \
  --error-logfile - \
  "app:app"

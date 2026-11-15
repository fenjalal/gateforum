#!/bin/bash
# DNet — simple development start (with Socket.IO support)
cd "$(dirname "$0")"
set -a; source .env 2>/dev/null || export $(grep -v '^#' .env | xargs); set +a
HOST="${DNet_HOST:-127.0.0.1}"
PORT="${DNet_PORT:-5000}"
echo "Dev mode: http://$HOST:$PORT"
[ -n "$DNet_ADMIN_PREFIX" ] && echo "Admin: http://$HOST:$PORT/${DNet_ADMIN_PREFIX}/${DNet_ADMIN_SUFFIX}" || echo "Admin address: see instance/.admin_path"
python3 app.py

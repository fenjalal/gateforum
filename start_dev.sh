#!/bin/bash
# GateForum: development start
cd "$(dirname "$0")"
set -a; source .env 2>/dev/null || export $(grep -v '^#' .env | xargs); set +a
HOST="${GATEFORUM_HOST:-127.0.0.1}"
PORT="${GATEFORUM_PORT:-5000}"
echo "Dev mode: http://$HOST:$PORT"
[ -n "$GATEFORUM_ADMIN_PREFIX" ] && echo "Admin: http://$HOST:$PORT/${GATEFORUM_ADMIN_PREFIX}/${GATEFORUM_ADMIN_SUFFIX}" || echo "Admin address: see instance/.admin_path"
python3 app.py

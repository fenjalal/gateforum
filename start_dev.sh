#!/bin/bash
# DNet — simple development start (with Socket.IO support)
cd "$(dirname "$0")"
set -a; source .env 2>/dev/null || export $(grep -v '^#' .env | xargs); set +a
HOST="${DNet_HOST:-127.0.0.1}"
PORT="${DNet_PORT:-5000}"
echo "Dev mode: http://$HOST:$PORT"
echo "Admin: http://$HOST:$PORT/${DNet_ADMIN_PREFIX:-ctrl9x4mQ7wZ2pL}/${DNet_ADMIN_SUFFIX:-auth8nK3vR6hJ1sT}"
python3 app.py

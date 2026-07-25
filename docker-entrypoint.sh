#!/bin/bash
set -e

# If DATABASE_URL points at postgres, wait for it to accept connections
# before handing off to gunicorn. db.create_all() runs at app import time
# (inside app.py), so the DB must already be reachable when gunicorn
# starts — otherwise every worker fails to boot.
if [[ "$DATABASE_URL" == postgres* ]]; then
    host=$(python3 -c "
import os, urllib.parse as p
u = p.urlparse(os.environ['DATABASE_URL'].replace('postgres://', 'postgresql://', 1))
print(u.hostname or '')
")
    port=$(python3 -c "
import os, urllib.parse as p
u = p.urlparse(os.environ['DATABASE_URL'].replace('postgres://', 'postgresql://', 1))
print(u.port or 5432)
")

    if [[ -n "$host" ]]; then
        echo "Waiting for database at ${host}:${port}..."
        for i in $(seq 1 30); do
            if python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('${host}', ${port}))
    sys.exit(0)
except Exception:
    sys.exit(1)
"; then
                echo "Database is up."
                break
            fi
            echo "  still waiting (${i}/30)..."
            sleep 2
        done
    fi
fi

exec "$@"

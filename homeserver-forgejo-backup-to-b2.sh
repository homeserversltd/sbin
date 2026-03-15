#!/bin/bash
# Run Forgejo backup (encrypt + upload + NAS) in a systemd scope so it is not in
# gunicorn's cgroup and cannot OOM-kill the webserver. Invoked by www-data via sudo.
# Usage: homeserver-forgejo-backup-to-b2.sh <bucket_id> <true|false>
set -e
BUCKET_ID="$1"
STORE_LOCAL="$2"
if [ -z "$BUCKET_ID" ] || [ -z "$STORE_LOCAL" ]; then
  echo "Usage: $0 <bucket_id> <true|false>" >&2
  exit 1
fi
VENV_PYTHON="/var/www/homeserver/venv/bin/python3"
RUNNER="/var/www/homeserver/backend/backblazeTab/forgejo_backup_runner.py"
if [ ! -x "$VENV_PYTHON" ] || [ ! -f "$RUNNER" ]; then
  echo "Missing $VENV_PYTHON or $RUNNER" >&2
  exit 1
fi
SCOPE_NAME="forgejo-backup-$(date +%s)"
# Run in background so sudo/route return immediately; backup runs in scope (separate cgroup)
systemd-run --scope --unit="$SCOPE_NAME" --uid=www-data --gid=www-data \
  "$VENV_PYTHON" "$RUNNER" "$BUCKET_ID" "$STORE_LOCAL" &
exit 0

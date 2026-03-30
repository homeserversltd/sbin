#!/bin/bash
# Run Forgejo backup (encrypt + upload + NAS) in a systemd scope so it is not in
# gunicorn's cgroup and cannot OOM-kill the webserver. Invoked by www-data via sudo.
# Usage: homeserver-forgejo-backup-to-b2.sh <bucket_id> <true|false> [job_id] [sync_id]
# Optional job_id and sync_id are passed to forgejo_backup_runner for the backup ledger
# (sudo often drops parent env; sync_id on the command line preserves correlation).
set -e
BUCKET_ID="$1"
STORE_LOCAL="$2"
JOB_ID="${3:-}"
SYNC_ID="${4:-}"
if [ -z "$BUCKET_ID" ] || [ -z "$STORE_LOCAL" ]; then
  echo "Usage: $0 <bucket_id> <true|false> [job_id] [sync_id]" >&2
  exit 1
fi
VENV_PYTHON="/var/www/homeserver/venv/bin/python3"
RUNNER="/var/www/homeserver/backend/backblazeTab/forgejo_backup_runner.py"
if [ ! -x "$VENV_PYTHON" ] || [ ! -f "$RUNNER" ]; then
  echo "Missing $VENV_PYTHON or $RUNNER" >&2
  exit 1
fi
SCOPE_NAME="forgejo-backup-$(date +%s)"
RUN_ARGS=("$BUCKET_ID" "$STORE_LOCAL")
[ -n "$JOB_ID" ] && RUN_ARGS+=("$JOB_ID")
[ -n "$SYNC_ID" ] && RUN_ARGS+=("$SYNC_ID")
# Run in background so sudo/route return immediately; backup runs in scope (separate cgroup)
systemd-run --scope --unit="$SCOPE_NAME" --uid=www-data --gid=www-data \
  "$VENV_PYTHON" "$RUNNER" "${RUN_ARGS[@]}" &
exit 0

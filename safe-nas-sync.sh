#!/bin/bash
# HOMESERVER Safe NAS Sync Wrapper
# Copyright (C) 2024 HOMESERVER LLC
#
# This script provides critical safety checks before executing rsync
# to prevent accidental sync to root filesystem when nas_backup isn't mounted.

set -euo pipefail

# Log prefix for systemd journal
LOG_TAG="nas-sync"

log_info() {
    echo "[INFO] $1"
    echo "$1" | systemd-cat -t "$LOG_TAG" -p info
}

log_error() {
    echo "[ERROR] $1" >&2
    echo "$1" | systemd-cat -t "$LOG_TAG" -p err
}

# CRITICAL SAFETY CHECK 1: Ensure nas_backup is mounted
if ! mountpoint -q /mnt/nas_backup; then
    log_error "CRITICAL: /mnt/nas_backup is not mounted. Aborting sync to prevent data loss."
    exit 1
fi

# CRITICAL SAFETY CHECK 2: Ensure nas is mounted
if ! mountpoint -q /mnt/nas; then
    log_error "CRITICAL: /mnt/nas is not mounted. Aborting sync - nothing to sync."
    exit 1
fi

# CRITICAL SAFETY CHECK 3: Ensure nas_backup is on external mount (not system partition)
MOUNT_SOURCE=$(findmnt -n -o SOURCE /mnt/nas_backup 2>/dev/null || echo "UNKNOWN")
MOUNT_TARGET=$(findmnt -n -o TARGET /mnt/nas_backup 2>/dev/null || echo "UNKNOWN")

# Resolve symlinks (e.g. /dev/disk/by-partlabel/...) to get block device for blkid
MOUNT_DEVICE="$MOUNT_SOURCE"
[[ -L "$MOUNT_SOURCE" ]] && MOUNT_DEVICE=$(readlink -f "$MOUNT_SOURCE" 2>/dev/null || echo "$MOUNT_SOURCE")
PARTLABEL=$(blkid -s PARTLABEL -o value "$MOUNT_DEVICE" 2>/dev/null || true)
case "$PARTLABEL" in
    homeserver-boot-efi|homeserver-boot|homeserver-swap|homeserver-vault|homeserver-deploy|homeserver-root)
        log_error "CRITICAL: /mnt/nas_backup is on system partition ($MOUNT_SOURCE, PARTLABEL=$PARTLABEL). Aborting sync."
        exit 1
        ;;
esac

if [[ "$MOUNT_TARGET" == "/" ]]; then
    log_error "CRITICAL: /mnt/nas_backup mount target is root filesystem. Aborting sync to prevent root filesystem destruction."
    exit 1
fi

# CRITICAL SAFETY CHECK 4: Verify mount points are different devices
NAS_DEVICE=$(findmnt -n -o SOURCE /mnt/nas 2>/dev/null || echo "UNKNOWN")
BACKUP_DEVICE=$(findmnt -n -o SOURCE /mnt/nas_backup 2>/dev/null || echo "UNKNOWN")

if [[ "$NAS_DEVICE" == "$BACKUP_DEVICE" ]] && [[ "$NAS_DEVICE" != "UNKNOWN" ]]; then
    log_error "CRITICAL: /mnt/nas and /mnt/nas_backup are on the same device ($NAS_DEVICE). Aborting sync."
    exit 1
fi

# All safety checks passed
log_info "Safety checks passed - Starting NAS sync"
log_info "  Source: /mnt/nas (device: $NAS_DEVICE)"
log_info "  Destination: /mnt/nas_backup (device: $BACKUP_DEVICE)"

# Execute the sync with proper options
/usr/bin/rsync -av --stats --delete-before --exclude=lost+found /mnt/nas/ /mnt/nas_backup/ >> /var/log/homeserver/auto-sync.log 2>&1
EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]]; then
    log_info "NAS sync completed successfully"
else
    log_error "NAS sync failed with exit code $EXIT_CODE"
fi

exit $EXIT_CODE


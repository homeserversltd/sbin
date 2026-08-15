#!/bin/bash

# update-kea-dhcp.sh
# Purpose: Atomically update Kea DHCP configuration with validation and rollback
# Usage: update-kea-dhcp.sh <config_file_path>

SCRIPT_NAME="update-kea-dhcp"
CONFIG_PATH="/etc/kea/kea-dhcp4.conf"
LOG_FILE="/var/log/homeserver/homeserver.log"
# TMP_DIR not needed - using /etc/kea/ directly
ERRORS=0

# Logging functions
log_info() {
    local message="[${SCRIPT_NAME}] INFO: $*"
    echo "$message"
    write_to_log "info" "$*"
}

log_warn() {
    local message="[${SCRIPT_NAME}] WARN: $*"
    echo "$message" >&2
    write_to_log "warning" "$*"
    ERRORS=$((ERRORS+1))
}

log_error() {
    local message="[${SCRIPT_NAME}] ERROR: $*"
    echo "$message" >&2
    write_to_log "error" "$*"
    ERRORS=$((ERRORS+1))
}

# Function to write to log file
write_to_log() {
    local level="$1"
    local message="$2"
    local timestamp=$(/usr/bin/date '+%Y-%m-%d %H:%M')
    /usr/bin/mkdir -p "$(/usr/bin/dirname "$LOG_FILE")" 2>/dev/null || true
    echo "[${timestamp}] [${SCRIPT_NAME}] [${level}] ${message}" | /usr/bin/tee -a "$LOG_FILE" >/dev/null 2>&1 || true
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [ -n "$TMP_FILE" ] && [ -f "$TMP_FILE" ]; then
        /usr/bin/rm -f "$TMP_FILE" 2>/dev/null || true
    fi
    if [ -n "$BACKUP_FILE" ] && [ -f "$BACKUP_FILE" ]; then
        if [ $exit_code -ne 0 ]; then
            # Keep backup file on error for manual recovery
            log_info "Backup file preserved at: $BACKUP_FILE"
        else
            /usr/bin/rm -f "$BACKUP_FILE" 2>/dev/null || true
        fi
    fi
    exit $exit_code
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Check arguments
if [ $# -ne 1 ]; then
    log_error "Usage: $0 <config_file_path>"
    exit 1
fi

INPUT_FILE="$1"

# Validate input file exists and is readable
if [ ! -f "$INPUT_FILE" ]; then
    log_error "Input file does not exist: $INPUT_FILE"
    exit 1
fi

if [ ! -r "$INPUT_FILE" ]; then
    log_error "Input file is not readable: $INPUT_FILE"
    exit 1
fi

log_info "Starting DHCP configuration update from: $INPUT_FILE"

# Create unique temporary file in /etc/kea/ for validation (kea-dhcp4 can read from there)
TMP_FILE="/etc/kea/kea-dhcp4.conf.tmp.$$"

# Copy input file to /etc/kea/ for validation
log_info "Copying configuration to temporary file in /etc/kea/: $TMP_FILE"
if ! /bin/cp "$INPUT_FILE" "$TMP_FILE" 2>/dev/null; then
    log_error "Failed to copy input file to temporary location"
    exit 1
fi

# Set proper ownership and permissions (same as actual config file)
if ! /bin/chown _kea:_kea "$TMP_FILE" 2>/dev/null; then
    log_error "Failed to set ownership on temporary file"
    /usr/bin/rm -f "$TMP_FILE"
    exit 1
fi

if ! /bin/chmod 640 "$TMP_FILE" 2>/dev/null; then
    log_error "Failed to set permissions on temporary file"
    /usr/bin/rm -f "$TMP_FILE"
    exit 1
fi

# Sync filesystem
/usr/bin/sync

# Verify temp file exists, is readable, and has content
if [ ! -f "$TMP_FILE" ] || [ ! -r "$TMP_FILE" ] || [ ! -s "$TMP_FILE" ]; then
    log_error "Temporary file verification failed"
    /usr/bin/rm -f "$TMP_FILE"
    exit 1
fi

# Validate configuration from /etc/kea/ location
# kea-dhcp4 must run as _kea user, not root
log_info "Validating configuration..."
VALIDATION_OUTPUT=$(sudo -u _kea /usr/sbin/kea-dhcp4 -t "$TMP_FILE" 2>&1)
VALIDATION_STATUS=$?

if [ $VALIDATION_STATUS -ne 0 ]; then
    log_error "Configuration validation failed: $VALIDATION_OUTPUT"
    log_error "Temp file: $TMP_FILE"
    /usr/bin/rm -f "$TMP_FILE"
    exit 1
fi

log_info "Configuration validation passed"

# Backup current config
BACKUP_FILE="/etc/kea/kea-dhcp4.conf.backup.$$"
log_info "Creating backup of current configuration: $BACKUP_FILE"

if [ -f "$CONFIG_PATH" ]; then
    if ! /bin/cp "$CONFIG_PATH" "$BACKUP_FILE" 2>/dev/null; then
        log_error "Failed to create backup of current configuration"
        exit 1
    fi
    log_info "Backup created successfully"
else
    log_warn "Current configuration file does not exist, skipping backup"
fi

# Apply new configuration atomically by moving temp file
log_info "Applying new configuration to: $CONFIG_PATH"
# Move is atomic on the same filesystem (/etc/kea/)
if ! /bin/mv "$TMP_FILE" "$CONFIG_PATH" 2>/dev/null; then
    log_error "Failed to apply configuration file"
    # Attempt rollback
    if [ -f "$BACKUP_FILE" ]; then
        log_info "Attempting rollback from backup..."
        /bin/cp "$BACKUP_FILE" "$CONFIG_PATH" 2>/dev/null || true
        /bin/chown _kea:_kea "$CONFIG_PATH" 2>/dev/null || true
        /bin/chmod 640 "$CONFIG_PATH" 2>/dev/null || true
    fi
    exit 1
fi
# Ownership and permissions already set on TMP_FILE, preserved by mv

# Sync filesystem again
/usr/bin/sync

# Validate the applied configuration
# kea-dhcp4 must run as _kea user, not root
log_info "Validating applied configuration..."
APPLIED_VALIDATION_OUTPUT=$(sudo -u _kea /usr/sbin/kea-dhcp4 -t "$CONFIG_PATH" 2>&1)
APPLIED_VALIDATION_STATUS=$?

if [ $APPLIED_VALIDATION_STATUS -ne 0 ]; then
    log_error "Applied configuration validation failed: $APPLIED_VALIDATION_OUTPUT"
    log_error "Rolling back to previous configuration"
    
    if [ -f "$BACKUP_FILE" ]; then
        if /bin/cp "$BACKUP_FILE" "$CONFIG_PATH" 2>/dev/null; then
            /bin/chown _kea:_kea "$CONFIG_PATH" 2>/dev/null || true
            /bin/chmod 640 "$CONFIG_PATH" 2>/dev/null || true
            /usr/bin/sync
            log_info "Rollback completed successfully"
        else
            log_error "Rollback failed - manual intervention required"
        fi
    else
        log_error "No backup available for rollback"
    fi
    exit 1
fi

log_info "Applied configuration validation passed"

# Restart kea-dhcp4-server service to apply new configuration
# (kea-dhcp4-server doesn't support reload, requires restart)
log_info "Restarting kea-dhcp4-server service to apply new configuration"
if ! /usr/bin/systemctl restart kea-dhcp4-server 2>/dev/null; then
    log_error "Failed to restart kea-dhcp4-server service"
    # Config is valid and applied, but service restart failed
    # This is still an error as the new config won't be active
    exit 1
fi

# Wait a moment and verify service is running
sleep 1
if ! /usr/bin/systemctl is-active kea-dhcp4-server >/dev/null 2>&1; then
    log_error "kea-dhcp4-server service failed to start after restart"
    exit 1
fi

log_info "DHCP configuration updated successfully"
exit 0


#!/bin/bash

# Script to unlock the vault LUKS container non-interactively.
# Reads password from standard input.
# Automatically starts the systemd vault.mount unit after unlocking.

# Get the valid config path using factoryFallback.sh
config_path=$(/usr/local/sbin/factoryFallback.sh)
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to get valid config path" >&2
    exit 1
fi

# Read vault config from the validated config file
if ! vault_config=$(jq -r '.global.mounts.vault | "\(.device)"' "$config_path"); then
    echo "ERROR: Failed to read vault config from ${config_path}" >&2
    exit 1
fi

# Parse device
device="$vault_config"
if [ -z "$device" ]; then
    echo "ERROR: Invalid vault configuration found in ${config_path}" >&2
    exit 1
fi

vault_device="/dev/${device}"
mapper_name="vault" # Standard mapper name

# Check if vault device exists
if [ ! -b "$vault_device" ]; then
    echo "ERROR: Vault device $vault_device does not exist." >&2
    exit 1
fi

# Check if already mapped
if [ -e "/dev/mapper/$mapper_name" ]; then
    echo "INFO: Vault is already unlocked." >&2
    # Start vault.mount if not already active
    if ! systemctl is-active vault.mount >/dev/null 2>&1; then
        echo "INFO: Starting vault.mount unit..." >&2
        if ! systemctl start vault.mount; then
            echo "ERROR: Failed to start vault.mount unit." >&2
            exit 1
        fi
        echo "INFO: vault.mount unit started successfully." >&2
    else
        echo "INFO: vault.mount unit is already active." >&2
    fi
    exit 0
fi

# Read password from stdin
read -r password

if [ -z "$password" ]; then
    echo "ERROR: No password provided via stdin." >&2
    exit 1
fi

# Attempt to decrypt the vault
if ! echo "$password" | cryptsetup open "$vault_device" "$mapper_name"; then
    echo "ERROR: Failed to decrypt vault. Incorrect password or LUKS error." >&2
    exit 1 # Exit code 1 for decryption failure
fi

echo "INFO: Vault decrypted successfully. Starting vault.mount unit..." >&2

# Start the vault.mount unit
if ! systemctl start vault.mount; then
    echo "ERROR: Failed to start vault.mount unit." >&2
    # Clean up by closing the mapper if mount fails
    cryptsetup close "$mapper_name"
    exit 1
fi

echo "INFO: vault.mount unit started successfully." >&2

# Start the mountNas.service unit in background
echo "INFO: Starting mountNas.service unit in background..." >&2
systemctl start mountNas.service &

echo "INFO: Vault setup completed. NAS mounting will continue in background." >&2
exit 0

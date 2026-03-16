#!/bin/bash

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

# Get the valid config path using factoryFallback.sh
config_path=$(/usr/local/sbin/factoryFallback.sh)
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to get valid config path"
    exit 1
fi

# Read vault config from the validated config file
if ! vault_config=$(jq -r '.global.mounts.vault | "\(.device)"' "$config_path"); then
    echo "Failed to read vault config from ${config_path}"
    exit 1
fi

# Parse device: config uses PARTLABEL (e.g. homeserver-vault) after agnostic-drive migration.
# Resolve to by-partlabel path so cryptsetup gets the real block device.
device="$vault_config"
if [ -e "/dev/disk/by-partlabel/${device}" ]; then
    vault_device="/dev/disk/by-partlabel/${device}"
elif [ -e "/dev/${device}" ]; then
    vault_device="/dev/${device}"
else
    echo "ERROR: Vault device not found. Tried by-partlabel /dev/disk/by-partlabel/${device} and /dev/${device}"
    exit 1
fi
mapper_name="vault"

# Enable debug output
#set -x

# Check if already mounted via systemd
if systemctl is-active vault.mount >/dev/null 2>&1; then
    echo "Vault is already mounted."
    exit 0
fi

decrypt_vault() {
    local passphrase
    local attempt=0
    local max_attempts=5
    local success=0

    while [ $attempt -lt $max_attempts ]; do
        echo "Attempt $(($attempt + 1)) of $max_attempts."
        
        # Prompt for passphrase
        echo -n "Enter passphrase for vault partition: " >&2
        read -s passphrase
        echo >&2

        # Validate input
        if [ -z "$passphrase" ]; then
            echo "Error: Empty passphrase provided. Please try again."
            ((attempt++))
            continue
        fi

        # Try to decrypt the vault with explicit LUKS2 options
        if printf "%s" "$passphrase" | cryptsetup --type luks2 \
            --key-file - \
            --disable-keyring \
            --allow-discards \
            open "$vault_device" "$mapper_name"; then
            
            # If decryption succeeds, use systemd to mount it
            echo "Vault decrypted successfully. Starting vault.mount unit..."
            if systemctl start vault.mount; then
                echo "Vault mounted successfully via systemd."
                
                # Start the mountNas.service unit in background
                echo "INFO: Starting mountNas.service unit in background..."
                systemctl start mountNas.service &
                echo "INFO: Vault setup completed. NAS mounting will continue in background."

                success=1
                break
            else
                echo "Failed to start vault.mount unit."
                # Clean up by closing the mapper
                cryptsetup close "$mapper_name"
                return 1
            fi
        else
            echo "Incorrect passphrase or error decrypting vault. Please try again."
        fi

        ((attempt++))
    done

    if [ $success -ne 1 ]; then
        echo "Failed to decrypt and mount vault after $max_attempts attempts. Exiting."
        return 1
    fi

    return 0
}

echo "Initiating decryption and mounting process for the vault partition..."
if decrypt_vault; then
    echo "Vault mounted successfully."
    exit 0
else
    echo "Failed to mount vault. Device will remain locked down."
    exit 1
fi

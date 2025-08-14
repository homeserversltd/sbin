#!/bin/bash
# siteSecretKey.sh - Generates and manages the AES-256 encryption key for the homeserver
# This script is installed in /usr/local/sbin and generates a secure random key
# for use with secure transmissions between client and server

set -e

# Configuration
KEY_FILE="/var/www/homeserver/src/config/secret.key"
KEY_LENGTH=32  # 32 bytes for AES-256

# Create directory if it doesn't exist
/bin/mkdir -p "$(/bin/dirname "$KEY_FILE")"

# Function to generate a new secret key
generate_new_key() {
    echo "Generating new AES-256 encryption key..."
    # Generate 32 random bytes and convert to hex
    NEW_KEY=$(/usr/bin/openssl rand -hex $KEY_LENGTH)
    echo "$NEW_KEY" > "$KEY_FILE"
    /bin/chmod 640 "$KEY_FILE"  # Readable by owner and group
    /bin/chown root:www-data "$KEY_FILE"  # Make readable by web server
    echo "New key generated and saved to $KEY_FILE"
}

# Function to get the current key
get_key() {
    if [ -f "$KEY_FILE" ]; then
        /bin/cat "$KEY_FILE"
    else
        echo "No key found. Generate one first."
        exit 1
    fi
}

# Main logic
case "$1" in
    generate)
        generate_new_key
        ;;
    get)
        get_key
        ;;
    *)
        echo "Usage: $0 {generate|get}"
        echo "  generate - Generate a new secret key"
        echo "  get      - Print the current secret key"
        exit 1
        ;;
esac

exit 0

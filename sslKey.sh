#!/bin/bash
# sslKey.sh - Generate a self-signed SSL certificate for nginx (home.arpa)
# This script creates /etc/ssl/home.arpa/cert.pem and key.pem for nginx use.
# Usage: sudo bash sslKey.sh

set -e

CERT_DIR="/etc/ssl/home.arpa"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
CONFIG_FILE="$CERT_DIR/openssl.conf"
FACTORY_FALLBACK="/usr/local/sbin/factoryFallback.sh"

# Create the directory if it doesn't exist
if [ ! -d "$CERT_DIR" ]; then
    mkdir -p "$CERT_DIR"
    echo "Created directory: $CERT_DIR"
fi

# Get the active config file using factoryFallback.sh
if [ ! -x "$FACTORY_FALLBACK" ]; then
    echo "Error: factoryFallback.sh not found or not executable at $FACTORY_FALLBACK"
    exit 1
fi

HOMESERVER_JSON=$("$FACTORY_FALLBACK")
if [ $? -ne 0 ]; then
    echo "Error: Failed to determine active config file"
    exit 1
fi

# Check if we're using the factory config
if [[ "$HOMESERVER_JSON" == *".factory" ]]; then
    echo "Error: Cannot generate SSL certificate while using factory config"
    echo "Please correct your homeserver.json configuration first"
    exit 1
fi

# Extract tailnet from homeserver.json
if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required but not installed. Exiting."
    exit 2
fi

# Extract tailnet from CORS allowed_origins (primary source)
tailnet=$(jq -r '.global.cors.allowed_origins[]' "$HOMESERVER_JSON" | grep -o 'home\.[a-zA-Z0-9-]*\.ts\.net' | head -n1 | cut -d. -f2)

if [[ -z "$tailnet" ]]; then
  echo "Could not determine tailnet from homeserver.json. Exiting."
  exit 3
fi

# Create OpenSSL config with SANs
cat > "$CONFIG_FILE" << EOL
[req]
default_bits = 4096
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
C = US
ST = State
L = City
O = HomeServer
OU = IT
CN = home.arpa

[v3_req]
basicConstraints = CA:TRUE
keyUsage = digitalSignature, keyEncipherment, keyCertSign
subjectAltName = @alt_names

[alt_names]
DNS.1 = home.arpa
DNS.2 = *.home.arpa
DNS.3 = home.${tailnet}.ts.net
EOL

# Generate the self-signed certificate and key with maximum validity across platforms
# Windows/macOS/iOS: 824 days (2 years + 94 days) is the maximum allowed
# Linux/Android: No strict limit, but using same maximum for consistency
openssl req -x509 -nodes -days 824 \
    -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -config "$CONFIG_FILE"

# Set permissions: key readable by root and ssl-cert group, cert world-readable
chmod 640 "$KEY_FILE"
chmod 644 "$CERT_FILE"

# Set group ownership to ssl-cert for proper nginx access
chown root:ssl-cert "$CERT_FILE" "$KEY_FILE"

# Ensure www-data is in ssl-cert group for nginx access
usermod -a -G ssl-cert www-data 2>/dev/null || true

# Show the certificate details
echo "Certificate generated with the following SANs:"
openssl x509 -in "$CERT_FILE" -text -noout | grep -A2 "Subject Alternative Name"

# Print result
ls -l "$CERT_FILE" "$KEY_FILE"
echo "Self-signed certificate and key generated at $CERT_DIR."

# Clean up the config file
rm -f "$CONFIG_FILE"

# Restart nginx if it's running
if systemctl is-active --quiet nginx; then
    systemctl restart nginx
    echo "Nginx restarted."
fi

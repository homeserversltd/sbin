#!/bin/bash
# createCertBundle.sh - Create a certificate bundle for client installation
# Usage: sudo bash createCertBundle.sh [platform]
# Platform options: windows, android, chromeos, linux, macos (default: linux)

set -e

# Default platform
PLATFORM="${1:-linux}"

# Validate platform
case "$PLATFORM" in
  windows|android|chromeos|linux|macos)
    ;;
  *)
    echo "Invalid platform. Must be one of: windows, android, chromeos, linux, macos"
    exit 1
    ;;
esac

# Create output directory
OUTPUT_DIR="/tmp/homeserver_certs"
mkdir -p "$OUTPUT_DIR"

# Source certificate and key
CERT_FILE="/etc/ssl/home.arpa/cert.pem"
KEY_FILE="/etc/ssl/home.arpa/key.pem"

# Set output file based on platform
case "$PLATFORM" in
  windows)
    OUTPUT_FILE="$OUTPUT_DIR/homeserver_ca.cer"
    # Convert to DER format for Windows
    openssl x509 -in "$CERT_FILE" -outform DER -out "$OUTPUT_FILE"
    ;;
  android|chromeos)
    OUTPUT_FILE="$OUTPUT_DIR/homeserver_ca.crt"
    # Copy PEM format for Android/ChromeOS
    cp "$CERT_FILE" "$OUTPUT_FILE"
    ;;
  linux|macos)
    OUTPUT_FILE="$OUTPUT_DIR/homeserver_ca.p12"
    # Create PKCS#12 bundle for Linux/macOS
    openssl pkcs12 -export \
      -in "$CERT_FILE" \
      -inkey "$KEY_FILE" \
      -out "$OUTPUT_FILE" \
      -name "HomeServer CA" \
      -password pass:homeserver
    ;;
esac

# Set permissions
chown www-data:www-data "$OUTPUT_FILE"
chmod 644 "$OUTPUT_FILE"

echo "Created certificate bundle at $OUTPUT_FILE" 
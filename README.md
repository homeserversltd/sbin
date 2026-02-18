# HOMESERVER System Administration Toolkit

Professional-grade system administration scripts for the HOMESERVER digital sovereignty platform. This toolkit provides enterprise-level infrastructure management, security hardening, and hardware validation capabilities.

## Overview

The HOMESERVER platform requires sophisticated system administration tools to maintain its enterprise-grade infrastructure. These scripts provide the operational backbone for managing certificates, storage, networking, and hardware validation in production environments.

## Scripts

### Configuration Management
- **`factoryFallback.sh`** - Intelligent configuration fallback system that validates and selects between `homeserver.json` and `homeserver.factory` configurations
- **`tailnetName`** - Python script for updating Nginx configurations with new Tailscale tailnet names, including backup/rollback functionality
- **`update-kea-dhcp.sh`** - Atomic Kea DHCP configuration update script with validation, backup, and rollback capabilities

### Security & Certificates
- **`sslKey.sh`** - Generate self-signed SSL certificates for nginx with Tailscale integration and cross-platform compatibility
- **`siteSecretKey.sh`** - AES-256 encryption key management for secure client-server communications
- **`createCertBundle.sh`** - Platform-specific certificate bundle creation for Windows, Android, ChromeOS, Linux, and macOS clients

### Storage & NAS Management
- **`setupNAS.sh`** - Comprehensive NAS setup script that mirrors backend route `/api/admin/diskman/apply-permissions`
- **`websiteMountVault.sh`** - Non-interactive LUKS vault unlocking with systemd integration

### Hardware Testing & Validation
- **`harddrive_test.sh`** - Comprehensive hard drive testing including badblocks, filesystem checks, and LUKS support
- **`thermalTest.sh`** - Thermal abuse testing with CPU stress testing and temperature monitoring (fails at 100°C)

### Tailscale Integration
- **`tailUp`** - Extract Tailscale login URLs for authentication URL generation
- **`tailget`** - Extract tailnet information from homeserver.json configuration

### Disaster Recovery (BackblazeTab B2)
- **`homeserver-backblaze-tab-b2-disaster-recovery.py`** - Standalone recovery for Backblaze B2 chunked backups. Reconstructs files from a chunk database + skeleton key + B2 credentials into a local zip. Self-contained: on first run creates a venv under `~/.local/share/homeserver-backblaze-recovery/venv` and installs b2sdk and cryptography, then runs. Use after a disaster (e.g. fire) on any machine—clone this sbin repo and run the script; no HOMESERVER or Backblaze tab required. Requires: chunk database (plain or `_chunk_database_backup_*.encrypted.db` from B2), skeleton key (FAK), B2 key_id and application_key, bucket name.

## Requirements

- **Operating System**: Linux (tested on Arch Linux)
- **Privileges**: Most scripts require root/sudo access
- **Dependencies**: 
  - `jq` for JSON processing
  - `openssl` for certificate operations
  - `cryptsetup` for LUKS operations
  - `nginx` for web server operations
  - `systemd` for service management
  - `kea-dhcp4` for DHCP configuration validation

## Installation

```bash
# Clone as submodule
git submodule add https://github.com/homeserversltd/sbin.git initialization/files/usr_local_sbin

# Install to system
sudo cp -r initialization/files/usr_local_sbin/* /usr/local/sbin/
sudo chmod +x /usr/local/sbin/*
```

## Usage Examples

### Generate SSL Certificate
```bash
sudo /usr/local/sbin/sslKey.sh
```

### Setup NAS Permissions
```bash
sudo /usr/local/sbin/setupNAS.sh
```

### Test Hard Drive
```bash
sudo /usr/local/sbin/harddrive_test.sh /dev/sdb full
```

### Thermal Testing
```bash
sudo /usr/local/sbin/thermalTest.sh
```

### Update Kea DHCP Configuration
```bash
sudo /usr/local/sbin/update-kea-dhcp.sh /path/to/config.json
```

### BackblazeTab B2 Disaster Recovery
```bash
# On any machine (e.g. after fire): clone sbin, then run (first run creates venv and installs deps)
./homeserver-backblaze-tab-b2-disaster-recovery.py \
  --database_path /path/to/_chunk_database_backup_YYYYMMDD_HHMMSS.encrypted.db \
  --skeleton_key "YOUR_FAK" \
  --bucket_name "my_bucket" \
  --key_id "YOUR_B2_KEY_ID" \
  --application_key "YOUR_B2_APP_KEY" \
  --output recovered_data.zip
```

## Architecture

These scripts are designed to integrate with the HOMESERVER platform's configuration management system:

- **Configuration Source**: Scripts use `factoryFallback.sh` to determine active configuration
- **Logging**: Integrated with system logging and HOMESERVER-specific log files
- **Error Handling**: Comprehensive error handling with rollback capabilities
- **State Management**: Integration with HOMESERVER's state management system

## Security Considerations

- All scripts require appropriate privilege escalation
- Certificate generation includes proper permission setting
- LUKS operations include proper cleanup on failure
- Configuration validation prevents invalid deployments

## Contributing

This toolkit is designed for enterprise environments. Contributions should maintain the professional-grade quality and security standards expected in production infrastructure.

## License

GPL-3.0

## Support

For HOMESERVER platform support, refer to the main project documentation. These scripts are part of the core infrastructure and are maintained as part of the platform.
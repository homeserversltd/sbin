# HOMESERVER System Administration Toolkit

Professional-grade system administration scripts for the HOMESERVER digital sovereignty platform. This toolkit provides enterprise-level infrastructure management, security hardening, and hardware validation capabilities.

## Overview

The HOMESERVER platform requires sophisticated system administration tools to maintain its enterprise-grade infrastructure. These scripts provide the operational backbone for managing certificates, storage, networking, and hardware validation in production environments.

## Scripts

### Configuration Management
- **`factoryFallback.sh`** - Selects `/etc/appliance/config.json` first; uses `/etc/appliance/config.factory` only as a read-only fallback. It requires a JSON object with a `global` object and allows `tabs` to be absent or an object.
- **`tailnetName`** - Reads the canonical appliance config and updates existing Nginx/certificate surfaces only for its declared tailnet. A different explicit value is refused; change it through Caduceus settings.
- **`update-kea-dhcp.sh`** - Atomic Kea DHCP configuration update script with validation, backup, and rollback capabilities

### Website Restoration
- **`fdwebsite --preserve-config`** - Preserves website themes only; appliance configuration is untouched.

### Security & Certificates
- **`sslKey.sh`** - Generate self-signed SSL certificates for nginx with Tailscale integration and cross-platform compatibility
- **`siteSecretKey.sh`** - AES-256 encryption key management for secure client-server communications
- **`createCertBundle.sh`** - Platform-specific certificate bundle creation for Windows, Android, ChromeOS, Linux, and macOS clients

### Storage & NAS Management
- **`agathodaimon/storage/nas/setup`** - Root-only, transactional NAS provisioning staff operation; requests enter through Caduceus at `/api/v1/storage/nas/setup`.
- **`agathodaimon/storage/disk-doors`** - Wipe-only disk utility. NAS provisioning and fixed-unit attachment are separate NAS staff operations.

### Hardware Testing & Validation
- **`harddrive_test.sh`** - Comprehensive hard drive testing including badblocks, filesystem checks, and LUKS support
- **`thermalTest.sh`** - Thermal abuse testing with CPU stress testing and temperature monitoring (fails at 100°C)

### Tailscale Integration
- **`tailUp`** - Extract Tailscale login URLs for authentication URL generation
- **`tailget`** - Extract the declared tailnet from `/etc/appliance/config.json` only

### Disaster Recovery (BackblazeTab B2)
- **`agathodaimon/storage/backup/homeserver-backblaze-tab-b2-disaster-recovery.py`** - Standalone recovery for Backblaze B2 chunked backups. Reconstructs files from a chunk database + skeleton key + B2 credentials into a local zip. Self-contained: on first run creates a venv under `~/.local/share/homeserver-backblaze-recovery/venv` and installs b2sdk and cryptography, then runs. Use after a disaster (e.g. fire) on any machine—clone this sbin repo and run the script; no HOMESERVER or Backblaze tab required. Requires: chunk database (plain or `_chunk_database_backup_*.encrypted.db` from B2), skeleton key (FAK), B2 key_id and application_key, bucket name.

### Forgejo Backup and Restore
- **`agathodaimon/storage/backup/homeserver-forgejo-migrate.py`** - Full-instance backup and restore for Forgejo (bare-metal install). **export:** stops forgejo.service, runs pg_dump for database `forgejo`, runs `forgejo dump` as user `git`, then starts the service; writes `forgejo_db_<timestamp>.sql` and `forgejo-dump-<timestamp>.zip` to the given output directory. **restore:** from local paths; stops the service, restores Postgres, extracts the dump zip into `/opt/forgejo`, chown git:git, starts the service, optional `forgejo doctor check --all`; requires `--yes`. **restore-from-b2:** download encrypted backup (zip + sql) from a Backblaze B2 bucket, decrypt with skeleton key (FAK), then run restore. Same encryption as Backblaze tab (salt `backblazetab_forgejo_backup_salt`). Use `--skeleton-key` or `--skeleton-key-file` (e.g. `/root/key/skeleton.key`) to provide the FAK from the HOMESERVER that created the backup. On first use the script may create a venv for b2sdk/cryptography. Requires root/sudo. The Backblaze tab can invoke export/restore via sudo with fixed paths.

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

### NAS Provisioning
Submit a root-only whole-disk device and `primary` or `backup` role through Caduceus at `/api/v1/storage/nas/setup`; the caller must obtain the owner's typed erasure confirmation. Disk initialization is destructive and returns per-step readbacks. Attach or detach the fixed NAS systemd units through Caduceus at `/api/v1/storage/nas/attach` and `/api/v1/storage/nas/detach`; these lifecycle actions do not provision or erase disks.

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
sudo /usr/local/sbin/agathodaimon/network/dhcp/update-kea-dhcp.sh /path/to/config.json
```

### BackblazeTab B2 Disaster Recovery
```bash
# On any machine (e.g. after fire): clone sbin, then run (first run creates venv and installs deps)
./agathodaimon/storage/backup/homeserver-backblaze-tab-b2-disaster-recovery.py \
  --database_path /path/to/_chunk_database_backup_YYYYMMDD_HHMMSS.encrypted.db \
  --skeleton_key "YOUR_FAK" \
  --bucket_name "my_bucket" \
  --key_id "YOUR_B2_KEY_ID" \
  --application_key "YOUR_B2_APP_KEY" \
  --output recovered_data.zip
```

### Forgejo Backup and Restore
```bash
# Export (writes forgejo_db_<timestamp>.sql and forgejo-dump-<timestamp>.zip to output dir)
sudo /usr/local/sbin/agathodaimon/storage/backup/homeserver-forgejo-migrate.py export --output-dir /var/www/homeserver/premium/forgejo_export

# Restore from local backup pair (--yes required; restore replaces the live instance)
sudo /usr/local/sbin/agathodaimon/storage/backup/homeserver-forgejo-migrate.py restore \
  --dump-zip /path/to/forgejo-dump-20260315_120000.zip \
  --db-dump /path/to/forgejo_db_20260315_120000.sql \
  --yes
# Skip post-restore doctor check: add --no-doctor

# Restore from B2: download encrypted backup, decrypt with skeleton key (FAK), then restore
sudo /usr/local/sbin/agathodaimon/storage/backup/homeserver-forgejo-migrate.py restore-from-b2 \
  --bucket-name my-bucket \
  --backup-key forgejo-backups/2026-03-15_14-30-00/ \
  --key-id YOUR_B2_KEY_ID \
  --application-key YOUR_B2_APPLICATION_KEY \
  --skeleton-key-file /root/key/skeleton.key \
  --yes
# Or use --skeleton-key "YOUR_FAK" instead of --skeleton-key-file
```

## Architecture

These scripts are designed to integrate with the HOMESERVER platform's configuration management system:

- **Configuration ownership**: Caduceus is the sole writer of `/etc/appliance/config.json`. `factoryFallback.sh` reads it first and may read `/etc/appliance/config.factory` as a read-only fallback; neither file is modified by the resolver. `tailget` and `tailnetName` read the canonical live config directly, so not every script uses the resolver.
- **Logging**: Integrated with system logging and HOMESERVER-specific log files
- **Error Handling**: Comprehensive error handling with rollback capabilities
- **State Management**: Integration with HOMESERVER's state management system

## Security Considerations

- All scripts require appropriate privilege escalation
- Certificate generation includes proper permission setting
- LUKS operations include proper cleanup on failure
- Configuration resolution accepts the baseline appliance object shape without legacy UI, CORS, version, or theme gates

## Contributing

This toolkit is designed for enterprise environments. Contributions should maintain the professional-grade quality and security standards expected in production infrastructure.

## License

GPL-3.0

## Support

For HOMESERVER platform support, refer to the main project documentation. These scripts are part of the core infrastructure and are maintained as part of the platform.
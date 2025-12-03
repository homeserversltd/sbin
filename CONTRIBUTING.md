# Contributing to HOMESERVER System Administration Toolkit

Thank you for your interest in contributing to the HOMESERVER sbin toolkit. These system administration scripts form the operational backbone of the HOMESERVER platform, and we welcome contributions that improve reliability, functionality, and maintainability.

## About This Repository

This toolkit provides professional-grade system administration scripts for HOMESERVER:
- Configuration management and fallback systems
- SSL/TLS certificate generation
- Storage and NAS setup
- Hardware testing and validation
- Tailscale VPN integration
- Security key management

**Importance**: These scripts handle critical infrastructure operations. Issues can affect:
- System initialization and configuration
- Certificate security and connectivity
- Storage reliability and data access
- Hardware validation and reliability testing

We prioritize backward compatibility, reliability, and thorough testing.

## Ways to Contribute

### High-Value Contributions

- **Bug fixes**: Address edge cases, error handling, or compatibility issues
- **Reliability improvements**: Better error recovery, validation, or logging
- **New features**: Additional system administration utilities that fit HOMESERVER architecture
- **Documentation**: Clarify usage, improve examples, document edge cases
- **Testing**: Validate scripts across different hardware and configurations
- **Cross-platform support**: Improve compatibility across Linux distributions

### Feature Requests

Have an idea for a new script or capability? Please:
1. Open an issue describing the use case
2. Explain how it fits into HOMESERVER architecture
3. Discuss design before implementing
4. Consider backward compatibility

## Getting Started

### Prerequisites

- **Shell scripting**: Bash proficiency
- **Linux administration**: System administration experience
- **HOMESERVER knowledge**: Understanding of platform architecture (helpful)
- **Testing environment**: VM or test system for validation

### Repository Setup

1. **Fork the repository** on GitHub:
   ```bash
   git clone git@github.com:YOUR_USERNAME/sbin.git
   cd sbin
   ```

2. **Add upstream remote**:
   ```bash
   git remote add upstream git@github.com:homeserversltd/sbin.git
   ```

3. **Study existing scripts**: Review patterns and conventions

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Your Changes

**General Principles:**
- **Backward compatibility**: Don't break existing functionality
- **Error handling**: Check return codes, provide meaningful errors
- **Logging**: Use consistent logging patterns
- **Configuration**: Use `factoryFallback.sh` for config access
- **Documentation**: Update comments and README
- **POSIX compliance**: When possible, write portable code

**Script Standards:**
```bash
#!/bin/bash
# Script name - Brief description
#
# Usage: scriptname [arguments]
#
# Description of what this script does and when to use it.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Source configuration helper if needed
CONFIG_JSON=$(factoryFallback.sh) || exit 1

# Functions
function_name() {
    local param1="$1"
    
    # Implementation with error checking
    if ! some_command; then
        echo "Error: operation failed" >&2
        return 1
    fi
    
    return 0
}

# Main logic
main() {
    # Script body
    function_name "arg"
}

main "$@"
```

### 3. Test Thoroughly

Testing is **required**. See [Testing Requirements](#testing-requirements).

### 4. Commit and Push

```bash
git add .
git commit -m "Descriptive commit message"
git push origin feature/your-feature-name
```

### 5. Open a Pull Request

Include comprehensive description and testing details.

## Code Quality Standards

### Shell Script Best Practices

**Error Handling:**
```bash
# GOOD: Check all operations
if ! mount /dev/sdb1 /mnt/data; then
    echo "Error: Failed to mount device" >&2
    cleanup_temp_files
    exit 1
fi
```

**Input Validation:**
```bash
# GOOD: Validate inputs
validate_device() {
    local device="$1"
    
    if [[ -z "$device" ]]; then
        echo "Error: Device parameter required" >&2
        return 1
    fi
    
    if [[ ! -b "$device" ]]; then
        echo "Error: $device is not a block device" >&2
        return 1
    fi
    
    return 0
}
```

**Configuration Access:**
```bash
# GOOD: Use configuration helper
get_tailnet_name() {
    local config_file
    config_file=$(factoryFallback.sh) || return 1
    
    jq -r '.tailscale.tailnet' "$config_file"
}
```

**Cross-Platform Considerations:**
```bash
# GOOD: Handle different Linux distributions
if command -v apt-get >/dev/null 2>&1; then
    apt-get install package
elif command -v pacman >/dev/null 2>&1; then
    pacman -S package
else
    echo "Warning: Unknown package manager" >&2
fi
```

## Testing Requirements

**All contributions must be tested before submission.**

### Required Testing

1. **Functional testing**: Script accomplishes intended purpose
2. **Error handling**: Test failure scenarios
3. **Input validation**: Test with invalid/unexpected inputs
4. **Integration**: Works with HOMESERVER configuration
5. **Idempotency**: Safe to run multiple times (where applicable)
6. **Cleanup**: Proper cleanup on success and failure

### Testing Documentation

Include in your PR:

```markdown
## Testing Performed

### Functional Tests
- Generated SSL certificate: SUCCESS
- Certificate installed correctly: VERIFIED
- Nginx restart successful: VERIFIED

### Error Handling Tests
- Missing configuration file: ERROR handled gracefully
- Invalid parameters: REJECTED with clear message
- Insufficient privileges: ERROR message displayed

### Integration Tests
- Works with factoryFallback.sh: VERIFIED
- Compatible with HOMESERVER nginx config: CONFIRMED
- Certificate format correct for services: TESTED

### Edge Cases
- Ran script multiple times: IDEMPOTENT
- Tested on Debian 12: SUCCESS
- Tested on Arch Linux: SUCCESS (if applicable)

### Test Environment
- OS: Debian 12 / Arch Linux
- HOMESERVER version: [version]
- Related services: nginx, systemd

### Test Commands
[List specific commands you ran to test]
```

## Commit Message Guidelines

Clear, descriptive commit messages:

```
Improve certificate generation in sslKey.sh

Enhanced SSL certificate generation with better defaults:
- Increased key size from 2048 to 4096 bits
- Added SAN (Subject Alternative Name) support
- Improved certificate expiration to 10 years
- Better error messages for common failures
- Added backup of existing certificates before overwrite

Changes made:
- sslKey.sh: Updated OpenSSL commands and parameters
- Added validation of certificate generation
- Improved logging throughout the process

Testing:
- Generated certificates on Debian 12: SUCCESS
- Nginx accepted new certificate format: VERIFIED
- Backed up and replaced existing cert: TESTED

Backward compatible: Existing certificates not affected unless regenerated.
```

## Pull Request Process

### PR Description Template

```markdown
## Summary
Brief description of what this PR accomplishes.

## Motivation
Why is this change needed? What problem does it solve?

## Changes Made
- Specific change 1
- Specific change 2
- Specific change 3

## Testing Performed
[Use testing template above]

## Backward Compatibility
Is this change backward compatible? Any migration needed?

## Documentation Updates
What documentation was updated?

## Checklist
- [ ] Follows shell script best practices
- [ ] Error handling is comprehensive
- [ ] Input validation included
- [ ] Tested on target OS (Debian/Arch)
- [ ] Works with HOMESERVER configuration system
- [ ] Backward compatible or migration path documented
- [ ] Documentation updated (README, inline comments)
```

### Review Process

1. **Code review**: Check for reliability, compatibility, code quality
2. **Testing**: May request additional testing or test independently
3. **Discussion**: Collaborate on improvements or concerns
4. **Approval**: Merge after satisfactory review

### Response Time

We aim to review PRs within **1 week**. Simple bug fixes may be reviewed faster.

## Architecture Understanding

### Script Categories

**Configuration Management:**
- `factoryFallback.sh` - Configuration selection and validation
- `tailnetName` - Nginx configuration updates

**Security & Certificates:**
- `sslKey.sh` - SSL certificate generation
- `siteSecretKey.sh` - Encryption key management
- `createCertBundle.sh` - Client certificate bundles

**Storage Management:**
- `setupNAS.sh` - NAS configuration and permissions
- `websiteMountVault.sh` - LUKS vault mounting

**Hardware Testing:**
- `harddrive_test.sh` - Drive testing and validation
- `thermalTest.sh` - Thermal stress testing

**Tailscale Integration:**
- `tailUp` - Authentication URL extraction
- `tailget` - Configuration extraction

### Integration Points

- **Configuration**: All scripts use `factoryFallback.sh` for config access
- **Systemd**: Many scripts integrate with systemd services
- **LUKS**: Storage scripts work with encrypted partitions
- **Nginx**: Certificate scripts integrate with web server
- **Keyman**: Security scripts may integrate with credential management

## Best Practices

### Script Design Principles

1. **Single responsibility**: Each script does one thing well
2. **Composability**: Scripts can be called from other scripts
3. **Idempotency**: Safe to run multiple times (where appropriate)
4. **Clear output**: Informative success/error messages
5. **Logging**: Log operations for troubleshooting
6. **Configuration-driven**: Use config file, not hardcoded values

### Maintainability

- **Clear naming**: Descriptive function and variable names
- **Comments**: Explain why, not just what
- **Modularity**: Break complex scripts into functions
- **Consistent style**: Follow existing patterns
- **Documentation**: Keep README current

### Reliability

- **Defensive programming**: Check assumptions, validate inputs
- **Error recovery**: Clean up on failure
- **Status codes**: Return meaningful exit codes
- **Dependencies**: Check for required commands
- **Graceful degradation**: Handle missing optional features

## Getting Help

### Resources

- **README**: Repository documentation
- **Existing scripts**: Study patterns and conventions
- **HOMESERVER docs**: Platform architecture
- **Man pages**: Linux command documentation

### Questions?

- **Open an issue**: General questions or discussions
- **Email**: For complex architectural questions (owner@arpaservers.com)
- **Review existing code**: Learn from current implementation

## Recognition

Contributors:
- Are credited in the repository
- Help maintain HOMESERVER infrastructure
- Build professional system administration portfolio
- Contribute to digital sovereignty movement

## License

This project is licensed under **GPL-3.0**. Contributions are accepted under this license, and no CLA is required.

---

**Thank you for contributing to HOMESERVER system administration tools!**

These scripts enable reliable, secure infrastructure management for digital sovereignty.

*HOMESERVER LLC - Professional Digital Sovereignty Solutions*


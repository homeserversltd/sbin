#!/bin/bash

# factoryFallback.sh
# Purpose: Determine which config file to use between homeserver.json and homeserver.factory
# Returns: Path to the config file that should be used

# Debug function
debug_log() {
    if [ "${DEBUG:-false}" = "true" ]; then
        echo "DEBUG: $1" >&2
        if [ -n "$2" ]; then
            echo "$2" >&2
        fi
    fi
}

CONFIG_PATH="/var/www/homeserver/src/config/homeserver.json"
FACTORY_PATH="/etc/homeserver.factory"
LOG_FILE="/var/log/homeserver/homeserver.log"

# Function to write to log file
write_to_log() {
    local level="$1"
    local message="$2"
    # Format timestamp like utils.py: YYYY-MM-DD HH:MM
    local timestamp=$(/usr/bin/date '+%Y-%m-%d %H:%M')
    echo "[${timestamp}] [config] [${level}] ${message}" | /usr/bin/sudo /usr/bin/tee -a "$LOG_FILE" >/dev/null
}

# Function to validate basic JSON structure
validate_json() {
    local config_file="$1"
    local error_output
    
    # First check if we can read the file
    if ! /usr/bin/sudo /usr/bin/test -r "$config_file"; then
        write_to_log "error" "Cannot read ${config_file}"
        echo "ERROR: Cannot read ${config_file}" >&2
        return 1
    fi
    
    # Capture both the exit code and error output
    error_output=$(/usr/bin/sudo /bin/cat "$config_file" 2>/dev/null | /usr/bin/jq empty 2>&1)
    if [ $? -eq 0 ]; then
        debug_log "JSON validation passed for ${config_file}"
        return 0
    else
        write_to_log "error" "Invalid JSON syntax in ${config_file}: ${error_output}"
        echo "ERROR: Invalid JSON syntax" >&2
        echo "Details: ${error_output}" >&2
        echo "$config_file" >&2
        return 1
    fi
}

# Function to validate tabs section
validate_tabs() {
    local config_file="$1"
    # Check if tabs exists and is an object
    if ! /usr/bin/jq -e '.tabs | type == "object"' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid tabs section structure"
        echo "ERROR: Invalid tabs section structure" >&2
        return 1
    fi

    # Debug output
    debug_log "Checking tab structure..." "$(/usr/bin/jq '.tabs | to_entries[] | select(.key != "starred") | .value.config' "$config_file")"

    # Validate each tab has required fields - modified to handle structure correctly
    if ! /usr/bin/jq -e '
        .tabs | 
        to_entries[] | 
        select(.key != "starred") |
        .value | 
        (
            has("config") and
            has("visibility") and
            has("data") and
            (.config | has("displayName") and has("adminOnly") and has("order") and has("isEnabled")) and
            (.visibility | has("tab") and has("elements"))
        )
        ' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "One or more tabs have invalid configuration"
        echo "ERROR: One or more tabs have invalid configuration" >&2
        return 1
    fi

    # Validate starred tab exists and points to a valid tab
    if ! /usr/bin/jq -e '
        .tabs.starred as $star |
        .tabs | 
        to_entries[] |
        select(.key == $star) |
        .value |
        has("config")
        ' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid or missing starred tab reference"
        echo "ERROR: Invalid or missing starred tab reference" >&2
        return 1
    fi
    return 0
}

# Function to validate global section
validate_global() {
    local config_file="$1"
    # Check if global exists and is an object
    if ! /usr/bin/jq -e '.global | type == "object"' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid global section structure"
        echo "ERROR: Invalid global section structure" >&2
        return 1
    fi

    # Validate version subsection
    if ! /usr/bin/jq -e '
        .global.version | 
        select(
            (.generation | type == "number") and
            (.buildId | type == "string") and
            (.lastUpdated | type == "string")
        )' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid version configuration"
        echo "ERROR: Invalid version configuration" >&2
        return 1
    fi

    # Validate theme
    if ! /usr/bin/jq -e '.global.theme.name | type == "string"' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid theme configuration"
        echo "ERROR: Invalid theme configuration" >&2
        return 1
    fi

    # Validate admin section
    if ! /usr/bin/jq -e '.global.admin.pin | type == "string"' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid admin configuration"
        echo "ERROR: Invalid admin configuration" >&2
        return 1
    fi

    # Debug output
    debug_log "Checking CORS structure..." "$(/usr/bin/jq '.global.cors.allowed_origins' "$config_file")"

    # Validate CORS - modified to check array and strings separately
    if ! /usr/bin/jq -e '.global.cors.allowed_origins | type == "array"' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid CORS configuration - not an array"
        echo "ERROR: Invalid CORS configuration - not an array" >&2
        return 1
    fi

    if ! /usr/bin/jq -e '.global.cors.allowed_origins | all(type == "string")' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid CORS configuration - array elements not all strings"
        echo "ERROR: Invalid CORS configuration - array elements not all strings" >&2
        return 1
    fi

    # Validate mounts
    if ! /usr/bin/jq -e '
        .global.mounts | 
        to_entries[] | .value | 
        select(
            (.device | type == "string") and
            (.mountPoint | type == "string") and
            (.encrypted | type == "boolean")
        )' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid mounts configuration"
        echo "ERROR: Invalid mounts configuration" >&2
        return 1
    fi

    # Validate permissions
    if ! /usr/bin/jq -e '
        .global.permissions | 
        to_entries[] | .value.applications | 
        to_entries[] | .value | 
        select(
            (.user | type == "string") and
            (.group | type == "string") and
            (.permissions | type == "string") and
            (.paths | type == "array") and
            (.recursive | type == "boolean")
        )' "$config_file" >/dev/null 2>&1; then
        write_to_log "error" "Invalid permissions configuration"
        echo "ERROR: Invalid permissions configuration" >&2
        return 1
    fi

    return 0
}

# Function to validate JSON config file
validate_config() {
    local file_path="$1"
    local validation_output
    local validation_status
    
    # First check basic JSON syntax
    validation_output=$(/usr/bin/sudo /usr/bin/jq '.' "$file_path" 2>&1)
    validation_status=$?
    
    if [ $validation_status -ne 0 ]; then
        write_to_log "error" "Invalid JSON syntax in ${file_path}: ${validation_output}"
        if [ "${DEBUG:-false}" = "true" ]; then
            echo "ERROR: Invalid JSON syntax in ${file_path}: ${validation_output}" >&2
        else
            echo "ERROR: Invalid JSON syntax in ${file_path}" >&2
        fi
        return 1
    fi
    
    # Check required top-level keys
    if ! /usr/bin/sudo /usr/bin/jq --exit-status '.tabs' "$file_path" >/dev/null 2>&1; then
        write_to_log "error" "Missing required key 'tabs' in ${file_path}"
        echo "ERROR: Missing required key 'tabs' in ${file_path}" >&2
        return 1
    fi
    
    if ! /usr/bin/sudo /usr/bin/jq --exit-status '.global' "$file_path" >/dev/null 2>&1; then
        write_to_log "error" "Missing required key 'global' in ${file_path}"
        echo "ERROR: Missing required key 'global' in ${file_path}" >&2
        return 1
    fi
    
    # Check required nested keys
    if ! /usr/bin/sudo /usr/bin/jq --exit-status '.global.cors.allowed_origins' "$file_path" >/dev/null 2>&1; then
        write_to_log "error" "Missing required key 'global.cors.allowed_origins' in ${file_path}"
        echo "ERROR: Missing required key 'global.cors.allowed_origins' in ${file_path}" >&2
        return 1
    fi
    
    # Validate data types
    # Check if tabs is an object
    if ! /usr/bin/sudo /usr/bin/jq --exit-status '.tabs | objects' "$file_path" >/dev/null 2>&1; then
        write_to_log "error" "Invalid 'tabs' structure in ${file_path} - must be an object"
        echo "ERROR: Invalid 'tabs' structure in ${file_path} - must be an object" >&2
        return 1
    fi
    
    # Check if global is an object
    if ! /usr/bin/sudo /usr/bin/jq --exit-status '.global | objects' "$file_path" >/dev/null 2>&1; then
        write_to_log "error" "Invalid 'global' structure in ${file_path} - must be an object"
        echo "ERROR: Invalid 'global' structure in ${file_path} - must be an object" >&2
        return 1
    fi
    
    # Check if CORS allowed_origins is an array
    if ! /usr/bin/sudo /usr/bin/jq --exit-status '.global.cors.allowed_origins | arrays' "$file_path" >/dev/null 2>&1; then
        write_to_log "error" "Invalid 'global.cors.allowed_origins' structure in ${file_path} - must be an array"
        echo "ERROR: Invalid 'global.cors.allowed_origins' structure in ${file_path} - must be an array" >&2
        return 1
    fi
    
    # If we get here, all validations passed
    return 0
}

# Function to check if file exists and is readable
check_file_readable() {
    local file_path="$1"
    if [ ! -f "$file_path" ]; then
        write_to_log "error" "File does not exist: ${file_path}"
        echo "ERROR: File does not exist: ${file_path}" >&2
        return 1
    fi
    
    if ! /usr/bin/sudo /usr/bin/test -r "$file_path"; then
        write_to_log "error" "File is not readable: ${file_path}"
        echo "ERROR: File is not readable: ${file_path}" >&2
        return 1
    fi
    
    return 0
}

# Ensure log directory exists
/usr/bin/mkdir -p "$(/usr/bin/dirname "$LOG_FILE")"

# Main logic
if check_file_readable "$CONFIG_PATH" >/dev/null 2>&1; then
    if validate_config "$CONFIG_PATH" >/dev/null 2>&1; then
        echo "$CONFIG_PATH"
        exit 0
    else
        write_to_log "warning" "Main config failed validation, checking factory default"
    fi
fi

# If main config is invalid/unreadable, check factory default
if check_file_readable "$FACTORY_PATH" >/dev/null 2>&1; then
    if validate_config "$FACTORY_PATH" >/dev/null 2>&1; then
        write_to_log "warning" "Using factory default config due to invalid or corrupt homeserver.json"
        echo "$FACTORY_PATH"
        exit 0
    else
        write_to_log "error" "Factory default config failed validation"
    fi
fi

# If both configs are invalid/missing, log error and exit with failure
write_to_log "error" "Both main config and factory default are invalid or missing"
[ "${DEBUG:-false}" = "true" ] && echo "No valid configuration found" >&2
exit 1 
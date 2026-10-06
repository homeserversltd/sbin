#!/bin/bash

# Select the canonical live appliance configuration, then its read-only birth fallback.
CONFIG_PATH="/etc/appliance/config.json"
FACTORY_PATH="/etc/appliance/config.factory"

refuse() {
    printf 'factoryFallback: %s\n' "$1" >&2
}

validate_config() {
    local config_file="$1"

    if ! /usr/bin/sudo /usr/bin/test -f "$config_file" || \
       ! /usr/bin/sudo /usr/bin/test -r "$config_file"; then
        return 1
    fi

    /usr/bin/sudo /usr/bin/jq -s -e '
        if length != 1 then false
        elif (.[0] | type) != "object" then false
        elif (.[0].global | type) != "object" then false
        elif (.[0] | has("tabs")) and (.[0].tabs | type) != "object" then false
        else true
        end
    ' "$config_file" >/dev/null 2>&1
}

if validate_config "$CONFIG_PATH"; then
    printf '%s\n' "$CONFIG_PATH"
    exit 0
fi

if validate_config "$FACTORY_PATH"; then
    refuse "canonical appliance config unavailable or invalid; using read-only factory fallback"
    printf '%s\n' "$FACTORY_PATH"
    exit 0
fi

refuse "no valid appliance configuration available"
exit 1

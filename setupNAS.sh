#!/bin/bash

# setupNAS.sh
#
# Purpose: Perform NAS setup to mirror the backend route
#          /api/admin/diskman/apply-permissions
#
# Behavior:
# - Reads active config via factoryFallback.sh
# - Iterates over configured applications under .global.permissions.nas.applications
# - For each application's paths:
#   - mkdir -p
#   - chown (optionally -R)
#   - chmod (optionally -R)
#   - ensure group write (chmod g+w)
#   - verify with stat
# - CalibreWeb: if /mnt/nas/books/metadata.db missing, copy from backup and set perms
# - Piwigo: verify /opt/piwigo/piwigo/galleries symlink target matches NAS photos path

SCRIPT_NAME="setupNAS"
ERRORS=0

log_info()  { echo "[${SCRIPT_NAME}] INFO: $*"; }
log_warn()  { echo "[${SCRIPT_NAME}] WARN: $*" >&2; }
log_error() { echo "[${SCRIPT_NAME}] ERROR: $*" >&2; ERRORS=$((ERRORS+1)); }

# --- Resolve active config path via factory fallback ---
CONFIG_PATH=$(/usr/local/sbin/factoryFallback.sh)
if [ $? -ne 0 ] || [ -z "$CONFIG_PATH" ] || [ ! -f "$CONFIG_PATH" ]; then
  log_error "Failed to resolve active config path via factoryFallback.sh"
  exit 1
fi
log_info "Using config: $CONFIG_PATH"

# --- Ensure jq is available ---
if ! command -v /usr/bin/jq >/dev/null 2>&1; then
  log_error "jq not found at /usr/bin/jq"
  exit 1
fi

# --- Read NAS base path ---
BASE_PATH=$(/usr/bin/jq -r '.global.permissions.nas.basePath // empty' "$CONFIG_PATH")
if [ -z "$BASE_PATH" ]; then
  log_error "No global.permissions.nas.basePath set in config"
  exit 1
fi
log_info "NAS base path: $BASE_PATH"

if [ ! -d "$BASE_PATH" ]; then
  log_warn "Base path $BASE_PATH does not exist. Creating it."
  if ! /usr/bin/mkdir -p "$BASE_PATH"; then
    log_error "Failed to create base path $BASE_PATH"
  fi
fi

# --- Collect application list ---
# If script arguments are provided, limit to those apps; otherwise use all configured apps
if [ "$#" -gt 0 ]; then
  APPS=("$@")
else
  mapfile -t APPS < <(/usr/bin/jq -r '.global.permissions.nas.applications | keys[]' "$CONFIG_PATH")
fi

if [ ${#APPS[@]} -eq 0 ]; then
  log_error "No applications configured under global.permissions.nas.applications"
  exit 1
fi

# --- Helpers ---
get_app_field() {
  local app="$1" field="$2"
  /usr/bin/jq -r --arg app "$app" --arg field "$field" '.global.permissions.nas.applications[$app][$field] // empty' "$CONFIG_PATH"
}

get_app_paths() {
  local app="$1"
  /usr/bin/jq -r --arg app "$app" '.global.permissions.nas.applications[$app].paths[]?' "$CONFIG_PATH"
}

apply_path_permissions() {
  local path="$1" user="$2" group="$3" mode="$4" recursive="$5"

  if [ -z "$path" ]; then
    log_warn "Empty path encountered; skipping"
    return 0
  fi

  # mkdir -p
  if ! /usr/bin/mkdir -p "$path"; then
    log_error "Failed to create directory: $path"
    return 1
  fi

  # chown (with -R if requested)
  if [ -n "$user" ] && [ -n "$group" ]; then
    if [ "$recursive" = "true" ]; then
      /usr/bin/chown -R "$user:$group" "$path" || {
        log_error "Failed to chown -R $user:$group $path"; return 1; }
    else
      /usr/bin/chown "$user:$group" "$path" || {
        log_error "Failed to chown $user:$group $path"; return 1; }
    fi
  else
    log_error "Missing user/group for $path"
    return 1
  fi

  # chmod (with -R if requested)
  if [ -n "$mode" ]; then
    if [ "$recursive" = "true" ]; then
      /usr/bin/chmod -R "$mode" "$path" || {
        log_error "Failed to chmod -R $mode $path"; return 1; }
    else
      /usr/bin/chmod "$mode" "$path" || {
        log_error "Failed to chmod $mode $path"; return 1; }
    fi
  else
    log_error "Missing permissions mode for $path"
    return 1
  fi

  # Ensure group write on the root path
  /usr/bin/chmod g+w "$path" || {
    log_error "Failed to ensure group write on $path"; return 1; }

  # Verify owner and perms
  local stat_out
  if ! stat_out=$(/usr/bin/stat -c '%U:%G %a' "$path" 2>/dev/null); then
    log_error "Failed to stat $path for verification"
    return 1
  fi
  local actual_owner actual_perms perm_digits group_digit
  actual_owner=$(echo "$stat_out" | awk '{print $1}')
  actual_perms=$(echo "$stat_out" | awk '{print $2}')
  perm_digits="${actual_perms: -3}" # last three digits
  group_digit="${perm_digits:1:1}"

  if [ "$actual_owner" != "$user:$group" ]; then
    log_error "Ownership verification failed for $path. Expected $user:$group, got $actual_owner"
    return 1
  fi

  if [ -n "$group_digit" ] && [ "$group_digit" -lt 6 ] 2>/dev/null; then
    log_warn "Group write may not be set for $path (perms: $actual_perms)"
  fi

  log_info "Applied permissions to $path (owner=$actual_owner perms=$actual_perms recursive=$recursive)"
  return 0
}

# --- Process applications ---
for app in "${APPS[@]}"; do
  log_info "Processing application: $app"

  user=$(get_app_field "$app" 'user')
  group=$(get_app_field "$app" 'group')
  mode=$(get_app_field "$app" 'permissions')
  recursive=$(get_app_field "$app" 'recursive')
  [ -z "$recursive" ] && recursive="false"

  if [ -z "$user" ] || [ -z "$group" ] || [ -z "$mode" ]; then
    log_error "Missing configuration for $app (user='$user' group='$group' mode='$mode')"
    continue
  fi

  mapfile -t PATHS < <(get_app_paths "$app")
  if [ ${#PATHS[@]} -eq 0 ]; then
    log_error "No paths configured for $app"
    continue
  fi

  for p in "${PATHS[@]}"; do
    apply_path_permissions "$p" "$user" "$group" "$mode" "$recursive" || true
  done

  # Special handling: CalibreWeb metadata.db bootstrap
  if [ "$app" = "CalibreWeb" ]; then
    for p in "${PATHS[@]}"; do
      if [ "$p" = "/mnt/nas/books" ]; then
        src_db="/var/www/homeserver/backup/metadata.db"
        dst_db="$p/metadata.db"
        if [ ! -f "$dst_db" ]; then
          if [ -f "$src_db" ]; then
            log_info "CalibreWeb: metadata.db not found. Copying from $src_db to $dst_db"
            if /usr/bin/cp "$src_db" "$dst_db"; then
              /usr/bin/chown "$user:$group" "$dst_db" || log_error "Failed to chown $dst_db"
              /usr/bin/chmod "$mode" "$dst_db" || log_error "Failed to chmod $dst_db"
              log_info "CalibreWeb: metadata.db seeded and permissions set"
            else
              log_error "Failed to copy $src_db to $dst_db"
            fi
          else
            log_warn "CalibreWeb: Source metadata.db ($src_db) not found. Skipping copy."
          fi
        else
          log_info "CalibreWeb: metadata.db already exists at $dst_db; skipping copy"
        fi
      fi
    done
  fi

  # Special handling: Piwigo galleries symlink verification
  if [ "$app" = "Piwigo" ]; then
    piwigo_target=$(get_app_paths "Piwigo" | head -n1)
    galleries_dir="/opt/piwigo/piwigo/galleries"
    if [ -e "$galleries_dir" ]; then
      if [ -L "$galleries_dir" ]; then
        actual_target=$(readlink "$galleries_dir")
        if [ "$actual_target" = "$piwigo_target" ]; then
          log_info "Piwigo: galleries symlink correctly points to $piwigo_target"
        else
          log_error "Piwigo: galleries symlink points to $actual_target instead of $piwigo_target"
        fi
      else
        log_error "Piwigo: $galleries_dir exists but is not a symlink to $piwigo_target"
      fi
    else
      log_info "Piwigo: $galleries_dir not present. Skipping symlink verification."
    fi
  fi
done

if [ $ERRORS -gt 0 ]; then
  log_error "Completed with $ERRORS error(s)"
  exit 1
else
  log_info "NAS setup completed successfully"
  exit 0
fi



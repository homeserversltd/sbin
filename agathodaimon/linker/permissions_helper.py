# -*- coding: utf-8 -*-
"""
Helper functions for resolving config path, loading homeserver.json, and determining
user/group/permissions for a given destination path based on the applications section.
"""
import json
import os
import pwd
import grp
import pathlib
from agathodaimon._envelope import appliance_runtime_path
from agathodaimon.linker.logger_utils import get_logger

logger = get_logger("linker.permissions")

_config_cache = None


def get_homeserver_config_path():
    """Use the staff's appliance config; isolated observations do not alter ownership."""
    if os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is not None:
        return None
    path = appliance_runtime_path("config")
    return str(path) if path.is_file() else None


def load_homeserver_config():
    """Load and cache the homeserver.json config as a dict."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    config_path = get_homeserver_config_path()
    if not config_path:
        return None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            _config_cache = json.load(f)
        return _config_cache
    except Exception as e:
        logger.error(f"Failed to load homeserver config: {e}")
        return None


def get_app_permissions_for_path(dest_path: pathlib.Path):
    """
    Given a destination path, return a dict with user, group, permissions if it matches
    any application path in the config. Otherwise, return None.
    """
    config = load_homeserver_config()
    if not config:
        return None
    perms = config.get("global", {}).get("permissions", {})
    for mount in perms.values():
        applications = mount.get("applications", {})
        for app, app_info in applications.items():
            for app_path in app_info.get("paths", []):
                try:
                    # If dest_path is inside app_path, apply permissions
                    if str(dest_path).startswith(app_path):
                        return {
                            "user": app_info["user"],
                            "group": app_info["group"],
                            "permissions": app_info["permissions"]
                        }
                except Exception as e:
                    logger.warning(f"Error checking permissions for {dest_path}: {e}")
    return None


def set_file_ownership_and_permissions(path: pathlib.Path, user: str, group: str, permissions: str):
    """
    Set the file/directory ownership and permissions.
    permissions: string like '775' (octal)
    """
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
        os.chown(str(path), uid, gid)
        os.chmod(str(path), int(permissions, 8))
        logger.info(f"Set ownership/permissions for {path}: {user}:{group} {permissions}")
    except Exception as e:
        logger.error(f"Failed to set ownership/permissions for {path}: {e}") 
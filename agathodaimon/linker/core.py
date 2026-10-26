#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Core hardlinking logic, including recursive handling for directories."""

import os
import sys
import pathlib
import shutil # For removing directories during overwrite
from agathodaimon.linker.logger_utils import get_logger, mutation
from agathodaimon.linker.permissions_helper import get_app_permissions_for_path, set_file_ownership_and_permissions

logger = get_logger("linker.core")

@mutation("deploy")
def create_hardlink(source: pathlib.Path, destination_dir: pathlib.Path, name: str | None, conflict_strategy: str = 'fail'):
    """
    Creates a hardlink from source to a name within destination_dir.
    If the source is a directory, it recursively creates hardlinks for all files in the tree (directories are created, not linked).

    Args:
        source: The source file or directory path.
        destination_dir: The directory where the hardlink (or directory structure) will be created.
        name: Optional name for the hardlink or top-level directory. If None, uses the source's name.
        conflict_strategy: How to handle existing files/links at the destination.
                           Options: 'fail' (default), 'skip', 'overwrite', 'rename'.
                           Note: 'rename' is only applied to file conflicts during recursion.
                                 For the top-level directory, 'rename' acts like 'fail'.

    Returns:
        True if successful or skipped, False if failed.
    """
    if not source.exists():
        logger.error(f"Source path '{source}' does not exist.")
        return False

    if not destination_dir.is_dir():
        logger.error(f"Destination '{destination_dir}' is not a directory or does not exist.")
        return False

    link_name = name if name else source.name
    link_path = destination_dir / link_name

    # --- Handle Directory Source Recursively ---
    if source.is_dir():
        logger.info(f"Source '{source.name}' is a directory. Recursively hardlinking all files.")
        target_dir_path = link_path
        if target_dir_path.exists():
            logger.warning(f"Target directory path '{target_dir_path}' already exists.")
            effective_dir_conflict_strategy = conflict_strategy
            if conflict_strategy == 'rename':
                logger.warning("'rename' conflict strategy not supported for top-level directory creation. Treating as 'fail'.")
                effective_dir_conflict_strategy = 'fail'
            if effective_dir_conflict_strategy == 'fail':
                logger.error("Conflict resolution set to 'fail'. Aborting directory creation.")
                return False
            elif effective_dir_conflict_strategy == 'skip':
                logger.warning("Conflict resolution set to 'skip'. Skipping directory creation and contents.")
                return True
            elif effective_dir_conflict_strategy == 'overwrite':
                logger.info("Conflict resolution set to 'overwrite'. Attempting to remove existing item...")
                try:
                    if target_dir_path.is_symlink():
                        target_dir_path.unlink()
                        logger.info(f"Removed existing link: {target_dir_path}")
                    elif target_dir_path.is_dir():
                        shutil.rmtree(target_dir_path)
                        logger.info(f"Removed existing directory: {target_dir_path}")
                    else:
                        target_dir_path.unlink()
                        logger.info(f"Removed existing file: {target_dir_path}")
                except OSError as e:
                    logger.error(f"Failed to overwrite '{target_dir_path}': {e}")
                    return False
        # Recursively walk the source directory
        all_success = True
        for root, dirs, files in os.walk(source):
            rel_root = pathlib.Path(root).relative_to(source)
            dest_root = target_dir_path / rel_root if rel_root != pathlib.Path('.') else target_dir_path
            # Create directories in destination
            try:
                dest_root.mkdir(parents=True, exist_ok=True)
                # Set permissions/ownership if needed
                perms = get_app_permissions_for_path(dest_root)
                if perms:
                    set_file_ownership_and_permissions(dest_root, perms['user'], perms['group'], perms['permissions'])
            except Exception as e:
                logger.error(f"Failed to create directory '{dest_root}': {e}")
                all_success = False
                continue
            for file in files:
                src_file = pathlib.Path(root) / file
                dest_file = dest_root / file
                # Handle conflicts for each file
                if dest_file.exists() or dest_file.is_symlink():
                    if conflict_strategy == 'fail':
                        logger.error(f"File conflict at '{dest_file}'. Skipping due to 'fail' strategy.")
                        all_success = False
                        continue
                    elif conflict_strategy == 'skip':
                        logger.info(f"File conflict at '{dest_file}'. Skipping due to 'skip' strategy.")
                        continue
                    elif conflict_strategy == 'overwrite':
                        try:
                            if dest_file.is_dir() and not dest_file.is_symlink():
                                shutil.rmtree(dest_file)
                            else:
                                dest_file.unlink()
                        except Exception as e:
                            logger.error(f"Failed to overwrite '{dest_file}': {e}")
                            all_success = False
                            continue
                    elif conflict_strategy == 'rename':
                        counter = 1
                        original_stem = dest_file.stem
                        original_suffix = dest_file.suffix
                        while dest_file.exists() or dest_file.is_symlink():
                            new_name = f"{original_stem} ({counter}){original_suffix}"
                            dest_file = dest_root / new_name
                            counter += 1
                            if counter > 999:
                                logger.error(f"Could not find available name for '{original_stem}' after 999 attempts. Skipping.")
                                all_success = False
                                continue
                try:
                    logger.info(f"Creating hardlink: '{src_file}' -> '{dest_file}'")
                    os.link(src_file, dest_file)
                    # Set permissions/ownership if needed
                    perms = get_app_permissions_for_path(dest_file)
                    if perms:
                        set_file_ownership_and_permissions(dest_file, perms['user'], perms['group'], perms['permissions'])
                except Exception as e:
                    logger.error(f"Failed to create hardlink '{src_file}' -> '{dest_file}': {e}")
                    all_success = False
        return all_success

    # --- Handle File Source (Hardlink Logic) ---
    elif source.is_file():
        if link_path.exists() or link_path.is_symlink():
            logger.warning(f"Destination path '{link_path}' already exists.")

            if conflict_strategy == 'fail':
                logger.error("Conflict resolution set to 'fail'. Aborting.")
                return False
            elif conflict_strategy == 'skip':
                logger.info("Conflict resolution set to 'skip'. Skipping creation.")
                return True # Indicate success/handled
            elif conflict_strategy == 'overwrite':
                logger.info("Conflict resolution set to 'overwrite'. Attempting to remove existing item...")
                try:
                    # Handle potential directory conflict when overwriting with a file link
                    if link_path.is_dir() and not link_path.is_symlink(): 
                        shutil.rmtree(link_path)
                        logger.info(f"Removed existing directory: {link_path}")
                    else: # Handle file or link
                        link_path.unlink()
                        logger.info(f"Removed existing file/link: {link_path}")
                except OSError as e:
                    logger.error(f"Failed to overwrite '{link_path}': {e}")
                    return False
            elif conflict_strategy == 'rename':
                logger.info("Conflict resolution set to 'rename'. Finding available name...")
                counter = 1
                original_stem = link_path.stem
                original_suffix = link_path.suffix
                while link_path.exists() or link_path.is_symlink():
                    link_name = f"{original_stem} ({counter}){original_suffix}"
                    link_path = destination_dir / link_name
                    counter += 1
                    if counter > 999: # Safety break
                        logger.error(f"Could not find an available name after 999 attempts for '{original_stem}'. Aborting.")
                        return False
                logger.info(f"Found available name: '{link_path}'")
                # link_name is updated, link_path is updated, proceed with creation below
            else:
                # Should not happen if validation is done in CLI/TUI
                logger.error(f"Unknown conflict strategy '{conflict_strategy}'. Aborting.")
                return False

        # Create the hardlink for the file
        try:
            logger.info(f"Creating hardlink: '{source}' -> '{link_path}'")
            os.link(source, link_path)
            # Set permissions/ownership if needed
            perms = get_app_permissions_for_path(link_path)
            if perms:
                set_file_ownership_and_permissions(link_path, perms['user'], perms['group'], perms['permissions'])
            return True
        except OSError as e:
            logger.error(f"Error creating hardlink '{link_path}' -> '{source}': {e}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during file hardlink creation: {e}")
            return False

    else:
        # Handle other source types (sockets, etc.) if necessary, or just report error
        logger.error(f"Source path '{source}' is not a file or directory. Type not supported.")
        return False


@mutation("delete")
def delete_path(path: pathlib.Path) -> dict:
    """Apply the TUI's guarded file/directory deletion rule."""
    if path.is_file():
        try:
            path.unlink()
            logger.info(f"Deleted file: {path.name}")
            return {"ok": True, "status": "deleted_file"}
        except OSError as error:
            logger.error(f"Error deleting file {path.name}: {error}")
            return {"ok": False, "status": "failed", "error": str(error)}
    if not path.is_dir():
        return {"ok": False, "status": "refused", "reason": "target is not a file or directory"}

    try:
        items_inside = list(path.iterdir())
    except OSError as error:
        logger.error(f"Error reading directory {path.name}: {error}")
        return {"ok": False, "status": "failed", "error": str(error)}

    if not items_inside:
        try:
            path.rmdir()
            logger.info(f"Removed empty directory: {path.name}")
            return {"ok": True, "status": "deleted_empty_directory"}
        except OSError as error:
            logger.error(f"Error removing empty directory {path.name}: {error}")
            return {"ok": False, "status": "failed", "error": str(error)}

    try:
        only_hardlinks = all(not item.is_dir() and item.stat().st_nlink > 1 for item in items_inside)
    except OSError as error:
        logger.error(f"Error reading directory {path.name}: {error}")
        return {"ok": False, "status": "failed", "error": str(error)}
    if not only_hardlinks:
        logger.info(f"Directory '{path.name}' contains non-hardlink items. Skipping deletion.")
        return {
            "ok": False,
            "status": "refused",
            "reason": "directory contains non-hardlink content",
        }

    try:
        for item in items_inside:
            item.unlink()
            logger.info(f"Deleted internal hardlink: {item.name}")
        path.rmdir()
        logger.info(f"Removed directory: {path.name}")
        return {"ok": True, "status": "deleted_hardlink_directory"}
    except OSError as error:
        logger.error(f"Error cleaning up directory {path.name}: {error}")
        return {"ok": False, "status": "failed", "error": str(error)}


@mutation("rename")
def rename_directory(path: pathlib.Path, new_name: str) -> dict:
    """Rename a directory with the retained TUI collision rule."""
    if not path.is_dir():
        return {"ok": False, "status": "refused", "reason": "target is not a directory"}
    new_path = path.parent / new_name
    if new_path.exists():
        return {"ok": False, "status": "refused", "reason": "target name already exists"}
    try:
        path.rename(new_path)
        logger.info(f"Renamed directory: {path} -> {new_path}")
        return {"ok": True, "status": "renamed", "path": str(new_path)}
    except OSError as error:
        logger.error(f"Failed to rename directory: {error}")
        return {"ok": False, "status": "failed", "error": str(error)}


@mutation("mkdir")
def create_directory(parent: pathlib.Path, new_name: str) -> dict:
    """Create a directory with the retained TUI collision rule."""
    new_path = parent / new_name
    if new_path.exists():
        return {"ok": False, "status": "refused", "reason": "target name already exists"}
    try:
        new_path.mkdir()
        logger.info(f"Created new directory: {new_path}")
        return {"ok": True, "status": "created", "path": str(new_path)}
    except OSError as error:
        logger.error(f"Failed to create directory: {error}")
        return {"ok": False, "status": "failed", "error": str(error)}

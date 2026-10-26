#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Hardlink indexing and management utilities for Linker."""

import pathlib
import os
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class HardlinkEntry:
    path: pathlib.Path
    nlink: int
    inode: int
    is_hardlink: bool  # True if nlink > 1
    is_dir: bool


def scan_hardlinks(base_path: pathlib.Path) -> List[HardlinkEntry]:
    """
    Scan for files and directories in base_path only (non-recursive), identifying hardlinks.

    Args:
        base_path: The directory to scan (non-recursive).

    Returns:
        List of HardlinkEntry objects for items in the current directory only.
    """
    entries = []
    
    # Only scan the current directory level, not recursively
    try:
        for item_path in base_path.iterdir():
            try:
                stat = item_path.stat()
                nlink = stat.st_nlink
                inode = stat.st_ino
                is_dir = item_path.is_dir()
                is_hardlink = nlink > 1 and not is_dir  # Directories can't be hardlinks
                
                entries.append(HardlinkEntry(
                    path=item_path,
                    nlink=nlink,
                    inode=inode,
                    is_hardlink=is_hardlink,
                    is_dir=is_dir
                ))
            except OSError:
                continue  # Permission denied or other error
    except OSError:
        # Permission denied or directory doesn't exist
        pass
        
    return entries 
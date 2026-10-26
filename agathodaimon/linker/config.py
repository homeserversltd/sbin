# -*- coding: utf-8 -*-
"""
Central configuration for linker TUI.
Contains static paths, keybinds, and other constants.
"""

# Default start directories (in order of preference)
DEFAULT_TORRENTS_DIR = "/mnt/nas/torrents/complete"
DEFAULT_DOWNLOADS_DIR = "/mnt/nas/downloads/complete"
DEFAULT_START_DIRS = [DEFAULT_TORRENTS_DIR, DEFAULT_DOWNLOADS_DIR]

# Keybinds for the TUI
TUI_KEYBINDS = [
    ("h", "go_up", "Go up dir"),
    ("j", "move_down", "Move down"),
    ("k", "move_up", "Move up"),
    ("l", "enter_dir", "Enter dir"),
    ("space", "toggle_select", "Select"),
    ("enter", "deploy", "Deploy"),
    ("d", "deploy", "Deploy"),
    ("p", "deploy", "Deploy"),
    ("delete", "delete_link", "Delete Hardlink"),
    ("r", "rename", "Rename folder"),
    ("n", "new_dir", "New directory"),
    ("q", "quit", "Quit"),
]


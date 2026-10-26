#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TUI browser for linker using Textual, providing nnn-like navigation and selection.

Default start directory:
- /mnt/nas/torrents/complete if exists
- else /mnt/nas/downloads/complete if exists
- else current working directory

After selection, prints 'LINKER_SELECTED:' followed by the absolute paths of selected files, one per line.
"""

import pathlib
import asyncio
from typing import Optional, Set, Dict
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Input, Button, Label
from textual.reactive import reactive
from textual import events
from textual.message import Message
from rich.text import Text
import os
import sys
from agathodaimon.linker.logger_utils import get_logger, deploy_deed
from agathodaimon.linker.config import DEFAULT_START_DIRS, TUI_KEYBINDS
from rich.panel import Panel
from textual.containers import Vertical
from textual.screen import ModalScreen

# Utility to scan for links in a directory
from agathodaimon.linker.link_index import scan_hardlinks
# Import the core link function
from agathodaimon.linker.core import create_directory, create_hardlink, delete_path, rename_directory

logger = get_logger("linker.tui")

class LinkerTUI(App):
    CSS_PATH = None  # Optional: add a CSS file for styling
    BINDINGS = TUI_KEYBINDS

    current_dir = reactive(pathlib.Path.cwd())
    selected: Set[pathlib.Path] = set()
    cursor_index: int = reactive(0)
    items: list = reactive([])
    link_map: Dict[str, bool] = reactive({})

    def __init__(self, start_dir: Optional[str] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if start_dir:
            self.current_dir = pathlib.Path(start_dir)
        else:
            # Use config for start dir preference
            found = False
            for candidate in DEFAULT_START_DIRS:
                p = pathlib.Path(candidate)
                if p.is_dir():
                    self.current_dir = p
                    found = True
                    break
            if not found:
                self.current_dir = pathlib.Path.cwd()
        self.selected = set()
        self.cursor_index = 0
        self.items = []
        self.link_map = {}

    def compose(self) -> ComposeResult:
        # Add a warning banner if not running as root
        if os.geteuid() != 0:
            yield Static(Panel("[bold red]WARNING: You are not running as root. For hardlinking to work, run this tool with sudo.[/bold red]", style="red"), id="root-warning")
        yield Header(show_clock=True)
        yield DataTable(id="filetable")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("#", "Name", "Type", "Hardlinked", "Selected")
        await self.load_directory(self.current_dir)
        table.focus()
        # No need to assign a handler; Textual will call on_data_table_cursor_moved automatically

    async def load_directory(self, path: pathlib.Path, preserve_cursor_index: Optional[int] = None):
        """Loads directory contents into the DataTable, optionally preserving cursor position."""
        self.current_dir = path.resolve()
        logger.debug(f"[load_directory] Loading directory: {self.current_dir}")
        original_items = self.items[:]
        self.items = []
        self.link_map = {}
        
        # Log the selected set once per load
        logger.debug(f"[load_directory] Current selected set: {self.selected}")

        # --- Diagnostic: List directory contents using os.listdir ---
        try:
            raw_listdir = os.listdir(str(self.current_dir))
            logger.debug(f"[load_directory] os.listdir({self.current_dir}): {raw_listdir}")
        except Exception as e:
            logger.error(f"[load_directory] os.listdir error for {self.current_dir}: {e}")
            raw_listdir = None
        
        # Scan for hardlinks in this directory
        hardlinks = scan_hardlinks(self.current_dir)
        hardlink_map = {e.path.name: e for e in hardlinks if not e.is_dir}
        
        # List items
        try:
            entries = list(self.current_dir.iterdir())
            logger.debug(f"iterdir found: {[e.name for e in entries]}")
            entries.sort(key=lambda p: (not p.is_dir(), p.name.lower()))
        except Exception as e:
            logger.error(f"Error listing directory {self.current_dir}: {e}")
            entries = []
        
        # --- Diagnostic: Warn if os.listdir shows files but iterdir is empty ---
        if raw_listdir is not None and len(raw_listdir) > 0 and len(entries) == 0:
            logger.warning(f"[load_directory] os.listdir shows files but iterdir is empty for {self.current_dir}!")
        
        self.items = entries
        self.link_map = {e.name: (e.name in hardlink_map and hardlink_map[e.name].is_hardlink) for e in entries}
        
        # Get the table widget
        table = self.query_one(DataTable)
        
        # Use clear() followed by add_row efficiently
        table.clear()
        
        # Add the rows
        for idx, entry in enumerate(entries):
            try:
                is_dir = entry.is_dir()
                is_entry_hardlink = False
                nlink = 1
                if not is_dir and entry.name in hardlink_map:
                    is_entry_hardlink = hardlink_map[entry.name].is_hardlink
                    nlink = hardlink_map[entry.name].nlink
                selected = entry.resolve() in self.selected
                name_text = Text(entry.name)
                if is_dir:
                    name_text.stylize("bold blue")
                if is_entry_hardlink:
                    name_text.stylize("magenta")
                
                table.add_row(
                    str(idx+1),
                    name_text,
                    "Dir" if is_dir else ("Hardlink" if is_entry_hardlink else "File"),
                    f"[magenta]{nlink}[/magenta]" if is_entry_hardlink else "",
                    "[green]✓[/green]" if selected else ""
                )
            except Exception as e:
                logger.error(f"ERROR processing entry {entry.name}: {e}")
        
        # Restore cursor position if requested and valid, otherwise keep current index if possible
        if preserve_cursor_index is not None and 0 <= preserve_cursor_index < len(entries):
            self.cursor_index = preserve_cursor_index
        elif self.cursor_index >= len(entries) or self.cursor_index < 0:
            self.cursor_index = 0
        # else: keep self.cursor_index as is

        if entries:
            table.cursor_coordinate = (self.cursor_index, 0)
        
        # Update header with current directory path
        self.query_one(Header).sub_title = str(self.current_dir)

    async def on_key(self, event: events.Key) -> None:
        """Handle key presses globally, block up/down/left/right arrows for navigation so only vim keys work."""
        table = self.query_one(DataTable)
        if table.has_focus:
            if event.key in ("up", "down", "left", "right"):
                event.prevent_default()
                event.stop()
            # Only vim keys (h/j/k/l) will work via BINDINGS

    def action_move_up(self):
        table = self.query_one(DataTable)
        if self.cursor_index > 0:
            self.cursor_index -= 1
            table.cursor_coordinate = (self.cursor_index, 0)
        # Always sync after move
        self.cursor_index = table.cursor_coordinate[0]
        print(f"[DEBUG] Highlighted row changed: {self.cursor_index}")

    def action_move_down(self):
        table = self.query_one(DataTable)
        if self.cursor_index < len(self.items) - 1:
            self.cursor_index += 1
            table.cursor_coordinate = (self.cursor_index, 0)
        # Always sync after move
        self.cursor_index = table.cursor_coordinate[0]
        print(f"[DEBUG] Highlighted row changed: {self.cursor_index}")

    def action_go_up(self):
        parent = self.current_dir.parent
        logger.debug(f"[go_up] Current: {self.current_dir}, Parent: {parent}")
        if parent != self.current_dir:
            asyncio.create_task(self.load_directory(parent))

    def action_enter_dir(self):
        if not self.items:
            logger.debug("[enter_dir] No items to enter.")
            return
        entry = self.items[self.cursor_index]
        logger.debug(f"[enter_dir] Attempting to enter: {entry}")
        if entry.is_dir():
            asyncio.create_task(self.load_directory(entry))

    def action_toggle_select(self):
        if not self.items or self.cursor_index >= len(self.items):
            logger.debug(f"[toggle_select] No items or cursor out of range. items={len(self.items)}, cursor_index={self.cursor_index}")
            return
        entry = self.items[self.cursor_index]
        entry_resolved = entry.resolve()
        logger.debug(f"[toggle_select] Attempting to toggle: {entry_resolved}")
        logger.debug(f"[toggle_select] Selected set BEFORE: {self.selected}")
        if entry_resolved in self.selected:
            logger.debug(f"[toggle_select] Removing from selection: {entry_resolved}")
            self.selected.remove(entry_resolved)
        else:
            logger.debug(f"[toggle_select] Adding to selection: {entry_resolved}")
            self.selected.add(entry_resolved)
        logger.debug(f"[toggle_select] Selected set AFTER: {self.selected}")
        # Move cursor down if not at the end
        if self.cursor_index < len(self.items) - 1:
            self.cursor_index += 1
        # Always reload the directory to update the UI, preserving new cursor position
        asyncio.create_task(self.load_directory(self.current_dir, preserve_cursor_index=self.cursor_index))

    def action_delete_link(self):
        if not self.items or self.cursor_index >= len(self.items):
            self.bell()
            return
        result = delete_path(self.items[self.cursor_index])
        if result["ok"]:
            current_index = self.cursor_index
            if current_index >= len(self.items) - 1 and len(self.items) > 1:
                current_index -= 1
            asyncio.create_task(self.load_directory(self.current_dir, preserve_cursor_index=current_index))
        elif result["status"] == "failed":
            self.bell()
    @deploy_deed
    def action_deploy(self):
        if not self.selected:
            self.bell()
            return
        destination_dir = self.current_dir.resolve()
        success_count = 0
        fail_count = 0
        items_to_deploy = list(self.selected)
        logger.info(f"Deploying {len(items_to_deploy)} selected items to: {destination_dir}")
        for source_path in items_to_deploy:
            if not source_path.exists():
                 logger.warning(f"Source {source_path} no longer exists. Skipping.")
                 fail_count += 1
                 continue
            success = create_hardlink(
                source=source_path, 
                destination_dir=destination_dir, 
                name=None, 
                conflict_strategy='rename' 
            )
            if success:
                success_count += 1
                logger.info(f"[OK] Hardlinked: {source_path.name}")
            else:
                fail_count += 1
                logger.error(f"[FAIL] Hardlinking: {source_path.name}")
        summary = f"Deployment complete. Success: {success_count}, Failed: {fail_count}."
        logger.info(summary)
        self.bell()
        self.selected = set()
        current_index = self.cursor_index
        asyncio.create_task(self.load_directory(self.current_dir, preserve_cursor_index=current_index))

    def action_quit(self):
        self.exit()

    def on_unmount(self) -> None:
        logger.info("Linker TUI session ended.")

    def on_data_table_row_highlighted(self, event) -> None:
        self.cursor_index = event.cursor_row
        print(f"[DEBUG] Highlighted row changed: {self.cursor_index}")

    def action_rename(self):
        if not self.items or self.cursor_index >= len(self.items):
            self.bell()
            return
        entry = self.items[self.cursor_index]
        if not entry.is_dir():
            self.bell()
            return
        old_name = entry.name

        async def do_rename(new_name):
            result = rename_directory(entry, new_name)
            if not result["ok"]:
                self.bell()
                return
            await self.load_directory(self.current_dir, preserve_cursor_index=self.cursor_index)

        async def cancel_rename():
            pass

        modal_screen = TextInputModalScreen(
            prompt=f"Rename folder: {old_name}",
            initial_value=old_name,
            on_submit=do_rename,
            on_cancel=cancel_rename,
            ok_label="OK",
            cancel_label="Cancel"
        )
        self.push_screen(modal_screen)
    def action_new_dir(self):
        async def do_create_dir(new_dir_name):
            result = create_directory(self.current_dir, new_dir_name)
            if not result["ok"]:
                self.bell()
                return
            await self.load_directory(self.current_dir, preserve_cursor_index=self.cursor_index)

        async def cancel_create_dir():
            pass

        modal_screen = TextInputModalScreen(
            prompt="New directory name:",
            initial_value="",
            on_submit=do_create_dir,
            on_cancel=cancel_create_dir,
            ok_label="Create",
            cancel_label="Cancel"
        )
        self.push_screen(modal_screen)
# --- Generic Modal for Text Input ---
class TextInputModalScreen(ModalScreen):
    """
    Generic modal dialog for text input. Can be used for renaming, creating, or any text entry.
    Accepts a prompt label, initial value, and callbacks for submit/cancel.
    """
    def __init__(self, prompt, initial_value, on_submit, on_cancel, ok_label="OK", cancel_label="Cancel"):
        super().__init__()
        self.prompt = prompt
        self.input = Input(value=initial_value, placeholder=prompt)
        self.on_submit = on_submit
        self.on_cancel = on_cancel
        self.error_label = Label("")
        self.ok_button = Button(ok_label, id="ok")
        self.cancel_button = Button(cancel_label, id="cancel")

    def compose(self):
        yield Vertical(
            Label(self.prompt),
            self.input,
            self.error_label,
            self.ok_button,
            self.cancel_button,
        )

    async def on_button_pressed(self, event):
        if event.button.id == "ok":
            await self._try_submit()
        elif event.button.id == "cancel":
            await self._cancel()

    async def on_key(self, event):
        if event.key == "escape" or event.key == "q":
            await self._cancel()
            event.stop()
        elif event.key == "enter":
            if self.input.has_focus:
                await self._try_submit()
                event.stop()

    async def _try_submit(self):
        value = self.input.value.strip()
        if not value:
            self.error_label.update("Value cannot be empty.")
            return
        self.dismiss()
        await self.on_submit(value)

    async def _cancel(self):
        await self.on_cancel()
        self.dismiss()

if __name__ == "__main__":
    import sys
    start_dir = sys.argv[1] if len(sys.argv) > 1 else None
    app = LinkerTUI(start_dir=start_dir)
    app.run()
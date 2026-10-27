"""Owner-side cache and lifetime management for the Face launch menu."""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


PINS = (
    "chromium.desktop", "org.kde.dolphin.desktop", "org.kde.kate.desktop",
    "org.kde.kcalc.desktop", "libreoffice-writer.desktop", "libreoffice-calc.desktop",
    "libreoffice-impress.desktop", "mpv.desktop",
)


def write_pins(home):
    home = Path(home)
    directories = (home / ".local/share/applications", Path("/usr/local/share/applications"),
                   Path("/usr/share/applications"))
    lines = []
    for index, desktop_id in enumerate(PINS):
        path = next((directory / desktop_id for directory in directories
                     if (directory / desktop_id).is_file()), None)
        if path is not None:
            lines.append(f"{100 - index} {path}\n")
    cache = home / ".local/state/hometv-launcher/wofi-drun-cache"
    cache.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(cache, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise OSError("unsafe launcher cache")
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.writelines(lines)
    finally:
        if fd >= 0:
            os.close(fd)
    return len(lines)


def walk(node):
    yield node
    for child in node.get("nodes", []) + node.get("floating_nodes", []):
        yield from walk(child)


def move_command(output, menu, pid):
    o, r = output["rect"], menu["rect"]
    return f"[pid={pid}] move absolute position {o['x'] + 12} {o['y'] + o['height'] - r['height'] - 44}"


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def watch(pid):
    placed = seen = False
    deadline = time.monotonic() + 3
    while alive(pid):
        try:
            result = subprocess.run(["swaymsg", "-t", "get_tree"], capture_output=True,
                                    text=True, timeout=2, check=True)
            nodes = list(walk(json.loads(result.stdout)))
            menu = next((node for node in nodes if node.get("pid") == pid), None)
            if menu and not placed:
                output = next((node for node in nodes if node.get("type") == "output"
                               and node.get("name") != "__i3"
                               and any(child is menu for child in walk(node))), None)
                if output:
                    subprocess.run(["swaymsg", "-q", move_command(output, menu, pid)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=2, check=True)
                    placed = True
            focused = next((node for node in nodes if node.get("focused")), None)
            if focused is not None and focused.get("pid") == pid:
                seen = True
            elif seen or time.monotonic() >= deadline:
                os.kill(pid, signal.SIGTERM)
                break
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            break
        time.sleep(0.1)


if __name__ == "__main__":
    if sys.argv[1] == "pin":
        print(write_pins(sys.argv[2]))
    elif sys.argv[1] == "watch":
        watch(int(sys.argv[2]))

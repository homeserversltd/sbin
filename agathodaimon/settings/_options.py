"""Live, read-only choices for the settings fields that have a known set."""
from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

from agathodaimon.settings import _shared


def _choices(items):
    return [{"value": value, "label": label} for value, label in items if value and label]


def _sound(devices):
    ok, text, _ = _shared.command(["pactl", "-f", "json", "list", devices])
    if ok:
        try:
            data = json.loads(text)
            if not isinstance(data, list):
                raise ValueError("not a list")
            return _choices((item.get("name"), item.get("description") or item.get("name"))
                            for item in data if isinstance(item, dict)
                            and not (devices == "sources" and
                                     (item.get("monitor_of_sink_name") or
                                      (isinstance(item.get("name"), str) and item["name"].endswith(".monitor")))))
        except (ValueError, TypeError):
            pass
    ok, text, _ = _shared.command(["pactl", "list", devices])
    if not ok:
        return []
    result = []
    for block in re.split(r"(?m)^(?:Sink|Source) #\d+\s*$", text):
        name = re.search(r"(?m)^\s*Name:\s*(.+?)\s*$", block)
        description = re.search(r"(?m)^\s*Description:\s*(.+?)\s*$", block)
        monitor = re.search(r"(?m)^\s*Monitor of Sink:\s*(.+?)\s*$", block)
        if name and not (devices == "sources" and
                         (name.group(1).endswith(".monitor") or
                          (monitor and monitor.group(1).lower() not in {"n/a", "none"}))):
            result.append((name.group(1), description.group(1) if description else name.group(1)))
    return _choices(result)


def _keyboard():
    text = Path('/usr/share/X11/xkb/rules/evdev.lst').read_text(encoding='utf-8')
    active = False
    result = []
    for line in text.splitlines():
        if line.startswith('!'):
            if active:
                break
            active = line.strip() == '! layout'
        elif active:
            parts = line.split(None, 1)
            if len(parts) == 2:
                result.append((parts[0], parts[1]))
    return _choices(result)


def _locales():
    ok, text, _ = _shared.command(['locale', '-a'])
    if not ok:
        return []
    result = []
    for raw in text.splitlines():
        match = re.fullmatch(r'([A-Za-z0-9_+-]+)\.(?:utf-?8)(@[A-Za-z0-9_-]+)?', raw, re.I)
        if not match:
            continue
        name, modifier = match.group(1), match.group(2) or ''
        value = name + '.UTF-8' + modifier
        label = value
        try:
            source = (Path('/usr/share/i18n/locales') / (name + modifier)).read_text(encoding='utf-8')
            section = re.search(r'(?ms)^LC_IDENTIFICATION\s*$\n(.*?)^END LC_IDENTIFICATION\s*$', source)
            title = re.search(r'(?m)^\s*title\s+"([^"]+)"', section.group(1)) if section else None
            if title:
                label = title.group(1)
        except (OSError, UnicodeError):
            pass
        result.append((value, label))
    return _choices(result)


def _ini(path, section):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read(path, encoding='utf-8')
    return parser[section] if parser.has_section(section) else {}


def _themes():
    icons, cursors, seen = [], [], set()
    for root in (_shared.home() / '.local/share/icons', Path('/usr/share/icons')):
        if not root.is_dir():
            continue
        for path in sorted(root.iterdir()):
            if not path.is_dir() or path.name in seen:
                continue
            seen.add(path.name)
            try:
                theme = _ini(path / 'index.theme', 'Icon Theme')
                label = theme.get('Name', path.name) or path.name
                if theme.get('Directories', '').strip():
                    icons.append((path.name, label))
                if (path / 'cursors').is_dir():
                    cursors.append((path.name, label))
            except (OSError, UnicodeError, configparser.Error):
                if (path / 'cursors').is_dir():
                    cursors.append((path.name, path.name))
    return {'icon_theme': _choices(icons), 'cursor_theme': _choices(cursors)}


def _applications():
    result = {key: [] for key in _shared.MIME_KEYS}
    seen = set()
    for root in (_shared.home() / '.local/share/applications', Path('/usr/share/applications')):
        if not root.is_dir():
            continue
        for path in sorted(root.rglob('*.desktop')):
            desktop_id = '-'.join(path.relative_to(root).parts)
            if desktop_id in seen:
                continue
            seen.add(desktop_id)
            try:
                entry = _ini(path, 'Desktop Entry')
                if entry.get('Type') != 'Application' or entry.get('NoDisplay', '').lower() == 'true' or entry.get('Hidden', '').lower() == 'true':
                    continue
                label = entry.get('Name', '').strip()
                if not label:
                    continue
                mimes = set(entry.get('MimeType', '').split(';'))
                categories = set(entry.get('Categories', '').split(';'))
                for field, types in _shared.MIME_KEYS.items():
                    if (field == 'terminal' and 'TerminalEmulator' in categories) or (field != 'terminal' and mimes.intersection(types)):
                        result[field].append((desktop_id, label))
            except (OSError, UnicodeError, configparser.Error):
                continue
    return {field: _choices(entries) for field, entries in result.items()}


def _timezones():
    ok, text, _ = _shared.command(['timedatectl', 'list-timezones'])
    return _choices((zone, zone.replace('_', ' ')) for zone in text.splitlines()) if ok else []


def options(kind):
    """Failures and empty enumerations leave the relevant field absent."""
    readers = {
        'sound': {'output_device': lambda: _sound('sinks'), 'input_device': lambda: _sound('sources')},
        'keyboard': {'keyboard_layout': _keyboard},
        'region': {'locale': _locales},
        'datetime': {'timezone': _timezones},
    }
    result = {}
    if kind in ('appearance', 'default-apps'):
        try:
            result = _themes() if kind == 'appearance' else _applications()
        except Exception:
            return {}
    else:
        for field, reader in readers.get(kind, {}).items():
            try:
                result[field] = reader()
            except Exception:
                continue
    return {field: entries for field, entries in result.items() if entries}

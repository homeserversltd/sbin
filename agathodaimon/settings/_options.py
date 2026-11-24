"""Live, read-only choices for the settings fields that have a known set."""
from __future__ import annotations

import configparser
import json
import os
import re
import shlex
import subprocess
from pathlib import Path

from agathodaimon.settings import _locale_names, _shared


def _choices(items):
    return [{"value": value, "label": label} for value, label in items if value and label]


_POWER_PROFILE_LABELS = {"power-saver": "Power saver", "balanced": "Balanced", "performance": "Performance"}


def power_profiles() -> tuple[str | None, list[dict[str, str | bool]]]:
    # Do not start a stopped service just by opening Settings.
    running, _, _ = _shared.command(["systemctl", "is-active", "--quiet", "power-profiles-daemon.service"])
    if not running:
        return None, []
    listed, text, _ = _shared.command(["powerprofilesctl", "list"])
    names = dict.fromkeys(re.findall(r"(?m)^[ \t]*\*?[ \t]*([a-z][a-z0-9-]*):[ \t]*$", text)) if listed else {}
    if not names:
        return None, []
    got, current, _ = _shared.command(["powerprofilesctl", "get"])
    if not got or current not in names:
        return None, []
    platform = (Path("/sys/firmware/acpi/platform_profile").is_file()
                or any(Path("/sys/class/platform-profile").glob("*/profile")))
    choices = _choices((name, _POWER_PROFILE_LABELS.get(name, name.replace("-", " ").capitalize()))
                       for name in names)
    if not platform:
        for choice in choices:
            # The door preserves extra properties of an accepted choice.
            choice["cpu_only"] = True
    return current, choices


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
                                     (item.get("monitor_source") or item.get("monitor_of_sink_name") or
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


def _locale_loads_as_utf8(value: str, environment: dict[str, str]) -> bool:
    try:
        answer = subprocess.run(['locale', 'charmap'], env={**environment, 'LC_ALL': value},
                                capture_output=True, timeout=3, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    # glibc may return 0 with a fallback charmap and warnings on stderr.
    return answer.returncode == 0 and not answer.stderr and answer.stdout.strip() == b'UTF-8'


def _installed_locales(supported: dict[str, str | None]) -> set[str] | None:
    ok, text, _ = _shared.command(['locale', '-a'])
    if not ok:
        return None
    native = text.splitlines()
    installed = {value for raw in native if (value := _locale_names.utf8_value(raw))}
    environment = os.environ.copy()
    locpath = environment.pop('LOCPATH', '')
    for raw in native:
        # A bare locale -a entry may use a legacy codeset (including C itself).
        value = _locale_names.utf8_value(raw, allow_bare=True)
        if value and value in supported and value not in installed and _locale_loads_as_utf8(raw, environment):
            installed.add(value)

    # locale -a sees the system inventory, not private localedef directories.
    # Let glibc confirm the compiled locale is loadable rather than trust the name.
    private = {**environment, 'LOCPATH': locpath}
    for root in filter(None, locpath.split(':')):
        try:
            for entry in Path(root).iterdir():
                value = _locale_names.utf8_value(entry.name, allow_bare=True)
                if (value and value in supported and value not in installed and (entry / 'LC_CTYPE').is_file()
                        and _locale_loads_as_utf8(value, private)):
                    installed.add(value)
        except OSError:
            continue
    return installed


def _locales():
    names = _locale_names.supported_labels()
    installed = _installed_locales(names) if names else None
    if installed is None:
        return []
    entries = [{'value': value, 'label': name or value, 'installed': value in installed}
               for value, name in names.items()]
    return sorted(entries, key=lambda entry: (entry['label'].casefold(), entry['value']))


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


def _exec_basename(command):
    lexer = shlex.shlex(command, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        program = lexer.get_token()
    except ValueError:
        return ''
    return Path(program).name if program else ''


def _applications(current_values=None):
    result = {key: [] for key in _shared.MIME_KEYS}
    current = current_values or {}
    wanted = {current.get(field) for field in result}
    current_labels = {}
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
                if entry.get('Type') != 'Application':
                    continue
                label = entry.get('Name', '').strip()
                # A current default can be named even when it is not a regular choice.
                if desktop_id in wanted:
                    current_labels[desktop_id] = label or _exec_basename(entry.get('Exec', ''))
                if not label or entry.get('NoDisplay', '').lower() == 'true' or entry.get('Hidden', '').lower() == 'true':
                    continue
                mimes = set(entry.get('MimeType', '').split(';'))
                categories = set(entry.get('Categories', '').split(';'))
                for field, types in _shared.MIME_KEYS.items():
                    if (field == 'terminal' and 'TerminalEmulator' in categories) or (field != 'terminal' and mimes.intersection(types)):
                        result[field].append((desktop_id, label))
            except (OSError, UnicodeError, configparser.Error):
                continue
    for field, entries in result.items():
        desktop_id = current.get(field)
        label = current_labels.get(desktop_id)
        if label and all(value != desktop_id for value, _ in entries):
            entries.append((desktop_id, label))
    return {field: _choices(entries) for field, entries in result.items()}


def _timezones():
    ok, text, _ = _shared.command(['timedatectl', 'list-timezones'])
    return _choices((zone, zone.replace('_', ' ')) for zone in text.splitlines()) if ok else []


def options(kind, *, current_values=None):
    """Failures and empty enumerations leave the relevant field absent."""
    readers = {
        'sound': {'output_device': lambda: _sound('sinks'), 'input_device': lambda: _sound('sources')},
        'keyboard': {'keyboard_layout': _keyboard},
        'region': {'locale': _locales},
        'datetime': {'timezone': _timezones,
                     'time_format': lambda: _choices((('24h', '24-hour'), ('12h', '12-hour')))},
    }
    result = {}
    if kind in ('appearance', 'default-apps'):
        try:
            result = _themes() if kind == 'appearance' else _applications(current_values)
        except Exception:
            return {}
    else:
        for field, reader in readers.get(kind, {}).items():
            try:
                result[field] = reader()
            except Exception:
                continue
    return {field: entries for field, entries in result.items() if entries}

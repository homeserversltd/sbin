"""Endonyms for glibc locales, shared by the region choices and readers."""
from __future__ import annotations

import gettext
import json
import re
import struct
import unicodedata
from collections import Counter
from functools import lru_cache
from pathlib import Path

_I18N = Path('/usr/share/i18n')
_ISO = Path('/usr/share/iso-codes/json')
_CATALOGS = '/usr/share/locale'
_LOCALE_ID = re.compile(r'([A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_-]+))?(@[A-Za-z0-9_-]+)?')
_UTF8 = {'utf-8', 'utf8'}
_ADDRESS = re.compile(r'(?ms)^LC_ADDRESS[^\S\n]*\n(.*?)^END LC_ADDRESS\b')
_ADDRESS_FIELDS = re.compile(r'(?m)^[ \t]*(lang_name|country_name|copy)[ \t]+"([^"]*)"')
_UNICODE = re.compile(r'<U([0-9A-Fa-f]{4,8})>')
_LABEL_LIMIT = 200  # settings option projection in Caduceus


def utf8_value(locale_id: str, *, allow_bare: bool = False) -> str | None:
    """Keep the base and modifier, spelling the UTF-8 codeset before the modifier."""
    match = _LOCALE_ID.fullmatch(locale_id)
    if not match:
        return None
    base, codeset, modifier = match.groups()
    if (codeset is None and allow_bare) or (codeset and codeset.lower() in _UTF8):
        return base + '.UTF-8' + (modifier or '')
    return None


def _supported_values() -> list[str]:
    try:
        text = (_I18N / 'SUPPORTED').read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return []
    values = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].lower() in _UTF8:
            value = utf8_value(fields[0], allow_bare=True)
            if value:
                values.append(value)
    return values


def _decoded(text: str) -> str:
    def character(match: re.Match[str]) -> str:
        point = int(match[1], 16)
        return chr(point) if 0 < point <= 0x10ffff and not 0xd800 <= point <= 0xdfff else ''

    return unicodedata.normalize('NFC', _UNICODE.sub(character, text).strip())


def _address_names(base: str, modifier: str) -> tuple[str, str]:
    """Follow LC_ADDRESS copies only within the language; keep the target's region."""
    language = base.partition('_')[0]
    source = base + modifier
    seen = set()
    while source not in seen:
        seen.add(source)
        try:
            text = (_I18N / 'locales' / source).read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            break
        section = _ADDRESS.search(text)
        if not section:
            break
        fields = dict(_ADDRESS_FIELDS.findall(section[1]))
        copy = fields.get('copy')
        if not copy:
            source_base = source.partition('@')[0]
            country = fields.get('country_name', '') if source_base == base else ''
            return _decoded(fields.get('lang_name', '')), _decoded(country)
        match = _LOCALE_ID.fullmatch(copy)
        if not match or match[1].partition('_')[0] != language:
            break
        source = match[1] + (match[3] or '')
    return '', ''


@lru_cache(maxsize=3)
def _iso_names(table: str) -> dict[str, str]:
    try:
        records = json.loads((_ISO / f'iso_{table}.json').read_text(encoding='utf-8'))[table]
        return {record[key]: record['name'] for record in records
                for key in ('alpha_2', 'alpha_3', 'bibliographic') if key in record}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def _iso_name(table: str, code: str, languages: list[str]) -> str:
    english = _iso_names(table).get(code, '')
    if not english:
        return ''
    try:
        catalog = gettext.translation(f'iso_{table}', localedir=_CATALOGS, languages=languages, fallback=True)
        return unicodedata.normalize('NFC', catalog.gettext(english).strip()) or english
    except (OSError, UnicodeError, struct.error):
        return english


def _name(base: str, modifier: str) -> str | None:
    if base in ('C', 'POSIX'):
        return 'C'
    language, _, territory = base.partition('_')
    lang_name, country_name = _address_names(base, modifier)
    languages = [base + modifier, language + modifier, language]
    if not lang_name:
        lang_name = _iso_name('639-2', language, languages) or _iso_name('639-3', language, languages)
    if not lang_name:
        return None
    if territory:
        country_name = country_name or _iso_name('3166-1', territory, languages)
    return f'{lang_name} ({country_name})' if territory and country_name else lang_name


def _qualified(name: str, suffix: str = '') -> str:
    room = _LABEL_LIMIT - len(suffix)
    if len(name) > room:
        name = name[:room - 1].rstrip() + '…'
    return name + suffix


def supported_labels() -> dict[str, str | None]:
    """Build the supported UTF-8 snapshot and disambiguate names across it."""
    labels = {}
    for value in _supported_values():
        base, _, rest = value.partition('.')
        _, sep, modifier = rest.partition('@')
        name = _name(base, sep + modifier)
        labels[value] = _qualified(name) if name else None

    repeats = Counter(labels.values())
    for value, name in labels.items():
        if name and repeats[name] > 1 and '@' in value:
            labels[value] = _qualified(name, ' — ' + value.split('@', 1)[1])

    # Leave true endonyms alone unless they still collide. Reserve the value
    # as the display fallback for a locale with no usable language name.
    repeats = Counter(name or value for value, name in labels.items())
    taken = set(repeats)
    for value, name in labels.items():
        if name and repeats[name] > 1:
            candidate = _qualified(name, f' [{value}]')
            index = 2
            while candidate in taken:
                candidate = _qualified(name, f' [{value} #{index}]')
                index += 1
            labels[value] = candidate
            taken.add(candidate)
    return labels


def label(locale_id: str) -> str | None:
    """Return the same endonym as the list, even for another codeset spelling."""
    match = _LOCALE_ID.fullmatch(locale_id)
    if not match:
        return None
    base, _, modifier = match.groups()
    modifier = modifier or ''
    labels = supported_labels()
    value = base + '.UTF-8' + modifier
    return labels[value] if value in labels else _name(base, modifier)

"""Owner-controlled HDMI EDID firmware, applied at the next boot."""
import hashlib
import os
import re
from pathlib import Path

from agathodaimon._nidus.path import appliance_runtime_path
from agathodaimon._nidus.run import run
from agathodaimon._nidus.write import WriteError, write

NAME = re.compile(r"HDMI-[A-Za-z0-9]+-[0-9]+")
REFERENCE = re.compile(r"drm\.edid_firmware=(HDMI-[A-Za-z0-9]+-[0-9]+):edid/([A-Za-z0-9_-]+\.bin)")
COMMANDS = [( ["update-initramfs", "-u", "-k", "all"], 600), (["update-grub"], 300)]


def path(name):
    # Use the existing validated scratch-root resolver, not a second root policy.
    return appliance_runtime_path("profile").parents[2] / name.lstrip("/")


def connectors():
    rows = []
    for entry in sorted(path('/sys/class/drm').glob('*-HDMI-*')):
        match = re.fullmatch(r'card[0-9]+-(HDMI-[A-Za-z0-9]+-[0-9]+)', entry.name)
        if not match:
            continue
        status = (entry / 'status').read_text().strip()
        edid = (entry / 'edid').read_bytes()
        rows.append((match.group(1), entry, status, edid))
    return rows


def configuration():
    hook = path('/etc/initramfs-tools/hooks/hdmi-hold-edid')
    grub = path('/etc/default/grub.d/90-hdmi-hold.cfg')
    try:
        text = grub.read_text()
    except FileNotFoundError:
        text = ''
    match = REFERENCE.search(text)
    return hook, grub, match


def read_state():
    hook, grub, match = configuration()
    connector, filename = match.groups() if match else (None, None)
    firmware = path('/usr/lib/firmware/edid/' + filename) if filename else None
    try:
        cmdline = path('/proc/cmdline').read_text()
    except FileNotFoundError:
        cmdline = ''
    current = REFERENCE.search(cmdline)
    forced = bool(current and f'video={current.group(1)}:e' in cmdline.split())
    return {'connectors': [{'connector': n, 'sysfs': str(p), 'status': s, 'edid_size': len(e)} for n, p, s, e in connectors()],
            'files': {'firmware': {'path': str(firmware) if firmware else None, 'exists': firmware.is_file() if firmware else False, 'connector': connector},
                      'hook': {'path': str(hook), 'exists': hook.is_file(), 'connector': connector},
                      'drop_in': {'path': str(grub), 'exists': grub.is_file(), 'connector': connector}},
            'held_now': forced, 'edid_firmware_now': bool(current), 'held_now_connector': current.group(1) if current else None,
            'held_next_boot': bool(match)}


def render(connector, edid):
    filename = connector + '.bin'
    hook = ('#!/bin/sh\n'
            '# settings/display/hdmi-hold: carry the held TV EDID into the initramfs (i915 loads there).\n'
            'PREREQ=""\n'
            'prereqs() { echo "$PREREQ"; }\n'
            'case "$1" in prereqs) prereqs; exit 0;; esac\n'
            '. /usr/share/initramfs-tools/hook-functions\n'
            'mkdir -p "${DESTDIR}/usr/lib/firmware/edid"\n'
            f'cp /usr/lib/firmware/edid/{filename} "${{DESTDIR}}/usr/lib/firmware/edid/{filename}"\n')
    grub = f'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT drm.edid_firmware={connector}:edid/{filename} video={connector}:e"\n'
    return [(path('/usr/lib/firmware/edid/' + filename), edid, 0o644),
            (path('/etc/initramfs-tools/hooks/hdmi-hold-edid'), hook.encode(), 0o755),
            (path('/etc/default/grub.d/90-hdmi-hold.cfg'), grub.encode(), 0o644)]


def execute(verb, payload):
    state = read_state()
    if verb == 'read':
        return {'ok': True, 'observed': state, 'mutationPerformed': False}
    dry = payload.get('dry-run', False)
    if not isinstance(dry, bool):
        raise ValueError('hdmi-hold-invalid-dry-run')
    hook, grub, old = configuration()
    if verb == 'hold':
        selected = payload.get('connector')
        rows = connectors()
        if selected is None:
            connected = [r for r in rows if r[2] == 'connected']
            if len(connected) != 1:
                raise ValueError('hdmi-hold-exactly-one-connected-required')
            selected = connected[0][0]
        if not isinstance(selected, str) or not NAME.fullmatch(selected):
            raise ValueError('hdmi-hold-invalid-connector')
        matches = [r for r in rows if r[0] == selected]
        if len(matches) != 1 or matches[0][2] != 'connected' or not matches[0][3]:
            raise ValueError('hdmi-hold-connected-edid-required')
        # Never orphan a prior firmware file or overwrite an unrecognized drop-in.
        if grub.exists() and (old is None or old.group(1) != selected or old.group(2) != selected + '.bin'):
            raise ValueError('hdmi-hold-existing-link-release-first')
        edits = render(selected, matches[0][3])
        # A fresh hold never adopts unrelated files at either fixed target.
        if not grub.exists() and any(p.exists() or p.is_symlink() for p, _, _ in edits[:2]):
            raise ValueError('hdmi-hold-existing-target-unmanaged')
        # An existing hook must be our exact rendered program, not another file.
        if grub.exists() and hook.exists() and hook.read_bytes() != edits[1][1]:
            raise ValueError('hdmi-hold-existing-hook-unmanaged')
    else:
        if grub.exists() and old is None:
            raise ValueError('hdmi-hold-drop-in-unrecognized')
        hook_file = None
        if hook.exists():
            hook_text = hook.read_text()
            hook_match = re.search(r'^cp /usr/lib/firmware/edid/([A-Za-z0-9_-]+\.bin) "\$\{DESTDIR\}/usr/lib/firmware/edid/\1"$', hook_text, re.MULTILINE)
            if not hook_match:
                raise ValueError('hdmi-hold-existing-hook-unmanaged')
            hook_file = hook_match.group(1)
            if old and old.group(2) != hook_file:
                raise ValueError('hdmi-hold-file-reference-mismatch')
        if old:
            firmware = path('/usr/lib/firmware/edid/' + old.group(2))
            edits = [(firmware, None, 0), (hook, None, 0), (grub, None, 0)]
        elif hook_file:
            firmware = path('/usr/lib/firmware/edid/' + hook_file)
            edits = [(firmware, None, 0), (hook, None, 0), (grub, None, 0)]
        else:
            edits = []
    plan = [{'path': str(p), 'action': 'remove' if data is None else 'write',
             'mode': oct(mode) if data is not None else None,
             'sha256': hashlib.sha256(data).hexdigest() if data is not None else None,
             'text': data.decode() if data is not None and p != edits[0][0] else None} for p, data, mode in edits]
    commands = [{'argv': argv, 'deadline_seconds': timeout} for argv, timeout in COMMANDS]
    result = {'ok': True, 'observed': state, 'could_change_to': {'files': plan, 'commands': commands},
              'attempt': {'attempted': False, 'steps': []}, 'final_receipt': {'ok': True},
              'changed': False, 'mutationPerformed': False, 'effective': 'next-boot'}
    if dry or not edits:
        return result
    if os.environ.get('AGATHODAIMON_SCRATCH_ROOT'):
        raise ValueError('hdmi-hold-scratch-mutation-refused')
    for p, data, mode in edits:
        if data is not None:
            p.parent.mkdir(parents=True, exist_ok=True)
    def rebuild():
        for argv, timeout in COMMANDS:
            outcome = run(argv, timeout=timeout)
            if outcome.returncode:
                raise RuntimeError(argv[0] + '-failed')
    try:
        parts = write([{'path': p, 'candidate': data, 'mode': mode, 'owner': ('root', 'root')} for p, data, mode in edits], reload=rebuild)
    except WriteError as exc:
        result.update(exc.parts)
        result['ok'] = False
        result['firstMissingSignal'] = exc.parts['final_receipt']['firstMissingSignal']
        result['restore_failed'] = bool(exc.restore_errors)
        return result
    result.update(parts)
    result['mutationPerformed'] = parts['changed']
    return result

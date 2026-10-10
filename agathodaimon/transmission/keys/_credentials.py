from __future__ import annotations

import json
import os
import pwd
import secrets
import stat
from typing import Any

from agathodaimon.transmission import runtime as rt

_CONFIG = "/etc/transmission-daemon/settings.json"
_CONFIG_DIRECTORY = "/etc/transmission-daemon"
_CONFIG_NAME = "settings.json"
_MAX_CONFIG_BYTES = 1024 * 1024


def _error(signal: str, step: str = "daemon-credential-seed", *, published: bool = False):
    detail = {"published": True} if published else None
    raise rt.TransmissionError(signal, step, detail)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate object key")
        value[key] = item
    return value


def _reject_constant(_value: str):
    raise ValueError("non-JSON constant")


def _read_settings(parent_fd: int) -> tuple[dict[str, Any], tuple[int, int]]:
    try:
        before = os.stat(_CONFIG_NAME, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        _error("transmission-daemon-settings-absent")
    except OSError:
        _error("transmission-daemon-settings-unreadable")
    if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_CONFIG_BYTES:
        _error("transmission-daemon-settings-unsafe")
    file_fd = None
    raw = bytearray()
    text = None
    chunk = None
    try:
        try:
            file_fd = os.open(
                _CONFIG_NAME,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK,
                dir_fd=parent_fd,
            )
            opened = os.fstat(file_fd)
            after = os.stat(_CONFIG_NAME, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            _error("transmission-daemon-settings-unsafe")
        identity = (opened.st_dev, opened.st_ino)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or (after.st_dev, after.st_ino) != identity
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_size > _MAX_CONFIG_BYTES):
            _error("transmission-daemon-settings-unsafe")
        while len(raw) <= _MAX_CONFIG_BYTES:
            try:
                chunk = os.read(file_fd, min(65536, _MAX_CONFIG_BYTES + 1 - len(raw)))
            except OSError:
                _error("transmission-daemon-settings-unreadable")
            if not chunk:
                break
            raw.extend(chunk)
            chunk = None
        if len(raw) > _MAX_CONFIG_BYTES:
            _error("transmission-daemon-settings-unsafe")
        try:
            text = raw.decode("utf-8")
            value = json.loads(
                text, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
            )
        except (UnicodeError, json.JSONDecodeError, ValueError):
            _error("transmission-daemon-settings-invalid")
        if not isinstance(value, dict):
            _error("transmission-daemon-settings-not-object")
        return value, identity
    finally:
        raw[:] = b"\x00" * len(raw)
        text = None
        chunk = None
        if file_fd is not None:
            os.close(file_fd)


def _remove_owned_stage(parent_fd: int, name: str | None,
                        identity: tuple[int, int] | None) -> None:
    if name is None or identity is None:
        return
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (stat.S_ISREG(info.st_mode)
                and (info.st_dev, info.st_ino) == identity):
            os.unlink(name, dir_fd=parent_fd)
    except OSError:
        pass


def seed_daemon_credentials() -> dict[str, Any]:
    parent_fd = None
    stage_fd = None
    stage_name = None
    stage_identity = None
    target_identity = None
    settings = None
    username = None
    password = None
    credentials = None
    serialized_text = None
    serialized_bytes = None
    serialized = bytearray()
    published = False
    try:
        try:
            daemon_user = pwd.getpwnam("debian-transmission")
        except KeyError:
            _error("transmission-daemon-owner-unavailable")
        try:
            parent_fd = rt._open_absolute_dir(_CONFIG_DIRECTORY)
        except FileNotFoundError:
            _error("transmission-daemon-config-directory-absent")
        except OSError:
            _error("transmission-daemon-config-directory-unsafe")
        settings, target_identity = _read_settings(parent_fd)
        try:
            with rt.exported_credentials("transmission") as credentials:
                username, password = credentials
                settings["rpc-authentication-required"] = True
                settings["rpc-username"] = username
                settings["rpc-password"] = password
                serialized_text = json.dumps(
                    settings, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
                ) + "\n"
                serialized_bytes = serialized_text.encode("utf-8")
                serialized.extend(serialized_bytes)
                serialized_bytes = None
                serialized_text = None
        except rt.TransmissionError:
            raise
        except Exception:
            _error("transmission-daemon-credential-export-failed")
        credentials = None
        username = None
        password = None

        stage_name = ".settings.json." + str(os.getpid()) + "." + secrets.token_hex(12) + ".tmp"
        try:
            stage_fd = os.open(
                stage_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600, dir_fd=parent_fd,
            )
            stage_stat = os.fstat(stage_fd)
            stage_identity = (stage_stat.st_dev, stage_stat.st_ino)
            os.fchown(stage_fd, daemon_user.pw_uid, daemon_user.pw_gid)
            os.fchmod(stage_fd, 0o600)
            stage_stat = os.fstat(stage_fd)
            if (stage_stat.st_uid != daemon_user.pw_uid
                    or stage_stat.st_gid != daemon_user.pw_gid
                    or stat.S_IMODE(stage_stat.st_mode) != 0o600):
                _error("transmission-daemon-stage-unsafe")
            view = memoryview(serialized)
            try:
                while view:
                    written = os.write(stage_fd, view)
                    if written <= 0:
                        _error("transmission-daemon-stage-write-failed")
                    view = view[written:]
            finally:
                view.release()
            os.fsync(stage_fd)
            os.close(stage_fd)
            stage_fd = None
            try:
                current = os.stat(_CONFIG_NAME, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                _error("transmission-daemon-settings-changed")
            if (not stat.S_ISREG(current.st_mode)
                    or (current.st_dev, current.st_ino) != target_identity):
                _error("transmission-daemon-settings-changed")
            os.replace(stage_name, _CONFIG_NAME, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            published = True
            os.fsync(parent_fd)
        except rt.TransmissionError as failure:
            if published:
                raise rt.TransmissionError(
                    failure.signal_name, failure.step, {"published": True},
                ) from None
            raise
        except OSError:
            _error("transmission-daemon-settings-publish-failed", published=published)
        return {
            "attempted": True,
            "outcome": "seeded",
            "published": True,
            "firstMissingSignal": "none",
        }
    finally:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
        if parent_fd is not None:
            _remove_owned_stage(parent_fd, stage_name, stage_identity)
            try:
                os.close(parent_fd)
            except OSError:
                pass
        serialized[:] = b"\x00" * len(serialized)
        if settings is not None:
            settings["rpc-username"] = None
            settings["rpc-password"] = None
        settings = None
        username = None
        password = None
        credentials = None
        serialized_text = None
        serialized_bytes = None

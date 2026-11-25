"""Read-only validation primitives for Forgejo's NAS restore source.

This module is not registered as a staff stop. The destructive restore worker
must not be exposed until its staging, no-stomp gate, and rollback are complete.
"""
from __future__ import annotations

import configparser
import os
import re
import stat


class SourceError(Exception):
    """A source is absent or cannot be safely interpreted."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _mount_id(fd: int) -> str:
    try:
        with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
            return next(line.split()[1] for line in stream if line.startswith("mnt_id:"))
    except (OSError, StopIteration, IndexError) as error:
        raise SourceError("source-missing") from error


def _directory(parent: int, name: str, mount_id: str | None = None) -> int:
    """Open the observed directory, not a link substituted after observation."""
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise SourceError("source-missing")
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        after = os.fstat(fd)
        try:
            if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or (mount_id is not None and _mount_id(fd) != mount_id)):
                raise SourceError("source-missing")
            return fd
        except BaseException:
            os.close(fd)
            raise
    except OSError as error:
        raise SourceError("source-missing") from error


def _regular(parent: int, name: str, mount_id: str | None = None) -> int:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            if (not stat.S_ISREG(os.fstat(fd).st_mode)
                    or (mount_id is not None and _mount_id(fd) != mount_id)):
                raise SourceError("source-missing")
            return fd
        except BaseException:
            os.close(fd)
            raise
    except OSError as error:
        raise SourceError("source-missing") from error


def _dump_trailer(fd: int) -> None:
    """Validate pg_dump 17's optional restrict pair and completion trailer.

    The token stays in memory and neither the source nor any output is changed.
    """
    token = None
    unrestrict = 0
    completed = False
    first_content = True
    try:
        with os.fdopen(os.dup(fd), "rb") as stream:
            for raw in stream:
                line = raw.rstrip(b"\r\n")
                stripped = line.strip()
                if first_content and stripped and not stripped.startswith(b"--"):
                    first_content = False
                    match = re.fullmatch(rb"\\restrict[ \t]+([^\s]+)", stripped)
                    if match:
                        token = match.group(1)
                if not completed:
                    if line == b"-- PostgreSQL database dump complete":
                        completed = True
                    continue
                if not stripped or stripped.startswith(b"--"):
                    continue
                match = re.fullmatch(rb"\\unrestrict[ \t]+([^\s]+)", stripped)
                if not match or token is None or match.group(1) != token:
                    raise SourceError("source-invalid")
                unrestrict += 1
                if unrestrict != 1:
                    raise SourceError("source-invalid")
    except OSError as error:
        raise SourceError("source-invalid") from error
    if not completed or (token is not None and unrestrict != 1):
        raise SourceError("source-invalid")


def _database_config(fd: int) -> None:
    try:
        with os.fdopen(os.dup(fd), encoding="utf-8", newline="") as stream:
            text = stream.read()
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string("[__top__]\n" + text)
        section = getattr(parser, "_sections", {}).get("database", {})
        if section.get("user", "").strip().strip('"') != "git" or "passwd" not in section:
            raise SourceError("source-invalid")
    except (OSError, UnicodeError, configparser.Error) as error:
        raise SourceError("source-invalid") from error


def validate_source(mount: str) -> None:
    """Validate the fixed export using only no-follow directory descriptors.

    Caller must retain source descriptors or repeat this validation under the
    synchronization lock before using the source for a destructive restore.
    """
    opened = []
    try:
        if not os.path.isabs(mount) or ".." in mount.split(os.sep):
            raise SourceError("source-missing")
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        opened.append(root)
        for name in [part for part in mount.split(os.sep) if part]:
            root = _directory(root, name)
            opened.append(root)
        mount_id = _mount_id(root)
        # The selected root must itself be a mount, not merely a child of one.
        with open("/proc/self/mountinfo", encoding="utf-8") as mounts:
            if not any(line.split()[0] == mount_id for line in mounts):
                raise SourceError("source-missing")
        parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=root)
        opened.append(parent)
        if _mount_id(parent) == mount_id:
            raise SourceError("source-missing")
        for name in ("backups", "forgejo", "nas", "export"):
            root = _directory(root, name, mount_id)
            opened.append(root)
            if name == "nas":
                info = os.fstat(root)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise SourceError("source-missing")
        for name in ("complete", "forgejo.sql"):
            fd = _regular(root, name, mount_id)
            opened.append(fd)
            if name == "forgejo.sql":
                _dump_trailer(fd)
        for name in ("repositories", "data", "custom"):
            child = _directory(root, name, mount_id)
            opened.append(child)
            if name == "custom":
                conf = _directory(child, "conf", mount_id)
                opened.append(conf)
                ini = _regular(conf, "app.ini", mount_id)
                opened.append(ini)
                _database_config(ini)
    except OSError as error:
        raise SourceError("source-missing") from error
    finally:
        for fd in reversed(opened):
            os.close(fd)

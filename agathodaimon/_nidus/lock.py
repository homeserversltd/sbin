"""Named household locks shared by composing staff writers."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
from functools import wraps
import os
from pathlib import Path
import threading

from agathodaimon._nidus.path import appliance_runtime_path

_guard = threading.Lock()
_locks: dict[str, threading.RLock] = {}
_depth: dict[str, int] = {}
_paths: dict[str, Path] = {}
IDENTITY_LOCK = "network-identity-claim"
IDENTITY_LOCK_PATH = Path("/var/lib/caduceus") / f"{IDENTITY_LOCK}.lock"


def identity_lock_path(path: str | Path | None = None) -> Path:
    return Path(path or os.environ.get("CADUCEUS_IDENTITY_LOCK") or appliance_runtime_path("identity-lock")).resolve()


class IdentityLockUnavailable(OSError):
    """The named household lock could not be acquired or released."""


def identity_locked(method):
    """Serialize the complete manager operation, including its reads."""
    @wraps(method)
    def wrapped(*args, **kwargs):
        with held(IDENTITY_LOCK, path=identity_lock_path()):
            return method(*args, **kwargs)
    return wrapped


def _after_fork() -> None:
    global _guard, _locks, _depth, _paths
    _guard = threading.Lock()
    _locks = {}
    _depth = {}
    _paths = {}


os.register_at_fork(after_in_child=_after_fork)


@contextmanager
def held(name: str, *, path: str | Path):
    """Hold one blocking exclusive lock; same-thread composition re-enters."""
    with _guard:
        mutex = _locks.setdefault(name, threading.RLock())
    with mutex:
        owner_pid = os.getpid()
        target = Path(path).resolve()
        if _depth.get(name, 0):
            if target != _paths[name]:
                raise RuntimeError(f"lock-path-mismatch:{name}")
            _depth[name] += 1
            try:
                yield
            finally:
                if os.getpid() == owner_pid:
                    _depth[name] -= 1
            return
        try:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        except OSError:
            raise IdentityLockUnavailable(f"identity-lock-unavailable:{name}") from None
        try:
            try:
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                raise IdentityLockUnavailable(f"identity-lock-unavailable:{name}") from None
            _depth[name] = 1
            _paths[name] = target
            try:
                yield
            finally:
                if os.getpid() == owner_pid:
                    del _depth[name]
                    del _paths[name]
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        raise IdentityLockUnavailable(f"identity-lock-unavailable:{name}") from None
        finally:
            os.close(fd)

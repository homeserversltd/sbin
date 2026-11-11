"""Named household locks shared by composing staff writers."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
from functools import wraps
import os
from pathlib import Path
import threading

_guard = threading.Lock()
_locks: dict[str, threading.RLock] = {}
_depth: dict[str, int] = {}
_paths: dict[str, Path] = {}
IDENTITY_LOCK = "network-identity-claim"
IDENTITY_LOCK_PATH = Path("/var/lib/caduceus") / f"{IDENTITY_LOCK}.lock"


def identity_lock_path(path: str | Path | None = None) -> Path:
    return Path(path or os.environ.get("CADUCEUS_IDENTITY_LOCK") or IDENTITY_LOCK_PATH).resolve()


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
def held(name: str, *, path: str | Path | None = None):
    """Hold one blocking exclusive lock; same-thread composition re-enters."""
    with _guard:
        mutex = _locks.setdefault(name, threading.RLock())
    with mutex:
        target = (Path(path) if path is not None else Path('/var/lib/caduceus') / f'{name}.lock').resolve()
        if _depth.get(name, 0):
            if target != _paths[name]:
                raise RuntimeError(f"lock-path-mismatch:{name}")
            _depth[name] += 1
            try:
                yield
            finally:
                _depth[name] -= 1
            return
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'a+') as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            _depth[name] = 1
            _paths[name] = target
            try:
                yield
            finally:
                del _depth[name]
                del _paths[name]
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

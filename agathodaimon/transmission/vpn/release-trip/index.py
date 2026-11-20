"""Clear the Transmission trip marker before native start."""
import os
import stat
from pathlib import Path

from agathodaimon.transmission import runtime as rt


def _entry_mode(name, parent_fd):
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return None


def _release_marker(result):
    marker = Path(rt.TRIP_MARKER)
    try:
        parent_fd = rt._open_absolute_dir(str(marker.parent))
    except FileNotFoundError:
        result["markerPresent"] = False
        return
    try:
        mode = _entry_mode(marker.name, parent_fd)
        result["markerPresent"] = mode is not None
        if mode is None:
            return
        if not stat.S_ISREG(mode):
            raise rt.TransmissionError("transmission-trip-marker-not-regular", "release-trip")
        result["attempt"]["attempted"] = True
        try:
            os.unlink(marker.name, dir_fd=parent_fd)
        except FileNotFoundError:
            # Another Start removed it after the initial observation.
            pass
        else:
            result["markerRemoved"] = True
        if _entry_mode(marker.name, parent_fd) is not None:
            raise rt.TransmissionError("transmission-trip-marker-still-present", "release-trip")
    finally:
        os.close(parent_fd)


def main(argv=None):
    del argv
    request = None
    result = {"ok": False, "markerRemoved": False, "observed": {"path": rt.TRIP_MARKER},
              "could_change_to": {"markerPresent": False}, "attempt": {"attempted": False}}
    try:
        request = rt.read_request(known_fields=(), declared_flags=())
        _release_marker(result)
    except rt.EnvelopeError:
        result["firstMissingSignal"] = "transmission-request-invalid"
    except rt.TransmissionError as failure:
        result["firstMissingSignal"] = failure.signal_name
    except OSError:
        result["firstMissingSignal"] = "transmission-trip-marker-io-failed"
    else:
        result.update(ok=True, firstMissingSignal="none")
    if "markerPresent" in result:
        result["observed"]["markerPresent"] = result["markerPresent"]
    removed = result["markerRemoved"]
    result.update(changed=removed, mutationPerformed=removed)
    result["attempt"]["outcome"] = "refused" if not result["ok"] else "removed" if removed else "kept"
    return rt.print_receipt(rt.finish(result, request), "transmission/vpn/release-trip")
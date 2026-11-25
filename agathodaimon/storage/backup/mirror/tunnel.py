#!/usr/bin/env python3
"""Rsync remote shell over the paired Caduceus HTTP upgrade."""
from __future__ import annotations

import json
import os
import re
import select
import socket
import sys
import time


DOOR_SIGNALS = ("backup-mirror-busy", "mirror-serve-lock-busy",
                "backup-pair-unknown", "backup-mirror-child-failed")


def idle_seconds():
    bound = 600.0
    if os.environ.get("AGATHODAIMON_SCRATCH_ROOT"):
        value = float(os.environ.get("CADUCEUS_MIRROR_PROOF_IDLE_SECONDS", bound))
        if 0 < value < bound:
            bound = value
    return bound


def refusal_signal(sock, lines, allowed, bound):
    status = lines[0].split()
    code = status[1].decode("ascii", "replace") if len(status) >= 2 else "invalid"
    fallback = "mirror-http-" + (code if re.fullmatch(r"[0-9]{3}", code) else "invalid")
    lengths = [line.split(b":", 1)[1].strip() for line in lines[1:]
               if line.lower().startswith(b"content-length:")]
    if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or int(lengths[0]) > 4096)):
        return fallback
    remaining = int(lengths[0]) if lengths else None
    body = bytearray()
    deadline = time.monotonic() + bound
    try:
        while remaining is None or remaining:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                return fallback
            sock.settimeout(timeout)
            chunk = sock.recv(remaining if remaining is not None else 4096 - len(body))
            if not chunk:
                if remaining:
                    return fallback
                break
            body.extend(chunk)
            if remaining is not None:
                remaining -= len(chunk)
            elif len(body) == 4096:
                return fallback
        value = json.loads(body)
        signal = value.get("signal") if isinstance(value, dict) else None
        return signal if signal in allowed else fallback
    except (OSError, ValueError, TypeError, UnicodeError):
        return fallback


def relay(sock, bound):
    # Bounded buffers and readiness-driven writes make backpressure part of the
    # same idle clock; progress in either direction renews it.
    sock.setblocking(False)
    outgoing = bytearray()
    incoming = bytearray()
    input_open = True
    socket_open = True
    write_shutdown = False
    last = time.monotonic()
    while socket_open or incoming:
        if not input_open and not outgoing and not write_shutdown:
            sock.shutdown(socket.SHUT_WR)
            write_shutdown = True
        timeout = bound - (time.monotonic() - last)
        if timeout <= 0:
            return refuse("mirror-copy-stalled")
        readers = ([0] if input_open and len(outgoing) < 65536 and socket_open else [])
        if socket_open and len(incoming) < 65536:
            readers.append(sock)
        writers = ([sock] if socket_open and outgoing else []) + ([1] if incoming else [])
        ready_r, ready_w, _ = select.select(readers, writers, [], timeout)
        if not ready_r and not ready_w:
            return refuse("mirror-copy-stalled")
        if 0 in ready_r:
            data = os.read(0, 65536 - len(outgoing))
            if data:
                outgoing.extend(data)
                last = time.monotonic()
            else:
                input_open = False
        if sock in ready_r:
            data = sock.recv(65536 - len(incoming))
            if data:
                incoming.extend(data)
                last = time.monotonic()
            else:
                socket_open = False
        if sock in ready_w and socket_open:
            count = sock.send(outgoing)
            if count:
                del outgoing[:count]
                last = time.monotonic()
        if 1 in ready_w:
            count = os.write(1, incoming[:4096])
            if count:
                del incoming[:count]
                last = time.monotonic()
    return 0


def wipe(value):
    for i in range(len(value)):
        value[i] = 0


def refuse(signal):
    print(json.dumps({"ok": False, "signal": signal}), file=sys.stderr, flush=True)
    return 1


def main():
    secret = bytearray()
    request = bytearray()
    sock = None
    fd = None
    try:
        bound = idle_seconds()
        if len(sys.argv) < 3:
            return refuse("mirror-remote-command-invalid")
        command = " ".join(sys.argv[2:]).encode("utf-8")
        if len(command) > 4096 or b"\n" in command or b"\r" in command:
            return refuse("mirror-remote-command-invalid")
        fd = int(os.environ["CADUCEUS_MIRROR_CREDENTIAL_FD"])
        secret = bytearray(8193)
        used = 0
        deadline = time.monotonic() + bound
        while used < len(secret):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                return refuse("mirror-tunnel-failed")
            count = os.readv(fd, [memoryview(secret)[used:]])
            if not count:
                break
            used += count
        del secret[used:]
        os.close(fd)
        fd = None
        if len(secret) > 8192 or secret.count(b"\n") != 1:
            return refuse("mirror-credential-invalid")
        split = secret.index(b"\n")
        mac = memoryview(secret)[:split]
        token = memoryview(secret)[split + 1:]
        if not re.fullmatch(rb"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", mac) or not token or any(c < 33 or c > 126 for c in token):
            return refuse("mirror-credential-invalid")
        allowed = tuple(signal for signal in DOOR_SIGNALS if bytes(token) not in signal.encode("ascii"))
        host = os.environ["CADUCEUS_MIRROR_IPV4"]
        port = int(os.environ["CADUCEUS_MIRROR_PORT"])
        sock = socket.create_connection((host, port), timeout=15)
        sock.settimeout(bound)
        request.extend(b"POST /api/v1/storage/backup/mirror/stream HTTP/1.1\r\nHost: ")
        request.extend(host.encode("ascii"))
        request.extend(b"\r\nConnection: Upgrade\r\nUpgrade: caduceus-rsync\r\nX-Caduceus-Pair-Mac: ")
        request.extend(bytes(mac).lower())
        request.extend(b"\r\nX-Caduceus-Pair-Credential: ")
        request.extend(token)
        request.extend(b"\r\nContent-Length: 0\r\n\r\n")
        sock.sendall(request)
        wipe(request)
        wipe(secret)
        header = bytearray()
        deadline = time.monotonic() + bound
        while not header.endswith(b"\r\n\r\n"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return refuse("mirror-tunnel-failed")
            sock.settimeout(remaining)
            chunk = sock.recv(1)
            if not chunk and not header:
                return refuse("mirror-tunnel-failed")
            if not chunk or len(header) >= 65536:
                return refuse("mirror-upgrade-invalid")
            header.extend(chunk)
        lines = header.split(b"\r\n")
        status = lines[0].split()
        if len(status) < 2 or status[1] != b"101":
            return refuse(refusal_signal(sock, lines, allowed, bound))
        if not any(line.lower() == b"upgrade: caduceus-rsync" for line in lines[1:]):
            return refuse("mirror-upgrade-invalid")
        sock.settimeout(bound)
        sock.sendall(command + b"\n")
        return relay(sock, bound)
    except (OSError, ValueError, KeyError, OverflowError):
        return refuse("mirror-tunnel-failed")
    finally:
        wipe(secret)
        wipe(request)
        if fd is not None:
            os.close(fd)
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    raise SystemExit(main())

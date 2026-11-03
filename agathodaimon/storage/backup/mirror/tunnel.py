#!/usr/bin/env python3
"""Rsync remote shell over the paired Caduceus HTTP upgrade."""
from __future__ import annotations

import json
import os
import re
import selectors
import socket
import sys


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
        if len(sys.argv) < 3:
            return refuse("mirror-remote-command-invalid")
        command = " ".join(sys.argv[2:]).encode("utf-8")
        if len(command) > 4096 or b"\n" in command or b"\r" in command:
            return refuse("mirror-remote-command-invalid")
        fd = int(os.environ["CADUCEUS_MIRROR_CREDENTIAL_FD"])
        secret = bytearray(8193)
        used = 0
        while used < len(secret):
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
        host = os.environ["CADUCEUS_MIRROR_IPV4"]
        port = int(os.environ["CADUCEUS_MIRROR_PORT"])
        sock = socket.create_connection((host, port), timeout=15)
        sock.settimeout(None)
        request.extend(b"POST /api/v1/storage/backup/mirror/stream HTTP/1.1\r\nHost: ")
        request.extend(host.encode("ascii"))
        request.extend(b"\r\nConnection: Upgrade\r\nUpgrade: caduceus-rsync\r\nX-Caduceus-Pair-Mac: ")
        request.extend(mac)
        request.extend(b"\r\nX-Caduceus-Pair-Credential: ")
        request.extend(token)
        request.extend(b"\r\nContent-Length: 0\r\n\r\n")
        sock.sendall(request)
        wipe(request)
        wipe(secret)
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            chunk = sock.recv(1)
            if not chunk or len(header) >= 65536:
                return refuse("mirror-upgrade-invalid")
            header.extend(chunk)
        lines = header.split(b"\r\n")
        status = lines[0].split()
        if len(status) < 2 or status[1] != b"101":
            code = status[1].decode("ascii", "replace") if len(status) >= 2 else "invalid"
            return refuse("mirror-http-" + (code if re.fullmatch(r"[0-9]{3}", code) else "invalid"))
        if not any(line.lower() == b"upgrade: caduceus-rsync" for line in lines[1:]):
            return refuse("mirror-upgrade-invalid")
        sock.sendall(command + b"\n")
        sel = selectors.DefaultSelector()
        sel.register(sys.stdin.buffer, selectors.EVENT_READ, "input")
        sel.register(sock, selectors.EVENT_READ, "socket")
        while sel.get_map():
            for key, _ in sel.select():
                if key.data == "input":
                    data = os.read(0, 65536)
                    if data:
                        sock.sendall(data)
                    else:
                        sel.unregister(key.fileobj)
                        sock.shutdown(socket.SHUT_WR)
                else:
                    data = sock.recv(65536)
                    if not data:
                        return 0
                    view = memoryview(data)
                    while view:
                        view = view[os.write(1, view):]
        return 0
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

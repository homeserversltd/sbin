"""One Git-helper get: consume inherited credential bytes, then forget them."""
import os
import sys


def main():
    material = bytearray()
    try:
        # Git supplies the public credential-helper protocol on stdin.
        request = sys.stdin.buffer.read(4097)
        if len(request) > 4096:
            return 1
        fields = dict(line.split(b"=", 1) for line in request.splitlines() if b"=" in line)
        if fields.get(b"protocol") != b"https" or fields.get(b"host") != b"git.home.arpa":
            return 1
        descriptor = int(os.environ.pop("THYRSUS_CREDENTIAL_FD"))
        try:
            while len(material) <= 8192:
                part = os.read(descriptor, 8193 - len(material))
                if not part:
                    break
                material.extend(part)
        finally:
            os.close(descriptor)
        if len(material) > 8192:
            return 1
        sys.stdout.buffer.write(material)
        sys.stdout.buffer.flush()
        return 0
    except (OSError, ValueError, KeyError):
        return 1
    finally:
        material[:] = b"\0" * len(material)


if __name__ == "__main__":
    raise SystemExit(main())

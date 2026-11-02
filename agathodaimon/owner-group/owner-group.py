#!/usr/bin/env python3
"""Keep the born owner account in the born Caduceus group."""
import argparse
import grp
import os
import pwd
import subprocess
import sys
import time


def current():
    try:
        owner = pwd.getpwnam('owner')
    except KeyError:
        raise RuntimeError('owner-absent') from None
    try:
        caduceus = grp.getgrnam('caduceus')
    except KeyError:
        raise RuntimeError('caduceus-group-absent') from None
    return caduceus.gr_gid in os.getgrouplist('owner', owner.pw_gid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'apply'])
    args = parser.parse_args()
    started = time.monotonic()
    try:
        # Apply re-observes as well: an earlier engine probe is not permission
        # to create an account/group, or to rewrite membership already current.
        settled = current()
        if args.action == 'check':
            print('current' if settled else 'needs-membership')
            return 0 if settled else 1
        if settled:
            return 0
        if os.geteuid() != 0:
            raise RuntimeError('root-required')
        result = subprocess.run(
            ['/usr/sbin/usermod', '-aG', 'caduceus', 'owner'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError('usermod-failed')
        if not current():
            raise RuntimeError('membership-not-current')
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        signal = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        if args.action == 'check':
            print(signal)
        else:
            field = {'owner-absent': 'owner', 'caduceus-group-absent': 'caduceus'}.get(signal, 'none')
            print(f'who={os.geteuid()} verb=append-group target=owner:caduceus outcome=failed duration_ms={int((time.monotonic()-started)*1000)} ids=none signal={signal} first_missing_field={field}', file=sys.stderr)
        return 1
    print(f'who={os.geteuid()} verb=append-group target=owner:caduceus outcome=added duration_ms={int((time.monotonic()-started)*1000)} ids=none', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

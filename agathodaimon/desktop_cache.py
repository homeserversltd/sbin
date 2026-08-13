"""Caduceus desktop launcher-cache actuator."""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "caduceus.desktop-cache.v1"
RECEIPT_SCHEMA = "caduceus.desktop-cache.receipt.v1"
DOMAINS = ("desktop-entry-database", "kde-kservice", "wofi-drun")


class DesktopCacheError(ValueError):
    """A stable desktop-cache refusal."""


def receipt(
    primitive: str,
    *,
    ok: bool,
    changed: bool,
    first_missing_signal: str = "none",
    **fields: Any,
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "primitive": primitive,
        "ok": ok,
        "changed": changed,
        "firstMissingSignal": first_missing_signal,
        **fields,
    }


def _absolute(value: str, signal: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise DesktopCacheError(signal)
    return path.resolve(strict=False)


def _user_dirs(user: str) -> tuple[pwd.struct_passwd, dict[str, Path]]:
    try:
        account = pwd.getpwnam(user)
    except KeyError as error:
        raise DesktopCacheError("caduceus-desktop-cache-user-missing") from error

    owns_environment = os.geteuid() == account.pw_uid
    home_value = os.environ.get("HOME") if owns_environment else None
    home = _absolute(home_value or account.pw_dir, "caduceus-desktop-cache-home-invalid")

    def xdg(name: str, fallback: Path, signal: str) -> Path:
        value = os.environ.get(name) if owns_environment else None
        return _absolute(value, signal) if value else fallback.resolve(strict=False)

    state = xdg("XDG_STATE_HOME", home / ".local/state", "caduceus-desktop-cache-state-invalid")
    cache = xdg("XDG_CACHE_HOME", home / ".cache", "caduceus-desktop-cache-cache-invalid")
    runtime = xdg("XDG_RUNTIME_DIR", Path(f"/run/user/{account.pw_uid}"), "caduceus-desktop-cache-runtime-invalid")
    return account, {"home": home, "state": state, "cache": cache, "runtime": runtime}


def _domain(value: str) -> tuple[str, bool]:
    optional = False
    domain = value
    for suffix in (":optional", "=optional", "?"):
        if domain.endswith(suffix):
            domain = domain[: -len(suffix)]
            optional = True
            break
    if domain not in DOMAINS:
        raise argparse.ArgumentTypeError(
            f"domain must be one of {', '.join(DOMAINS)} (append :optional to mark optional)"
        )
    return domain, optional


def _run_as_user(
    command: list[str], account: pwd.struct_passwd, directories: dict[str, Path]
) -> subprocess.CompletedProcess[str]:
    if os.geteuid() not in (0, account.pw_uid):
        raise DesktopCacheError("caduceus-desktop-cache-user-switch-refused")

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(directories["home"]),
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "XDG_STATE_HOME": str(directories["state"]),
            "XDG_CACHE_HOME": str(directories["cache"]),
            "XDG_RUNTIME_DIR": str(directories["runtime"]),
        }
    )

    demote: Any = None
    if os.geteuid() == 0 and account.pw_uid != 0:
        def _demote() -> None:
            os.initgroups(account.pw_name, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

        demote = _demote

    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        cwd=directories["home"],
        env=environment,
        preexec_fn=demote,
    )


def _utility(names: Sequence[str]) -> str | None:
    search_path = os.environ.get(
        "CADUCEUS_DESKTOP_CACHE_UTILITY_PATH", "/usr/local/bin:/usr/bin:/bin"
    )
    for name in names:
        found = shutil.which(name, path=search_path)
        if found:
            return found
    return None


def _result(domain: str, optional: bool, status: str, **fields: Any) -> dict[str, Any]:
    return {"domain": domain, "optional": optional, "status": status, **fields}


def _command_domain(
    domain: str,
    optional: bool,
    utilities: Sequence[str],
    arguments: Sequence[str],
    account: pwd.struct_passwd,
    directories: dict[str, Path],
    required_path: Path | None = None,
) -> dict[str, Any]:
    if required_path is not None and not required_path.is_dir():
        if optional:
            return _result(domain, optional, "absent-optional", absent=str(required_path))
        return _result(
            domain,
            optional,
            "failed",
            blocker=f"caduceus-desktop-cache-{domain}-input-missing",
            required_path=str(required_path),
        )

    utility = _utility(utilities)
    if utility is None:
        if optional:
            return _result(domain, optional, "absent-optional", absent=list(utilities))
        return _result(
            domain,
            optional,
            "failed",
            blocker=f"caduceus-desktop-cache-{domain}-utility-missing",
            utilities=list(utilities),
        )

    command = [utility, *arguments]
    result = _run_as_user(command, account, directories)
    fields = {
        "command": command,
        "exit": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
    if result.returncode != 0:
        return _result(
            domain,
            optional,
            "failed",
            blocker=f"caduceus-desktop-cache-{domain}-refresh-failed",
            **fields,
        )
    return _result(domain, optional, "refreshed", **fields)


def _bounded_deletion(path: Path, roots: Sequence[Path]) -> Path:
    candidate = path.resolve(strict=False)
    for root in roots:
        boundary = root.resolve(strict=False)
        try:
            relative = candidate.relative_to(boundary)
        except ValueError:
            continue
        if relative != Path("."):
            return candidate
    raise DesktopCacheError("caduceus-desktop-cache-delete-out-of-root")


def _wofi_domain(optional: bool, directories: dict[str, Path]) -> dict[str, Any]:
    cache_file = directories["state"] / "arch-tv-launcher/wofi-drun-cache"
    if not cache_file.exists() and not cache_file.is_symlink():
        status = "absent-optional" if optional else "unchanged"
        return _result("wofi-drun", optional, status, path=str(cache_file))
    try:
        bounded = _bounded_deletion(cache_file, (directories["cache"], directories["state"]))
        if bounded.is_dir():
            raise DesktopCacheError("caduceus-desktop-cache-delete-not-file")
        cache_file.unlink()
    except (DesktopCacheError, OSError) as error:
        return _result(
            "wofi-drun",
            optional,
            "failed",
            blocker=str(error),
            path=str(cache_file),
        )
    return _result("wofi-drun", optional, "refreshed", path=str(cache_file), removed=True)


def refresh(user: str, declarations: Sequence[tuple[str, bool]]) -> dict[str, Any]:
    account, directories = _user_dirs(user)
    seen: set[str] = set()
    results: list[dict[str, Any]] = []

    for domain, optional in declarations:
        if domain in seen:
            raise DesktopCacheError("caduceus-desktop-cache-domain-duplicate")
        seen.add(domain)
        if domain == "desktop-entry-database":
            applications = directories["home"] / ".local/share/applications"
            result = _command_domain(
                domain,
                optional,
                ("update-desktop-database",),
                (str(applications),),
                account,
                directories,
                required_path=applications,
            )
        elif domain == "kde-kservice":
            result = _command_domain(
                domain,
                optional,
                ("kbuildsycoca6", "kbuildsycoca5"),
                ("--noincremental",),
                account,
                directories,
            )
        else:
            result = _wofi_domain(optional, directories)
        results.append(result)

    blocker = next(
        (
            str(item.get("blocker"))
            for item in results
            if item["status"] == "failed" and not item["optional"]
        ),
        "none",
    )
    changed = any(item["status"] == "refreshed" for item in results)
    return receipt(
        "refresh",
        ok=blocker == "none",
        changed=changed,
        first_missing_signal=blocker,
        state_schema=SCHEMA,
        user={"name": account.pw_name, "uid": account.pw_uid, "gid": account.pw_gid},
        directories={name: str(path) for name, path in directories.items()},
        domains=results,
    )


def _emit(call) -> int:
    try:
        value = call()
    except (DesktopCacheError, OSError, subprocess.SubprocessError) as error:
        value = receipt(
            "invalid",
            ok=False,
            changed=False,
            first_missing_signal=str(error),
            state_schema=SCHEMA,
        )
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-desktop-cache")
    sub = parser.add_subparsers(dest="command", required=True)
    refresh_parser = sub.add_parser("refresh")
    refresh_parser.add_argument("--user", default="owner")
    refresh_parser.add_argument(
        "--domain",
        action="append",
        required=True,
        type=_domain,
        metavar="DOMAIN[:optional]",
        help=f"repeatable; one of {', '.join(DOMAINS)}; append :optional when absence is allowed",
    )
    args = parser.parse_args(argv)
    return _emit(lambda: refresh(args.user, args.domain))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Converge Forgejo remotes and Git credential-helper wiring without exposing secrets."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import uuid
from pathlib import Path

from agathodaimon.lib.receipts.index import emit

HELPER_PATH = "/usr/local/sbin/caduceus-forgejo-credential"
DEFAULT_FULCRUM_ROOT = "/fulcrum"
DEFAULT_ATTACHMENTS_ROOT = "/fulcrum/attachments"
DEFAULT_OWNER_HOME = "/home/owner"
DEFAULT_RECEIPT_ROOT = "/var/lib/caduceus/receipts"
GIT = "/usr/bin/git"


def fulcrum_root() -> Path:
    return Path(os.environ.get("CADUCEUS_FORGEJO_FULCRUM_ROOT", DEFAULT_FULCRUM_ROOT))


def attachments_root() -> Path:
    return Path(os.environ.get("CADUCEUS_FORGEJO_ATTACHMENTS_ROOT", DEFAULT_ATTACHMENTS_ROOT))


def owner_home() -> Path:
    return Path(os.environ.get("CADUCEUS_FORGEJO_OWNER_HOME", DEFAULT_OWNER_HOME))


def credential_store() -> Path:
    override = os.environ.get("CADUCEUS_FORGEJO_CREDENTIAL_STORE")
    return Path(override) if override is not None else owner_home() / ".git-credentials-forgejo"


def run_git(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
    """Run Git with captured output and stderr discarded so config values stay private."""
    try:
        return subprocess.run(
            [GIT, *args],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None


def repositories() -> list[Path] | None:
    roots = [fulcrum_root()]
    try:
        roots.extend(sorted(attachments_root().iterdir(), key=lambda item: item.name))
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        return None

    found: list[Path] = []
    for root in roots:
        try:
            if root.is_symlink() or not root.is_dir():
                continue
            git_marker = root / ".git"
            if git_marker.exists() or git_marker.is_file():
                found.append(root)
        except (OSError, ValueError):
            return None
    return found


def repo_git(repo: Path, args: list[str]):
    env = os.environ.copy()
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "safe.directory"
    env["GIT_CONFIG_VALUE_0"] = str(repo)
    return run_git(["-C", str(repo), *args], env=env)


def remote_origin(repo: Path) -> tuple[str | None, bool]:
    result = repo_git(repo, ["config", "--local", "--get", "remote.origin.url"])
    if result is None:
        return None, False
    if result.returncode == 0:
        return result.stdout.rstrip("\n"), True
    if result.returncode == 1:
        return None, True
    return None, False


def local_helper_present(repo: Path) -> bool | None:
    result = repo_git(repo, ["config", "--local", "--get-all", "credential.helper"])
    if result is None:
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def system_helpers() -> list[str] | None:
    result = run_git(["config", "--system", "--get-all", "credential.helper"])
    if result is None:
        return None
    if result.returncode == 0:
        return result.stdout.splitlines()
    if result.returncode == 1:
        return []
    return None


def state() -> bool | None:
    try:
        repos = repositories()
        helpers = system_helpers()
        if repos is None or helpers is None:
            return None
        different = helpers != [HELPER_PATH] or os.path.lexists(credential_store())
        for repo in repos:
            origin, origin_ok = remote_origin(repo)
            has_local_helper = local_helper_present(repo)
            if not origin_ok or has_local_helper is None:
                return None
            if has_local_helper:
                different = True
            if origin is not None and origin.startswith("git@git.home.arpa:HOMESERVERSLTD/"):
                different = True
        return not different
    except (OSError, ValueError):
        return None


def _not_attempted(name: str) -> dict:
    return {"name": name, "outcome": "not-attempted"}


def apply_changes() -> tuple[bool, list[dict], list[str]]:
    steps: list[dict] = []
    touched_paths: list[str] = []
    repos = repositories()
    if repos is None:
        steps.extend(
            [
                {"name": "discover-repositories", "outcome": "failed"},
                _not_attempted("repository-remotes-and-local-helpers"),
                _not_attempted("remove-legacy-credential-store"),
                _not_attempted("set-system-helper"),
            ]
        )
        return False, steps, touched_paths
    steps.append({"name": "discover-repositories", "outcome": "succeeded", "count": len(repos)})

    for index, repo in enumerate(repos):
        origin, origin_ok = remote_origin(repo)
        if not origin_ok:
            steps.append({"name": "read-remote-origin", "outcome": "failed", "repository": str(repo)})
            steps.append(_not_attempted("rewrite-remote-origin"))
            steps.append(_not_attempted("unset-local-credential-helper"))
            for remaining in repos[index + 1 :]:
                steps.append({"name": "repository-configuration", "outcome": "not-attempted", "repository": str(remaining)})
            steps.extend([_not_attempted("remove-legacy-credential-store"), _not_attempted("set-system-helper")])
            return False, steps, touched_paths
        steps.append({"name": "read-remote-origin", "outcome": "succeeded", "repository": str(repo)})

        if origin is not None and origin.startswith("git@git.home.arpa:HOMESERVERSLTD/"):
            suffix = origin[len("git@git.home.arpa:") :]
            result = repo_git(repo, ["remote", "set-url", "origin", f"https://git.home.arpa/{suffix}"])
            if result is None or result.returncode != 0:
                steps.append({"name": "rewrite-remote-origin", "outcome": "failed", "repository": str(repo)})
                steps.append(_not_attempted("unset-local-credential-helper"))
                for remaining in repos[index + 1 :]:
                    steps.append({"name": "repository-configuration", "outcome": "not-attempted", "repository": str(remaining)})
                steps.extend([_not_attempted("remove-legacy-credential-store"), _not_attempted("set-system-helper")])
                return False, steps, touched_paths
            touched_paths.append(str(repo))
            steps.append({"name": "rewrite-remote-origin", "outcome": "succeeded", "repository": str(repo)})
        else:
            steps.append({"name": "rewrite-remote-origin", "outcome": "not-needed", "repository": str(repo)})

        result = repo_git(repo, ["config", "--local", "--unset-all", "credential.helper"])
        if result is None or result.returncode not in (0, 5):
            steps.append({"name": "unset-local-credential-helper", "outcome": "failed", "repository": str(repo)})
            for remaining in repos[index + 1 :]:
                steps.append({"name": "repository-configuration", "outcome": "not-attempted", "repository": str(remaining)})
            steps.extend([_not_attempted("remove-legacy-credential-store"), _not_attempted("set-system-helper")])
            return False, steps, touched_paths
        if result.returncode == 0:
            touched_paths.append(str(repo))
            outcome = "succeeded"
        else:
            outcome = "already-absent"
        steps.append({"name": "unset-local-credential-helper", "outcome": outcome, "repository": str(repo)})

    store = credential_store()
    try:
        if os.path.lexists(store):
            if store.is_dir() and not store.is_symlink():
                steps.append({"name": "remove-legacy-credential-store", "outcome": "failed", "path": str(store)})
                steps.append(_not_attempted("set-system-helper"))
                return False, steps, touched_paths
            store.unlink()
            touched_paths.append(str(store))
            steps.append({"name": "remove-legacy-credential-store", "outcome": "succeeded", "path": str(store)})
        else:
            steps.append({"name": "remove-legacy-credential-store", "outcome": "already-absent", "path": str(store)})
    except OSError:
        steps.append({"name": "remove-legacy-credential-store", "outcome": "failed", "path": str(store)})
        steps.append(_not_attempted("set-system-helper"))
        return False, steps, touched_paths

    result = run_git(["config", "--system", "--replace-all", "credential.helper", HELPER_PATH])
    if result is None or result.returncode != 0:
        steps.append({"name": "set-system-helper", "outcome": "failed"})
        return False, steps, touched_paths
    touched_paths.append(os.environ.get("GIT_CONFIG_SYSTEM", "/etc/gitconfig"))
    steps.append({"name": "set-system-helper", "outcome": "succeeded"})
    return True, steps, touched_paths


def _write_apply_receipt(receipt: dict) -> bool:
    run_id = uuid.uuid4().hex
    receipt_path = (
        Path(os.environ.get("CADUCEUS_RECEIPT_ROOT", DEFAULT_RECEIPT_ROOT))
        / run_id
        / "run.json"
    )
    try:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with receipt_path.open("x", encoding="utf-8") as stream:
            with contextlib.redirect_stdout(stream):
                emit({**receipt, "run_id": run_id})
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, TypeError, ValueError):
        print("caduceus-receipt-write-failed", file=sys.stderr)
        return False
    return True


def _apply() -> int:
    try:
        observed = state()
    except Exception:
        observed = None
    observed_blocker = observed is None

    apply_blocker: str | None = None
    try:
        changed_ok, steps, touched_paths = apply_changes()
    except Exception:
        changed_ok = False
        steps = [{"name": "apply-changes", "outcome": "failed"}]
        touched_paths = []
        apply_blocker = "credential-mediation-apply-failed"

    try:
        final = state()
    except Exception:
        final = None
    final_blocker = final is None
    converged = final is True
    receipt = {
        "schema": "agathodaimon.forgejo-credential.apply.v1",
        "kernel": "caduceus.staff.v1",
        "routine": "agathodaimon.exousia.forgejo-credential",
        "target": {
            "fulcrum_root": str(fulcrum_root()),
            "attachments_root": str(attachments_root()),
            "credential_store": str(credential_store()),
            "system_git_config": os.environ.get("GIT_CONFIG_SYSTEM", "/etc/gitconfig"),
        },
        "flags": {"apply": True},
        "ok": (
            not observed_blocker
            and apply_blocker is None
            and changed_ok
            and not final_blocker
            and converged
        ),
        "changed": None if apply_blocker is not None else bool(touched_paths),
        "touched_paths": touched_paths,
        "observed": (
            {"converged": observed}
            if observed is not None
            else {"converged": None, "blocker": "credential-mediation-observation-failed"}
        ),
        "could_change": {
            "remote_origin": "https://git.home.arpa/HOMESERVERSLTD/<repository>",
            "local_credential_helper": "absent",
            "legacy_credential_store": "absent",
            "system_credential_helper": HELPER_PATH,
        },
        "attempt": {
            "attempted": True,
            "ok": changed_ok,
            "steps": steps,
            **({"blocker": apply_blocker} if apply_blocker is not None else {}),
        },
        "final": (
            {"converged": final}
            if final is not None
            else {"converged": None, "blocker": "credential-mediation-observation-failed"}
        ),
    }
    receipt_written = _write_apply_receipt(receipt)

    if final is not None:
        print("converged" if final else "different")
    if observed_blocker:
        print("credential-mediation-initial-observation-failed", file=sys.stderr)
    if apply_blocker is not None or not changed_ok:
        print("credential-mediation-failed", file=sys.stderr)
    if final_blocker:
        print("credential-mediation-observation-failed", file=sys.stderr)
    return 0 if receipt["ok"] and receipt_written else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--check"]:
        converged = state()
        if converged is None:
            print("credential-mediation-observation-failed", file=sys.stderr)
            return 1
        print("converged" if converged else "different")
        return 0
    if args == ["--apply"]:
        return _apply()
    print("usage: forgejo-credential --check|--apply", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""The household commit staff; Forgejo owns all review state."""
from __future__ import annotations

import base64
import contextlib
import http.client
import importlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import signal
import ssl
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote
import uuid

from agathodaimon._envelope import (
    EnvelopeError, Request, appliance_runtime_path, attach, read,
)
from agathodaimon.lib.keyman_export.index import KeymanExportError, export_credential
from agathodaimon.keyman._common import _scrub
from agathodaimon.lib.receipts.index import emit, now_iso

FORGE = "git.home.arpa"
SERVICE = "thyrsus_forgejo"
VERBS = ("propose", "admit", "forge-token", "forge")
WRITES = frozenset(VERBS[:3])
MAX_INPUT = 65536
MAX_RESPONSE = 65536
GIT = "/usr/bin/git"


class Refusal(Exception):
    def __init__(self, signal, **details):
        super().__init__(signal)
        self.signal = signal
        self.details = details


def _zero(value):
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _rooted(path):
    # Use the same isolated-root coordinate as the staff's config/profile reader.
    config = appliance_runtime_path("config")
    return config.parents[2] / path.lstrip("/")


def _json_file(coordinate):
    try:
        with appliance_runtime_path(coordinate).open(encoding="utf-8") as stream:
            value = json.load(stream)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def _configuration():
    block = _json_file("config").get("thyrsus")
    if not isinstance(block, dict) or block.get("enabled") is not True:
        raise Refusal("thyrsus-disabled")
    # This is a household coordinate, never a caller-selected credential destination.
    if block.get("forge", FORGE) != FORGE:
        raise Refusal("thyrsus-forge-invalid")
    profile = _json_file("profile").get("profile")
    if profile not in {"homeserver", "homesi"}:
        raise Refusal("thyrsus-profile-unsupported")
    return profile


def _vault():
    vault = _rooted("/vault")
    if not (vault / ".keys").is_dir():
        raise Refusal("thyrsus-vault-locked")
    if os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is None and not os.path.ismount(vault):
        raise Refusal("thyrsus-vault-locked")
    return vault


def _token_present(profile):
    try:
        path = (appliance_runtime_path("skeleton") if profile == "homeserver"
                else _vault() / ".keys" / (SERVICE + ".key"))
        metadata = path.lstat()
        return stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0
    except (OSError, ValueError, Refusal):
        return False


def _credential_bytes(profile):
    username = bytearray()
    password = bytearray()
    try:
        if profile == "homeserver":
            try:
                with appliance_runtime_path("skeleton").open("rb") as stream:
                    password = bytearray(stream.read(4097))
            except OSError:
                raise Refusal("thyrsus-token-absent") from None
            if password.endswith(b"\n"):
                del password[-1:]
            username.extend(b"owner")
        else:
            _vault()
            # Scratch never borrows the body's real vault or an exporter stand-in.
            if os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is not None:
                raise Refusal("thyrsus-token-absent")
            try:
                username, password = export_credential(SERVICE)
            except KeymanExportError as error:
                if error.signal == "missing-key":
                    raise Refusal("thyrsus-token-absent") from None
                if error.signal in {"non-root", "uninitialized-system", "preflight-unobservable"}:
                    raise Refusal("thyrsus-vault-locked") from None
                raise Refusal("thyrsus-keyman-" + error.signal) from None
        if not password or len(password) > 4096 or any(x in password for x in (0, 10, 13)):
            raise Refusal("thyrsus-token-absent")
        try:
            owner = username.decode("ascii")
        except UnicodeError:
            raise Refusal("thyrsus-token-absent") from None
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", owner):
            raise Refusal("thyrsus-token-absent")
        yield owner, username, password
    finally:
        _zero(username)
        _zero(password)


_credential = contextlib.contextmanager(_credential_bytes)


def _connection():
    return http.client.HTTPSConnection(FORGE, timeout=5, context=ssl.create_default_context())


def _api(profile, method, path, payload=None):
    # A fresh export for each API call; headers and response bodies are never forwarded.
    with _credential(profile) as (owner, username, password):
        authentication = bytearray()
        encoded = bytearray()
        connection = _connection()
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        response = None
        try:
            if profile == "homeserver":
                authentication.extend(username)
                authentication.extend(b":")
                authentication.extend(password)
                encoded.extend(base64.b64encode(authentication))
                headers["Authorization"] = "Basic " + encoded.decode("ascii")
            else:
                headers["Authorization"] = "token " + password.decode("ascii")
            body = json.dumps(payload, separators=(",", ":")) if payload is not None else None
            connection.request(method, "/api/v1" + path(owner), body=body, headers=headers)
            response = connection.getresponse()
            status_code = response.status
            if not 200 <= status_code < 300:
                raise Refusal("thyrsus-forge-refused", http_status=status_code)
            content = response.read(MAX_RESPONSE + 1)
            if len(content) > MAX_RESPONSE:
                raise Refusal("thyrsus-forge-refused", http_status=status_code)
            if not content:
                return {}, owner, status_code
            try:
                value = json.loads(content)
            except (ValueError, UnicodeError):
                raise Refusal("thyrsus-forge-refused", http_status=status_code) from None
            if not isinstance(value, dict):
                raise Refusal("thyrsus-forge-refused", http_status=status_code)
            return value, owner, status_code
        except Refusal:
            raise
        except (OSError, http.client.HTTPException, UnicodeError):
            raise Refusal("thyrsus-forge-unreachable") from None
        finally:
            headers.clear()
            _zero(authentication)
            _zero(encoded)
            if response is not None:
                response.close()
            connection.close()


def _reachable():
    connection = _connection()
    response = None
    try:
        connection.request("GET", "/api/v1/version", headers={"Accept": "application/json"})
        response = connection.getresponse()
        return True
    except (OSError, http.client.HTTPException):
        return False
    finally:
        if response is not None:
            response.close()
        connection.close()


def _git_environment():
    environment = {key: os.environ[key] for key in (
        "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR",
    ) if key in os.environ}
    environment.update(GIT_TERMINAL_PROMPT="0")
    if os.geteuid() == 0:
        environment["HOME"] = pwd.getpwnam("owner").pw_dir
    return environment


def _git_identity(repo) -> dict[str, Any]:
    # A privileged crossing reads secrets, but Git and repository hooks stay owner-plane.
    if os.geteuid() != 0:
        return {}
    owner = pwd.getpwnam("owner")
    if repo.stat().st_uid != owner.pw_uid:
        raise Refusal("thyrsus-repo-not-a-worktree")
    return {"user": owner.pw_uid, "group": owner.pw_gid, "extra_groups": os.getgrouplist(owner.pw_name, owner.pw_gid)}


def _git(repo, arguments, *, environment=None, inherited=(), capture=True, http_status=False):
    try:
        command = [GIT, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "-C", str(repo), *arguments]
        options: dict[str, Any] = dict(
            env=environment if environment is not None else _git_environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE if http_status else subprocess.DEVNULL, pass_fds=inherited,
            **_git_identity(repo),
        )
        if not http_status:
            return subprocess.run(command, timeout=45, check=False, **options)
        process = subprocess.Popen(command, start_new_session=True, **options)
        status_code: list[int | None] = [None]
        error_stream = process.stderr
        assert error_stream is not None

        def drain():
            window = b""
            while True:
                chunk = error_stream.read(4096)
                if not chunk:
                    return
                window = (window + chunk)[-8192:]
                found = re.search(rb"returned error:\s*([1-5][0-9]{2})", window)
                if found:
                    status_code[0] = int(found.group(1))

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=45)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            process.wait()
            raise
        finally:
            reader.join(timeout=1)
            error_stream.close()
        return SimpleNamespace(returncode=code, stdout=b"", http_status=status_code[0])
    except (OSError, subprocess.SubprocessError):
        raise Refusal("thyrsus-git-failed") from None


def _worktree(value):
    try:
        candidate = Path(value).expanduser().resolve(strict=True)
        result = _git(candidate, ["rev-parse", "--show-toplevel"])
        if result.returncode != 0:
            raise ValueError()
        root = Path(result.stdout.decode("utf-8").strip()).resolve(strict=True)
        result = _git(root, ["rev-parse", "--is-inside-work-tree"])
        if result.returncode != 0 or result.stdout.strip() != b"true":
            raise ValueError()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", root.name):
            raise ValueError()
        return root
    except (TypeError, OSError, ValueError, UnicodeError, Refusal):
        raise Refusal("thyrsus-repo-not-a-worktree") from None


def _push(repo, branch, profile):
    with _credential(profile) as (owner, username, password):
        record = bytearray(b"username=")
        read_fd, write_fd = os.pipe()
        try:
            record.extend(username)
            record.extend(b"\npassword=")
            record.extend(password)
            record.extend(b"\n\n")
            os.set_blocking(write_fd, False)
            if os.write(write_fd, record) != len(record):
                raise Refusal("thyrsus-token-absent")
            os.close(write_fd)
            write_fd = -1
            helper = Path(__file__).with_name("_credential.py")
            command = "!" + shlex.join([sys.executable, "-B", str(helper)])
            environment = _git_environment()
            # No netrc or configured global helper can become a second credential source.
            environment.update(HOME="/nonexistent", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
            # Only a descriptor number crosses the environment, never credential bytes.
            environment["THYRSUS_CREDENTIAL_FD"] = str(read_fd)
            remote = "https://" + FORGE + "/" + owner + "/" + repo.name + ".git"
            result = _git(repo, [
                "-c", "credential.helper=", "-c", "credential.helper=" + command,
                "-c", "credential.useHttpPath=true", "-c", "core.askPass=",
                "-c", "http.followRedirects=false", "-c", "http.sslVerify=true",
                "push", "--quiet", "--", remote, branch + ":refs/heads/" + branch,
            ], environment=environment, inherited=(read_fd,), capture=False, http_status=True)
            if result.returncode != 0:
                if not _reachable():
                    raise Refusal("thyrsus-forge-unreachable")
                if result.http_status is None:
                    raise Refusal("thyrsus-git-failed", git_status=result.returncode)
                raise Refusal("thyrsus-forge-refused", http_status=result.http_status, git_status=result.returncode)
        finally:
            _zero(record)
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)


def _repo_api(repo, owner):
    return "/repos/" + quote(owner, safe="") + "/" + quote(repo.name, safe="")


def _propose(payload, profile, receipt):
    repo = _worktree(payload.get("repo"))
    message = payload.get("message")
    if not isinstance(message, str) or not message.strip() or "\0" in message:
        raise Refusal("thyrsus-message-invalid")
    branch = payload.get("branch")
    if branch is None:
        from datetime import datetime, timezone
        branch = "thyrsus/" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if not isinstance(branch, str) or branch.startswith("-"):
        raise Refusal("thyrsus-branch-invalid")
    if _git(repo, ["check-ref-format", "--branch", branch]).returncode != 0:
        raise Refusal("thyrsus-branch-invalid")
    if _git(repo, ["show-ref", "--verify", "--quiet", "refs/heads/" + branch]).returncode == 0:
        raise Refusal("thyrsus-branch-exists")
    original_branch = _git(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    original_head = _git(repo, ["rev-parse", "--verify", "HEAD"])
    if original_branch.returncode not in {0, 1} or (original_branch.returncode and original_head.returncode):
        raise Refusal("thyrsus-git-failed")
    if original_branch.returncode == 0:
        restore = ["switch", "--quiet", original_branch.stdout.decode("utf-8").strip()]
        if original_head.returncode != 0:
            restore = ["symbolic-ref", "HEAD", "refs/heads/" + original_branch.stdout.decode("utf-8").strip()]
    else:
        restore = ["switch", "--quiet", "--detach", original_head.stdout.decode("ascii").strip()]
    receipt["branch"] = branch
    receipt["observed"] = {"worktree": True}
    for step, command in (("branch", ["switch", "--quiet", "-c", branch]),
                          ("stage", ["add", "--all", "--"])):
        if _git(repo, command, capture=False).returncode != 0:
            raise Refusal("thyrsus-git-failed")
        receipt["mutationPerformed"] = True
        receipt["attempt"].append({"step": step, "ok": True})
    difference = _git(repo, ["diff", "--cached", "--quiet", "--exit-code"])
    if difference.returncode == 0:
        if _git(repo, restore, capture=False).returncode != 0:
            raise Refusal("thyrsus-git-failed")
        receipt["attempt"].append({"step": "restore-original", "ok": True})
        if original_head.returncode == 0:
            if _git(repo, ["branch", "--delete", "--", branch], capture=False).returncode != 0:
                raise Refusal("thyrsus-git-failed")
            receipt["attempt"].append({"step": "delete-empty-branch", "ok": True})
        receipt["mutationPerformed"] = False
        raise Refusal("thyrsus-nothing-to-propose")
    if difference.returncode != 1:
        raise Refusal("thyrsus-git-failed")
    receipt["mutationPerformed"] = True
    if _git(repo, ["commit", "--quiet", "-m", message], capture=False).returncode != 0:
        raise Refusal("thyrsus-git-failed")
    receipt["attempt"].append({"step": "commit", "ok": True})
    # Local commits remain visible on failure. No remote rollback is invented.
    if not _reachable():
        raise Refusal("thyrsus-forge-unreachable")
    metadata, _, status_code = _api(profile, "GET", lambda owner: _repo_api(repo, owner))
    base = metadata.get("default_branch")
    if not isinstance(base, str) or not base:
        raise Refusal("thyrsus-forge-refused", http_status=status_code)
    _push(repo, branch, profile)
    receipt["attempt"].append({"step": "push", "ok": True})
    pull, owner, status_code = _api(profile, "POST", lambda owner: _repo_api(repo, owner) + "/pulls", {
        "head": branch, "base": base, "title": message.splitlines()[0], "body": message,
    })
    number = pull.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        raise Refusal("thyrsus-forge-refused", http_status=status_code)
    confirmed, owner, status_code = _api(profile, "GET", lambda owner: _repo_api(repo, owner) + "/pulls/" + str(number))
    head = confirmed.get("head")
    if confirmed.get("state") != "open" or not isinstance(head, dict) or head.get("ref") != branch:
        raise Refusal("thyrsus-pr-unobserved", http_status=status_code)
    receipt["pr_url"] = "https://" + FORGE + "/" + quote(owner, safe="") + "/" + quote(repo.name, safe="") + "/pulls/" + str(number)
    receipt["attempt"].append({"step": "pull-request", "ok": True})


def _admit(payload, profile, receipt):
    repo = _worktree(payload.get("repo"))
    number = payload.get("pr")
    if isinstance(number, bool) or not re.fullmatch(r"[1-9][0-9]*", str(number)):
        raise Refusal("thyrsus-pr-invalid")
    if not _reachable():
        raise Refusal("thyrsus-forge-unreachable")
    path = lambda owner: _repo_api(repo, owner) + "/pulls/" + str(number)
    receipt["observed"] = {"worktree": True}
    receipt["mutationPerformed"] = None
    _api(profile, "POST", lambda owner: path(owner) + "/merge", {"Do": "merge"})
    receipt["mutationPerformed"] = True
    receipt["attempt"].append({"step": "merge", "ok": True})
    pull, _, status_code = _api(profile, "GET", path)
    merged_sha = pull.get("merge_commit_sha")
    if pull.get("merged") is not True or not isinstance(merged_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", merged_sha):
        raise Refusal("thyrsus-merge-unobserved", http_status=status_code)
    receipt["merged_sha"] = merged_sha
    receipt["attempt"].append({"step": "merged-readback", "ok": True})


def _set_token(raw, payload, profile, receipt):
    # The setter never changes the HomeServer's skeleton authentication source.
    _vault()
    if os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is not None:
        raise Refusal("thyrsus-token-absent")
    token = payload.get("token") if payload is not None else raw.removesuffix("\n")
    if not isinstance(token, str) or not token or len(token.encode("utf-8")) > 511:
        raise Refusal("thyrsus-token-absent")
    if any(character in token for character in "\0\r\n\""):
        raise Refusal("thyrsus-token-invalid")
    secret = bytearray(token.encode("utf-8"))
    output = io.StringIO()
    original = sys.stdin
    try:
        sys.stdin = io.StringIO(token)
        setter = importlib.import_module("agathodaimon.keyman.newkey.index")
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status_code = setter.main([SERVICE, "--username", "owner", "--pword", "-", "--replace"])
        backend = json.loads(output.getvalue())
        receipt["mutationPerformed"] = backend.get("mutationPerformed")
        if status_code != 0 or backend.get("ok") is not True:
            signal = backend.get("firstMissingSignal", "")
            if signal.endswith(("non-root", "root-required", "uninitialized-system")):
                raise Refusal("thyrsus-vault-locked")
            raise Refusal("thyrsus-token-absent")
        receipt["attempt"].append({"step": "store-credential", "ok": True})
    finally:
        sys.stdin = original
        output.close()
        _zero(secret)
        token = None


def _primitive_request(verb, payload, original=None):
    value = dict(original or {})
    for key, default in (("schema", "caduceus.staff.v1"), ("intent_id", "thyrsus-" + uuid.uuid4().hex),
                         ("transition", "thyrsus/" + verb), ("version", "1.0.0"), ("timestamp", now_iso())):
        value.setdefault(key, default)
    value["payload"] = payload
    return Request(value, True, payload, json.dumps(value), value["intent_id"],
                   value["transition"], value["version"], value["timestamp"])


def _input(verb, arguments):
    if verb == "forge-token" and arguments:
        raise Refusal("thyrsus-token-stdin-required")
    if verb == "forge" and arguments:
        raise Refusal("thyrsus-arguments-invalid")
    # Ordinary positional CLI calls never wait for stdin. A tty read belongs
    # only to the explicit secret setter; envelope crossings arrive on a pipe.
    raw = "" if arguments or (verb != "forge-token" and sys.stdin.isatty()) else sys.stdin.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise Refusal("thyrsus-request-too-large")
    request = None
    payload = None
    if raw.lstrip().startswith("{"):
        original = sys.stdin
        try:
            sys.stdin = io.StringIO(raw)
            request = read(known_fields=("repo", "message", "branch", "pr", "token"))
            payload = request.payload
            if not request.envelope and isinstance(request.value.get("payload"), dict):
                payload = dict(request.value["payload"])
        finally:
            sys.stdin = original
    if arguments:
        import argparse
        class Arguments(argparse.ArgumentParser):
            def error(self, message):
                raise Refusal("thyrsus-arguments-invalid")

        parser = Arguments(prog="cli.py thyrsus " + verb)
        if verb in {"propose", "admit"}:
            parser.add_argument("repo")
        if verb == "propose":
            parser.add_argument("-m", dest="message", required=True)
            parser.add_argument("--branch", default=None)
        if verb == "admit":
            parser.add_argument("pr")
        payload = vars(parser.parse_args(arguments))
    if payload is None:
        payload = {}
    if request is None:
        request = _primitive_request(verb, {} if verb == "forge-token" else payload)
    elif not request.envelope:
        request = _primitive_request(verb, payload, request.value)
    if verb == "forge-token":
        token = payload.get("token")
        secrets = {token} if isinstance(token, str) and token else set()
        value = _scrub(request.value, secrets)
        request = Request(value, request.envelope, {}, json.dumps(value), value.get("intent_id"),
                          value.get("transition"), value.get("version"), value.get("timestamp"),
                          request.load_context_present, _scrub(request.load_context, secrets))
    return raw, payload, request


def _deed(verb, receipt, started):
    # Logs / Canonical Log Line: only static metadata, no repository/message/body.
    line = json.dumps({"who": "agathodaimon", "verb": "thyrsus-" + verb, "target": "household-forge",
                       "outcome": "ok" if receipt["ok"] else "failed",
                       "duration_ms": int((time.monotonic() - started) * 1000),
                       "id": uuid.uuid4().hex, "signal": receipt["firstMissingSignal"],
                       "first_missing_field": None if receipt["ok"] else "thyrsus/" + verb},
                      separators=(",", ":")) + "\n"
    path = _rooted("/var/log/appliance/appliance.log")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        encoded = line.encode("utf-8")
        if len(encoded) >= 1024 or os.write(descriptor, encoded) != len(encoded):
            raise OSError("ledger-write-failed")
    finally:
        os.close(descriptor)


def main_for(verb, arguments=None):
    started = time.monotonic()
    request = _primitive_request(verb, {})
    receipt = {"schema": "caduceus.staff.v1", "ok": False, "firstMissingSignal": "none",
               "mutationPerformed": False, "observed": None, "could-change": [], "attempt": []}
    if verb == "propose":
        receipt.update(branch=None, pr_url=None)
    if verb == "admit":
        receipt.update(merged_sha=None)
    if verb == "forge":
        receipt.update(forge=FORGE, token_present=False, reachable=False)
    try:
        profile = _configuration()
        raw, payload, request = _input(verb, list(arguments or []))
        if verb == "forge":
            receipt.update(token_present=_token_present(profile), reachable=_reachable())
            receipt["observed"] = {key: receipt[key] for key in ("forge", "token_present", "reachable")}
        elif verb == "propose":
            receipt["could-change"] = ["branch", "stage", "commit", "push", "pull-request"]
            _propose(payload, profile, receipt)
        elif verb == "admit":
            receipt["could-change"] = ["merge"]
            _admit(payload, profile, receipt)
        else:
            receipt["could-change"] = ["store-credential"]
            _set_token(raw, payload if raw.lstrip().startswith("{") else None, profile, receipt)
        receipt["ok"] = True
    except Refusal as error:
        receipt.update(firstMissingSignal=error.signal, **error.details)
    except EnvelopeError:
        receipt["firstMissingSignal"] = "thyrsus-envelope-invalid"
    except (OSError, ValueError, UnicodeError, KeyError, TypeError):
        receipt["firstMissingSignal"] = "thyrsus-observation-failed"
    finally:
        receipt["final"] = {"ok": receipt["ok"], "signal": receipt["firstMissingSignal"],
                            "mutationPerformed": receipt["mutationPerformed"]}
        if verb in WRITES:
            try:
                _deed(verb, receipt, started)
            except (OSError, ValueError):
                receipt.update(ok=False, firstMissingSignal="thyrsus-ledger-unavailable")
                receipt["final"].update(ok=False, signal="thyrsus-ledger-unavailable")
    return emit(attach(receipt, request) if request is not None else receipt)

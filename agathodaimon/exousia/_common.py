import json
import subprocess
import sys


class MalformedInput(ValueError):
    pass


class ExousiaUnprovisioned(RuntimeError):
    pass


def text(value, name):
    item = value.get(name)
    if not isinstance(item, str) or not item or len(item) > 512:
        raise MalformedInput(name + " missing or invalid")
    return item


def payload(fields):
    try:
        value = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise MalformedInput("invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != fields:
        raise MalformedInput("unexpected exousia fields")
    return value


def invoke_launcher(executable, value):
    completed = subprocess.run(
        ["/usr/bin/sudo", "-n", executable],
        input=json.dumps(value, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid exousia launcher response") from exc
    if not isinstance(result, dict):
        raise RuntimeError("invalid exousia launcher response")
    # The real launchers use rc=1 for valid negative JSON outcomes.
    return result


def _unprovisioned(result):
    signal = result.get("firstMissingSignal")
    if result.get("ok") is False and isinstance(signal, str) and signal:
        raise ExousiaUnprovisioned(signal)


def bind():
    payload(set())
    result = invoke_launcher("/usr/local/sbin/caduceus-bind", {})
    _unprovisioned(result)
    public_key, epoch = result.get("publicKey"), result.get("epoch")
    if result.get("ok") is not True or not isinstance(public_key, str) or not isinstance(epoch, str):
        raise RuntimeError("invalid caduceus bind response")
    return {"ok": True, "publicKey": public_key, "epoch": epoch}


def verify():
    value = payload({"pin", "publicKey"})
    public_key = text(value, "publicKey")
    if len(public_key) != 64:
        raise MalformedInput("publicKey missing or invalid")
    try:
        int(public_key, 16)
    except ValueError as exc:
        raise MalformedInput("publicKey missing or invalid") from exc
    result = invoke_launcher(
        "/usr/local/sbin/caduceus-verify",
        {"pin": text(value, "pin"), "publicKey": public_key},
    )
    verified = result.get("verified")
    if not isinstance(verified, bool):
        raise RuntimeError("invalid caduceus verify response")
    return {"verified": verified}


def execute(action):
    if action == "bind":
        return bind()
    if action == "verify":
        return verify()
    raise MalformedInput("unknown exousia verb")


def run(action, argv=None):
    try:
        if argv:
            raise MalformedInput("one exousia verb is required")
        result = execute(action)
    except MalformedInput as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except ExousiaUnprovisioned as exc:
        print(json.dumps({"ok": False, "firstMissingSignal": str(exc)}))
        return 0
    except Exception:  # noqa: BLE001
        print("exousia internal failure", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0

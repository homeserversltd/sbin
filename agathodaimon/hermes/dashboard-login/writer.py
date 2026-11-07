"""Update one Hermes dashboard config using its round-trip YAML editor."""
import json
import os
from pathlib import Path
import sys
import tempfile

# Isolated Python omits the agent source tree; this is the installed source seat.
sys.path.insert(0, "/opt/hermes/hermes-agent")
from hermes_yaml import roundtrip_yaml


def main():
    if len(sys.argv) != 2:
        return 2
    path = Path(sys.argv[1])
    data = json.load(sys.stdin)
    if not isinstance(data, dict) or not isinstance(data.get("password"), str) or not isinstance(data.get("secret"), str):
        return 2
    yaml = roundtrip_yaml()
    with path.open("r", encoding="utf-8") as stream:
        config = yaml.load(stream)
    if not isinstance(config, dict):
        return 2
    dashboard = config.setdefault("dashboard", {})
    if not isinstance(dashboard, dict):
        return 2
    auth = dashboard.setdefault("basic_auth", {})
    if not isinstance(auth, dict):
        return 2
    auth["password"] = data["password"]
    auth["secret"] = data["secret"]
    auth.pop("password_hash", None)
    fd, temporary = tempfile.mkstemp(prefix=".dashboard-login-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yaml.dump(config, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

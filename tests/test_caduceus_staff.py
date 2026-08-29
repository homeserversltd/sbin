import json
import os
import stat
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

from agathodaimon.lib.actuators import ACTUATORS

ROOT = Path(__file__).resolve().parents[1]


def run(*args, input_text=None):
    proc = subprocess.run(
        [sys.executable, "agathodaimon/cli.py", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input=input_text,
    )
    if not proc.stdout:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


class CaduceusStaffTests(unittest.TestCase):
    def test_lists_staff_actuators(self):
        data = run()
        self.assertEqual(data["schema"], "agathodaimon.cli.spine.v1")
        ids = set(data["nouns"])
        legacy_ids = {
            "backblaze-recover",
            "forgejo-backup-b2",
            "forgejo-migrate",
            "calibre-helper",
            "calibre-watch",
        }
        self.assertIn("network", ids)
        self.assertIn("lib", ids)


    def test_band_lists_verbs(self):
        data = run("network")
        self.assertEqual(data["noun"], "network")
        self.assertEqual(data["verbs"], ["dhcp", "dns", "firewall", "identity", "child-device", "wake-on-lan", "linker", "cert"])

    def test_attendance_and_pin_noun_surfaces_are_exact(self):
        self.assertEqual(run("attendance")["verbs"], ["bind", "verify"])
        self.assertEqual(run("pin")["verbs"], ["change", "reset-default"])

    def test_pin_change_refusal_is_ok_false_and_exact_payload_is_required(self):
        with self.subTest("exact payload"):
            proc = subprocess.run(
                [sys.executable, "agathodaimon/cli.py", "pin", "change"],
                cwd=ROOT, text=True, input=json.dumps({"oldPin": "2468", "newPin": "8642", "extra": "no"}),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 2)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for relative in ("key/skeleton.key", "vault/service_suite.key", "vault/caduceus.key"):
                path = base / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("x")
            module = base / "keyman.py"
            module.write_text("""class S:
    public_key_hex = 'a' * 64
    signer_epoch = 'b' * 64
    def close(self): pass
def change_caduceus_pin(old, new, **kwargs): raise RuntimeError('caduceus-pin-refused')
def bind_derived_caduceus(**kwargs): return S()
""")
            env = dict(os.environ, AGATHODAIMON_KEYMAN_MODULE=str(module), CADUCEUS_KEYMAN_KEY_DIR=str(base / "key"), CADUCEUS_KEYMAN_VAULT_DIR=str(base / "vault"))
            proc = subprocess.run(
                [sys.executable, "agathodaimon/cli.py", "pin", "change"], cwd=ROOT, env=env,
                text=True, input=json.dumps({"oldPin": "wrong", "newPin": "8642"}),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout), {"ok": False})

    def test_pin_reset_default_provisions_when_caduceus_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for relative in ("key/skeleton.key", "vault/service_suite.key"):
                path = base / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("x")
            module = base / "keyman.py"
            module.write_text("""calls = []
class S:
    public_key_hex = 'a' * 64
    signer_epoch = 'b' * 64
    def close(self): calls.append(("close",))
def provision_caduceus(pin, **kwargs): calls.append(("provision", pin, kwargs))
def bind_derived_caduceus(**kwargs): calls.append(("bind", kwargs)); return S()
""")
            env = dict(os.environ, AGATHODAIMON_KEYMAN_MODULE=str(module), CADUCEUS_KEYMAN_KEY_DIR=str(base / "key"), CADUCEUS_KEYMAN_VAULT_DIR=str(base / "vault"))
            proc = subprocess.run(
                [sys.executable, "agathodaimon/cli.py", "pin", "reset-default"], cwd=ROOT, env=env,
                text=True, input="{}", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout), {"ok": True, "publicKey": "a" * 64, "epoch": "b" * 64})

    def test_pin_reset_default_changes_present_caduceus_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for relative in ("key/skeleton.key", "vault/service_suite.key", "vault/caduceus.key"):
                path = base / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("x")
            module = base / "keyman.py"
            module.write_text("""class S:
    public_key_hex = 'c' * 64
    signer_epoch = 'd' * 64
    def close(self): pass
def change_caduceus_pin(old, new, **kwargs):
    assert (old, new) == ("1", "1")
def bind_derived_caduceus(**kwargs): return S()
""")
            env = dict(os.environ, AGATHODAIMON_KEYMAN_MODULE=str(module), CADUCEUS_KEYMAN_KEY_DIR=str(base / "key"), CADUCEUS_KEYMAN_VAULT_DIR=str(base / "vault"))
            proc = subprocess.run(
                [sys.executable, "agathodaimon/cli.py", "pin", "reset-default"], cwd=ROOT, env=env,
                text=True, input="{}", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout), {"ok": True, "publicKey": "c" * 64, "epoch": "d" * 64})

    def test_pin_reset_default_refusal_is_ok_false(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for relative in ("key/skeleton.key", "vault/service_suite.key"):
                path = base / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("x")
            module = base / "keyman.py"
            module.write_text("def provision_caduceus(pin, **kwargs): raise RuntimeError(\"agathodaimon-pin-refused\")\n")
            env = dict(os.environ, AGATHODAIMON_KEYMAN_MODULE=str(module), CADUCEUS_KEYMAN_KEY_DIR=str(base / "key"), CADUCEUS_KEYMAN_VAULT_DIR=str(base / "vault"))
            proc = subprocess.run(
                [sys.executable, "agathodaimon/cli.py", "pin", "reset-default"], cwd=ROOT, env=env,
                text=True, input="{}", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout), {"ok": False})

    def test_read_only_exemplar_is_truthful(self):
        data = run("network", "dhcp", "status")
        self.assertFalse(data.get("mutationPerformed", False))
        self.assertIn("ok", data)


    def test_directly_executed_python_staff_have_shebang(self):
        paths = [ROOT / "agathodaimon/cli.py"]
        paths.extend(
            sorted(
                path
                for path in (ROOT / "agathodaimon").rglob("*.py")
                if path.stat().st_mode & stat.S_IXUSR
            )
        )
        for path in paths:
            self.assertTrue(
                path.read_bytes().startswith(b"#!/usr/bin/env python3\n"),
                path,
            )


if __name__ == "__main__":
    unittest.main()

import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from agathodaimon.exousia import _common
from agathodaimon.exousia.change import index as change


class ExousiaLauncherTests(unittest.TestCase):
    def completed(self, payload, returncode=0):
        return subprocess.CompletedProcess([], returncode, json.dumps(payload), "")

    def test_bind_maps_success_and_uses_exact_sudo_argv(self):
        with patch.object(_common.subprocess, "run", return_value=self.completed({"ok": True, "publicKey": "a" * 64, "epoch": "b" * 64})) as run:
            with patch("sys.stdin", io.StringIO("{}")):
                self.assertEqual(_common.bind(), {"ok": True, "publicKey": "a" * 64, "epoch": "b" * 64})
        run.assert_called_once_with(
            ["/usr/bin/sudo", "-n", "/usr/local/sbin/caduceus-bind"],
            input="{}", capture_output=True, text=True, check=False,
        )

    def test_bind_unprovisioned_preserves_first_missing_signal(self):
        response = {"ok": False, "firstMissingSignal": "caduceus-bind-launcher-missing"}
        with patch.object(_common.subprocess, "run", return_value=self.completed(response, 1)):
            with patch("sys.stdin", io.StringIO("{}")):
                with self.assertRaisesRegex(_common.ExousiaUnprovisioned, response["firstMissingSignal"]):
                    _common.bind()

    def test_verify_maps_both_boolean_results_and_validated_json(self):
        public_key = "c" * 64
        for verified in (True, False):
            returncode = 1 if not verified else 0
            with self.subTest(verified=verified), patch.object(_common.subprocess, "run", return_value=self.completed({"verified": verified}, returncode)) as run:
                with patch("sys.stdin", io.StringIO(json.dumps({"pin": "1234", "publicKey": public_key}))):
                    self.assertEqual(_common.verify(), {"verified": verified})
            run.assert_called_once_with(
                ["/usr/bin/sudo", "-n", "/usr/local/sbin/caduceus-verify"],
                input=json.dumps({"pin": "1234", "publicKey": public_key}, separators=(",", ":")),
                capture_output=True, text=True, check=False,
            )

    def test_nonzero_launcher_without_json_is_an_invocation_failure(self):
        completed = subprocess.CompletedProcess([], 1, "", "launcher failed")
        with patch.object(_common.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "invalid exousia launcher response"):
                _common.invoke_launcher("/usr/local/sbin/caduceus-bind", {})

    def test_change_routes_exact_pin_shape_to_atomic_launcher(self):
        response = {"ok": True, "publicKey": "d" * 64, "epoch": "e" * 64}
        request = {"oldPin": "1111", "newPin": "2222"}
        with patch.object(change, "invoke_launcher", return_value=response) as invoke:
            with patch("sys.stdin", io.StringIO(json.dumps(request))):
                with patch.object(change.sys, "argv", ["change"]):
                    self.assertEqual(change.main(), 0)
        invoke.assert_called_once_with("/usr/local/sbin/caduceus-atomic-change-pin", request)

    def test_change_preserves_pin_refusal_contract(self):
        response = {"ok": False, "firstMissingSignal": "caduceus-staff-derived-key-mismatch"}
        with patch.object(change, "invoke_launcher", return_value=response):
            with patch("sys.stdin", io.StringIO(json.dumps({"oldPin": "1111", "newPin": "2222"}))):
                with patch.object(change.sys, "argv", ["change"]):
                    with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                        self.assertEqual(change.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"ok": False})

    def test_common_has_no_direct_keyman_or_store_paths(self):
        source = Path(_common.__file__).read_text()
        self.assertNotIn("keyman_caduceus_access", source)
        self.assertNotIn("/root", source)
        self.assertNotIn("/vault", source)


if __name__ == "__main__":
    unittest.main()

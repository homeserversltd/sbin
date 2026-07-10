from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class HouseCaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cert_dir = Path(self.tmp.name) / "certs"
        self.bundle_dir = Path(self.tmp.name) / "bundles"
        os.environ["CADUCEUS_CERT_DIR"] = str(self.cert_dir)
        os.environ["CADUCEUS_CERT_BUNDLE_DIR"] = str(self.bundle_dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *args: str) -> dict:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.run(
            [sys.executable, "-m", "caduceus_staff.house_ca", *args],
            check=True,
            text=True,
            capture_output=True,
            env=env,
        )
        return json.loads(proc.stdout)

    def test_ca_stable_across_leaf_reissues(self) -> None:
        a = self._run("issue-leaf", "--sans", "alpha.home.arpa")
        b = self._run("issue-leaf", "--sans", "beta.home.arpa")
        self.assertTrue(a["ok"])
        self.assertTrue(b["ok"])
        self.assertEqual(a["ca_fingerprint"], b["ca_fingerprint"])
        self.assertNotEqual(a["leaf_fingerprint"], b["leaf_fingerprint"])
        self.assertFalse(a["client_reinstall_required"])
        self.assertFalse(b["client_reinstall_required"])

    def test_bundle_no_private_key(self) -> None:
        self._run("issue-leaf")
        b = self._run("bundle", "linux")
        self.assertTrue(b["ok"])
        raw = Path(b["path"]).read_bytes()
        self.assertNotIn(b"PRIVATE KEY", raw)

    def test_rotate_requires_flag_and_changes_ca(self) -> None:
        first = self._run("issue-leaf")
        denied = subprocess.run(
            [sys.executable, "-m", "caduceus_staff.house_ca", "rotate-ca"],
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": str(ROOT)},
        )
        self.assertNotEqual(denied.returncode, 0)
        rotated = self._run("rotate-ca", "--i-understand-clients-reinstall")
        self.assertTrue(rotated["ok"])
        self.assertTrue(rotated["client_reinstall_required"])
        self.assertNotEqual(first["ca_fingerprint"], rotated["ca_fingerprint"])


if __name__ == "__main__":
    unittest.main()

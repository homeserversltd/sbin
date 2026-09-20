from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class HouseCaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cert_dir = Path(self.tmp.name) / "certs"
        self.bundle_dir = Path(self.tmp.name) / "bundles"
        self.nginx_dir = Path(self.tmp.name) / "nginx"
        self.nginx_dir.mkdir()
        os.environ["CADUCEUS_CERT_DIR"] = str(self.cert_dir)
        os.environ["CADUCEUS_CERT_BUNDLE_DIR"] = str(self.bundle_dir)
        os.environ["CADUCEUS_NGINX_DIR"] = str(self.nginx_dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *args: str) -> dict:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.run(
            [sys.executable, "agathodaimon/cli.py", "cert", "house-ca", *args],
            check=True,
            text=True,
            capture_output=True,
            env=env,
        )
        return json.loads(proc.stdout)

    def _house_ca_module(self):
        path = ROOT / "agathodaimon" / "network" / "cert" / "house-ca" / "index.py"
        spec = importlib.util.spec_from_file_location("house_ca_test_module", path)
        if spec is None or spec.loader is None:
            self.fail("unable to load house-ca module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_apply_nginx_emits_sse_directives_and_retires_legacy_vhost(self) -> None:
        portal = "portal.example.home.arpa"
        target = self.nginx_dir / "agathodaimon-portal-example-home-arpa.conf"
        legacy = self.nginx_dir / "caduceus-portal-example-home-arpa.conf"
        legacy.write_bytes(b"legacy-vhost")

        first = self._run("apply-nginx", portal, "http://127.0.0.1:3013", "/cert.pem", "/key.pem")

        expected = (
            b"server { listen 443 ssl; server_name portal.example.home.arpa; "
            b"ssl_certificate /cert.pem; ssl_certificate_key /key.pem; "
            b"location / { proxy_buffering off; proxy_http_version 1.1; "
            b"proxy_read_timeout 60s; proxy_set_header Host $host; "
            b"proxy_set_header X-Forwarded-Proto $scheme; "
            b"proxy_set_header X-Forwarded-Host $host; "
            b"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; "
            b"proxy_pass http://127.0.0.1:3013; } }\n"
        )
        self.assertEqual(target.read_bytes(), expected)
        self.assertFalse(legacy.exists())
        self.assertTrue(first["changed"])
        self.assertEqual(first["legacy_path"], str(legacy))
        self.assertTrue(first["legacy_present"])
        self.assertTrue(first["legacy_retired"])
        self.assertFalse(first["legacy_remaining"])
        self.assertTrue(first["replacement_written"])

        second = self._run("apply-nginx", portal, "http://127.0.0.1:3013", "/cert.pem", "/key.pem")
        self.assertFalse(second["changed"])
        self.assertFalse(second["legacy_present"])
        self.assertFalse(second["legacy_retired"])
        self.assertFalse(second["replacement_written"])

    def test_apply_nginx_dry_run_preserves_legacy_vhost(self) -> None:
        portal = "portal.example.home.arpa"
        legacy = self.nginx_dir / "caduceus-portal-example-home-arpa.conf"
        original = b"legacy-vhost"
        legacy.write_bytes(original)

        result = self._run("apply-nginx", portal, "https://127.0.0.1:3013", "/cert.pem", "/key.pem", "--dry-run")

        self.assertFalse(result["changed"])
        self.assertTrue(result["legacy_present"])
        self.assertFalse(result["legacy_retired"])
        self.assertFalse(result["replacement_written"])
        self.assertEqual(legacy.read_bytes(), original)
        self.assertFalse((self.nginx_dir / "agathodaimon-portal-example-home-arpa.conf").exists())

    def test_apply_nginx_write_failure_preserves_legacy_vhost(self) -> None:
        module = self._house_ca_module()
        portal = "portal.example.home.arpa"
        legacy = self.nginx_dir / "caduceus-portal-example-home-arpa.conf"
        original = b"legacy-vhost"
        legacy.write_bytes(original)

        with patch.object(module.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                module.apply_nginx(portal, "http://127.0.0.1:3013", "/cert.pem", "/key.pem")

        self.assertEqual(legacy.read_bytes(), original)
        self.assertFalse((self.nginx_dir / "agathodaimon-portal-example-home-arpa.conf").exists())

    def test_apply_nginx_retries_legacy_retirement_after_unlink_failure(self) -> None:
        module = self._house_ca_module()
        portal = "portal.example.home.arpa"
        legacy = self.nginx_dir / "caduceus-portal-example-home-arpa.conf"
        legacy.write_bytes(b"legacy-vhost")
        original_unlink = Path.unlink

        def fail_legacy_unlink(path, *args, **kwargs):
            if path == legacy:
                raise OSError("unlink failed")
            return original_unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", fail_legacy_unlink):
            with self.assertRaises(OSError):
                module.apply_nginx(portal, "http://127.0.0.1:3013", "/cert.pem", "/key.pem")

        self.assertTrue(legacy.exists())
        retry = module.apply_nginx(portal, "http://127.0.0.1:3013", "/cert.pem", "/key.pem")
        self.assertTrue(retry["changed"])
        self.assertFalse(retry["replacement_written"])
        self.assertTrue(retry["legacy_present"])
        self.assertTrue(retry["legacy_retired"])
        self.assertFalse(legacy.exists())

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

    def test_stdin_envelope_supplies_house_ca_args(self) -> None:
        proc = subprocess.run(
            [sys.executable, "agathodaimon/cli.py", "cert", "house-ca"],
            input=json.dumps({"args": ["status"]}),
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": str(ROOT)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        body = json.loads(proc.stdout)
        self.assertIsInstance(body, dict)
        self.assertTrue(body["ok"])

    def test_rotate_requires_flag_and_changes_ca(self) -> None:
        first = self._run("issue-leaf")
        denied = subprocess.run(
            [sys.executable, "agathodaimon/cli.py", "cert", "house-ca", "rotate-ca"],
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

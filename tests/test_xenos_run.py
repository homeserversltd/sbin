import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agathodaimon.xenos import _launcher
from agathodaimon.xenos.run import index as run_face

ROOT = Path(__file__).resolve().parents[1]


class XenosLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.xenia_root = Path(self.temporary.name) / "xenia"
        self.clone = self.xenia_root / "alpha"
        self.permissions = self.clone / "permissions"
        self.permissions.mkdir(parents=True)
        self.clone.chmod(0o755)
        self.permissions.chmod(0o755)
        self.command = self.clone / "allowed"
        self.command.write_text("#!/bin/sh\nprintf 'root-output\\n'\n", encoding="utf-8")
        self.command.chmod(0o755)

    def grant(self, line=None, mode=0o440):
        if line is None:
            line = f"caduceus ALL=(root) NOPASSWD: {self.command} literal"
        grant = self.permissions / "xenia"
        if grant.exists() or grant.is_symlink():
            grant.unlink()
        grant.write_text(line + "\n", encoding="utf-8")
        grant.chmod(mode)
        return grant

    def owner_and_visudo(self, visudo="/bin/true"):
        return (
            patch.object(_launcher, "_allowed_owner_uids", return_value={os.getuid()}),
            patch.object(_launcher, "_visudo", return_value=visudo),
        )

    def refusal(self, expected, operation):
        with self.assertRaises(_launcher.Refusal) as raised:
            operation()
        self.assertEqual(raised.exception.first_missing_signal, expected)
        return raised.exception

    def test_launcher_is_inside_shelf_executable_and_has_only_two_verbs(self):
        launcher = ROOT / "agathodaimon" / "caduceus-xenos-run"
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o755)
        source = launcher.read_text(encoding="utf-8")
        self.assertIn("xenos-run-root-required", source)
        self.assertIn(
            "exec /usr/bin/python3 /usr/local/sbin/agathodaimon/xenos/_launcher.py \"$@\"",
            source,
        )
        self.assertEqual(
            json.loads((ROOT / "agathodaimon" / "xenos" / "index.json").read_text())["children"],
            ["run"],
        )
        self.assertEqual(json.loads((ROOT / "agathodaimon" / "index.json").read_text())["children"][-1], "xenos")
        with patch.object(_launcher.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(_launcher.main(["alpha", "third", "value"]), 0)
        self.assertEqual(json.loads(output.getvalue())["firstMissingSignal"], "xenos-run-verb-invalid")

    def test_python_root_assertion_refuses_before_dispatch(self):
        with patch.object(_launcher.os, "geteuid", return_value=1000), patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(_launcher.main(["alpha", "band", "probe"]), 1)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "firstMissingSignal": "xenos-run-root-required"})

    def test_id_contract(self):
        for accepted in ("a", "a0", "a-b", "a" * 63):
            with self.subTest(accepted=accepted):
                _launcher._validate_id(accepted)
        for rejected in ("", "A", "-a", "a_", "a" * 64, "a/b"):
            with self.subTest(rejected=rejected):
                self.refusal("xenos-id-invalid", lambda value=rejected: _launcher._validate_id(value))

    def test_python_privilege_drop_clears_groups_then_gid_then_uid(self):
        calls = []
        staff = SimpleNamespace(pw_uid=977, pw_gid=977)
        with patch.object(_launcher.os, "setgroups", side_effect=lambda groups: calls.append(("groups", groups))), patch.object(
            _launcher.os, "setgid", side_effect=lambda gid: calls.append(("gid", gid))
        ), patch.object(_launcher.os, "setuid", side_effect=lambda uid: calls.append(("uid", uid))):
            _launcher._drop_to_staff(staff)()
        self.assertEqual(calls, [("groups", []), ("gid", 977), ("uid", 977)])

    def test_band_passes_envelope_clone_cwd_minimal_env_and_drop(self):
        cli = self.clone / "staff" / "cli.py"
        cli.parent.mkdir()
        cli.write_text("# guest", encoding="utf-8")
        captured = {}

        def fake_run(argv, stdin_bytes, **kwargs):
            captured.update(argv=argv, stdin=stdin_bytes, **kwargs)
            return 0, b"guest-output\n", b"", False

        old_schema = os.environ.get("XENIA_SCHEMA_BASE")
        os.environ["XENIA_SCHEMA_BASE"] = "https://schema.example"
        self.addCleanup(
            lambda: os.environ.pop("XENIA_SCHEMA_BASE", None)
            if old_schema is None
            else os.environ.__setitem__("XENIA_SCHEMA_BASE", old_schema)
        )
        with patch.object(_launcher, "XENIA_ROOT", self.xenia_root), patch.object(
            _launcher, "_staff_identity", return_value=SimpleNamespace(pw_uid=977, pw_gid=977)
        ), patch.object(_launcher, "_run", side_effect=fake_run):
            receipt = _launcher.run_band("alpha", "probe/status", b'{"round":"trip"}')
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["stdout"], "guest-output\n")
        self.assertEqual(captured["argv"], [_launcher.PYTHON3, str(cli), "probe/status"])
        self.assertEqual(captured["stdin"], b'{"round":"trip"}')
        self.assertEqual(captured["cwd"], self.clone)
        self.assertEqual(
            captured["environment"],
            {
                "HOME": "/var/lib/caduceus",
                "PATH": _launcher.SAFE_PATH,
                "XENIA_ID": "alpha",
                "XENIA_SEAT": str(self.clone),
                "XENIA_SCHEMA_BASE": "https://schema.example",
            },
        )
        self.assertIsNotNone(captured["preexec_fn"])

    def test_band_timeout_is_exact_refusal(self):
        cli = self.clone / "staff" / "cli.py"
        cli.parent.mkdir()
        cli.write_text("# guest", encoding="utf-8")
        with patch.object(_launcher, "XENIA_ROOT", self.xenia_root), patch.object(
            _launcher, "_staff_identity", return_value=SimpleNamespace(pw_uid=977, pw_gid=977)
        ), patch.object(_launcher, "_run", return_value=(-9, b"partial", b"", True)):
            self.assertEqual(
                _launcher.run_band("alpha", "sleep", b"{}"),
                {"ok": False, "firstMissingSignal": "xenos-run-timeout"},
            )

    def test_exec_exact_match_runs_with_clone_cwd_and_root_environment(self):
        self.grant()
        owner, visudo = self.owner_and_visudo()
        with owner, visudo, patch.object(_launcher, "XENIA_ROOT", self.xenia_root), patch.object(
            _launcher, "_run", return_value=(0, b"root-output\n", b"", False)
        ) as invoked:
            receipt = _launcher.run_exec("alpha", [str(self.command), "literal"], b"stdin")
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["stdout"], "root-output\n")
        argv, stdin_bytes = invoked.call_args.args
        self.assertEqual(argv, [str(self.command), "literal"])
        self.assertEqual(stdin_bytes, b"stdin")
        self.assertEqual(invoked.call_args.kwargs["cwd"], self.clone)
        self.assertEqual(invoked.call_args.kwargs["environment"]["HOME"], "/root")
        self.assertNotIn("preexec_fn", invoked.call_args.kwargs)

    def test_grant_owner_and_directory_write_modes_refuse(self):
        self.grant()
        with patch.object(_launcher, "_allowed_owner_uids", return_value={0}):
            self.refusal("xenia-grant-file-owner-refused", lambda: _launcher._load_grants(self.clone))
        with patch.object(_launcher, "_allowed_owner_uids", return_value={os.getuid()}):
            self.permissions.chmod(0o777)
            self.refusal("xenia-permissions-directory-world-writable", lambda: _launcher._load_grants(self.clone))
            self.permissions.chmod(0o755)
            self.clone.chmod(0o777)
            self.refusal("xenos-clone-world-writable", lambda: _launcher._load_grants(self.clone))

    def test_exec_command_symlink_cannot_escape_clone(self):
        link = self.clone / "escape"
        link.symlink_to("/bin/true")
        self.grant(f"caduceus ALL=(root) NOPASSWD: {link}")
        owner, visudo = self.owner_and_visudo()
        with owner, visudo, patch.object(_launcher, "XENIA_ROOT", self.xenia_root):
            self.refusal(
                "xenos-exec-path-outside-clone",
                lambda: _launcher.run_exec("alpha", [str(link)], b""),
            )

    def test_grant_path_outside_clone_refuses_with_line(self):
        self.grant("caduceus ALL=(root) NOPASSWD: /tmp/outside")
        owner, visudo = self.owner_and_visudo()
        with owner, visudo:
            refusal = self.refusal("xenia-grant-path-outside-clone", lambda: _launcher._load_grants(self.clone))
        self.assertEqual(refusal.line_number, 1)

    def test_grant_all_and_parent_segments_refuse_with_line(self):
        cases = (
            (f"caduceus ALL=(root) NOPASSWD: {self.clone}/ALL-tool", "xenia-grant-all-refused"),
            (f"caduceus ALL=(root) NOPASSWD: {self.clone}/tools/../allowed", "xenia-grant-parent-segment-refused"),
        )
        for line, expected in cases:
            with self.subTest(expected=expected):
                self.grant(line)
                owner, visudo = self.owner_and_visudo()
                with owner, visudo:
                    refusal = self.refusal(expected, lambda: _launcher._load_grants(self.clone))
                self.assertEqual(refusal.line_number, 1)

    def test_grant_wildcard_refuses_with_line(self):
        self.grant(f"caduceus ALL=(root) NOPASSWD: {self.command} *")
        owner, visudo = self.owner_and_visudo()
        with owner, visudo:
            refusal = self.refusal("xenia-grant-wildcard-refused", lambda: _launcher._load_grants(self.clone))
        self.assertEqual(refusal.line_number, 1)

    def test_grantee_other_than_caduceus_refuses_with_line(self):
        self.grant(f"xenia ALL=(root) NOPASSWD: {self.command}")
        owner, visudo = self.owner_and_visudo()
        with owner, visudo:
            refusal = self.refusal("xenia-grant-grantee-refused", lambda: _launcher._load_grants(self.clone))
        self.assertEqual(refusal.line_number, 1)

    def test_symlinked_grant_file_refuses(self):
        target = Path(self.temporary.name) / "grant-target"
        target.write_text(f"caduceus ALL=(root) NOPASSWD: {self.command}\n")
        (self.permissions / "xenia").symlink_to(target)
        self.refusal("xenia-grant-file-symlink", lambda: _launcher._load_grants(self.clone))

    def test_world_writable_grant_file_refuses(self):
        self.grant(mode=0o646)
        with patch.object(_launcher, "_allowed_owner_uids", return_value={os.getuid()}):
            self.refusal("xenia-grant-file-writable", lambda: _launcher._load_grants(self.clone))

    def test_visudo_failure_refuses_before_line_use(self):
        self.grant()
        owner, visudo = self.owner_and_visudo("/bin/false")
        with owner, visudo:
            self.refusal("xenia-visudo-invalid", lambda: _launcher._load_grants(self.clone))

    def test_argument_mismatch_refuses(self):
        self.grant()
        owner, visudo = self.owner_and_visudo()
        with owner, visudo, patch.object(_launcher, "XENIA_ROOT", self.xenia_root):
            self.refusal(
                "xenia-grant-argument-mismatch",
                lambda: _launcher.run_exec("alpha", [str(self.command), "different"], b""),
            )

    def test_requested_path_outside_clone_refuses_before_grant(self):
        with patch.object(_launcher, "XENIA_ROOT", self.xenia_root):
            self.refusal(
                "xenos-exec-path-outside-clone",
                lambda: _launcher.run_exec("alpha", ["/tmp/outside"], b""),
            )

    def test_visudo_resolution_prefers_sbin_then_bin_and_refuses_absence(self):
        with patch.object(_launcher.os.path, "isfile", return_value=True), patch.object(_launcher.os, "access", return_value=True):
            self.assertEqual(_launcher._visudo(), "/usr/sbin/visudo")
        with patch.object(_launcher.os.path, "isfile", side_effect=lambda path: path == "/usr/bin/visudo"), patch.object(
            _launcher.os, "access", return_value=True
        ):
            self.assertEqual(_launcher._visudo(), "/usr/bin/visudo")
        with patch.object(_launcher.os.path, "isfile", return_value=False):
            self.refusal("xenia-visudo-unavailable", _launcher._visudo)

    def test_xenos_run_face_forwards_raw_envelope_and_attaches_stamp(self):
        envelope = {
            "schema": "caduceus.staff.v1",
            "intent_id": "intent-xenos",
            "transition": "xenos.run",
            "version": 1,
            "timestamp": "2026-09-14T00:00:00Z",
            "payload": {"id": "alpha", "band": "probe/status"},
            "unknown": {"preserve": True},
        }
        raw = json.dumps(envelope, separators=(",", ":"))
        completed = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "stdout": "guest\n"}), "")
        with patch("sys.stdin", io.StringIO(raw)), patch("sys.stdout", new_callable=io.StringIO) as output, patch.object(
            run_face.subprocess, "run", return_value=completed
        ) as invoked:
            self.assertEqual(run_face.main([]), 0)
        invoked.assert_called_once_with(
            [str(run_face.LAUNCHER), "alpha", "band", "probe/status"],
            input=raw,
            capture_output=True,
            text=True,
            check=False,
        )
        receipt = json.loads(output.getvalue())
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["intent_id"], "intent-xenos")
        self.assertEqual(receipt["raw_envelope"], raw)
        self.assertEqual(receipt["envelope"]["unknown"], {"preserve": True})
        self.assertEqual(receipt["staff"]["verb"], "run")
        self.assertEqual(receipt["staff"]["outcome"], "ok")

    def test_guest_kit_runs_in_staff_without_agathodaimon_import(self):
        clone = Path(self.temporary.name) / "guest-clone"
        staff = clone / "staff"
        band = staff / "probe"
        band.mkdir(parents=True)
        shutil.copy2(ROOT / "agathodaimon" / "xenos" / "guest" / "cli.py", staff / "cli.py")
        shutil.copy2(ROOT / "agathodaimon" / "xenos" / "guest" / "_envelope.py", staff / "_envelope.py")
        (staff / "index.json").write_text('{"children":["probe"]}\n', encoding="utf-8")
        (band / "index.py").write_text(
            "from _envelope import attach, read_fields\n"
            "import importlib.util, json\n"
            "def main(argv=None):\n"
            "    request = read_fields('value')\n"
            "    result = attach({'ok': True, 'value': request.payload.get('value'), 'agathodaimonImportable': importlib.util.find_spec('agathodaimon') is not None}, request)\n"
            "    print(json.dumps(result))\n"
            "    return 0\n",
            encoding="utf-8",
        )
        envelope = {
            "schema": "caduceus.staff.v1",
            "intent_id": "guest-intent",
            "transition": "guest.probe",
            "version": 1,
            "timestamp": "2026-09-14T00:00:00Z",
            "payload": {"value": "round-trip"},
        }
        completed = subprocess.run(
            ["/usr/bin/python3", str(staff / "cli.py"), "probe"],
            cwd=clone,
            env={"PATH": "/usr/bin:/bin", "PYTHONPYCACHEPREFIX": str(Path(self.temporary.name) / "pycache")},
            input=json.dumps(envelope),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = json.loads(completed.stdout)
        self.assertEqual(receipt["value"], "round-trip")
        self.assertFalse(receipt["agathodaimonImportable"])
        self.assertEqual(receipt["intent_id"], "guest-intent")

    def test_guest_kit_is_exact_shelf_copy_except_cli_bootstrap(self):
        shelf_cli = (ROOT / "agathodaimon" / "cli.py").read_text(encoding="utf-8")
        expected_guest = shelf_cli.replace(
            "if str(ROOT.parent) not in sys.path: sys.path.insert(0, str(ROOT.parent))",
            "if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))",
        )
        self.assertEqual(
            (ROOT / "agathodaimon" / "xenos" / "guest" / "cli.py").read_text(encoding="utf-8"),
            expected_guest,
        )
        self.assertEqual(
            (ROOT / "agathodaimon" / "xenos" / "guest" / "_envelope.py").read_bytes(),
            (ROOT / "agathodaimon" / "_envelope.py").read_bytes(),
        )

    def test_readme_names_sudoers_custody_prune_and_outer_cap(self):
        source = (ROOT / "agathodaimon" / "xenos" / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "caduceus ALL=(root) NOPASSWD: /usr/local/sbin/agathodaimon/caduceus-xenos-run * *",
            source,
        )
        self.assertIn("prune: true", source)
        self.assertIn("64 KiB", source)
        self.assertIn("Harmonia", source)


if __name__ == "__main__":
    unittest.main()

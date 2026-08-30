import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.exousia import _common

ROOT = Path(__file__).parents[1]


def load_face(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def envelope(transition, payload=None, **extra):
    value = {
        "schema": "caduceus.staff.v1", "intent_id": "intent-test",
        "transition": transition, "version": {"future": True},
        "timestamp": "2026-08-31T00:00:00Z",
        "payload": payload or {}, "unknownKernelExtension": {"must": "survive"},
    }
    value.update(extra)
    return value


def invoke(fn, value):
    out = io.StringIO()
    with patch("sys.stdin", io.StringIO(json.dumps(value))), contextlib.redirect_stdout(out):
        code = fn([])
    return code, json.loads(out.getvalue()) if out.getvalue().strip() else None


def invoke_argv(fn, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fn(argv)
    return code, json.loads(out.getvalue()) if out.getvalue().strip() else None


class EnvelopeContractTests(unittest.TestCase):
    def test_legacy_fields_are_narrow_and_raw_text_is_exact(self):
        raw = '{"pin":"p","publicKey":"k","extra":7}'
        with patch("sys.stdin", io.StringIO(raw)):
            request = read(known_fields=("pin", "publicKey"), declared_flags=("pin",))
        self.assertEqual(request.payload, {"pin": "p", "publicKey": "k"})
        self.assertEqual(request.raw_envelope, raw)
        self.assertFalse(request.envelope)

    def test_attach_adds_absent_and_list_stamps_but_preserves_malformed(self):
        for prior in (None, [{"verb": "prior"}]):
            value = envelope("settings.display.read", {"brightness": 25})
            if prior is not None:
                value["stamps"] = prior
            raw = json.dumps(value, separators=(",", ":"))
            with patch("sys.stdin", io.StringIO(raw)):
                request = read(known_fields=("brightness",))
            result = attach({"ok": True}, request)
            self.assertEqual(result["raw_envelope"], raw)
            self.assertEqual(result["stamps"][:-1], prior or [])
            self.assertEqual(result["envelope"]["stamps"], result["stamps"])
        value = envelope("settings.display.read", {"brightness": 25}, stamps={"caller": "kept"})
        with patch("sys.stdin", io.StringIO(json.dumps(value))):
            request = read(known_fields=("brightness",))
        result = attach({"ok": True}, request)
        self.assertEqual(result["envelope"]["stamps"], {"caller": "kept"})
        self.assertEqual(result["stamps"], [result["staff"]])

    def test_wire_edges_and_truthful_failed_outcome(self):
        for transition in ("settings.display.mutate", "/settings/display/mutate", "settings:display:mutate"):
            value = envelope(transition, {"brightness": 25})
            with patch("sys.stdin", io.StringIO(json.dumps(value))):
                self.assertEqual(read(known_fields=("brightness",)).verb, "mutate")
        value = envelope("settings.display.read", {"brightness": 25})
        with patch("sys.stdin", io.StringIO(json.dumps(value))):
            request = read(known_fields=("brightness",))
        self.assertEqual(attach({"verified": False}, request)["staff"]["outcome"], "failed")

    def test_kernel_schema_and_version_contract(self):
        value = envelope("settings.display.read", {"brightness": 25})
        value["version"] = {"unknown": True}
        with patch("sys.stdin", io.StringIO(json.dumps(value))):
            self.assertEqual(read(known_fields=("brightness",)).version, value["version"])
        del value["timestamp"]
        with patch("sys.stdin", io.StringIO(json.dumps(value))):
            with self.assertRaises(EnvelopeError): read(known_fields=("brightness",))
        value["timestamp"] = "now"; value["schema"] = "foreign.v1"
        with patch("sys.stdin", io.StringIO(json.dumps(value))):
            with self.assertRaises(EnvelopeError): read(known_fields=("brightness",))


class ExousiaActuatorTests(unittest.TestCase):
    def test_bind_legacy_and_envelope_and_foreign(self):
        face = load_face("bind_face", "agathodaimon/exousia/bind/index.py")
        with patch.dict(face.run.__globals__, {"invoke_launcher": lambda executable, value: {"ok": True, "publicKey": "a" * 64, "epoch": "b" * 64}}):
            code, result = invoke(face.main, {})
            self.assertEqual((code, result["ok"]), (0, True)); self.assertNotIn("intent_id", result)
            value = envelope("exousia.bind", {"unknown": 1})
            code, result = invoke(face.main, value)
            self.assertEqual(result["intent_id"], "intent-test"); self.assertEqual(result["envelope"]["payload"], {"unknown": 1})
            bad = dict(value); bad["schema"] = "foreign.v1"
            code, result = invoke(face.main, bad)
            self.assertEqual(code, 2); self.assertIsNone(result)

    def test_verify_legacy_flags_payload_and_foreign(self):
        face = load_face("verify_face", "agathodaimon/exousia/verify/index.py")
        with patch.dict(face.run.__globals__, {"invoke_launcher": lambda executable, value: {"verified": True}}):
            for value in ({"pin": "p", "publicKey": "a" * 64, "extra": 1}, envelope("exousia.verify", {"publicKey": "a" * 64, "flags": {"exousia": {"pin": "p", "extra": 1}}})):
                code, result = invoke(face.main, value)
                self.assertEqual((code, result["verified"]), (0, True))
                if value.get("schema"): self.assertEqual(result["intent_id"], "intent-test")
            bad = envelope("exousia.verify", {"publicKey": "a" * 64}); bad["schema"] = "foreign.v1"
            self.assertEqual(invoke(face.main, bad)[0], 2)

    def test_change_and_reset_are_real_faces_with_legacy_and_envelope(self):
        change = load_face("change_face", "agathodaimon/exousia/change/index.py")
        with patch.dict(change.main.__globals__, {"invoke_launcher": lambda executable, value: {"ok": True, "publicKey": "a" * 64, "epoch": "b" * 64}}):
            for value in ({"oldPin": "old", "newPin": "new", "extra": 1}, envelope("exousia.change", {"oldPin": "old", "newPin": "new", "extra": 1})):
                code, result = invoke(change.main, value)
                self.assertEqual(code, 0); self.assertTrue(result["ok"]); self.assertEqual(result.get("intent_id"), "intent-test" if value.get("schema") else None)
        reset = load_face("reset_face", "agathodaimon/exousia/reset-default/index.py")
        for value in ({"extra": 1}, envelope("exousia.reset-default", {"extra": 1})):
            code, result = invoke(reset.main, value)
            self.assertEqual((code, result["firstMissingSignal"]), (0, "keyman-default-pin-authority-absent"))
            if value.get("schema"): self.assertEqual(result["intent_id"], "intent-test")
        bad = envelope("exousia.reset-default", {}); bad["schema"] = "foreign.v1"
        self.assertEqual(invoke(reset.main, bad)[0], 2)

    def test_cli_legacy_argv_preserves_raw_envelope_bytes(self):
        raw = (
            '{ "payload" : { "unknown" : { "keep" : [1, 2] } }, '
            '"timestamp" : "2026-08-31T00:00:00Z", '
            '"unknownKernelExtension" : true, "schema" : "caduceus.staff.v1", '
            '"version" : { "future" : true }, "intent_id" : "intent-cli", '
            '"transition" : "exousia.reset-default" }'
        )
        completed = subprocess.run(
            [sys.executable, str(ROOT / "agathodaimon" / "cli.py"), "exousia/reset-default", raw],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertFalse(result["ok"])
        self.assertEqual(result["firstMissingSignal"], "keyman-default-pin-authority-absent")
        self.assertEqual(result["intent_id"], "intent-cli")
        self.assertEqual(result["raw_envelope"], raw)
        self.assertEqual(result["envelope"]["payload"]["unknown"], {"keep": [1, 2]})

    def test_cli_stdin_preserves_raw_envelope_bytes(self):
        raw = (
            '{  "payload": {"unknown": [1, 2]}, '
            '"timestamp":"2026-08-31T00:00:00Z", '
            '"unknownKernelExtension":true, "schema":"caduceus.staff.v1", '
            '"version":{"future":true}, "intent_id":"intent-stdin", '
            '"transition":"exousia.reset-default" }\n'
        )
        completed = subprocess.run(
            [sys.executable, str(ROOT / "agathodaimon" / "cli.py"), "exousia/reset-default"],
            cwd=ROOT, input=raw, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["intent_id"], "intent-stdin")
        self.assertEqual(result["raw_envelope"], raw)
        self.assertEqual(result["envelope"]["payload"]["unknown"], [1, 2])

    def test_cli_invalid_stdin_refuses(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "agathodaimon" / "cli.py"), "exousia/reset-default"],
            cwd=ROOT, input="{not-json", capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, "invalid envelope JSON\n")


class SettingsActuatorTests(unittest.TestCase):
    def test_shared_families_legacy_and_whole_envelope_reads(self):
        from agathodaimon.settings import _shared
        for kind, fields in _shared.FIELDS.items():
            with self.subTest(kind=kind), patch.object(_shared, "get_values", return_value={field: "value" for field in fields}):
                code, result = invoke_argv(_shared.main, [kind, "get", "--json"])
                self.assertEqual((code, result["values"][fields[0]]), (0, "value"))
                value = envelope(f"settings.{kind}.read", {fields[0]: 1, "unknown": 2}, kernelUnknown=True)
                code, result = invoke(_shared.main, value)
                self.assertEqual((code, result["intent_id"]), (0, "intent-test"))
                self.assertEqual(result["envelope"]["payload"]["unknown"], 2)
        bad = envelope("settings.display.read", {}); bad["schema"] = "foreign.v1"
        self.assertEqual(invoke(_shared.main, bad)[0], 1)

    def test_shared_mutation_filters_unknown_and_unknown_only_refuses(self):
        from agathodaimon.settings import _shared
        receipt = MagicMock(); receipt.finish.return_value = {"ok": True, "changed": True}
        with patch.object(_shared, "Receipt", return_value=receipt), patch.object(_shared, "set_value") as setter:
            code, result = invoke(_shared.main, envelope("settings.display.set", {"brightness": 42, "unknown": 9}))
            self.assertEqual((code, result["ok"]), (0, True)); setter.assert_called_once_with("display", "brightness", 42, receipt)
        code, result = invoke(_shared.main, envelope("settings.display.set", {"unknown": 9}))
        self.assertEqual((code, result["firstMissingSignal"]), (1, "no-fields-supplied"))

    def test_input_legacy_crossing_and_envelope(self):
        face = load_face("input_face", "agathodaimon/settings/input/index.py")
        with patch.object(face, "read_values", return_value={"values": {"pointer_sensitivity": 1}}):
            code, result = invoke(face.main, {"args": ["get", "--json"]})
            self.assertEqual((code, result["ok"]), (0, True))
            code, result = invoke(face.main, envelope("settings.input.read", {"unknown": 1}))
            self.assertEqual((code, result["intent_id"]), (0, "intent-test"))
            bad = envelope("settings.input.read", {}); bad["schema"] = "foreign.v1"
            self.assertEqual(invoke(face.main, bad)[0], 1)

    def test_ssh_status_legacy_and_envelope(self):
        face = load_face("ssh_face", "agathodaimon/settings/ssh/index.py")
        status = {"schema": face.SCHEMA, "ok": True, "state": "status", "readback": {"mock": True}}
        with patch.object(face, "status", return_value=status):
            code, result = invoke_argv(face.main, ["status"])
            self.assertEqual((code, result["ok"]), (0, True))
            code, result = invoke(face.main, envelope("settings.ssh.status", {"state": "status", "unknown": 1}))
            self.assertEqual((code, result["intent_id"]), (0, "intent-test"))
            bad = envelope("settings.ssh.status", {}); bad["schema"] = "foreign.v1"
            self.assertEqual(invoke(face.main, bad)[0], 1)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import base64
import json
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from caduceus_staff.attendance import (  # noqa: E402
    DOMAIN,
    PIN_ROTATION_ACTION,
    PIN_ROTATION_TARGET,
    AccessRefused,
    AttendanceStaff,
    public_error,
)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(numbers.x.to_bytes(32, "big")),
        "y": b64u(numbers.y.to_bytes(32, "big")),
    }


@dataclass
class Clock:
    now: float = 1000

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


class Tokens:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> str:
        self.n += 1
        return f"opaque-{self.n}"


class FakeKeyman:
    def __init__(self, pin: str = "2468") -> None:
        self.pin = pin
        self.rotations: list[str] = []

    def verify_pin(self, pin: str) -> bool:
        return pin == self.pin

    def rotate_pin(self, new_pin: str) -> bool:
        self.pin = new_pin
        self.rotations.append(new_pin)
        return True


class AttendanceStaffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.tokens = Tokens()
        self.keyman = FakeKeyman()
        self.staff = AttendanceStaff(self.keyman, clock=self.clock, token_factory=self.tokens)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.wrong_key = ec.generate_private_key(ec.SECP256R1())

    def sign(self, key: ec.EllipticCurvePrivateKey, challenge: dict) -> str:
        context = self.staff._challenges[challenge["challenge_id"]].context
        message = DOMAIN + json.dumps(
            {"challenge_id": challenge["challenge_id"], "challenge": challenge["challenge"], "purpose": self.staff._challenges[challenge["challenge_id"]].purpose, "context": context},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        return b64u(key.sign(message, ec.ECDSA(hashes.SHA256())))

    def challenge(self, purpose: str, context: dict) -> dict:
        return self.staff.challenge_mint(purpose, context)

    def mint(self, *, key: ec.EllipticCurvePrivateKey | None = None, pin: str = "2468") -> dict:
        challenge = self.challenge("session.mint", {"public_jwk": jwk(self.key)})
        return self.staff.session_mint(pin=pin, challenge_id=challenge["challenge_id"], signature=self.sign(key or self.key, challenge))

    def prove(self, ticket: str, *, read: str = "admin.status", method: str = "GET", target: str = "/api/v1/admin/status", key: ec.EllipticCurvePrivateKey | None = None) -> dict:
        ch = self.challenge("session.prove", {"ticket": ticket, "read": read, "method": method, "target": target})
        return self.staff.session_prove(ticket=ticket, challenge_id=ch["challenge_id"], signature=self.sign(key or self.key, ch), read=read, method=method, target=target)

    def cap(self, ticket: str, *, action: str = "network.apply", target: str = "lan", key: ec.EllipticCurvePrivateKey | None = None) -> dict:
        ch = self.challenge("capability.mint", {"ticket": ticket, "action": action, "target": target})
        return self.staff.capability_mint(ticket=ticket, challenge_id=ch["challenge_id"], signature=self.sign(key or self.key, ch), action=action, target=target)

    def assert_refused(self, call) -> None:
        with self.assertRaises(AccessRefused):
            call()

    def test_pin_only_mint_is_denied_and_proof_binds_p256_document_key(self) -> None:
        self.assert_refused(lambda: self.staff.session_mint(pin="2468", challenge_id="missing", signature="not-a-proof"))
        ch = self.challenge("session.mint", {"public_jwk": jwk(self.key)})
        self.assert_refused(lambda: self.staff.session_mint(pin="2468", challenge_id=ch["challenge_id"], signature=self.sign(self.wrong_key, ch)))
        session = self.mint()
        self.assertIn("ticket", session)
        self.assertNotIn("exp", session)
        self.assertNotIn("refresh", session)

    def test_same_attendance_performs_multiple_independent_proves_and_capabilities_without_pin(self) -> None:
        ticket = self.mint()["ticket"]
        self.assertTrue(self.prove(ticket)["ok"])
        self.assertTrue(self.prove(ticket, read="metrics", target="/api/v1/metrics")["ok"])
        first, second = self.cap(ticket), self.cap(ticket, action="service.restart", target="kea")
        self.assertNotEqual(first["capability"], second["capability"])
        self.assertEqual(self.keyman.pin, "2468")

    def test_ticket_alone_wrong_scope_or_wrong_key_are_refused(self) -> None:
        ticket = self.mint()["ticket"]
        self.assert_refused(lambda: self.staff.session_prove(ticket=ticket, challenge_id="none", signature="none", read="admin.status", method="GET", target="/api/v1/admin/status"))
        ch = self.challenge("session.prove", {"ticket": ticket, "read": "admin.status", "method": "GET", "target": "/api/v1/admin/status"})
        signature = self.sign(self.key, ch)
        self.assert_refused(lambda: self.staff.session_prove(ticket=ticket, challenge_id=ch["challenge_id"], signature=signature, read="other", method="GET", target="/api/v1/admin/status"))
        # The mismatched attempt consumes the challenge: it cannot be repurposed.
        self.assert_refused(lambda: self.staff.session_prove(ticket=ticket, challenge_id=ch["challenge_id"], signature=signature, read="admin.status", method="GET", target="/api/v1/admin/status"))
        self.assert_refused(lambda: self.prove(ticket, key=self.wrong_key))
        cap_challenge = self.challenge("capability.mint", {"ticket": ticket, "action": "network.apply", "target": "lan"})
        cap_signature = self.sign(self.key, cap_challenge)
        self.assert_refused(lambda: self.staff.capability_mint(ticket=ticket, challenge_id=cap_challenge["challenge_id"], signature=cap_signature, action="service.restart", target="lan"))
        self.assert_refused(lambda: self.staff.capability_mint(ticket=ticket, challenge_id=cap_challenge["challenge_id"], signature=cap_signature, action="network.apply", target="lan"))

    def test_challenge_expiry_and_replay_fail_closed(self) -> None:
        ticket = self.mint()["ticket"]
        ch = self.challenge("session.prove", {"ticket": ticket, "read": "admin.status", "method": "GET", "target": "/api/v1/admin/status"})
        self.clock.advance(31)
        self.assert_refused(lambda: self.staff.session_prove(ticket=ticket, challenge_id=ch["challenge_id"], signature=self.sign(self.key, ch), read="admin.status", method="GET", target="/api/v1/admin/status"))
        ch = self.challenge("session.prove", {"ticket": ticket, "read": "admin.status", "method": "GET", "target": "/api/v1/admin/status"})
        signature = self.sign(self.key, ch)
        self.assertTrue(self.staff.session_prove(ticket=ticket, challenge_id=ch["challenge_id"], signature=signature, read="admin.status", method="GET", target="/api/v1/admin/status")["ok"])
        self.assert_refused(lambda: self.staff.session_prove(ticket=ticket, challenge_id=ch["challenge_id"], signature=signature, read="admin.status", method="GET", target="/api/v1/admin/status"))

    def test_clear_and_fresh_process_revoke_old_ticket(self) -> None:
        ticket = self.mint()["ticket"]
        clear = self.challenge("session.clear", {"ticket": ticket})
        self.assertTrue(self.staff.session_clear(ticket=ticket, challenge_id=clear["challenge_id"], signature=self.sign(self.key, clear))["ok"])
        self.assert_refused(lambda: self.prove(ticket))
        # A process restart creates a fresh daemon map: old bearer material is inert.
        restarted = AttendanceStaff(self.keyman, clock=self.clock, token_factory=Tokens())
        self.assert_refused(lambda: restarted.session_prove(ticket=ticket, challenge_id="any", signature="any", read="admin.status", method="GET", target="/api/v1/admin/status"))

    def test_capability_is_one_use_and_child_of_active_attendance(self) -> None:
        ticket = self.mint()["ticket"]
        cap = self.cap(ticket)
        self.assertTrue(self.staff.consume_capability(ticket=ticket, capability=cap["capability"], action="network.apply", target="lan"))
        self.assertFalse(self.staff.consume_capability(ticket=ticket, capability=cap["capability"], action="network.apply", target="lan"))
        cap = self.cap(ticket)
        clear = self.challenge("session.clear", {"ticket": ticket})
        self.staff.session_clear(ticket=ticket, challenge_id=clear["challenge_id"], signature=self.sign(self.key, clear))
        self.assert_refused(lambda: self.cap(ticket))
        self.assert_refused(lambda: self.staff.consume_capability(ticket=ticket, capability=cap["capability"], action="network.apply", target="lan"))

    def test_pin_change_requires_proof_scoped_one_use_capability_and_never_reenters_old_pin(self) -> None:
        ticket = self.mint()["ticket"]
        cap = self.cap(ticket, action=PIN_ROTATION_ACTION, target=PIN_ROTATION_TARGET)
        ch = self.challenge("pin.change", {"ticket": ticket, "action": PIN_ROTATION_ACTION, "target": PIN_ROTATION_TARGET})
        signature = self.sign(self.key, ch)
        self.assertTrue(self.staff.pin_change(ticket=ticket, challenge_id=ch["challenge_id"], signature=signature, capability=cap["capability"], new_pin="8642")["ok"])
        self.assertEqual(self.keyman.rotations, ["8642"])
        self.assert_refused(lambda: self.staff.pin_change(ticket=ticket, challenge_id=ch["challenge_id"], signature=signature, capability=cap["capability"], new_pin="9999"))
        bad = self.cap(ticket, action="network.apply", target="lan")
        ch = self.challenge("pin.change", {"ticket": ticket, "action": PIN_ROTATION_ACTION, "target": PIN_ROTATION_TARGET})
        self.assert_refused(lambda: self.staff.pin_change(ticket=ticket, challenge_id=ch["challenge_id"], signature=self.sign(self.key, ch), capability=bad["capability"], new_pin="1111"))

    def test_errors_and_public_receipts_do_not_echo_secrets(self) -> None:
        secret = "ticket-pin-signature-capability-private-key"
        body = json.dumps(public_error(AccessRefused(secret)))
        self.assertNotIn(secret, body)
        self.assertEqual(json.loads(body)["error"], "access-refused")


if __name__ == "__main__":
    unittest.main()

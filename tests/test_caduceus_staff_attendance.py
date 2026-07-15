from __future__ import annotations

import base64, json, socket, sys, tempfile, threading, time, unittest
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from caduceus_staff.attendance import (DOMAIN, PIN_ROTATION_ACTION, PIN_ROTATION_TARGET, AccessRefused, AttendanceStaff, StaffSocketDaemon, challenge_message, public_error) # noqa: E402


def b64(raw: bytes) -> str: return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
def jwk(key):
    n = key.public_key().public_numbers()
    return {"kty":"EC","crv":"P-256","x":b64(n.x.to_bytes(32,"big")),"y":b64(n.y.to_bytes(32,"big"))}

@dataclass
class Clock:
    now: float = 1000
    def __call__(self): return self.now
    def advance(self, n): self.now += n

class Signer:
    def __init__(self, epoch): self.private, self.epoch, self.closed = ed25519.Ed25519PrivateKey.generate(), str(epoch), False
    @property
    def public_key(self): return self.private.public_key().public_bytes_raw()
    def sign(self, payload): return self.private.sign(payload)
    def close(self): self.closed = True

class FakeKeyman:
    def __init__(self, pin="2468"):
        self.pin, self.epoch, self.signer, self.bind_ok, self.changes = pin, 1, Signer(1), True, []
    def bind_derived_caduceus(self):
        if not self.bind_ok: raise RuntimeError("unavailable")
        return self.signer
    def verify_and_derive_caduceus(self, pin):
        if pin != self.pin: raise RuntimeError("bad pin")
        # Keyman returns a separately closable derived seat with equal projection.
        derived = Signer(self.epoch); derived.private = self.signer.private
        return derived
    def change_caduceus_pin(self, old, new):
        if old != self.pin:
            raise RuntimeError("bad old")
        self.pin, self.epoch, self.signer = new, self.epoch + 1, Signer(self.epoch + 1)
        self.changes.append((old,new))

class AttendanceTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.keyman, self.events = Clock(), FakeKeyman(), []
        self.staff = AttendanceStaff(self.keyman, clock=self.clock, token_factory=self.token, audit_sink=self.events.append)
        self.key, self.wrong = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        self.n = 0
    def token(self): self.n += 1; return f"random-{self.n}"
    def sign(self, key, ch):
        item = self.staff._challenges[ch["challenge_id"]]
        der = key.sign(challenge_message(ch["challenge_id"], ch["challenge"], item.purpose, item.context), ec.ECDSA(hashes.SHA256()))
        r,s = decode_dss_signature(der)
        return b64(r.to_bytes(32,"big") + s.to_bytes(32,"big")) # WebCrypto raw P1363, never DER.
    def challenge(self, purpose, context): return self.staff.challenge_mint(purpose,context)
    def mint(self, key=None, pin="2468"):
        ch = self.challenge("session.mint", {"document_public_key":jwk(self.key)})
        return self.staff.session_mint(pin=pin,challenge_id=ch["challenge_id"],signature=self.sign(key or self.key,ch))
    def prove(self,ticket, key=None, read="admin.status", method="GET", target="/admin"):
        ch=self.challenge("session.prove",{"ticket":ticket,"read":read,"method":method,"target":target})
        return self.staff.session_prove(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(key or self.key,ch),read=read,method=method,target=target)
    def cap(self,ticket, action="network.apply",target="lan"):
        ch=self.challenge("capability.mint",{"ticket":ticket,"action":action,"target":target})
        return self.staff.capability_mint(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch),action=action,target=target)
    def refused(self, call):
        with self.assertRaises(AccessRefused): call()
    def test_tablet_fixture_binds_public_epoch_and_signed_ticket(self):
        status=self.staff.signing_status(); self.assertEqual(status["posture"],"BOUND"); self.assertEqual(status["epoch"],"1"); self.assertEqual(base64.urlsafe_b64decode(status["public_key"]+"=="),self.keyman.signer.public_key)
        ticket=self.mint()["ticket"]; envelope=json.loads(base64.urlsafe_b64decode(ticket+"==")); self.assertEqual(json.loads(base64.urlsafe_b64decode(envelope["payload"]+"=="))["kind"],"attendance")
    def test_raw_webcrypto_signature_and_32_byte_jwk_are_exact(self):
        self.assertTrue(self.mint()["ticket"])
        bad={"kty":"EC","crv":"P-256","x":b64(b"x"*31),"y":b64(b"y"*32)}
        self.refused(lambda:self.staff.challenge_mint("session.mint",{"document_public_key":bad}))
        ch=self.challenge("session.mint",{"document_public_key":jwk(self.key)})
        self.refused(lambda:self.staff.session_mint(pin="2468",challenge_id=ch["challenge_id"],signature=b64(b"der")))
    def test_pin_wrong_key_ticket_only_scope_and_replay_refuse(self):
        ch=self.challenge("session.mint",{"document_public_key":jwk(self.key)})
        self.refused(lambda:self.staff.session_mint(pin="bad",challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch)))
        self.refused(lambda:self.staff.session_mint(pin="2468",challenge_id="none",signature="no"))
        self.refused(lambda:self.mint(key=self.wrong))
        ticket=self.mint()["ticket"]
        self.refused(lambda:self.prove(ticket,key=self.wrong))
        ch=self.challenge("session.prove",{"ticket":ticket,"read":"admin.status","method":"GET","target":"/admin"})
        self.refused(lambda:self.staff.session_prove(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch),read="other",method="GET",target="/admin"))
    def test_two_proves_and_capabilities_need_no_second_pin(self):
        ticket=self.mint()["ticket"]; self.assertTrue(self.prove(ticket)["ok"]); self.assertTrue(self.prove(ticket,read="metrics",target="/metrics")["ok"])
        a,b=self.cap(ticket),self.cap(ticket,"service.restart","kea"); self.assertNotEqual(a["capability"],b["capability"]); self.assertEqual(self.keyman.pin,"2468")
    def test_challenge_expiry_replay_capability_expiry_and_clear(self):
        ticket=self.mint()["ticket"]; ch=self.challenge("session.prove",{"ticket":ticket,"read":"x","method":"GET","target":"/x"}); self.clock.advance(31)
        self.refused(lambda:self.staff.session_prove(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch),read="x",method="GET",target="/x"))
        cap=self.cap(ticket); self.clock.advance(61); self.assertFalse(self.staff.consume_capability(ticket=ticket,capability=cap["capability"],action="network.apply",target="lan"))
        clear=self.challenge("session.clear",{"ticket":ticket}); self.staff.session_clear(ticket=ticket,challenge_id=clear["challenge_id"],signature=self.sign(self.key,clear)); self.refused(lambda:self.prove(ticket))
    def test_capability_replay_and_post_clear_fail(self):
        ticket=self.mint()["ticket"]; cap=self.cap(ticket); self.assertTrue(self.staff.consume_capability(ticket=ticket,capability=cap["capability"],action="network.apply",target="lan")); self.assertFalse(self.staff.consume_capability(ticket=ticket,capability=cap["capability"],action="network.apply",target="lan"))
        cap=self.cap(ticket); clear=self.challenge("session.clear",{"ticket":ticket}); self.staff.session_clear(ticket=ticket,challenge_id=clear["challenge_id"],signature=self.sign(self.key,clear)); self.refused(lambda:self.staff.consume_capability(ticket=ticket,capability=cap["capability"],action="network.apply",target="lan"))
    def test_pin_change_old_pin_ladder_epoch_rebind_and_restart(self):
        ticket=self.mint()["ticket"]; cap=self.cap(ticket,PIN_ROTATION_ACTION,PIN_ROTATION_TARGET); ch=self.challenge("pin.change",{"ticket":ticket,"action":PIN_ROTATION_ACTION,"target":PIN_ROTATION_TARGET})
        self.refused(lambda:self.staff.pin_change(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch),capability=cap["capability"],old_pin="bad",new_pin="8642")); self.assertEqual(self.keyman.pin,"2468"); self.assertIn(cap["capability"],self.staff._capabilities)
        cap=self.cap(ticket,PIN_ROTATION_ACTION,PIN_ROTATION_TARGET); ch=self.challenge("pin.change",{"ticket":ticket,"action":PIN_ROTATION_ACTION,"target":PIN_ROTATION_TARGET}); result=self.staff.pin_change(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch),capability=cap["capability"],old_pin="2468",new_pin="8642")
        self.assertEqual(result["epoch"],"2"); self.refused(lambda:self.prove(ticket)); self.refused(lambda:AttendanceStaff(self.keyman).attendance_current(ticket))
    def test_stale_derived_refuses_and_audit_is_redacted(self):
        self.keyman.bind_ok=False; staff=AttendanceStaff(self.keyman,audit_sink=self.events.append); self.assertEqual(staff.signing_status()["posture"],"UNBOUND"); self.refused(lambda:staff.challenge_mint("session.mint",{"document_public_key":jwk(self.key)}))
        blob=json.dumps(self.events); self.assertNotIn("2468",blob); self.assertNotIn("random-",blob); self.assertTrue(any(e["operation"]=="signing.bind" for e in self.events))
    def test_public_error_is_secret_safe(self):
        self.assertNotIn("secret",json.dumps(public_error(AccessRefused("secret"))))

class SocketTests(unittest.TestCase):
    def request(self,path,payload):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.connect(path); c.sendall(payload); return json.loads(c.recv(8192))
    def test_real_socket_one_request_framing_refusal_and_persistent_state(self):
        with tempfile.TemporaryDirectory() as d:
            path=str(Path(d)/"staff.sock"); keyman=FakeKeyman(); staff=AttendanceStaff(keyman); daemon=StaffSocketDaemon(staff,path); thread=threading.Thread(target=daemon.serve_forever,daemon=True); thread.start()
            for _ in range(50):
                if Path(path).exists(): break
                time.sleep(.01)
            status=self.request(path,b'{"op":"signing.status"}\n'); self.assertEqual(status["posture"],"BOUND")
            self.assertFalse(self.request(path,b'{"op":"nope"}\n')["ok"]); self.assertFalse(self.request(path,b"x"*8193)["ok"])
            key=ec.generate_private_key(ec.SECP256R1()); payload=json.dumps({"op":"challenge.mint","purpose":"session.mint","context":{"document_public_key":jwk(key)}}).encode()+b"\n"
            first=self.request(path,payload); self.assertIn("challenge_id",first)
            mint_context={"document_public_key":jwk(key),"document_key_thumbprint": b64(__import__("hashlib").sha256(json.dumps({"crv":"P-256","kty":"EC","x":jwk(key)["x"],"y":jwk(key)["y"]},sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).digest())}
            der=key.sign(challenge_message(first["challenge_id"],first["challenge"],"session.mint",mint_context),ec.ECDSA(hashes.SHA256())); r,s=decode_dss_signature(der)
            minted=self.request(path,json.dumps({"op":"session.mint","pin":"2468","challenge_id":first["challenge_id"],"signature":b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))}).encode()+b"\n")
            self.assertIn("ticket",minted) # state survived the prior connection.
            daemon.stop(); thread.join(1)

if __name__ == "__main__": unittest.main()

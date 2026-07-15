from __future__ import annotations

import base64, io, json, socket, sys, tempfile, threading, time, unittest
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from caduceus_staff.attendance import (DOMAIN, PIN_ROTATION_ACTION, PIN_ROTATION_TARGET, AccessRefused, AttendanceStaff, KeymanAdapter, StaffSocketDaemon, challenge_message, public_error) # noqa: E402
from caduceus_staff.staff_daemon import production_staff # noqa: E402


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
    """Faithful admitted Keyman signer surface: no public_key or sign method."""
    def __init__(self, epoch): self.private, self.epoch, self.signer_epoch, self.closed = ed25519.Ed25519PrivateKey.generate(), str(epoch), str(epoch), False
    @property
    def public_key_hex(self): return self.private.public_key().public_bytes_raw().hex()
    def private_key(self): return self.private
    def close(self): self.closed = True

class FakeKeyman:
    def __init__(self, pin="2468", epoch="1"):
        self.pin, self.epoch, self.signer, self.bind_ok, self.changes = pin, epoch, Signer(epoch), True, []
    def bind_derived_caduceus(self):
        if not self.bind_ok: raise RuntimeError("unavailable")
        return self.signer
    def verify_and_derive_caduceus(self, pin):
        if pin != self.pin: raise RuntimeError("bad pin")
        derived = Signer(self.epoch); derived.private = self.signer.private
        return derived
    def change_caduceus_pin(self, old, new):
        if old != self.pin: raise RuntimeError("bad old")
        self.pin, self.epoch, self.signer = new, str(int(self.epoch) + 1), Signer(str(int(self.epoch) + 1))
        self.changes.append((old,new))

class LongTokenKeyman(FakeKeyman):
    def __init__(self): super().__init__(epoch="a" * 64)

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
        return b64(r.to_bytes(32,"big") + s.to_bytes(32,"big"))
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
    def test_admitted_surface_binds_public_epoch_and_signed_ticket(self):
        status=self.staff.signing_status(); self.assertEqual(status["posture"],"BOUND"); self.assertEqual(status["epoch"],"1"); self.assertEqual(base64.urlsafe_b64decode(status["public_key"]+"=="),bytes.fromhex(self.keyman.signer.public_key_hex))
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
    def test_wrong_old_pin_spends_capability_but_keeps_attendance_and_epoch(self):
        ticket=self.mint()["ticket"]; before=self.staff.signing_status().copy(); cap=self.cap(ticket,PIN_ROTATION_ACTION,PIN_ROTATION_TARGET); ch=self.challenge("pin.change",{"ticket":ticket,"action":PIN_ROTATION_ACTION,"target":PIN_ROTATION_TARGET})
        self.refused(lambda:self.staff.pin_change(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch),capability=cap["capability"],old_pin="bad0",new_pin="8642"))
        self.assertEqual(self.keyman.pin,"2468"); self.assertEqual(before,self.staff.signing_status()); self.assertTrue(self.staff.attendance_current(ticket)["current"]); self.assertNotIn(cap["capability"],self.staff._capabilities)
        self.assertFalse(self.staff.consume_capability(ticket=ticket,capability=cap["capability"],action=PIN_ROTATION_ACTION,target=PIN_ROTATION_TARGET))
        cap=self.cap(ticket,PIN_ROTATION_ACTION,PIN_ROTATION_TARGET); ch=self.challenge("pin.change",{"ticket":ticket,"action":PIN_ROTATION_ACTION,"target":PIN_ROTATION_TARGET}); result=self.staff.pin_change(ticket=ticket,challenge_id=ch["challenge_id"],signature=self.sign(self.key,ch),capability=cap["capability"],old_pin="2468",new_pin="8642")
        self.assertEqual(result["epoch"],"2"); self.refused(lambda:self.prove(ticket)); self.refused(lambda:AttendanceStaff(self.keyman).attendance_current(ticket))
    def test_production_sized_ticket_round_trips_every_ticket_context(self):
        keyman, clock = LongTokenKeyman(), Clock(); n = 0
        def token():
            nonlocal n; n += 1; return f"{n:02d}" + "x" * 41
        staff=AttendanceStaff(keyman,clock=clock,token_factory=token); key=ec.generate_private_key(ec.SECP256R1())
        mint_context={"document_public_key":jwk(key)}; ch=staff.challenge_mint("session.mint",mint_context)
        item=staff._challenges[ch["challenge_id"]]; der=key.sign(challenge_message(ch["challenge_id"],ch["challenge"],item.purpose,item.context),ec.ECDSA(hashes.SHA256())); r,s=decode_dss_signature(der)
        ticket=staff.session_mint(pin="2468",challenge_id=ch["challenge_id"],signature=b64(r.to_bytes(32,"big")+s.to_bytes(32,"big")))["ticket"]
        self.assertGreaterEqual(len(ticket), 719)
        def signed(purpose, context):
            challenge=staff.challenge_mint(purpose,context); item=staff._challenges[challenge["challenge_id"]]
            der=key.sign(challenge_message(challenge["challenge_id"],challenge["challenge"],item.purpose,item.context),ec.ECDSA(hashes.SHA256())); r,s=decode_dss_signature(der)
            return challenge, b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
        prove, signature=signed("session.prove",{"ticket":ticket,"read":"admin.status","method":"GET","target":"/admin"})
        self.assertTrue(staff.session_prove(ticket=ticket,challenge_id=prove["challenge_id"],signature=signature,read="admin.status",method="GET",target="/admin")["ok"])
        cap, signature=signed("capability.mint",{"ticket":ticket,"action":"network.apply","target":"lan"})
        self.assertIn("capability",staff.capability_mint(ticket=ticket,challenge_id=cap["challenge_id"],signature=signature,action="network.apply",target="lan"))
        pin, _=signed("pin.change",{"ticket":ticket,"action":PIN_ROTATION_ACTION,"target":PIN_ROTATION_TARGET}); self.assertIn("challenge_id",pin)
        clear, signature=signed("session.clear",{"ticket":ticket}); self.assertTrue(staff.session_clear(ticket=ticket,challenge_id=clear["challenge_id"],signature=signature)["ok"])
    def test_stale_derived_refuses_and_audit_is_redacted(self):
        self.keyman.bind_ok=False; staff=AttendanceStaff(self.keyman,audit_sink=self.events.append); self.assertEqual(staff.signing_status()["posture"],"UNBOUND"); self.refused(lambda:staff.challenge_mint("session.mint",{"document_public_key":jwk(self.key)}))
        blob=json.dumps(self.events); self.assertNotIn("2468",blob); self.assertNotIn("random-",blob); self.assertTrue(any(e["operation"]=="signing.bind" for e in self.events))
    def test_public_error_is_secret_safe(self): self.assertNotIn("secret",json.dumps(public_error(AccessRefused("secret"))))

class AdapterAndAuditTests(unittest.TestCase):
    def test_adapter_loads_dataclass_module_and_production_sink_is_redacted(self):
        source = '''from dataclasses import dataclass\nfrom cryptography.hazmat.primitives.asymmetric import ed25519\n_key=ed25519.Ed25519PrivateKey.generate()\n@dataclass\nclass DerivedCaduceusSigner:\n    signer_epoch: str = "a" * 64\n    epoch: str = "a" * 64\n    def private_key(self): return _key\n    @property\n    def public_key_hex(self): return _key.public_key().public_bytes_raw().hex()\n    def close(self): pass\ndef bind_derived_caduceus(): return DerivedCaduceusSigner()\ndef verify_and_derive_caduceus(pin):\n    if pin != "2468": raise RuntimeError("bad")\n    return DerivedCaduceusSigner()\ndef change_caduceus_pin(old, new):\n    if old != "2468": raise RuntimeError("bad")\n'''
        with tempfile.TemporaryDirectory() as d:
            module_path=Path(d)/"admitted_keyman_shape.py"; module_path.write_text(source)
            adapter=KeymanAdapter(str(module_path)); self.assertEqual(adapter._load().DerivedCaduceusSigner().epoch, "a" * 64)
            old, capture = sys.stderr, io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            try:
                sys.stderr=capture; staff=production_staff(str(module_path)); self.assertEqual(staff.signing_status()["posture"],"BOUND")
                event=capture.buffer.getvalue().decode(); self.assertIn('"operation":"signing.bind"',event); self.assertNotIn("2468",event); self.assertNotIn("ticket",event)
            finally: sys.stderr=old

class SocketTests(unittest.TestCase):
    def request(self,path,payload,parts=None):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.connect(path)
            if parts:
                for part in parts: c.sendall(part); time.sleep(.01)
            else: c.sendall(payload)
            return json.loads(c.recv(8192))
    def test_fragmented_line_and_malformed_framing_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            path=str(Path(d)/"staff.sock"); daemon=StaffSocketDaemon(AttendanceStaff(FakeKeyman()),path); thread=threading.Thread(target=daemon.serve_forever,daemon=True); thread.start()
            for _ in range(50):
                if Path(path).exists(): break
                time.sleep(.01)
            self.assertEqual(self.request(path,b"",[b'{"op":"sign',b'ing.status"}\n'])["posture"],"BOUND")
            self.assertFalse(self.request(path,b'{"op":"signing.status"}\n{"op":"signing.status"}\n')["ok"])
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
                c.connect(path); c.sendall(b'{"op":"signing.status"}'); c.shutdown(socket.SHUT_WR); self.assertFalse(json.loads(c.recv(8192))["ok"])
            self.assertFalse(self.request(path,b"x"*8193)["ok"])
            daemon.stop(); thread.join(1)

if __name__ == "__main__": unittest.main()

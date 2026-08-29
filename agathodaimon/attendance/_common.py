import importlib.util,json,os,sys
from pathlib import Path
KEYMAN_PATH=Path(os.environ.get("AGATHODAIMON_KEYMAN_MODULE","/opt/keyman/runtime/lib/keyman_caduceus_access.py"))
class MalformedInput(ValueError): pass
class AttendanceUnprovisioned(RuntimeError): pass
def paths(): return Path(os.environ.get("CADUCEUS_KEYMAN_KEY_DIR","/root/key")),Path(os.environ.get("CADUCEUS_KEYMAN_VAULT_DIR","/vault/.keys"))
def ensure_provisioned(k,v):
 for p in (k/"skeleton.key",v/"service_suite.key",v/"caduceus.key"):
  if not p.is_file(): raise AttendanceUnprovisioned("attendance-unprovisioned")
 if not KEYMAN_PATH.is_file(): raise AttendanceUnprovisioned("attendance-unprovisioned")
def keyman():
 k,v=paths(); ensure_provisioned(k,v)
 s=importlib.util.spec_from_file_location("attendance_keyman",KEYMAN_PATH)
 if s is None or s.loader is None: raise RuntimeError("keyman module load failure")
 m=importlib.util.module_from_spec(s)
 sys.modules[s.name]=m
 try:s.loader.exec_module(m)
 except Exception as e:
  if sys.modules.get(s.name) is m: del sys.modules[s.name]
  raise RuntimeError("keyman module import failure") from e
 return m
def text(o,n):
 v=o.get(n)
 if not isinstance(v,str) or not v or len(v)>512: raise MalformedInput(n+" missing or invalid")
 return v
def payload(fields):
 try:v=json.load(sys.stdin)
 except Exception as e: raise MalformedInput("invalid JSON") from e
 if not isinstance(v,dict) or set(v)!=fields: raise MalformedInput("unexpected attendance fields")
 return v
def public(s):
 p=getattr(s,"public_key_hex",None); e=getattr(s,"signer_epoch",getattr(s,"epoch",None)); p=p() if callable(p) else p; e=e() if callable(e) else e
 if not isinstance(p,str) or len(p)!=64 or not isinstance(e,str) or len(e)!=64: raise RuntimeError("invalid signer")
 try:int(p,16); int(e,16)
 except ValueError as x: raise RuntimeError("invalid signer") from x
 return p,e
def close(s):
 f=getattr(s,"close",None)
 if callable(f):
  try:f()
  except Exception:pass
def pin_refused(e): return "caduceus-pin-refused" in str(e).lower()
def verify_pin(pin,expected=None):
 k,v=paths()
 try:s=keyman().verify_and_derive_caduceus(pin,key_dir=k,vault_dir=v)
 except Exception as e:
  if not pin_refused(e): raise
  return False
 try:p,_=public(s); return expected is None or p==expected
 finally:close(s)
def bind():
 k,v=paths(); s=keyman().bind_derived_caduceus(key_dir=k,vault_dir=v)
 try:p,e=public(s); return {"ok":True,"publicKey":p,"epoch":e}
 finally:close(s)
def verify():
 o=payload({"pin","publicKey"}); p=text(o,"publicKey")
 if len(p)!=64:
  raise MalformedInput("publicKey missing or invalid")
 try:int(p,16)
 except ValueError as e: raise MalformedInput("publicKey missing or invalid") from e
 return {"ok":True,"verified":verify_pin(text(o,"pin"),p)}
def open_document():
 o=payload({"documentId","documentIncarnation","pin"}); i=text(o,"documentId"); n=text(o,"documentIncarnation")
 return {"ok":True,"verified":verify_pin(text(o,"pin")),"documentId":i,"documentIncarnation":n}
def process_state(action):
 o=payload({"attendance","documentId","documentIncarnation"})
 return {"ok":True,"handled":True,"mutationPerformed":False,"action":action,"stateOwner":"caduceus","attendance":text(o,"attendance"),"documentId":text(o,"documentId"),"documentIncarnation":text(o,"documentIncarnation")}
def change_pin():
 try:o=json.load(sys.stdin)
 except Exception as e: raise MalformedInput("invalid JSON") from e
 if not isinstance(o,dict): raise MalformedInput("invalid attendance fields")
 if set(o)=={"oldPin","newPin"}: old,new=text(o,"oldPin"),text(o,"newPin"); context={}
 elif set(o)=={"attendance","documentId","documentIncarnation","currentPin","newPin"}: context={n:text(o,n) for n in ("attendance","documentId","documentIncarnation")}; old,new=text(o,"currentPin"),text(o,"newPin")
 else: raise MalformedInput("unexpected attendance fields")
 k,v=paths(); m=keyman()
 try:m.change_caduceus_pin(old,new,key_dir=k,vault_dir=v)
 except Exception as e:
  if not pin_refused(e): raise
  return {"ok":False,"changed":False,"verified":False,"firstMissingSignal":"caduceus-attendance-change-failed"}
 s=m.bind_derived_caduceus(key_dir=k,vault_dir=v)
 try:p,e=public(s)
 finally:close(s)
 return {"ok":True,"changed":True,"publicKey":p,"epoch":e,**context}
def execute(action):
 if action=="bind":return bind()
 if action=="verify":return verify()
 if action=="open":return open_document()
 if action in {"touch","invalidate"}:return process_state(action)
 if action=="change-pin":return change_pin()
 raise MalformedInput("unknown attendance verb")
def run(action,argv=None):
 try:
  if argv: raise MalformedInput("one attendance verb is required")
  r=execute(action)
 except MalformedInput as e: print(str(e),file=sys.stderr); return 2
 except AttendanceUnprovisioned:
  print(json.dumps({"ok":False,"firstMissingSignal":"attendance-unprovisioned"})); return 0
 except Exception as e:
  print("attendance internal failure",file=sys.stderr); return 1
 print(json.dumps(r,separators=(",",":"))); return 0

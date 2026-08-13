from __future__ import annotations
import base64,json,os,re,stat,subprocess,sys,tempfile,urllib.error,urllib.request
from pathlib import Path
SCHEMA="caduceus.backblaze.config.v1"; URL="https://api.backblazeb2.com/b2api/v2/b2_authorize_account"; NEWKEY="/vault/keyman/newkey.sh"; CONFIG=Path("/etc/appliance/config.json")
class Refusal(ValueError):
 def __init__(self,step,reason): self.step,self.reason=step,reason
def fail(step,reason): return {"schema":SCHEMA,"ok":False,"step":step,"reason":reason,"mutationPerformed":False}
def req(p,k):
 v=p.get(k)
 if not isinstance(v,str) or not v: raise Refusal("shape",f"{k} must be a non-empty string")
 return v
def parse(p):
 if set(p)!={"keyId","applicationKey","bucket","prefix","paths"}: raise Refusal("shape","payload fields must be keyId, applicationKey, bucket, prefix, and paths")
 k,a,b=req(p,"keyId"),req(p,"applicationKey"),req(p,"bucket"); x=p["prefix"]; paths=p["paths"]
 if x is not None and not isinstance(x,str): raise Refusal("shape","prefix must be a string or null")
 if not isinstance(paths,list) or not paths or any(not isinstance(v,str) or not v.startswith("/") or "\0" in v for v in paths): raise Refusal("shape","paths must be a non-empty list of absolute paths")
 s=b.replace("-","_")
 if not re.fullmatch(r"[a-zA-Z0-9_]+",s): raise Refusal("shape","bucket cannot be normalized to a Keyman service name")
 return k,a,b,x,paths,s
def load():
 try:
  raw=CONFIG.read_text(); d=json.loads(raw)
 except OSError as e: raise Refusal("config",f"unable to read appliance config: {e}")
 except json.JSONDecodeError as e: raise Refusal("config",f"invalid appliance config: {e}")
 if not isinstance(d,dict): raise Refusal("config","appliance config must be a JSON object")
 return d
def verify(k,a):
 q=urllib.request.Request(URL,headers={"Authorization":"Basic "+base64.b64encode(f"{k}:{a}".encode()).decode()})
 try:
  with urllib.request.urlopen(q,timeout=15) as r: r.read()
 except urllib.error.HTTPError as e: raise Refusal("verify",e.read().decode("utf-8","replace"))
 except urllib.error.URLError as e: raise Refusal("verify",str(e.reason))
 except OSError as e: raise Refusal("verify",str(e))
def write(d):
 fd,tmp=tempfile.mkstemp(prefix=".config.",dir=CONFIG.parent,text=True)
 try:
  os.fchmod(fd,stat.S_IMODE(CONFIG.stat().st_mode))
  with os.fdopen(fd,"w") as h: h.write(json.dumps(d,indent=2)+"\n"); h.flush(); os.fsync(h.fileno())
  os.replace(tmp,CONFIG)
 except BaseException:
  try: os.unlink(tmp)
  except FileNotFoundError: pass
  raise
def dispatch(e):
 if set(e)!={"actuator","metadata"} or e.get("actuator")!="backblaze-config" or not isinstance(e.get("metadata"),dict): raise Refusal("shape","invalid Backblaze staff envelope")
 k,a,b,p,paths,s=parse(e["metadata"]); d=load()
 tabs=d.get("tabs",{})
 if not isinstance(tabs,dict): raise Refusal("config","tabs must be a JSON object")
 backblaze=tabs.get("backblaze",{})
 if not isinstance(backblaze,dict): raise Refusal("config","tabs.backblaze must be a JSON object")
 if backblaze.get("locked") is True: return fail("locked","configuration is locked after initial setup")
 verify(k,a)
 try: r=subprocess.run([NEWKEY,s,k,a],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,check=False)
 except OSError as e: raise Refusal("seed_keyman",f"Keyman seed failed: {e}")
 if r.returncode: raise Refusal("seed_keyman",r.stderr.strip() or "Keyman seed failed")
 cfg={"bucket":b,"paths":paths}
 if p is not None: cfg["prefix"]=p
 tabs=d.setdefault("tabs",{})
 backblaze=tabs.setdefault("backblaze",{})
 backblaze["config"]=cfg
 backblaze["locked"]=True
 try: write(d)
 except OSError as e: raise Refusal("write_config",f"unable to write appliance config: {e}")
 return {"schema":SCHEMA,"ok":True,"locked":True,"bucket":b,"keyman_service":s,"mutationPerformed":True}
def main():
 try:
  raw=sys.stdin.buffer.read(16385)
  if len(raw)>16384: raise Refusal("shape","request is too large")
  x=json.loads(raw.decode()); out=dispatch(x if isinstance(x,dict) else (_ for _ in ()).throw(Refusal("shape","request must be a JSON object")))
 except (UnicodeDecodeError,json.JSONDecodeError): out=fail("shape","request must be valid UTF-8 JSON")
 except Refusal as e: out=fail(e.step,e.reason)
 print(json.dumps(out,separators=(",",":"))); return 0 if out["ok"] else 1
if __name__=="__main__": raise SystemExit(main())

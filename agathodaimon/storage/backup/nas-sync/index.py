from __future__ import annotations
import json, os, subprocess, sys, tempfile, uuid
from pathlib import Path
SCHEMA="caduceus.nas.sync.v1"; MODULE="agathodaimon.storage.backup.nas_sync"; BASH="/usr/bin/bash"; SAFE_SYNC="/usr/local/sbin/agathodaimon/storage/backup/safe-nas-sync.sh"; SYSTEMCTL="/usr/bin/systemctl"; RM="/usr/bin/rm"; UNIT_DIR="/etc/systemd/system"; SERVICE="agathodaimon-nas-sync.service"; TIMER="agathodaimon-nas-sync.timer"
class Refusal(ValueError): pass
def root(): return Path(os.environ.get("CADUCEUS_NAS_JOB_ROOT","/var/lib/caduceus/jobs/nas-sync"))
def atomic(path,text):
 path.parent.mkdir(parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix=".nas-sync.",dir=path.parent,text=True)
 try:
  with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(text); f.flush(); os.fsync(f.fileno())
  os.replace(tmp,path)
 except BaseException:
  try: os.unlink(tmp)
  except FileNotFoundError: pass
  raise
def receipt(action,planned,commands,**extra): return {"schema":SCHEMA,"ok":True,"action":action,"planned":planned,"mutationPerformed":not planned,"commands":commands,"receiptFamily":SCHEMA,"firstMissingSignal":"none",**extra}
def fail(signal): return {"schema":SCHEMA,"ok":False,"action":"unknown","planned":False,"mutationPerformed":False,"commands":[],"firstMissingSignal":signal}
def schedule(v):
 if not isinstance(v,dict): raise Refusal("agathodaimon-nas-schedule-invalid")
 if set(v)-{"frequency","time","weekday","day","at","enabled"}: raise Refusal("agathodaimon-nas-schedule-field-invalid")
 f=v.get("frequency","daily"); t=v.get("time",v.get("at","02:00")); w=v.get("weekday",v.get("day","Mon"))
 if f not in {"daily","weekly"}: raise Refusal("agathodaimon-nas-schedule-frequency-invalid")
 if not isinstance(t,str) or len(t)!=5 or t[2]!=":" or not t[:2].isdigit() or not t[3:].isdigit() or int(t[:2])>23 or int(t[3:])>59: raise Refusal("agathodaimon-nas-schedule-time-invalid")
 if f=="weekly" and w not in {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}: raise Refusal("agathodaimon-nas-schedule-weekday-invalid")
 return {"frequency":f,"time":t,"weekday":w if f=="weekly" else None}
def units(s, enabled=True):
 cal="*-*-* "+s['time']+":00" if s['frequency']=="daily" else s['weekday']+" *-*-* "+s['time']+":00"
 record={**s,"enabled":enabled}
 marker="# agathodaimon-nas-sync-schedule: "+json.dumps(record,sort_keys=True,separators=(",",":"))
 return ("[Unit]\nDescription=Homeserver safe NAS sync\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/bash /usr/local/sbin/agathodaimon/storage/backup/safe-nas-sync.sh\n",f"{marker}\n[Unit]\nDescription=Homeserver safe NAS sync timer\n\n[Timer]\nOnCalendar={cal}\nPersistent=true\nUnit={SERVICE}\n\n[Install]\nWantedBy=timers.target\n")
def ctl(*a): return [SYSTEMCTL,*a]
def sync_now(planned):
 cmd=[BASH,SAFE_SYNC]
 if planned: return receipt("sync-now",True,[cmd],commandAuthority=SAFE_SYNC,workerCommand=[sys.executable,"-m",MODULE,"--worker","<jobHandle>"],jobHandle=None,progress=None,status="planned")
 h=uuid.uuid4().hex; rec=root()/f"{h}.json"; log=root()/f"{h}.log"; atomic(rec,json.dumps({"handle":h,"status":"queued","progress":0})+"\\n"); w=[sys.executable,"-m",MODULE,"--worker",h]
 try:
  with log.open("ab") as out: child=subprocess.Popen(w,stdout=out,stderr=out,start_new_session=True)
 except OSError as e: atomic(rec,json.dumps({"handle":h,"status":"failed","progress":100,"exitCode":None,"error":str(e)})+"\\n"); raise Refusal("agathodaimon-nas-sync-worker-launch-failed") from e
 atomic(rec,json.dumps({"handle":h,"status":"queued","progress":0,"workerPid":child.pid})+"\\n"); return receipt("sync-now",False,[cmd],commandAuthority=SAFE_SYNC,workerCommand=w,jobHandle=h,progress=0,status="queued")
def read_timer_schedule(text):
 for line in text.splitlines()[:1]:
  if line.startswith("# agathodaimon-nas-sync-schedule: "):
   value=json.loads(line.split(": ",1)[1]); base=schedule(value)
   enabled=value.get("enabled",True)
   if not isinstance(enabled,bool): raise Refusal("agathodaimon-nas-schedule-enabled-invalid")
   return {**base,"enabled":enabled}
 return {**schedule({}),"enabled":False}
def schedule_read(planned):
 sp=Path(UNIT_DIR)/SERVICE; tp=Path(UNIT_DIR)/TIMER; cmds=[ctl("is-enabled",TIMER),ctl("is-active",TIMER),ctl("show",TIMER,"--property=NextElapseUSecRealtime","--value")]; ts={"enabled":None,"active":None,"nextFire":None,"planned":True}
 if not planned:
  q=lambda *a: subprocess.run(ctl(*a),text=True,capture_output=True,check=False).stdout.strip(); ts={"enabled":q("is-enabled",TIMER)=="enabled","active":q("is-active",TIMER)=="active","nextFire":q("show",TIMER,"--property=NextElapseUSecRealtime","--value") or None,"planned":False}
 sv=sp.read_text() if sp.is_file() else units(schedule({}),False)[0]; tv=tp.read_text() if tp.is_file() else units(schedule({}),False)[1]; s=read_timer_schedule(tv) if tp.is_file() else {**schedule({}),"enabled":False}; return receipt("sync-schedule",planned,cmds,unitPaths={"service":str(sp),"timer":str(tp)},unitContents={"service":sv,"timer":tv},schedule=s,timerState=ts)
def schedule_update(p,planned):
 n=p.get("schedule")
 if not isinstance(n,dict): raise Refusal("agathodaimon-nas-schedule-invalid")
 s=schedule(n); enabled=n.get("enabled",True)
 if not isinstance(enabled,bool): raise Refusal("agathodaimon-nas-schedule-enabled-invalid")
 sv,tv=units(s,enabled); sp=str(Path(UNIT_DIR)/SERVICE); tp=str(Path(UNIT_DIR)/TIMER); cmds=[ctl("daemon-reload"),ctl("enable","--now",TIMER)] if enabled else [ctl("disable","--now",TIMER),[RM,"-f",sp,tp],ctl("daemon-reload")]; extra={"unitPaths":{"service":sp,"timer":tp},"unitContents":{"service":sv,"timer":tv},"schedule":{**s,"enabled":enabled},"enabled":enabled,"timerState":{"enabled":None,"active":None,"nextFire":None,"planned":True}}
 if planned: return receipt("sync-schedule-update",True,cmds,**extra)
 if enabled:
  atomic(Path(sp),sv); atomic(Path(tp),tv)
  for c in cmds:
   if subprocess.run(c,check=False).returncode: raise Refusal("agathodaimon-nas-schedule-update-refused")
 else:
  if subprocess.run(cmds[0],check=False).returncode: raise Refusal("agathodaimon-nas-schedule-update-refused")
  if subprocess.run(cmds[1],check=False).returncode:
   raise Refusal("agathodaimon-nas-schedule-update-refused")
  if subprocess.run(cmds[2],check=False).returncode: raise Refusal("agathodaimon-nas-schedule-update-refused")
 out=schedule_read(False); out.update({"action":"sync-schedule-update","schedule":{**s,"enabled":enabled},"enabled":enabled}); return out
def valid(h): return isinstance(h,str) and len(h)==32 and all(c in "0123456789abcdef" for c in h)
def job_status(p,planned):
 h=p.get("jobHandle",p.get("handle"))
 if not valid(h): raise Refusal("agathodaimon-nas-job-handle-invalid")
 if planned: return receipt("sync-job-status",True,[],jobHandle=h,status="planned",progress=None)
 rec=root()/f"{h}.json"
 if not rec.is_file(): raise Refusal("agathodaimon-nas-job-not-found")
 st=json.loads(rec.read_text()); return receipt("sync-job-status",False,[],jobHandle=h,status=st.get("status"),progress=st.get("progress"),exitCode=st.get("exitCode"),workerPid=st.get("workerPid"))
def worker(h):
 if not valid(h): return 2
 rec=root()/f"{h}.json"; log=root()/f"{h}.log"
 try:
  old=json.loads(rec.read_text()) if rec.is_file() else {"handle":h}; atomic(rec,json.dumps({**old,"handle":h,"status":"running","progress":0})+"\\n")
  with log.open("ab") as out: result=subprocess.run([BASH,SAFE_SYNC],stdout=out,stderr=out,check=False)
  atomic(rec,json.dumps({"handle":h,"status":"completed" if result.returncode==0 else "failed","progress":100,"exitCode":result.returncode})+"\\n"); return result.returncode
 except BaseException as e:
  try: atomic(rec,json.dumps({"handle":h,"status":"failed","progress":100,"exitCode":None,"error":str(e)})+"\\n")
  except BaseException: pass
  return 1
def dispatch(x):
 if set(x)-{"actuator","metadata"} or x.get("actuator")!="nas-sync" or not isinstance(x.get("metadata"),dict): raise Refusal("agathodaimon-nas-request-invalid")
 p=x["metadata"]; a=p.get("action"); planned=p.get("dryRun",p.get("planned",False))
 if not isinstance(planned,bool): raise Refusal("agathodaimon-nas-planned-invalid")
 if a=="sync-now": return sync_now(planned)
 if a=="sync-schedule": return schedule_read(planned)
 if a=="sync-schedule-update": return schedule_update(p,planned)
 if a=="sync-job-status": return job_status(p,planned)
 raise Refusal("agathodaimon-nas-action-invalid")
def main():
 if len(sys.argv)==3 and sys.argv[1]=="--worker": return worker(sys.argv[2])
 try: value=dispatch(json.loads(sys.stdin.buffer.read(65537).decode()))
 except (UnicodeDecodeError,json.JSONDecodeError,Refusal,OSError,subprocess.SubprocessError) as e: value=fail(str(e) if isinstance(e,Refusal) else "agathodaimon-nas-request-invalid")
 print(json.dumps(value,sort_keys=True)); return 0 if value["ok"] else 1
if __name__=="__main__": raise SystemExit(main())

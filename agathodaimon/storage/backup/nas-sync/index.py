from __future__ import annotations
import errno,fcntl,json,os,re,shlex,stat,subprocess,sys,tempfile,time,uuid
from pathlib import Path

SCHEMA="caduceus.nas.sync.v1"; LAUNCHER="/usr/local/sbin/caduceus-nas-sync"; RSYNC="/usr/bin/rsync"; FINDMNT="/usr/bin/findmnt"; LSBLK="/usr/bin/lsblk"; BLKID="/usr/sbin/blkid"; JOURNALCTL="/usr/bin/journalctl"; SYSTEMCTL="/usr/bin/systemctl"; RM="/usr/bin/rm"
SOURCE=Path("/mnt/nas"); DESTINATION=Path("/mnt/nas_backup"); UNIT_DIR=Path("/etc/systemd/system"); SERVICE="agathodaimon-nas-sync.service"; TIMER="agathodaimon-nas-sync.timer"; MARKER="# agathodaimon-nas-sync-schedule: "; MAX_INPUT=65536
DENYLIST={"homeserver-boot-efi","homeserver-boot","homeserver-swap","homeserver-vault","homeserver-deploy","homeserver-root"}
KERNEL_ERROR=re.compile(r"(?:\bXFS\b.*(?:error|corrupt|shutdown)|\bI/O error\b|\bdevice-mapper\b.*(?:error|fail)|\bblk_update_request\b|\bBuffer I/O error\b)",re.I)
class Refusal(RuntimeError): pass

def state_root(): return Path(os.environ.get("CADUCEUS_NAS_STATE_ROOT","/var/lib/caduceus/nas-sync"))
def state_file(): return Path(os.environ.get("CADUCEUS_NAS_STATE_FILE",str(state_root()/"last-good.json")))
def receipt_root(): return Path(os.environ.get("CADUCEUS_NAS_RECEIPT_ROOT",str(state_root()/"receipts")))
def job_root(): return Path(os.environ.get("CADUCEUS_NAS_JOB_ROOT",str(state_root()/"jobs")))
def lock_file(): return Path(os.environ.get("CADUCEUS_NAS_LOCK","/run/homeserver-nas-sync.lock"))
def atomic(path,text,mode=0o640):
 path.parent.mkdir(parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent,text=True)
 try:
  os.fchmod(fd,mode)
  with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(text); f.flush(); os.fsync(f.fileno())
  os.replace(tmp,path); dfd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
  try: os.fsync(dfd)
  finally: os.close(dfd)
 except BaseException:
  try: os.unlink(tmp)
  except FileNotFoundError: pass
  raise
def atomic_json(path,value): atomic(path,json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
def bounded(e): return (str(e).replace("\n"," ").strip() or type(e).__name__)[:512]
def receipt(action,outcome,planned=False,mutation=False,**fields):
 return {"schema":SCHEMA,"receiptFamily":SCHEMA,"action":action,"ok":outcome=="ok","outcome":outcome,"planned":planned,"mutationPerformed":mutation,"firstMissingSignal":"none" if outcome=="ok" else fields.get("reason",outcome),**fields}
def write_receipt(v):
 p=receipt_root()/(str(time.time_ns())+"-"+uuid.uuid4().hex+".json"); atomic_json(p,v); return p
def finish(v):
 try: p=write_receipt(v)
 except Exception as e:
  return {**v,"ok":False,"outcome":"failed","firstMissingSignal":"nas-sync-receipt-write-failed","receiptPersisted":False,"receiptWriteError":bounded(e)}
 return {**v,"receiptPersisted":True,"receiptPath":str(p)}
def refused(action,reason,checks=None,**fields): return finish(receipt(action,"refused",reason=reason,checks=checks or [],**fields))
def command(argv): return subprocess.run(argv,text=True,capture_output=True,check=False)
def run(argv,runner):
 try: r=runner(list(argv))
 except FileNotFoundError as e: raise Refusal("required-tool-missing:"+argv[0]) from e
 except OSError as e: raise Refusal("command-unavailable:"+argv[0]+":"+bounded(e)) from e
 if not hasattr(r,"returncode") or not hasattr(r,"stdout"): raise Refusal("command-result-malformed:"+argv[0])
 return r
def checked(checks,name,**facts): checks.append({"name":name,"ok":True,**facts})

def mount_info(path,runner):
 r=run([FINDMNT,"-n","-e","-o","SOURCE,TARGET","--target",str(path)],runner); lines=[x for x in r.stdout.splitlines() if x.strip()]
 if r.returncode or len(lines)!=1: raise Refusal("mountpoint-unevaluable:"+str(path))
 try: fields=shlex.split(lines[0])
 except ValueError as e: raise Refusal("mountpoint-output-malformed:"+str(path)) from e
 if len(fields)!=2: raise Refusal("mountpoint-output-malformed:"+str(path))
 source,target=fields
 if path==DESTINATION and target=="/": raise Refusal("backup-target-is-root")
 if target!=str(path): raise Refusal("not-a-real-mountpoint:"+str(path))
 source=source.split("[",1)[0]
 if not source.startswith("/dev/"): raise Refusal("mount-source-not-block-device:"+str(path))
 return source,target
def device_facts(source,runner):
 resolved=os.path.realpath(source)
 if not resolved.startswith("/dev/"): raise Refusal("device-alias-unresolvable:"+source)
 r=run([LSBLK,"-s","-n","-r","-P","-o","NAME,KNAME,PKNAME,PATH,MAJ:MIN","--",resolved],runner)
 if r.returncode or not r.stdout.strip(): raise Refusal("backing-device-unevaluable:"+source)
 ids={source,resolved}; roots=set()
 for line in r.stdout.splitlines():
  try: fields=dict(item.split("=",1) for item in shlex.split(line))
  except (ValueError,TypeError) as e: raise Refusal("backing-device-output-malformed:"+source) from e
  if set(fields)!={"NAME","KNAME","PKNAME","PATH","MAJ:MIN"}: raise Refusal("backing-device-output-malformed:"+source)
  name,kname,parent,path,majmin=(fields[k] for k in ("NAME","KNAME","PKNAME","PATH","MAJ:MIN"))
  if not name or not kname or not path or not majmin: raise Refusal("backing-device-output-malformed:"+source)
  ids.update({name,kname,path,majmin,"/dev/"+name,"/dev/"+kname})
  if parent: ids.update({parent,"/dev/"+parent})
  else: roots.update({kname,path,majmin})
 if not roots: raise Refusal("backing-device-root-unevaluable:"+source)
 return {"source":source,"resolved":resolved,"identities":ids,"roots":roots}
def partlabel(device,runner):
 r=run([BLKID,"-s","PARTLABEL","-o","value","--",device],runner); labels=[x.strip() for x in r.stdout.splitlines() if x.strip()]
 if r.returncode or len(labels)!=1: raise Refusal("backup-partlabel-unevaluable:"+device)
 return labels[0]
def tokens(facts):
 out=set()
 for raw in facts["identities"]:
  value=str(raw).strip().casefold()
  if value: out.update({value,Path(value).name})
 return out-{"dev","mapper"}
def names_device(line,identities):
 folded=line.casefold()
 return any(re.search(r"(?<![a-z0-9_.:-])"+re.escape(t)+r"(?![a-z0-9_.:-])",folded) for t in sorted(identities,key=len,reverse=True))
def kernel_gate(a,b,runner):
 r=run([JOURNALCTL,"-k","-b","--no-pager","-o","cat"],runner)
 if r.returncode: raise Refusal("current-boot-kernel-log-unevaluable")
 identities=tokens(a)|tokens(b)
 if any(KERNEL_ERROR.search(line) and names_device(line,identities) for line in r.stdout.splitlines()): raise Refusal("current-boot-kernel-error-names-backing-drive")
def measure(root):
 if not root.is_dir(): raise Refusal("source-unreadable:"+str(root))
 count=total=0; stack=[root]
 while stack:
  directory=stack.pop()
  try: entries=list(os.scandir(directory))
  except OSError as e: raise Refusal("source-directory-unreadable:"+str(directory)) from e
  for entry in entries:
   if entry.name=="lost+found" and Path(entry.path).parent==root: continue
   try: info=entry.stat(follow_symlinks=False)
   except OSError as e: raise Refusal("source-entry-unreadable:"+entry.path) from e
   if stat.S_ISDIR(info.st_mode): stack.append(Path(entry.path))
   else: count+=1; total+=info.st_size
 return count,total
def load_state():
 p=state_file()
 try: raw=p.read_text(encoding="utf-8")
 except FileNotFoundError: return None
 except (OSError,UnicodeDecodeError) as e: raise Refusal("last-good-state-unreadable-or-malformed") from e
 try: v=json.loads(raw)
 except json.JSONDecodeError as e: raise Refusal("last-good-state-unreadable-or-malformed") from e
 if not isinstance(v,dict) or type(v.get("fileCount")) is not int or type(v.get("totalBytes")) is not int or v["fileCount"]<0 or v["totalBytes"]<0: raise Refusal("last-good-state-unreadable-or-malformed")
 return {"fileCount":v["fileCount"],"totalBytes":v["totalBytes"]}
def shrink_reasons(files,bytes_,old):
 out=[]
 if bytes_*100<old["totalBytes"]*90: out.append("byte-count-shrank-more-than-10-percent")
 if files*100<old["fileCount"]*80: out.append("file-count-shrank-more-than-20-percent")
 return out
def parse_rsync_stats(text):
 out={}
 for line in text.splitlines():
  if ":" not in line: continue
  key,value=line.split(":",1); key=key.strip(); value=value.strip()
  if key: out[key[:96]]=value[:256]
 return out
def acquire_lock():
 p=lock_file()
 try: p.parent.mkdir(parents=True,exist_ok=True); fd=os.open(p,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC,0o640)
 except OSError as e: raise Refusal("single-instance-lock-unavailable:"+bounded(e)) from e
 try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except OSError as e:
  os.close(fd)
  if e.errno in (errno.EACCES,errno.EAGAIN): raise Refusal("single-instance-lock-contended") from e
  raise Refusal("single-instance-lock-unavailable:"+bounded(e)) from e
 return fd

def sync(accept_shrink=False,runner=command,measure_fn=None):
 action="sync-run"; checks=[]; facts={"sourcePath":str(SOURCE),"destinationPath":str(DESTINATION)}; fd=None
 try:
  if measure_fn is None: measure_fn=measure
  fd=acquire_lock(); checked(checks,"single-instance-lock",mode="nonblocking")
  s,st=mount_info(SOURCE,runner); checked(checks,"source-mountpoint",source=s,target=st)
  d,dt=mount_info(DESTINATION,runner); checked(checks,"destination-mountpoint",source=d,target=dt)
  sf,df=device_facts(s,runner),device_facts(d,runner); facts.update(sourceDevice=s,destinationDevice=d)
  if sf["roots"]&df["roots"]: raise Refusal("source-and-destination-share-backing-device")
  checked(checks,"different-backing-devices",sourceRoots=sorted(sf["roots"]),destinationRoots=sorted(df["roots"]))
  label=partlabel(df["resolved"],runner); facts["backupPartlabel"]=label
  if label in DENYLIST: raise Refusal("backup-partlabel-denied:"+label)
  checked(checks,"backup-partlabel-allowed",partlabel=label); kernel_gate(sf,df,runner); checked(checks,"current-boot-kernel-log-clean")
  files,bytes_=measure_fn(SOURCE); old=load_state(); facts.update(currentFileCount=files,currentTotalBytes=bytes_,priorState=old); checked(checks,"source-measured",fileCount=files,totalBytes=bytes_)
  if old is None:
   facts.update(coldStart=True,notice="COLD START: no last-good state; current file count sets the deletion cap")
   if accept_shrink:
    facts.update(humanOverride="--accept-shrink",overrideNotice="CRITICAL HUMAN OVERRIDE: --accept-shrink was supplied on cold start; no shrink baseline existed and every safety check remained enforced")
    print(facts["overrideNotice"],file=sys.stderr,flush=True)
  else:
   reasons=shrink_reasons(files,bytes_,old)
   if reasons and not accept_shrink: raise Refusal("source-shrink-refused:"+",".join(reasons))
   checked(checks,"shrink-canary",exceeded=bool(reasons),bypassed=bool(reasons and accept_shrink))
   if accept_shrink:
    facts.update(humanOverride="--accept-shrink",overrideNotice="CRITICAL HUMAN OVERRIDE: --accept-shrink bypassed only shrink; every other safety check remained enforced")
    print(facts["overrideNotice"],file=sys.stderr,flush=True)
  reference=files if old is None else old["fileCount"]; cap=max(1000,(reference*20)//100); basis="cold-start-current-file-count" if old is None else "last-good-file-count"
  argv=[RSYNC,"-aH","--stats","--delete-delay","--exclude=lost+found","--max-delete="+str(cap),str(SOURCE)+"/",str(DESTINATION)+"/"]; facts.update(rsyncArgv=argv,maxDelete=cap,maxDeleteBasis=basis)
  r=run(argv,runner); facts.update(rsyncExitCode=r.returncode,rsyncStats=parse_rsync_stats(r.stdout))
  if r.returncode==25: return finish(receipt(action,"failed",mutation=True,reason="CRITICAL: rsync deletion cap "+str(cap)+" was exceeded",checks=checks,exitCode=25,**facts))
  if r.returncode: return finish(receipt(action,"failed",mutation=True,reason="rsync-failed:exit-"+str(r.returncode),checks=checks,exitCode=r.returncode,**facts))
  final_files,final_bytes=measure_fn(SOURCE); checked(checks,"source-remeasured-after-sync",fileCount=final_files,totalBytes=final_bytes)
  try: atomic_json(state_file(),{"fileCount":final_files,"totalBytes":final_bytes})
  except Exception as e: return finish(receipt(action,"failed",mutation=True,reason="last-good-state-write-failed:"+bounded(e),checks=checks,exitCode=1,**facts))
  facts.update(finalFileCount=final_files,finalTotalBytes=final_bytes); checked(checks,"last-good-state-persisted",path=str(state_file()))
  return finish(receipt(action,"ok",mutation=True,checks=checks,exitCode=0,**facts))
 except Refusal as e: return refused(action,str(e),checks=checks,**facts)
 except Exception as e: return finish(receipt(action,"failed",reason="unexpected-sync-failure:"+bounded(e),checks=checks,exitCode=1,**facts))
 finally:
  if fd is not None: os.close(fd)

def valid_handle(h): return isinstance(h,str) and re.fullmatch(r"[0-9a-f]{32}",h) is not None
def job_path(h): return job_root()/(h+".json")
def write_job(v): atomic_json(job_path(v["handle"]),v)
def read_job(h):
 p=job_path(h)
 if not p.is_file(): raise Refusal("agathodaimon-nas-job-not-found")
 try: v=json.loads(p.read_text(encoding="utf-8"))
 except Exception as e: raise Refusal("agathodaimon-nas-job-state-unreadable-or-malformed") from e
 if not isinstance(v,dict) or v.get("handle")!=h or v.get("status") not in {"queued","running","completed","failed","refused"} or type(v.get("progress")) is not int or not 0<=v["progress"]<=100: raise Refusal("agathodaimon-nas-job-state-unreadable-or-malformed")
 return v
def sync_now(planned):
 template=[LAUNCHER,"--worker","<jobHandle>"]
 if planned: return finish(receipt("sync-now","ok",planned=True,workerCommand=template,jobHandle=None,status="planned",progress=None))
 h=uuid.uuid4().hex; job={"handle":h,"status":"queued","progress":0,"exitCode":None}
 try: write_job(job)
 except Exception as e: return refused("sync-now","job-state-write-failed:"+bounded(e),jobHandle=h)
 cmd=[LAUNCHER,"--worker",h]; log=job_root()/(h+".log")
 try:
  log.parent.mkdir(parents=True,exist_ok=True)
  with log.open("ab") as out: child=subprocess.Popen(cmd,stdout=out,stderr=out,start_new_session=True)
 except OSError as e:
  job.update(status="failed",progress=100,error=bounded(e))
  try: write_job(job)
  except Exception: pass
  return refused("sync-now","worker-launch-failed:"+bounded(e),jobHandle=h,workerCommand=cmd)
 job["workerPid"]=child.pid
 try: write_job(job)
 except Exception as e: return finish(receipt("sync-now","failed",mutation=True,reason="queued-job-state-write-failed:"+bounded(e),jobHandle=h,workerPid=child.pid,workerCommand=cmd))
 return finish(receipt("sync-now","ok",mutation=True,jobHandle=h,workerPid=child.pid,workerCommand=cmd,status="queued",progress=0))
def worker(h,runner=command,measure_fn=None):
 if not valid_handle(h): return 2
 try: job=read_job(h); job.update(status="running",progress=0,workerPid=os.getpid()); write_job(job)
 except Exception: return 1
 result=sync(runner=runner,measure_fn=measure_fn); outcome=result["outcome"]; code=int(result.get("exitCode",0 if outcome=="ok" else 1))
 job.update(status="completed" if outcome=="ok" else outcome,progress=100,exitCode=code,runOutcome=outcome,runReceipt=result.get("receiptPath"),reason=result.get("reason"))
 try: write_job(job)
 except Exception: return 1
 return code
def job_status(p,planned):
 h=p.get("jobHandle",p.get("handle"))
 if not valid_handle(h): raise Refusal("agathodaimon-nas-job-handle-invalid")
 if planned: return finish(receipt("sync-job-status","ok",planned=True,jobHandle=h,status="planned",progress=None))
 v=read_job(h); fields={k:v.get(k) for k in ("status","progress","exitCode","workerPid","runOutcome","runReceipt","reason")}
 return finish(receipt("sync-job-status","ok",jobHandle=h,**fields))

def schedule(v):
 if not isinstance(v,dict): raise Refusal("agathodaimon-nas-schedule-invalid")
 if set(v)-{"frequency","time","weekday","day","at","enabled"}: raise Refusal("agathodaimon-nas-schedule-field-invalid")
 f=v.get("frequency","daily"); at=v.get("time",v.get("at","02:00")); day=v.get("weekday",v.get("day","Mon")); enabled=v.get("enabled",True)
 if f not in {"daily","weekly"}: raise Refusal("agathodaimon-nas-schedule-frequency-invalid")
 if not isinstance(at,str) or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d",at) is None: raise Refusal("agathodaimon-nas-schedule-time-invalid")
 if f=="weekly" and day not in {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}: raise Refusal("agathodaimon-nas-schedule-weekday-invalid")
 if type(enabled) is not bool: raise Refusal("agathodaimon-nas-schedule-enabled-invalid")
 return {"frequency":f,"time":at,"weekday":day if f=="weekly" else None,"enabled":enabled}
def units(s):
 cal="*-*-* "+s["time"]+":00" if s["frequency"]=="daily" else s["weekday"]+" *-*-* "+s["time"]+":00"; marker=MARKER+json.dumps(s,sort_keys=True,separators=(",",":"))
 service="[Unit]\nDescription=Homeserver governed NAS sync\n\n[Service]\nType=oneshot\nExecStart="+LAUNCHER+" --run\n"
 timer=marker+"\n[Unit]\nDescription=Homeserver governed NAS sync timer\n\n[Timer]\nOnCalendar="+cal+"\nPersistent=true\nUnit="+SERVICE+"\n\n[Install]\nWantedBy=timers.target\n"
 return service,timer
def systemctl_value(args,runner,allowed={0}):
 r=run([SYSTEMCTL,*args],runner)
 if r.returncode not in allowed: raise Refusal("systemctl-readback-failed:"+args[0])
 return r.stdout.strip()
def parse_timer(text):
 lines=text.splitlines()
 if not lines or not lines[0].startswith(MARKER): raise Refusal("agathodaimon-nas-schedule-state-malformed")
 try: return schedule(json.loads(lines[0][len(MARKER):]))
 except Exception as e: raise Refusal("agathodaimon-nas-schedule-state-malformed") from e
def schedule_read(planned,runner=command):
 sp,tp=UNIT_DIR/SERVICE,UNIT_DIR/TIMER; default=schedule({"enabled":False}); sv,tv=units(default); cmds=[[SYSTEMCTL,"is-enabled",TIMER],[SYSTEMCTL,"is-active",TIMER],[SYSTEMCTL,"show",TIMER,"--property=NextElapseUSecRealtime","--value"]]
 if planned: return finish(receipt("sync-schedule","ok",planned=True,commands=cmds,unitPaths={"service":str(sp),"timer":str(tp)},unitContents={"service":sv,"timer":tv},schedule=default,timerState={"enabled":None,"active":None,"nextFire":None,"planned":True}))
 try: sv=sp.read_text(encoding="utf-8") if sp.is_file() else sv; tv=tp.read_text(encoding="utf-8") if tp.is_file() else tv
 except Exception as e: raise Refusal("agathodaimon-nas-schedule-state-unreadable") from e
 seated=parse_timer(tv) if tp.is_file() else default; enabled=systemctl_value(["is-enabled",TIMER],runner,{0,1})=="enabled"; active=systemctl_value(["is-active",TIMER],runner,{0,3})=="active"; next_fire=systemctl_value(["show",TIMER,"--property=NextElapseUSecRealtime","--value"],runner) or None; state={"enabled":enabled,"active":active,"nextFire":next_fire,"planned":False}; seated["enabled"]=enabled
 return finish(receipt("sync-schedule","ok",commands=cmds,unitPaths={"service":str(sp),"timer":str(tp)},unitContents={"service":sv,"timer":tv},schedule=seated,timerState=state))
def schedule_update(p,planned,runner=command):
 s=schedule(p.get("schedule")); sv,tv=units(s); sp,tp=UNIT_DIR/SERVICE,UNIT_DIR/TIMER; cmds=[[SYSTEMCTL,"daemon-reload"],[SYSTEMCTL,"enable","--now",TIMER]] if s["enabled"] else [[SYSTEMCTL,"disable","--now",TIMER],[RM,"-f",str(sp),str(tp)],[SYSTEMCTL,"daemon-reload"]]; common={"commands":cmds,"unitPaths":{"service":str(sp),"timer":str(tp)},"unitContents":{"service":sv,"timer":tv},"schedule":s}
 if planned: return finish(receipt("sync-schedule-update","ok",planned=True,**common))
 mutation=False
 try:
  if s["enabled"]: atomic(sp,sv,0o644); atomic(tp,tv,0o644); mutation=True
  for cmd in cmds:
   r=run(cmd,runner)
   if r.returncode: raise Refusal("schedule-update-command-failed:"+cmd[1])
   mutation=True
  enabled=systemctl_value(["is-enabled",TIMER],runner,{0,1})=="enabled"; active=systemctl_value(["is-active",TIMER],runner,{0,3})=="active"; next_fire=systemctl_value(["show",TIMER,"--property=NextElapseUSecRealtime","--value"],runner) or None
  if enabled!=s["enabled"]: raise Refusal("schedule-update-readback-mismatch")
  return finish(receipt("sync-schedule-update","ok",mutation=mutation,timerState={"enabled":enabled,"active":active,"nextFire":next_fire,"planned":False},**common))
 except Refusal as e: return finish(receipt("sync-schedule-update","refused",mutation=mutation,reason=str(e),**common))
 except Exception as e: return finish(receipt("sync-schedule-update","failed",mutation=mutation,reason="schedule-update-failed:"+bounded(e),**common))

def dispatch(x):
 if not isinstance(x,dict) or set(x)-{"actuator","metadata"} or x.get("actuator")!="nas-sync" or not isinstance(x.get("metadata"),dict): raise Refusal("agathodaimon-nas-request-invalid")
 p=x["metadata"]; action=p.get("action"); planned=p.get("dryRun",p.get("planned",False))
 if type(planned) is not bool: raise Refusal("agathodaimon-nas-planned-invalid")
 allowed={"sync-now":{"action","dryRun","planned"},"sync-job-status":{"action","dryRun","planned","jobHandle","handle"},"sync-schedule":{"action","dryRun","planned"},"sync-schedule-update":{"action","dryRun","planned","schedule"}}
 if action not in allowed: raise Refusal("agathodaimon-nas-action-invalid")
 if set(p)-allowed[action]: raise Refusal("agathodaimon-nas-action-field-invalid")
 if action=="sync-now": return sync_now(planned)
 if action=="sync-job-status": return job_status(p,planned)
 if action=="sync-schedule": return schedule_read(planned)
 return schedule_update(p,planned)
def read_envelope():
 raw=sys.stdin.buffer.read(MAX_INPUT+1)
 if len(raw)>MAX_INPUT: raise Refusal("agathodaimon-nas-request-too-large")
 if not raw: raise Refusal("agathodaimon-nas-request-empty")
 try: return json.loads(raw.decode())
 except Exception as e: raise Refusal("agathodaimon-nas-request-invalid") from e
def main(argv=None):
 args=list(sys.argv[1:] if argv is None else argv)
 try:
  if args==["--run"]: v=sync()
  elif args in (["--accept-shrink"],["--run","--accept-shrink"]): v=sync(accept_shrink=True)
  elif len(args)==2 and args[0]=="--worker": return worker(args[1])
  elif args: raise Refusal("agathodaimon-nas-cli-arguments-invalid")
  else: v=dispatch(read_envelope())
 except Refusal as e: v=refused("unknown",str(e))
 except Exception as e: v=finish(receipt("unknown","failed",reason="agathodaimon-nas-unexpected:"+bounded(e)))
 print(json.dumps(v,sort_keys=True)); return 0 if v["outcome"]=="ok" else int(v.get("exitCode",1)) or 1
if __name__=="__main__": raise SystemExit(main())

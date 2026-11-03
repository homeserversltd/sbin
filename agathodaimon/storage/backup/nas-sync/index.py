from __future__ import annotations
import errno,fcntl,json,os,re,shlex,stat,subprocess,sys,time
from pathlib import Path
from agathodaimon.storage.nas import deed

SCHEMA="caduceus.nas.sync.v1"; RSYNC="/usr/bin/rsync"; FINDMNT="/usr/bin/findmnt"; LSBLK="/usr/bin/lsblk"; BLKID="/usr/sbin/blkid"; JOURNALCTL="/usr/bin/journalctl"
SOURCE=Path("/mnt/nas"); DESTINATION=Path("/mnt/nas_backup"); MAX_INPUT=65536
DENYLIST={"homeserver-boot-efi","homeserver-boot","homeserver-swap","homeserver-vault","homeserver-deploy","homeserver-root"}
KERNEL_ERROR=re.compile(r"(?:\bXFS\b.*(?:error|corrupt|shutdown)|\bI/O error\b|\bdevice-mapper\b.*(?:error|fail)|\bblk_update_request\b|\bBuffer I/O error\b)",re.I)
class Refusal(RuntimeError): pass
class KernelRefusal(Refusal):
 def __init__(self,reason,attach_scopes): super().__init__(reason); self.attach_scopes=attach_scopes

def lock_file():
 root=os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
 if root is None: return Path("/run/homeserver-nas-sync.lock")
 try:
  base=Path(root)
  if not base.is_absolute(): raise ValueError("relative scratch root")
  base=base.resolve(strict=True)
  if base==Path("/"): raise ValueError("root scratch")
  target=Path(os.environ.get("CADUCEUS_NAS_LOCK",str(base/"run/homeserver-nas-sync.lock")))
  if not target.is_absolute() or not target.resolve(strict=False).is_relative_to(base): raise ValueError("lock outside scratch")
  return target
 except (OSError,RuntimeError,ValueError) as e: raise Refusal("single-instance-lock-invalid") from e
def bounded(e): return (str(e).replace("\n"," ").strip() or type(e).__name__)[:512]
def receipt(action,outcome,planned=False,mutation=False,**fields):
 defaults={"reason":None,"checks":[],"rsyncExitCode":None,"rsyncStats":None,"maxDelete":None,"maxDeleteBasis":None,"coldStart":None}
 return {"schema":SCHEMA,"receiptFamily":SCHEMA,"action":action,"ok":outcome=="ok","outcome":outcome,"planned":planned,"mutationPerformed":mutation,"firstMissingSignal":"none" if outcome=="ok" else fields.get("reason",outcome),**defaults,**fields}
def finish(v): return v
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
 r=run([LSBLK,"-s","-n","-P","-o","NAME,KNAME,PKNAME,PATH,MAJ:MIN,TYPE,PARTLABEL","--",resolved],runner)
 if r.returncode or not r.stdout.strip(): raise Refusal("backing-device-unevaluable:"+source)
 ids={source,resolved}; roots=set(); rows=[]
 for line in r.stdout.splitlines():
  try: fields=dict(item.split("=",1) for item in shlex.split(line))
  except (ValueError,TypeError) as e: raise Refusal("backing-device-output-malformed:"+source) from e
  if set(fields)!={"NAME","KNAME","PKNAME","PATH","MAJ:MIN","TYPE","PARTLABEL"}: raise Refusal("backing-device-output-malformed:"+source)
  name,kname,parent,path,majmin=(fields[k] for k in ("NAME","KNAME","PKNAME","PATH","MAJ:MIN"))
  if not name or not kname or not path or not majmin: raise Refusal("backing-device-output-malformed:"+source)
  ids.update({name,kname,path,majmin,"/dev/"+name,"/dev/"+kname})
  if parent: ids.update({parent,"/dev/"+parent})
  if fields["TYPE"]=="disk": roots.update({kname,path,majmin})
  rows.append(fields)
 if not roots: raise Refusal("backing-device-root-unevaluable:"+source)
 partitions=[row["PARTLABEL"].strip() for row in rows if row["TYPE"]=="part" and row["PKNAME"]==rows[0]["KNAME"]]
 return {"source":source,"resolved":resolved,"identities":ids,"roots":roots,"partitionLabels":partitions}
def partlabel(facts,runner):
 labels=facts["partitionLabels"]
 if len(labels)!=1 or not labels[0]: raise Refusal("backup-partlabel-unevaluable:"+facts["resolved"])
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
 r=run([JOURNALCTL,"-k","-b","--no-pager","-o","json"],runner)
 if r.returncode: raise Refusal("current-boot-kernel-log-unevaluable")
 boundaries=[]
 for facts in (a,b):
  disks=sorted(v for v in facts["roots"] if re.fullmatch(r"[0-9]+:[0-9]+",v)); paths=sorted(v for v in facts["roots"] if str(v).startswith("/dev/")); times={}
  for disk in disks:
   try:
    lines=(Path("/run/udev/data")/("b"+disk)).read_text(encoding="utf-8").splitlines()
    values=[int(line[2:]) for line in lines if line.startswith("I:") and line[2:].isdigit()]
    if len(values)!=1: raise ValueError("missing initialization time")
    times[disk]=values[0]
   except (OSError,UnicodeError,ValueError): times[disk]=None
  roots=[]; mapped=set()
  if len(disks)==1:
   roots=[(tokens(facts),times[disks[0]])]
  elif disks and len(paths)==len(disks):
   for path in paths:
    probe=run([LSBLK,"-d","-n","-r","-P","-o","NAME,KNAME,PATH,MAJ:MIN","--",path],runner)
    try:
     lines=probe.stdout.splitlines()
     if probe.returncode or len(lines)!=1: raise ValueError("root identity")
     fields=dict(item.split("=",1) for item in shlex.split(lines[0]))
     disk=fields["MAJ:MIN"]
     if disk not in times or disk in mapped or fields["PATH"]!=path: raise ValueError("root identity")
     mapped.add(disk); roots.append((tokens({"identities":{path,fields["NAME"],fields["KNAME"],disk}}),times[disk]))
    except (KeyError,ValueError,TypeError): roots=[]; break
  mapped_roots=len(roots)==len(disks) and bool(roots)
  if not mapped_roots: roots=[(tokens(facts),None)]
  if mapped_roots and len(disks)>1:
   for alias in sorted(v for v in facts["identities"] if str(v).startswith("/dev/")):
    if any(names_device(alias,root_tokens) for root_tokens,_ in roots): continue
    probe=run([LSBLK,"-s","-n","-r","-P","-o","NAME,KNAME,PKNAME,PATH,MAJ:MIN","--",alias],runner)
    try:
     rows=[dict(item.split("=",1) for item in shlex.split(line)) for line in probe.stdout.splitlines()]
     if probe.returncode or not rows or os.path.realpath(rows[0]["PATH"])!=os.path.realpath(alias): raise ValueError("alias identity")
     backing={row["MAJ:MIN"] for row in rows if not row["PKNAME"]}
     if not backing or not backing.issubset(times): raise ValueError("alias roots")
     first=rows[0]; limits=[times[disk] for disk in backing]
     threshold=min(limits) if all(limit is not None for limit in limits) else None
     roots.append((tokens({"identities":{alias,first["PATH"],first["NAME"],first["KNAME"],first["MAJ:MIN"]}}),threshold))
    except (KeyError,ValueError,TypeError): continue
  fallback=min(times.values()) if times and all(v is not None for v in times.values()) else None
  boundaries.append((tokens(facts),roots,fallback,{"roots":[{"device":d,"attachMonotonicUsec":times[d],"scope":"since-attach" if times[d] is not None else "whole-boot-fallback"} for d in disks],"rootIdentityScope":"per-root" if mapped_roots else "whole-boot-fallback","unmappedScope":"since-earliest-attach" if fallback is not None else "whole-boot-fallback"}))
 for line in r.stdout.splitlines():
  try:
   event=json.loads(line); message=event.get("MESSAGE",""); timestamp=event.get("__MONOTONIC_TIMESTAMP")
   if not isinstance(message,str): raise ValueError("message")
   when=int(timestamp) if timestamp is not None else None
  except (ValueError,TypeError,AttributeError): raise Refusal("current-boot-kernel-log-unevaluable")
  if KERNEL_ERROR.search(message):
   for identities,roots,fallback,_ in boundaries:
    matched=[limit for root_tokens,limit in roots if names_device(message,root_tokens)]
    if not matched and names_device(message,identities): matched=[fallback]
    if any(limit is None or when is None or when>limit for limit in matched):
     raise KernelRefusal("current-boot-kernel-error-names-backing-drive",[entry[3] for entry in boundaries])
 return [entry[3] for entry in boundaries]
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
 try:
  p.parent.mkdir(parents=True,exist_ok=True); fd=os.open(p,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o640)
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
   os.close(fd); raise Refusal("single-instance-lock-invalid")
 except OSError as e: raise Refusal("single-instance-lock-unavailable:"+bounded(e)) from e
 try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except OSError as e:
  os.close(fd)
  if e.errno in (errno.EACCES,errno.EAGAIN): raise Refusal("single-instance-lock-contended") from e
  raise Refusal("single-instance-lock-unavailable:"+bounded(e)) from e
 return fd

def sync(baseline=None,accept_shrink=False,planned=False,runner=command,measure_fn=None):
 action="sync"; checks=[]; facts={"sourcePath":str(SOURCE),"destinationPath":str(DESTINATION),"coldStart":baseline is None,"rsyncExitCode":None,"rsyncStats":None,"maxDelete":None,"maxDeleteBasis":None}; fd=None; attempted=False
 try:
  if measure_fn is None: measure_fn=measure
  fd=acquire_lock(); checked(checks,"single-instance-lock",mode="nonblocking")
  s,st=mount_info(SOURCE,runner); checked(checks,"source-mountpoint",source=s,target=st)
  d,dt=mount_info(DESTINATION,runner); checked(checks,"destination-mountpoint",source=d,target=dt)
  sf,df=device_facts(s,runner),device_facts(d,runner); facts.update(sourceDevice=s,destinationDevice=d)
  if sf["roots"]&df["roots"]: raise Refusal("source-and-destination-share-backing-device")
  checked(checks,"different-backing-devices",sourceRoots=sorted(sf["roots"]),destinationRoots=sorted(df["roots"]))
  label=partlabel(df,runner); facts["backupPartlabel"]=label
  if label in DENYLIST: raise Refusal("backup-partlabel-denied:"+label)
  checked(checks,"backup-partlabel-allowed",partlabel=label); scopes=kernel_gate(sf,df,runner); checked(checks,"current-boot-kernel-log-clean",attachScopes=scopes)
  files,bytes_=measure_fn(SOURCE); old=baseline; facts.update(currentFileCount=files,currentTotalBytes=bytes_,priorState=old); checked(checks,"source-measured",fileCount=files,totalBytes=bytes_)
  if old is None:
   facts.update(coldStart=True,notice="COLD START: no last-good state; current file count sets the deletion cap")
   if accept_shrink:
    facts.update(shrinkOverride="metadata.acceptShrink",overrideNotice="CRITICAL OVERRIDE: metadata.acceptShrink was supplied on cold start; no shrink baseline existed and every safety check remained enforced")
    print(facts["overrideNotice"],file=sys.stderr,flush=True)
  else:
   reasons=shrink_reasons(files,bytes_,old)
   if reasons and not accept_shrink: raise Refusal("source-shrink-refused:"+",".join(reasons))
   checked(checks,"shrink-canary",exceeded=bool(reasons),bypassed=bool(reasons and accept_shrink))
   if accept_shrink:
    facts.update(shrinkOverride="metadata.acceptShrink",overrideNotice="CRITICAL OVERRIDE: metadata.acceptShrink was supplied; only the shrink gate may be bypassed, and every other safety check remained enforced")
    print(facts["overrideNotice"],file=sys.stderr,flush=True)
  reference=files if old is None else old["fileCount"]; cap=max(1000,(reference*20)//100); basis="cold-start-current-file-count" if old is None else "last-good-file-count"
  argv=[RSYNC,"-aH","--stats","--delete-delay","--exclude=lost+found","--max-delete="+str(cap),str(SOURCE)+"/",str(DESTINATION)+"/"]; facts.update(rsyncArgv=argv,maxDelete=cap,maxDeleteBasis=basis)
  if planned: return finish(receipt(action,"ok",planned=True,checks=checks,reason=None,**facts))
  attempted=True; r=run(argv,runner); facts.update(rsyncExitCode=r.returncode,rsyncStats=parse_rsync_stats(r.stdout))
  if r.returncode==25: return finish(receipt(action,"failed",mutation=True,reason="CRITICAL: rsync deletion cap "+str(cap)+" was exceeded",checks=checks,exitCode=25,**facts))
  if r.returncode: return finish(receipt(action,"failed",mutation=True,reason="rsync-failed:exit-"+str(r.returncode),checks=checks,exitCode=r.returncode,**facts))
  final_files,final_bytes=measure_fn(SOURCE); checked(checks,"source-remeasured-after-sync",fileCount=final_files,totalBytes=final_bytes)
  facts.update(finalFileCount=final_files,finalTotalBytes=final_bytes)
  return finish(receipt(action,"ok",mutation=True,checks=checks,reason=None,exitCode=0,**facts))
 except Refusal as e:
  if isinstance(e,KernelRefusal): checks.append({"name":"current-boot-kernel-log-clean","ok":False,"attachScopes":e.attach_scopes})
  if attempted:
   not_launched=str(e)=="required-tool-missing:"+RSYNC or str(e).startswith("command-unavailable:"+RSYNC+":")
   return finish(receipt(action,"failed",mutation=not not_launched,reason=str(e),checks=checks,**facts))
  return refused(action,str(e),checks=checks,**facts)
 except Exception as e: return finish(receipt(action,"failed",mutation=attempted,reason="unexpected-sync-failure:"+bounded(e),checks=checks,exitCode=1,**facts))
 finally:
  if fd is not None: os.close(fd)

def dispatch(x):
 if not isinstance(x,dict): raise Refusal("agathodaimon-nas-request-invalid")
 body=x.get("payload")
 actuator=x["actuator"] if "actuator" in x else body.get("actuator") if isinstance(body,dict) else None
 if actuator!="nas-sync": raise Refusal("agathodaimon-nas-request-invalid")
 metadata=x["metadata"] if "metadata" in x else body.get("metadata") if isinstance(body,dict) else None
 if not isinstance(metadata,dict): raise Refusal("agathodaimon-nas-request-invalid")
 p=metadata; action=p.get("action"); planned=p.get("dryRun",False); override=p.get("acceptShrink",False); baseline=p.get("baseline")
 if action!="sync": raise Refusal("agathodaimon-nas-action-invalid")
 if type(planned) is not bool or type(override) is not bool: raise Refusal("agathodaimon-nas-planned-invalid")
 if baseline is not None:
  if not isinstance(baseline,dict) or any(type(baseline.get(k)) is not int or baseline[k]<0 for k in ("fileCount","totalBytes")): raise Refusal("agathodaimon-nas-baseline-invalid")
  baseline={k:baseline[k] for k in ("fileCount","totalBytes")}
 return sync(baseline,override,planned)
def read_envelope():
 raw=sys.stdin.buffer.read(MAX_INPUT+1)
 if len(raw)>MAX_INPUT: raise Refusal("agathodaimon-nas-request-too-large")
 if not raw: raise Refusal("agathodaimon-nas-request-empty")
 try: return json.loads(raw.decode())
 except Exception as e: raise Refusal("agathodaimon-nas-request-invalid") from e
def main(argv=None):
 args=list(sys.argv[1:] if argv is None else argv); request=None; started=time.monotonic()
 try:
  if args: raise Refusal("agathodaimon-nas-cli-arguments-invalid")
  request=read_envelope(); v=dispatch(request)
 except Refusal as e: v=refused("sync",str(e))
 except Exception as e: v=finish(receipt("sync","failed",reason="agathodaimon-nas-unexpected:"+bounded(e)))
 body=request.get("payload") if isinstance(request,dict) else None
 metadata=request.get("metadata") if isinstance(request,dict) else None
 if metadata is None and isinstance(body,dict): metadata=body.get("metadata")
 if isinstance(metadata,dict) and metadata.get("action")=="sync" and metadata.get("dryRun") is not True:
  reason=v.get("firstMissingSignal")
  signal=reason.split(":",1)[0] if isinstance(reason,str) else "nas-operation-failed"
  safe_receipt={"ok":v.get("ok") is True,"outcome":v.get("outcome"),"firstMissingSignal":signal}
  stats=v.get("rsyncStats")
  raw=stats.get("Total transferred file size") if isinstance(stats,dict) else None
  match=re.fullmatch(r"([0-9][0-9,]*) bytes",raw) if isinstance(raw,str) else None
  transferred=int(match.group(1).replace(",","")) if match else None
  try: deed.record("nas-sync-mirror","nas-sync",safe_receipt,started,transferred_bytes=transferred)
  except Exception:
   v["deedLogSignal"]="agathodaimon-nas-deed-log-unavailable"
   if v.get("ok") is True:
    v["ok"]=False; v["outcome"]="failed"; v["firstMissingSignal"]=v["deedLogSignal"]
 if isinstance(request,dict): v["envelope"]=request
 print(json.dumps(v,sort_keys=True)); return 0 if v["outcome"]=="ok" else int(v.get("exitCode",1)) or 1
if __name__=="__main__": raise SystemExit(main())

"""Hermes Agent maintenance with Caduceus-owned user timer lifecycle."""
from __future__ import annotations
import argparse, fcntl, json, os, re, subprocess, tempfile
from pathlib import Path
from typing import Sequence

SCHEMA="caduceus.hermes-agent-maintenance.v1"
SERVICE="""[Unit]
Description=Update Hermes Agent through Caduceus staff
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/agathodaimon/caduceus-hermes-agent-maintenance --maintain
Nice=10
IOSchedulingClass=idle
"""
TIMER="""[Unit]
Description=Daily Hermes Agent maintenance through Caduceus staff

[Timer]
OnCalendar=*-*-* 04:15:00
AccuracySec=1min
RandomizedDelaySec=15min
Persistent=true
Unit=caduceus-hermes-agent-maintenance.service

[Install]
WantedBy=timers.target
"""
def run(argv:list[str], env:dict[str,str]|None=None)->dict:
 p=subprocess.run(argv,text=True,capture_output=True,check=False,env=env); return {"argv":argv,"exit":p.returncode,"stdout":p.stdout.strip(),"stderr":p.stderr.strip()}
def atomic(path:Path,text:str)->None:
 path.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=path.parent,prefix=f".{path.name}.",delete=False) as out: out.write(text);out.flush();os.fsync(out.fileno());tmp=Path(out.name)
 os.chmod(tmp,0o644);os.replace(tmp,path)
def units(unit_dir:Path)->dict[str,Path]: return {"service":unit_dir/"caduceus-hermes-agent-maintenance.service","timer":unit_dir/"caduceus-hermes-agent-maintenance.timer"}
def userctl(command:list[str], owner:str)->dict: return run(["runuser","-u",owner,"--","systemctl","--user",*command])
def lifecycle(install:bool, unit_dir:Path, owner:str, plan:bool)->dict:
 paths=units(unit_dir); name="install" if install else "uninstall"; commands=[["daemon-reload"],["enable","--now","caduceus-hermes-agent-maintenance.timer"]] if install else [["disable","--now","caduceus-hermes-agent-maintenance.timer"],["daemon-reload"]]
 answer={"schema":SCHEMA,"ok":True,"operation":name,"planned":plan,"owner":owner,"units":{k:str(v) for k,v in paths.items()},"commands":[["systemctl","--user",*x] for x in commands],"firstMissingSignal":"none"}
 if plan:return answer
 if install: atomic(paths["service"],SERVICE);atomic(paths["timer"],TIMER)
 first=userctl(commands[0],owner)
 if first["exit"] and not install and "not loaded" not in first["stderr"]: return {**answer,"ok":False,"results":[first],"firstMissingSignal":"hermes-maintenance-unit-uninstall-failed"}
 if not install:
  for p in paths.values():p.unlink(missing_ok=True)
 second=userctl(commands[1],owner); answer["results"]=[first,second];answer["ok"]=all(x["exit"]==0 for x in answer["results"])
 if not answer["ok"]:answer["firstMissingSignal"]=f"hermes-maintenance-unit-{name}-failed"
 return answer
def maintain(profile:str,mode:str,backup:str,hermes:str,receipt:Path,lock:Path,owner:str,plan:bool)->dict:
 if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*",profile): return {"schema":SCHEMA,"ok":False,"firstMissingSignal":"hermes-maintenance-profile-invalid"}
 if mode not in ("dedicated","multiplex-default","none"):return {"schema":SCHEMA,"ok":False,"firstMissingSignal":"hermes-maintenance-gateway-mode-invalid"}
 if backup not in ("default","force","skip"):return {"schema":SCHEMA,"ok":False,"firstMissingSignal":"hermes-maintenance-backup-mode-invalid"}
 cli=[hermes] if profile=="default" else [hermes,"-p",profile]; gateway="hermes-gateway.service" if profile=="default" or mode=="multiplex-default" else f"hermes-gateway-{profile}.service"; update=[*cli,"update","--yes"]+(["--backup"] if backup=="force" else ["--no-backup"] if backup=="skip" else [])
 commands=[[hermes,"--version"],[*cli,"update","--check"],update,[hermes,"--version"]]+([] if mode=="none" else [["systemctl","--user","restart",gateway],["systemctl","--user","is-active","--quiet",gateway],[*cli,"gateway","status"]])
 answer={"schema":SCHEMA,"ok":True,"operation":"maintain","planned":plan,"profile":profile,"gatewayMode":mode,"gatewayUnit":None if mode=="none" else gateway,"commands":commands,"receipt":str(receipt),"firstMissingSignal":"none"}
 if plan:return answer
 receipt.mkdir(parents=True,exist_ok=True);lock.parent.mkdir(parents=True,exist_ok=True)
 with lock.open("a+") as held:
  try:fcntl.flock(held.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return {**answer,"changed":False,"state":"skipped-locked"}
  before=run(commands[0]);check=run(commands[1]);text=(check["stdout"]+"\n"+check["stderr"]).lower();available="update available" in text and "no update available" not in text
  if not available and not any(word in text for word in ("up to date","up-to-date","already current","no update available")):return {**answer,"ok":False,"results":[before,check],"firstMissingSignal":"hermes-update-check-ambiguous"}
  outcomes=[before,check];
  if available:outcomes.extend([run(update),run(commands[3])])
  if mode!="none":outcomes.extend([run(x) for x in commands[-3:]])
 answer["results"]=outcomes;answer["changed"]=available;answer["ok"]=all(x["exit"]==0 for x in outcomes);answer["state"]=("updated" if available else "current")+("-no-gateway" if mode=="none" else "-gateway")
 (receipt/"latest.json").write_text(json.dumps(answer,sort_keys=True)+"\n",encoding="utf-8")
 if not answer["ok"]:answer["firstMissingSignal"]="hermes-maintenance-command-failed"
 return answer
def main(argv:Sequence[str]|None=None)->int:
 p=argparse.ArgumentParser(prog="caduceus-hermes-agent-maintenance");g=p.add_mutually_exclusive_group();g.add_argument("--install",action="store_true");g.add_argument("--uninstall",action="store_true");g.add_argument("--maintain",action="store_true");p.add_argument("--plan",action="store_true");p.add_argument("--owner",default=os.environ.get("CADUCEUS_HERMES_OWNER","owner"));p.add_argument("--unit-dir",type=Path,default=Path(os.environ.get("CADUCEUS_HERMES_UNIT_DIR",str(Path.home()/".config/systemd/user"))));p.add_argument("--profile",default=os.environ.get("HERMES_MAINTENANCE_PROFILE","default"));p.add_argument("--gateway-mode",default=os.environ.get("HERMES_MAINTENANCE_GATEWAY_MODE","dedicated"));p.add_argument("--backup-mode",default=os.environ.get("HERMES_MAINTENANCE_BACKUP_MODE","default"));p.add_argument("--hermes",default=os.environ.get("HERMES_MAINTENANCE_HERMES_BIN","hermes"));p.add_argument("--receipt",type=Path,default=Path(os.environ.get("HERMES_MAINTENANCE_RECEIPT_DIR",str(Path.home()/".local/state/harmonia/hermes-agent-maintenance"))));p.add_argument("--lock",type=Path,default=Path(os.environ.get("HERMES_MAINTENANCE_LOCK_PATH",str(Path("/tmp")/"hermes-agent-maintenance-default.lock"))));a=p.parse_args(argv);v=lifecycle(True,a.unit_dir,a.owner,a.plan) if a.install else lifecycle(False,a.unit_dir,a.owner,a.plan) if a.uninstall else maintain(a.profile,a.gateway_mode,a.backup_mode,a.hermes,a.receipt,a.lock,a.owner,a.plan);print(json.dumps(v,sort_keys=True));return 0 if v["ok"] else 1
if __name__=="__main__":raise SystemExit(main())

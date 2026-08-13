"""Caduceus disk-door actuator; secrets only ever cross child stdin."""
from __future__ import annotations
import json, os, posixpath, re, subprocess, sys
from typing import Any, Sequence
SCHEMA="caduceus.disk.door.v1"; MAX_INPUT_BYTES=64*1024
EXPORT_NAS="/vault/scripts/exportNAS.sh"; MOUNT_DRIVE="/vault/scripts/mountDrive.sh"; UNMOUNT_DRIVE="/vault/scripts/unmountDrive.sh"
CRYPTSETUP="/usr/sbin/cryptsetup"; FINDMNT="/usr/bin/findmnt"; BASH="/usr/bin/bash"; TEST="/usr/bin/test"
SETUP_NAS="/usr/local/sbin/setupNAS.sh"; DU="/usr/bin/du"; MKDIR="/usr/bin/mkdir"; CHOWN="/usr/bin/chown"; RSYNC="/usr/bin/rsync"
WIPEFS="/usr/sbin/wipefs"; SGDISK="/usr/sbin/sgdisk"; UDEVADM="/usr/sbin/udevadm"; MKFS_XFS="/usr/sbin/mkfs.xfs"
_COMPONENT=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"); _MAPPER=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}_crypt$"); _FORBIDDEN=re.compile(r"(?:ssh|lan\.key|authorized_keys)",re.I)
class Refusal(ValueError): pass
def _sudo(a:Sequence[str])->list[str]: return ["sudo","-n",*a]
def _run(a:list[str], secret: str|None=None)->subprocess.CompletedProcess[str]: return subprocess.run(a,input=secret,text=True,capture_output=True,check=False)
def _receipt(action:str,planned:bool,commands:list[list[str]],**extra:Any)->dict[str,Any]: return {"schema":SCHEMA,"ok":True,"action":action,"planned":planned,"mutationPerformed":not planned,"commands":commands,"firstMissingSignal":"none",**extra}
def _fail(signal:str)->dict[str,Any]: return {"schema":SCHEMA,"ok":False,"action":"unknown","planned":False,"mutationPerformed":False,"commands":[],"firstMissingSignal":signal}
def _device(v:Any)->str:
 if not isinstance(v,str) or not v.startswith("/dev/") or "\x00" in v or "/" in v[5:] or not _COMPONENT.fullmatch(v[5:]): raise Refusal("caduceus-disk-device-invalid")
 return v
def _is_partition_name(n:str)->bool: return bool(re.fullmatch(r"(?:[a-z]+\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)",n))
def _whole_disk(v:Any)->str:
 d=_device(v)
 if not re.fullmatch(r"(?:sd[a-z]+|nvme\d+n\d+)",d[5:]): raise Refusal("caduceus-disk-whole-disk-required")
 return d
def _partition(d:str)->str: return f"{d}p1" if re.fullmatch(r"(?:nvme\d+n\d+|mmcblk\d+)",d[5:]) else f"{d}1"
_NAS_PARTITION=re.compile(r"(?:sd[a-z]+\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)$")
def _nas_target(v:Any)->tuple[str,str,str]:
 d=_device(v); n=d[5:]
 if re.fullmatch(r"(?:sd[a-z]+|nvme\d+n\d+)",n): return d,d,"1"
 if not _NAS_PARTITION.fullmatch(n): raise Refusal("caduceus-disk-nas-device-invalid")
 if n.startswith("nvme") or n.startswith("mmcblk"): disk=re.sub(r"p\d+$","",d)
 else: disk=re.sub(r"\d+$","",d)
 part=n[len(disk)-5:] if disk.startswith("/dev/") else ""
 if part.startswith("p"): part=part[1:]
 if not part.isdigit(): raise Refusal("caduceus-disk-nas-device-invalid")
 return d,disk,part
def assign_nas(p:dict[str,Any],planned:bool,role:str,label:str)->dict[str,Any]:
 device,disk,partition=_nas_target(p.get("device")); cmd=_sudo([SGDISK,"-c",f"{partition}:{label}",disk]); trigger=_sudo([UDEVADM,"trigger","--subsystem-match=block","--action=change"]); cmds=[cmd,trigger]
 if planned:return _receipt(role,True,cmds,device=device,disk=disk,partition=partition,partlabel=label,roleBinding="PARTLABEL")
 if _run(cmd).returncode!=0 or _run(trigger).returncode!=0: raise Refusal("caduceus-disk-nas-role-refused")
 return _receipt(role,False,cmds,device=device,disk=disk,partition=partition,partlabel=label,roleBinding="PARTLABEL")
def _mapper(v:Any)->str:
 if not isinstance(v,str) or not _MAPPER.fullmatch(v): raise Refusal("caduceus-disk-mapper-invalid")
 return v
def _mountpoint(v:Any)->str:
 if not isinstance(v,str) or "\x00" in v or not v.startswith("/mnt/") or posixpath.normpath(v)!=v: raise Refusal("caduceus-disk-mountpoint-invalid")
 if any(not _COMPONENT.fullmatch(x) for x in v[5:].split("/")): raise Refusal("caduceus-disk-mountpoint-invalid")
 return v
def _forbid(v:Any)->None:
 if isinstance(v,dict):
  for k,x in v.items():
   if _FORBIDDEN.search(str(k)): raise Refusal("caduceus-disk-secret-path-forbidden")
   _forbid(x)
 elif isinstance(v,list):
  for x in v: _forbid(x)

def _find(m:str)->list[str]: return _sudo([FINDMNT,"-n","-o","SOURCE,TARGET","--target",m])
def _mapper_path(m:str)->str: return f"/dev/mapper/{m}"
def _mapper_cmd(m:str)->list[str]: return _sudo([TEST,"-e",_mapper_path(m)])
def _mapper_readback(m:str)->dict[str,Any]: return {"path":_mapper_path(m),"exists":os.path.exists(_mapper_path(m))}
def _mount_readback(r:subprocess.CompletedProcess[str],m:str)->dict[str,Any]:
 f=r.stdout.strip().split(None,1) if r.returncode==0 else []
 if len(f)==2:
  source,target=f; mounted=bool(source) and target==m
  return {"mountpoint":m,"mounted":mounted,"source":source if mounted else None,"target":target}
 return {"mountpoint":m,"mounted":False,"source":None,"target":None}
def _observed_mount(m:str)->dict[str,Any]: return _mount_readback(_run(_find(m)),m)
def unlock(p:dict[str,Any],planned:bool)->dict[str,Any]:
 d=_device(p.get("device")); mapper=_mapper(f"{posixpath.basename(d)}_crypt")
 export=_sudo([BASH,EXPORT_NAS]); op=_sudo([CRYPTSETUP,"open",d,mapper]); mr=_mapper_cmd(mapper); cmds=[export,op,mr]
 if planned:return _receipt("unlock",True,cmds,device=d,mapper=mapper,mapperReadback={"path":_mapper_path(mapper),"exists":None,"planned":True})
 r=_run(export); secret=r.stdout.strip() if r.returncode==0 else ""
 if not secret: raise Refusal("caduceus-disk-vault-export-failed")
 opened=_run(op,secret); readback=_mapper_readback(mapper)
 if opened.returncode!=0: raise Refusal("caduceus-disk-cryptsetup-open-refused")
 if not readback["exists"]: raise Refusal("caduceus-disk-mapper-readback-missing")
 return _receipt("unlock",False,cmds,device=d,mapper=mapper,mapperReadback=readback)

def _mount_device(v:Any)->tuple[str,str|None]:
 if isinstance(v,str) and v.startswith("/dev/mapper/"): return v,_mapper(v[12:])
 return _device(v),None
def mount(p:dict[str,Any],planned:bool)->dict[str,Any]:
 d,embedded=_mount_device(p.get("device")); m=_mountpoint(p.get("mountpoint")); mv=p.get("mapper"); mapper=_mapper(mv) if mv is not None else embedded
 cmd=_sudo([BASH,MOUNT_DRIVE,"mount",d,m]+([mapper] if mapper else [])); rb=_find(m); cmds=[cmd,rb]
 planned_rb={"mountpoint":m,"mounted":True,"source":d,"target":m,"planned":True}
 if planned:return _receipt("mount",True,cmds,device=d,mountpoint=m,mapper=mapper,mountReadback=planned_rb)
 if _run(cmd).returncode!=0: raise Refusal("caduceus-disk-mount-refused")
 readback=_mount_readback(_run(rb),m)
 if not readback["mounted"] or readback["target"]!=m: raise Refusal("caduceus-disk-mount-readback-missing")
 return _receipt("mount",False,cmds,device=d,mountpoint=m,mapper=mapper,mountReadback=readback)

def unmount(p:dict[str,Any],planned:bool)->dict[str,Any]:
 d=_device(p.get("device")); m=_mountpoint(p.get("mountpoint")); mv=p.get("mapper"); mapper=_mapper(mv) if mv is not None else None
 um=_sudo([BASH,UNMOUNT_DRIVE,d,m]+([mapper] if mapper else [])); rb=_find(m); cmds=[um,rb]
 if mapper: cmds += [_mapper_cmd(mapper),_sudo([CRYPTSETUP,"close",mapper]),_mapper_cmd(mapper)]
 planned_mount={"mountpoint":m,"mounted":False,"source":None,"target":None,"planned":True}
 planned_mapper={"path":_mapper_path(mapper),"exists":False,"planned":True} if mapper else None
 if planned:return _receipt("unmount",True,cmds,device=d,mountpoint=m,mapper=mapper,mountReadback=planned_mount,mapperReadback=planned_mapper)
 script=_run(um); mount_readback=_observed_mount(m)
 if mount_readback["mounted"]: raise Refusal("caduceus-disk-mount-remains")
 mapper_readback=None
 if mapper:
  mapper_readback=_mapper_readback(mapper)
  if mapper_readback["exists"]:
   if _run(_sudo([CRYPTSETUP,"close",mapper])).returncode!=0: raise Refusal("caduceus-disk-cryptsetup-close-refused")
   mapper_readback=_mapper_readback(mapper)
   if mapper_readback["exists"]: raise Refusal("caduceus-disk-mapper-remains")
 if script.returncode!=0 and (mount_readback["mounted"] or (mapper_readback and mapper_readback["exists"])): raise Refusal("caduceus-disk-unmount-refused")
 return _receipt("unmount",False,cmds,device=d,mountpoint=m,mapper=mapper,mountReadback=mount_readback,mapperReadback=mapper_readback)

def _format_commands(d:str)->list[list[str]]:
 return [_sudo([WIPEFS,"-a",d]),_sudo([SGDISK,"-o",d]),_sudo([SGDISK,"-n","1:0:0",d]),_sudo([SGDISK,"-t","1:8300",d]),_sudo([UDEVADM,"trigger","--subsystem-match=block","--action=change"]),_sudo([TEST,"-b",_partition(d)]),_sudo([MKFS_XFS,"-f",_partition(d)])]
def format_disk(p:dict[str,Any],planned:bool)->dict[str,Any]:
 d=_whole_disk(p.get("device")); cmds=_format_commands(d)
 if planned:return _receipt("format",True,cmds,device=d,target=_partition(d),partition=_partition(d))
 for cmd in cmds:
  if _run(cmd).returncode!=0: raise Refusal("caduceus-disk-format-refused")
 return _receipt("format",False,cmds,device=d,target=_partition(d),partition=_partition(d))
def _encrypt_target(v:Any)->tuple[str,list[list[str]],str]:
 d=_device(v); n=d[5:]
 if not _is_partition_name(n):
  target=_partition(d)
  return target,[_sudo([WIPEFS,"-a",d]),_sudo([SGDISK,"-o",d]),_sudo([SGDISK,"-n","1:0:0",d]),_sudo([SGDISK,"-t","1:8300",d]),_sudo([UDEVADM,"trigger","--subsystem-match=block","--action=change"]),_sudo([TEST,"-b",target])],d
 return d,[_sudo([WIPEFS,"-a",d])],d

def encrypt_disk(p:dict[str,Any],planned:bool)->dict[str,Any]:
 target,prep,requested=_encrypt_target(p.get("device")); mapper=_mapper(f"{posixpath.basename(target)}_crypt")
 export=_sudo([BASH,EXPORT_NAS]); key=["--key-file","-"]; luks=_sudo([CRYPTSETUP,"luksFormat","--type","luks2",*key,target,"-q","--batch-mode"]); op=_sudo([CRYPTSETUP,"open",*key,target,mapper]); mkfs=_sudo([MKFS_XFS,"-f",_mapper_path(mapper)])
 cmds=prep+[export,luks,op,mkfs,_mapper_cmd(mapper)]
 if planned:return _receipt("encrypt",True,cmds,device=requested,target=target,mapper=mapper,keyMaterial="redacted",keyInput="stdin",mapperReadback={"path":_mapper_path(mapper),"exists":None,"planned":True})
 for cmd in prep:
  if _run(cmd).returncode!=0: raise Refusal("caduceus-disk-encrypt-refused")
 secret_proc=_run(export); secret=secret_proc.stdout.strip() if secret_proc.returncode==0 else ""
 if not isinstance(secret,str) or not secret: raise Refusal("caduceus-disk-vault-export-failed")
 if _run(luks,secret).returncode!=0 or _run(op,secret).returncode!=0 or _run(mkfs).returncode!=0: raise Refusal("caduceus-disk-encrypt-refused")
 if not _mapper_readback(mapper)["exists"]: raise Refusal("caduceus-disk-mapper-readback-missing")
 return _receipt("encrypt",False,cmds,device=requested,target=target,mapper=mapper,keyMaterial="redacted",keyInput="stdin",mapperReadback=_mapper_readback(mapper))
def wipe_disk(p:dict[str,Any],planned:bool)->dict[str,Any]:
 d=_device(p.get("device")); cmds=[_sudo([WIPEFS,"-a",d])]
 if planned:return _receipt("wipe",True,cmds,device=d,target=d)
 if _run(cmds[0]).returncode!=0: raise Refusal("caduceus-disk-wipe-refused")
 return _receipt("wipe",False,cmds,device=d,target=d)

def setup_nas(p:dict[str,Any],planned:bool)->dict[str,Any]:
 d=_device(p.get("device")); apps=p.get("apps",[])
 if not isinstance(apps,list) or any(not isinstance(app,str) or not _COMPONENT.fullmatch(app) for app in apps): raise Refusal("caduceus-disk-nas-apps-invalid")
 cmd=_sudo([BASH,SETUP_NAS,*apps])
 if planned:return _receipt("setup-nas",True,[cmd],device=d,apps=apps)
 if _run(cmd).returncode!=0: raise Refusal("caduceus-disk-nas-setup-refused")
 return _receipt("setup-nas",False,[cmd],device=d,apps=apps)

def import_to_nas(p:dict[str,Any])->dict[str,Any]:
 source=_device(p.get("sourceDevice")); destination=_mountpoint(p.get("destination")); temp=_mountpoint(p.get("temporaryMountpoint","/mnt/caduceus-import"))
 owner=p.get("owner","caduceus"); group=p.get("group","caduceus")
 if not isinstance(owner,str) or not _COMPONENT.fullmatch(owner) or not isinstance(group,str) or not _COMPONENT.fullmatch(group): raise Refusal("caduceus-disk-nas-owner-invalid")
 mount=_sudo([BASH,MOUNT_DRIVE,"mount",source,temp]); estimate=_sudo([DU,"-sx","--bytes",temp]); mkdir=_sudo([MKDIR,"-p",destination]); chown=_sudo([CHOWN,"-R",f"{owner}:{group}",destination]); rsync=_sudo([RSYNC,"-a",f"{temp}/",f"{destination}/"]); unmount=_sudo([BASH,UNMOUNT_DRIVE,"unmount",source,temp]); cmds=[mount,estimate,mkdir,chown,rsync,unmount]
 return _receipt("import-to-nas",True,cmds,sourceDevice=source,temporaryMountpoint=temp,destination=destination,owner=owner,group=group,estimatedBytes=None,cleanupRequired=True)

def dispatch(x:dict[str,Any])->dict[str,Any]:
 if set(x)-{"actuator","metadata"} or not isinstance(x.get("metadata"),dict): raise Refusal("caduceus-disk-request-invalid")
 p=x["metadata"]; _forbid(p); a=p.get("action"); planned=p.get("dryRun",p.get("planned",False))
 if not isinstance(planned,bool): raise Refusal("caduceus-disk-planned-invalid")
 if a=="format": return format_disk(p,planned)
 if a=="encrypt": return encrypt_disk(p,planned)
 if a=="wipe": return wipe_disk(p,planned)
 if a=="unlock": return unlock(p,planned)
 if a=="mount": return mount(p,planned)
 if a=="unmount": return unmount(p,planned)
 if a=="assign-primary-nas": return assign_nas(p,planned,a,"homeserver-primary-nas")
 if a=="assign-nas-backup": return assign_nas(p,planned,a,"homeserver-backup-nas")
 if a=="unassign-nas": return assign_nas(p,planned,a,"data")
 if a=="setup-nas": return setup_nas(p,planned)
 if a=="import-to-nas": return import_to_nas(p)
 raise Refusal("caduceus-disk-action-invalid")
def main(argv:Sequence[str]|None=None)->int:
 del argv
 try:
  raw=sys.stdin.buffer.read(MAX_INPUT_BYTES+1)
  if len(raw)>MAX_INPUT_BYTES: raise Refusal("caduceus-disk-request-too-large")
  x=json.loads(raw.decode()); receipt=dispatch(x) if isinstance(x,dict) else _fail("caduceus-disk-request-invalid")
 except (UnicodeDecodeError,json.JSONDecodeError,Refusal) as e: receipt=_fail(str(e) if isinstance(e,Refusal) else "caduceus-disk-request-invalid")
 print(json.dumps(receipt,sort_keys=True)); return 0 if receipt["ok"] else 1
if __name__=="__main__": raise SystemExit(main())

"""Bounded console restart ladder: steam, stream, then seat."""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time
from pathlib import Path
from typing import Any, Sequence
OWNER="owner"; GAMESCOPE="gamescope"; STEAM="steam"
SUNSHINE_UNIT="app-dev.lizardbyte.app.Sunshine.service"; SEAT_UNIT="sddm.service"; STEAM_EXECUTABLE="/usr/bin/steam"
SCHEMA="agathodaimon.console.restart.v1"
DISPLAY_KEYS=("WAYLAND_DISPLAY","DISPLAY")
OPTIONAL_SESSION_KEYS=("DBUS_SESSION_BUS_ADDRESS","XDG_SESSION_ID","XDG_SESSION_TYPE")

def _result(argv, completed=None, *, error=None):
    if error is not None: return {"argv":argv,"ok":False,"exit_code":None,"stdout":"","stderr":error}
    return {"argv":argv,"ok":completed.returncode==0,"exit_code":completed.returncode,"stdout":completed.stdout[-1200:].strip(),"stderr":completed.stderr[-1200:].strip()}

def _command(argv):
    try: return _result(argv, subprocess.run(argv,text=True,capture_output=True,check=False,timeout=30))
    except (OSError,subprocess.SubprocessError) as exc: return _result(argv,error=f"{type(exc).__name__}: {exc}")

def _pids(name):
    try: c=subprocess.run(["pgrep","-u",OWNER,"-x",name],text=True,capture_output=True,check=False,timeout=10)
    except (OSError,subprocess.SubprocessError): return []
    return [int(x) for x in c.stdout.split() if x.isdigit()] if c.returncode==0 else []

def _session(pid):
    try: c=subprocess.run(["ps","-o","sid=","-p",str(pid)],text=True,capture_output=True,check=False,timeout=10)
    except (OSError,subprocess.SubprocessError): return None
    value=c.stdout.strip(); return value if c.returncode==0 and value.isdigit() else None

def _proc_environment(pid):
    try:
        env={}
        for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
            if b"=" in item:
                key,value=item.split(b"=",1); env[key.decode("utf-8")]=value.decode("utf-8")
        return env
    except (OSError,UnicodeDecodeError): return None

def _gamescope_session():
    for pid in _pids(GAMESCOPE):
        env=_proc_environment(pid)
        if env is not None: return pid,env
    return None

def _shared_graphical_coordinates(gamescope_env,steam_env):
    runtime=gamescope_env.get("XDG_RUNTIME_DIR")
    if not runtime or steam_env.get("XDG_RUNTIME_DIR")!=runtime: return None
    coordinates={"XDG_RUNTIME_DIR":runtime}
    displays=[key for key in DISPLAY_KEYS if gamescope_env.get(key) and steam_env.get(key)==gamescope_env[key]]
    if not displays: return None
    for key in displays: coordinates[key]=gamescope_env[key]
    for key in OPTIONAL_SESSION_KEYS:
        if gamescope_env.get(key) and gamescope_env.get(key)==steam_env.get(key): coordinates[key]=gamescope_env[key]
    return coordinates

def _steam_targets(gamescope_env):
    matches=[]
    for pid in _pids(STEAM):
        env=_proc_environment(pid)
        if env is not None:
            coordinates=_shared_graphical_coordinates(gamescope_env,env)
            if coordinates is not None: matches.append((pid,env,coordinates))
    return matches

def _coordinates_match(expected,env):
    return all(env.get(key)==value for key,value in expected.items())

def _stop_readback(old_pid,gamescope_pid,timeout=15):
    argv=["readback","steam-stop",str(old_pid),str(gamescope_pid)]
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if gamescope_pid not in _pids(GAMESCOPE):
            return {"argv":argv,"ok":False,"exit_code":None,"stdout":"","stderr":"gamescope PID disappeared during Steam stop readback"},"console-restart-steam-gamescope-disappeared-during-stop-readback"
        if old_pid not in _pids(STEAM):
            return {"argv":argv,"ok":True,"exit_code":0,"stdout":f"old_pid={old_pid} absent; gamescope_pid={gamescope_pid} alive","stderr":""},None
        time.sleep(.2)
    if gamescope_pid not in _pids(GAMESCOPE):
        signal="console-restart-steam-gamescope-disappeared-during-stop-readback"
    else:
        signal="console-restart-steam-old-pid-did-not-exit"
    return {"argv":argv,"ok":False,"exit_code":None,"stdout":"","stderr":signal},signal

def _replacement(old_pid,gamescope_pid,expected,timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if gamescope_pid not in _pids(GAMESCOPE): return None
        for pid in _pids(STEAM):
            if pid!=old_pid:
                env=_proc_environment(pid)
                if env is not None and _coordinates_match(expected,env):
                    return pid,env
        time.sleep(.2)
    return None

def _unit_state(unit,user):
    prefix=["systemctl"]+(["--user","-M",f"{OWNER}@.host"] if user else [])
    argv=[*prefix,"show",unit,"--property=LoadState","--value"]
    try: c=subprocess.run(argv,text=True,capture_output=True,check=False,timeout=30)
    except (OSError,subprocess.SubprocessError) as exc: return False,[_result(argv,error=f"{type(exc).__name__}: {exc}")]
    return c.returncode==0 and c.stdout.strip()=="loaded",[_result(argv,c)]

def _active_readback(unit,user):
    prefix=["systemctl"]+(["--user","-M",f"{OWNER}@.host"] if user else [])
    argv=[*prefix,"is-active",unit]
    try: return _result(argv,subprocess.run(argv,text=True,capture_output=True,check=False,timeout=30))
    except (OSError,subprocess.SubprocessError) as exc: return _result(argv,error=f"{type(exc).__name__}: {exc}")

def _refusal(degree,signal,*,command_results=None,**fields):
    return {"schema":SCHEMA,"ok":False,"degree":degree,"units_touched":[],"processes_touched":[],"command_results":command_results or [],"mutation_performed":False,"first_missing_signal":signal,**fields}

def restart(degree):
    if degree not in {"steam","stream","seat"}: return _refusal(degree,"console-restart-degree-required-one-of-steam-stream-seat")
    if degree=="steam":
        scope=_gamescope_session()
        if scope is None: return _refusal(degree,"console-restart-steam-gamescope-session-or-process-absent")
        gamescope_pid,gamescope_env=scope
        targets=_steam_targets(gamescope_env)
        if not targets: return _refusal(degree,"console-restart-steam-graphical-session-coordinate-mismatch-or-process-absent",gamescope_pid=gamescope_pid)
        if len(targets)>1: return _refusal(degree,"console-restart-steam-ambiguous-graphical-session-matches",gamescope_pid=gamescope_pid,matching_pids=[target[0] for target in targets])
        old_pid,steam_env,coordinates=targets[0]
        if not Path(STEAM_EXECUTABLE).is_file(): return _refusal(degree,"console-restart-steam-executable-absent",target_pid=old_pid,gamescope_pid=gamescope_pid,graphical_session_coordinates=coordinates)
        stop=_command(["kill","-TERM",str(old_pid)])
        stop_readback,stop_signal=_stop_readback(old_pid,gamescope_pid)
        if not stop["ok"]:
            return {"schema":SCHEMA,"ok":False,"degree":degree,"units_touched":[],"processes_touched":["Steam"],"command_results":[stop,stop_readback],"mutation_performed":True,"first_missing_signal":"console-restart-steam-stop-failed","target_pid":old_pid,"gamescope_pid":gamescope_pid,"graphical_session_coordinates":coordinates}
        if stop_signal:
            return {"schema":SCHEMA,"ok":False,"degree":degree,"units_touched":[],"processes_touched":["Steam"],"command_results":[stop,stop_readback],"mutation_performed":True,"first_missing_signal":stop_signal,"target_pid":old_pid,"gamescope_pid":gamescope_pid,"graphical_session_coordinates":coordinates}
        launch_argv=["runuser","--preserve-environment","-u",OWNER,"--",STEAM_EXECUTABLE]
        try:
            proc=subprocess.Popen(launch_argv,env={**os.environ,**gamescope_env},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            launch={"argv":launch_argv,"ok":True,"exit_code":None,"pid":proc.pid,"stdout":"","stderr":""}
        except OSError as exc: launch=_result(launch_argv,error=f"{type(exc).__name__}: {exc}")
        replacement=_replacement(old_pid,gamescope_pid,coordinates) if launch["ok"] else None
        readback={"argv":["readback","steam"],"ok":replacement is not None,"exit_code":0 if replacement else None,"stdout":str(replacement[0]) if replacement else "","stderr":"" if replacement else "replacement Steam PID/session environment not verified"}
        ok=bool(launch["ok"] and replacement)
        return {"schema":SCHEMA,"ok":ok,"degree":degree,"units_touched":[],"processes_touched":["Steam"],"command_results":[stop,stop_readback,launch,readback],"mutation_performed":True,"first_missing_signal":"none" if ok else ("console-restart-steam-replacement-readback-failed" if launch["ok"] else "console-restart-steam-launch-failed"),"target_pid":old_pid,"replacement_pid":replacement[0] if replacement else None,"gamescope_pid":gamescope_pid,"graphical_session_coordinates":coordinates}

    unit=SUNSHINE_UNIT if degree=="stream" else SEAT_UNIT; user=degree=="stream"; present,checks=_unit_state(unit,user)
    base={"schema":SCHEMA,"ok":False,"degree":degree,"units_touched":[],"processes_touched":[],"command_results":checks,"mutation_performed":False,"first_missing_signal":f"console-restart-{degree}-unit-absent","target_unit":unit}
    if not present: return base
    prefix=["systemctl"]+(["--user","-M",f"{OWNER}@.host"] if user else []); outcome=_command([*prefix,"restart",unit]); results=[*checks,outcome]
    attempted={**base,"units_touched":[unit],"command_results":results,"mutation_performed":True}
    if not outcome["ok"]: return {**attempted,"first_missing_signal":f"console-restart-{degree}-command-failed"}
    readback=_active_readback(unit,user); results.append(readback); active=readback["ok"] and readback["stdout"]=="active"
    return {**attempted,"ok":active,"command_results":results,"first_missing_signal":"none" if active else f"console-restart-{degree}-active-readback-failed"}

def main(argv:Sequence[str]|None=None):
    parser=argparse.ArgumentParser(prog="agathodaimon-console-restart"); parser.add_argument("degree",nargs="*"); args=parser.parse_args(argv); degree=args.degree[0] if len(args.degree)==1 else None
    if len(args.degree)>1: degree="<multiple-degrees>"
    if not args.degree and not sys.stdin.isatty():
        try:
            raw=sys.stdin.read().strip(); envelope=json.loads(raw) if raw else {}
            if isinstance(envelope,dict):
                degree=envelope.get("degree")
                if not isinstance(degree,str): degree="<multiple-degrees>" if degree is not None else None
        except json.JSONDecodeError: degree=None
    receipt=restart(degree); print(json.dumps(receipt,sort_keys=True)); return 0 if receipt["ok"] else 1

if __name__=="__main__": raise SystemExit(main())

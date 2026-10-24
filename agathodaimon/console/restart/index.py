"""Bounded console restart degrees for Sunshine and SDDM."""
from __future__ import annotations
import argparse, json, subprocess, sys
from typing import Sequence

OWNER="owner"
SUNSHINE_UNIT="app-dev.lizardbyte.app.Sunshine.service"; SEAT_UNIT="sddm.service"
SCHEMA="agathodaimon.console.restart.v1"


def _result(argv, completed=None, *, error=None):
    if error is not None: return {"argv":argv,"ok":False,"exit_code":None,"stdout":"","stderr":error}
    return {"argv":argv,"ok":completed.returncode==0,"exit_code":completed.returncode,"stdout":completed.stdout[-1200:].strip(),"stderr":completed.stderr[-1200:].strip()}


def _command(argv):
    try: return _result(argv, subprocess.run(argv,text=True,capture_output=True,check=False,timeout=30))
    except (OSError,subprocess.SubprocessError) as exc: return _result(argv,error=f"{type(exc).__name__}: {exc}")


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
    if degree not in {"stream","seat"}: return _refusal(degree,"console-restart-degree-required-one-of-stream-seat")
    unit=SUNSHINE_UNIT if degree=="stream" else SEAT_UNIT; user=degree=="stream"; present,checks=_unit_state(unit,user)
    base={"schema":SCHEMA,"ok":False,"degree":degree,"units_touched":[],"processes_touched":[],"command_results":checks,"mutation_performed":False,"first_missing_signal":f"console-restart-{degree}-unit-absent","target_unit":unit}
    if not present: return base
    prefix=["systemctl"]+(["--user","-M",f"{OWNER}@.host"] if user else []); outcome=_command([*prefix,"restart",unit]); results=[*checks,outcome]
    attempted={**base,"units_touched":[unit],"command_results":results,"mutation_performed":True}
    if not outcome["ok"]: return {**attempted,"first_missing_signal":f"console-restart-{degree}-command-failed"}
    readback=_active_readback(unit,user); results.append(readback); active=readback["ok"] and readback["stdout"]=="active"
    return {**attempted,"ok":active,"command_results":results,"first_missing_signal":"none" if active else f"console-restart-{degree}-active-readback-failed"}


def main(argv:Sequence[str]|None=None):
    parser=argparse.ArgumentParser(prog="agathodaimon-console-restart"); parser.add_argument("degree",nargs="*",metavar="{stream|seat}"); args=parser.parse_args(argv); degree=args.degree[0] if len(args.degree)==1 else None
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

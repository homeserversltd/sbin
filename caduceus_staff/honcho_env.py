"""Converge Honcho's non-secret environment while preserving its API key."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Sequence

VALUES = {
    "DATABASE_URL": "postgresql://127.0.0.1:55432/honcho", "REDIS_URL": "redis://127.0.0.1:56379/0",
    "EMBED_MESSAGES": "true", "EMBEDDING_VECTOR_DIMENSIONS": "1024",
    "EMBEDDING_MODEL_CONFIG__TRANSPORT": "openai", "EMBEDDING_MODEL_CONFIG__MODEL": "honcho-dedicated-embedder",
    "EMBEDDING_MODEL_CONFIG__OVERRIDES__BASE_URL": "http://127.0.0.1:8081/v1", "EMBEDDING_MODEL_CONFIG__OVERRIDES__API_KEY_ENV": "HONCHO_LOCAL_OPENAI_API_KEY",
    "DERIVER_MODEL_CONFIG__TRANSPORT": "openai", "DERIVER_MODEL_CONFIG__MODEL": "honcho-qwen-worker",
    "DERIVER_MODEL_CONFIG__OVERRIDES__BASE_URL": "http://127.0.0.1:8085/v1", "DERIVER_MODEL_CONFIG__OVERRIDES__API_KEY_ENV": "HONCHO_LOCAL_OPENAI_API_KEY",
    "SUMMARY_MODEL_CONFIG__TRANSPORT": "openai", "SUMMARY_MODEL_CONFIG__MODEL": "honcho-qwen-worker",
    "SUMMARY_MODEL_CONFIG__OVERRIDES__BASE_URL": "http://127.0.0.1:8085/v1", "SUMMARY_MODEL_CONFIG__OVERRIDES__API_KEY_ENV": "HONCHO_LOCAL_OPENAI_API_KEY",
    "UNIO_HONCHO_STATE__ENABLED": "false",
}


def converge(path: Path, plan: bool) -> dict:
    if not path.is_file():
        return {"schema":"caduceus.honcho.env.v1","ok":False,"changed":False,"firstMissingSignal":"honcho-env-secret-bearing-file-missing"}
    raw = path.read_text(encoding="utf-8")
    if not any(line.startswith("HONCHO_LOCAL_OPENAI_API_KEY=") and line.split("=",1)[1] for line in raw.splitlines()):
        return {"schema":"caduceus.honcho.env.v1","ok":False,"changed":False,"firstMissingSignal":"honcho-env-required-key-missing: HONCHO_LOCAL_OPENAI_API_KEY"}
    seen=set(); rendered=[]
    for line in raw.splitlines():
        key=line.split("=",1)[0] if "=" in line else ""
        if key in VALUES:
            rendered.append(f"{key}={VALUES[key]}"); seen.add(key)
        else: rendered.append(line)
    rendered.extend(f"{key}={value}" for key,value in VALUES.items() if key not in seen)
    updated="\n".join(rendered)+"\n"; changed=updated != raw
    receipt={"schema":"caduceus.honcho.env.v1","ok":True,"changed":changed,"path":str(path),"preservedSecret":True,"firstMissingSignal":"none","planned":plan}
    if plan or not changed: return receipt
    fd,tmp=tempfile.mkstemp(prefix=f".{path.name}.caduceus.",dir=path.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as out: out.write(updated); out.flush(); os.fsync(out.fileno())
        os.chmod(tmp,0o600)
        if os.geteuid()==0:
            owner=os.environ.get("CADUCEUS_HONCHO_OWNER","owner"); import pwd; identity=pwd.getpwnam(owner); os.chown(tmp,identity.pw_uid,identity.pw_gid)
        os.replace(tmp,path)
    finally: Path(tmp).unlink(missing_ok=True)
    return receipt


def main(argv: Sequence[str] | None=None)->int:
    parser=argparse.ArgumentParser(prog="caduceus-honcho-env")
    parser.add_argument("path",type=Path); parser.add_argument("--plan",action="store_true")
    args=parser.parse_args(argv); value=converge(args.path,args.plan); print(json.dumps(value,sort_keys=True)); return 0 if value["ok"] else 1
if __name__=="__main__": raise SystemExit(main())

"""Translator-toolchain convergence with explicit laptop variant."""
from __future__ import annotations
import argparse, json, os, shutil, subprocess
from typing import Sequence

def command(argv:list[str])->dict:
    p=subprocess.run(argv,text=True,capture_output=True,check=False); return {'argv':argv,'exit':p.returncode,'stdout':p.stdout.strip(),'stderr':p.stderr.strip()}
def converge(variant:str,plan:bool)->dict:
    prefix=['runuser','-u',os.environ.get('CADUCEUS_TRANSLATOR_OWNER','owner'),'--']; cli=os.environ.get('CADUCEUS_FULCRUM_CLI','/fulcrum/cli.py')
    steps=[]
    if variant=='laptop-01' and shutil.which('grok') is None: steps.append(['npm','install','-g','@xai-official/grok'])
    steps.append(prefix+[cli,'scry','status'])
    if plan: return {'schema':'caduceus.translator.toolchain.v1','ok':True,'changed':bool(variant=='laptop-01' and shutil.which('grok') is None),'planned':True,'variant':variant,'steps':steps,'firstMissingSignal':'none'}
    results=[command(step) for step in steps]
    ok=all(item['exit']==0 for item in results)
    return {'schema':'caduceus.translator.toolchain.v1','ok':ok,'changed':bool(variant=='laptop-01'),'planned':False,'variant':variant,'results':results,'firstMissingSignal':'none' if ok else 'caduceus-translator-toolchain-command-failed'}
def main(argv:Sequence[str]|None=None)->int:
    p=argparse.ArgumentParser(prog='caduceus-translator-toolchain'); p.add_argument('variant',choices=['laptop-01','laptop-02']); p.add_argument('--plan',action='store_true'); a=p.parse_args(argv); value=converge(a.variant,a.plan); print(json.dumps(value,sort_keys=True)); return 0 if value['ok'] else 1
if __name__=='__main__': raise SystemExit(main())

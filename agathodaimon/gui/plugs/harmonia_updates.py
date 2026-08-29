"""Harmonia Updates plug using Caduceus HTTP doors."""
from __future__ import annotations
import json, os, threading, urllib.parse
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
try:
    from ._common import _receipt_ok, _request, _signal
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec=_importlib_util.spec_from_file_location("_common",__file__.replace(__file__.split("/")[-1],"_common.py")); _mod=_importlib_util.module_from_spec(_spec); _sys.modules["_common"]=_mod; _spec.loader.exec_module(_mod)
    from _common import _receipt_ok, _request, _signal
PLUG={"id":"harmonia-updates","title":"Updates","icon":"software-update-available-symbolic","order":10,"parent":None}
STATUS_DOOR="/api/v1/update/status"; TIMER_DOOR="/api/v1/update/service/status"; UPDATE_DOOR="/api/v1/update/now"; MODULES_DOOR="/api/v1/update/modules"; INTERACTABLES_DOOR="/api/v1/interactables"
STATE_PATH=Path(os.environ.get("XDG_STATE_HOME",str(Path.home()/".local/state")))/"harmonia-update-modal/state.json"; STATE_SCHEMA="harmonia.update-modal.state.v2"
def _text(v:Any,fallback=""): return v.strip() if isinstance(v,str) else fallback
class State:
    def __init__(self):
        self.data={"schema":STATE_SCHEMA,"module_overrides":{},"hidden_interactables":{}}
        try:
            v=json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if isinstance(v,dict) and v.get("schema") in {"harmonia.update-modal.state.v1",STATE_SCHEMA}: self.data.update(v); self.data["schema"]=STATE_SCHEMA
        except (OSError,json.JSONDecodeError,TypeError,ValueError): pass
    def hidden(self):
        v=self.data.get("hidden_interactables",{})
        if isinstance(v,dict): return {k for k in v if isinstance(k,str)}
        return {x for x in v if isinstance(x,str)} if isinstance(v,list) else set()
    def hidden_items(self):
        v=self.data.get("hidden_interactables",{})
        return [dict(x, id=k) if not _text(x.get("id")) else x for k,x in v.items() if isinstance(k,str) and isinstance(x,dict)] if isinstance(v,dict) else [{"id":x,"name":x} for x in sorted(self.hidden())]
    def _save(self):
        temp=None
        try:
            STATE_PATH.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
            with NamedTemporaryFile(dir=STATE_PATH.parent,prefix=".state.",delete=False,mode="w",encoding="utf-8") as f:
                temp=Path(f.name); f.write(json.dumps(self.data,sort_keys=True)+"\n"); f.flush(); os.fsync(f.fileno())
            os.chmod(temp,0o600); os.replace(temp,STATE_PATH); return True
        except OSError:
            if temp: temp.unlink(missing_ok=True)
            return False
    def hide(self,item):
        ident=_text(item.get("id"))
        if not ident:return False
        v=self.data.get("hidden_interactables",{}); v={x:{"id":x,"name":x} for x in self.hidden()} if isinstance(v,list) else v if isinstance(v,dict) else {}; v[ident]=dict(item); self.data["hidden_interactables"]=v; return self._save()
    def unhide(self,ident):
        v=self.data.get("hidden_interactables",{})
        if isinstance(v,dict): v.pop(ident,None)
        elif isinstance(v,list): self.data["hidden_interactables"]=[x for x in v if x!=ident]
        return self._save()
def build_widget()->Any:
    import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")
    from gi.repository import Adw,GLib,Gtk
    page=Adw.PreferencesPage(title="Updates",icon_name=PLUG["icon"]); state=State(); data={"busy":False,"modules":[],"interactables":[]}
    sg=Adw.PreferencesGroup(title="Update status"); sr=Adw.ActionRow(title="Appliance software",subtitle="Reading Caduceus…"); icon=Gtk.Image.new_from_icon_name("content-loading-symbolic"); sr.add_prefix(icon); sg.add(sr); page.add(sg)
    tg=Adw.PreferencesGroup(title="Automatic updates"); tr=Adw.ActionRow(title="Update timer",subtitle="Reading Caduceus…"); tg.add(tr); page.add(tg)
    mg=Adw.PreferencesGroup(title="Update modules"); mbox=Gtk.Box(orientation=Gtk.Orientation.VERTICAL); mg.add(mbox); page.add(mg)
    pg=Adw.PreferencesGroup(title="Pending updates"); pbox=Gtk.Box(orientation=Gtk.Orientation.VERTICAL); pg.add(pbox); page.add(pg)
    hg=Adw.PreferencesGroup(title="Hidden updates"); hbox=Gtk.Box(orientation=Gtk.Orientation.VERTICAL); hg.add(hbox); page.add(hg)
    ag=Adw.PreferencesGroup(title="Update now"); ar=Adw.ActionRow(title="Apply available updates",subtitle="Caduceus performs the update and returns its receipt."); button=Gtk.Button(label="Update Now (0)",valign=Gtk.Align.CENTER); button.add_css_class("suggested-action"); ar.add_suffix(button); ag.add(ar); page.add(ag)
    pending=lambda:[x for x in data["interactables"] if _text(x.get("id")) not in state.hidden()]
    def set_label(s=""): button.set_label(f"Update Now ({len(pending())})"+(f" · {s}" if s else ""))
    def clear(box):
        c=box.get_first_child()
        while c: n=c.get_next_sibling(); box.remove(c); c=n
    def empty(box,msg): r=Adw.ActionRow(title="Caduceus unavailable",subtitle=msg); r.set_sensitive(False); box.append(r)
    def render_modules():
        clear(mbox)
        if not data["modules"]: empty(mbox,"No update modules reported"); return
        for item in data["modules"]:
            ident=_text(item.get("id"));
            if not ident: continue
            row=Adw.ActionRow(title=ident,subtitle="Enabled" if item.get("enabled") is True else "Disabled"); sw=Gtk.Switch(active=item.get("enabled") is True,valign=Gtk.Align.CENTER); row.add_suffix(sw); sw.connect("state-set",toggle,ident,row); mbox.append(row)
    def render_interactables():
        clear(pbox); clear(hbox); live={_text(x.get("id")):x for x in data["interactables"]}
        if not pending(): empty(pbox,"No pending interactables")
        for item in pending():
            ident=_text(item.get("id")); row=Adw.ActionRow(title=_text(item.get("name"),ident),subtitle=f"{ident} — {_text(item.get('description'),'No description provided')}"); a=Gtk.Button(label="Agree",valign=Gtk.Align.CENTER); a.add_css_class("suggested-action"); h=Gtk.Button(label="Hide",valign=Gtk.Align.CENTER); a.connect("clicked",agree,ident); h.connect("clicked",hide,item); row.add_suffix(a); row.add_suffix(h); pbox.append(row)
        if not state.hidden_items(): empty(hbox,"No hidden interactables")
        for stored in state.hidden_items():
            ident=_text(stored.get("id")); item=live.get(ident,stored); row=Adw.ActionRow(title=_text(item.get("name"),ident),subtitle=f"{ident} — {_text(item.get('description'),'No description provided')}"); u=Gtk.Button(label="Un-hide",valign=Gtk.Align.CENTER); u.connect("clicked",unhide,ident); row.add_suffix(u); hbox.append(row)
        set_label()
    def status(r,e):
        if e: sr.set_subtitle(e); icon.set_from_icon_name("dialog-warning-symbolic"); button.set_sensitive(False); return False
        ok=_receipt_ok(r or {}); sr.set_subtitle("Ready" if ok else _signal(r or {}) or "Update service unavailable"); icon.set_from_icon_name("emblem-ok-symbolic" if ok else "dialog-warning-symbolic"); button.set_sensitive(ok and not data["busy"]); return False
    def timer(r,e):
        if e: tr.set_subtitle(e)
        else: tr.set_title(str((r or {}).get("timer","Update timer"))); tr.set_subtitle(str((r or {}).get("timerState","unknown")))
        return False
    def modules(r,e):
        if e: clear(mbox); empty(mbox,e); return False
        if not isinstance(r,dict) or r.get("ok") is not True:
            clear(mbox); empty(mbox,_signal(r or {}) or "Module read refused"); return False
        v=(r or {}).get("modules"); data["modules"]=[x for x in v if isinstance(x,dict)] if isinstance(v,list) else []; render_modules(); return False
    def interactables(r,e):
        if e: clear(pbox); empty(pbox,e); set_label(); return False
        if not isinstance(r,dict) or r.get("ok") is not True:
            clear(pbox); empty(pbox,_signal(r or {}) or "Interactable read refused"); set_label(); return False
        v=(r or {}).get("interactables"); data["interactables"]=[x for x in v if isinstance(x,dict) and _text(x.get("id"))] if isinstance(v,list) else []; render_interactables(); return False
    def read(path,done):
        try: GLib.idle_add(done,_request(path),None)
        except RuntimeError as e: GLib.idle_add(done,None,str(e))
    def refresh():
        for path,done in ((STATUS_DOOR,status),(TIMER_DOOR,timer),(MODULES_DOOR,modules),(INTERACTABLES_DOOR,interactables)): threading.Thread(target=read,args=(path,done),daemon=True).start()
    def periodic_refresh():
        refresh(); return True
    def mutate(path,payload,done):
        try: GLib.idle_add(done,_request(path,"POST",payload),None)
        except RuntimeError as e: GLib.idle_add(done,None,str(e))
    def toggle(sw,enabled,ident,row):
        old=not enabled; sw.set_sensitive(False)
        def done(r,e):
            if e or not _receipt_ok(r or {}): sw.set_active(old); row.set_subtitle(e or _signal(r or {}) or "Module change refused")
            else: row.set_subtitle("Enabled" if enabled else "Disabled")
            sw.set_sensitive(True); refresh(); return False
        threading.Thread(target=mutate,args=(f"{MODULES_DOOR}/{urllib.parse.quote(ident,safe='')}",{"enabled":enabled},done),daemon=True).start(); return False
    def agree(b,ident):
        b.set_sensitive(False); set_label("agreeing")
        def done(r,e): ar.set_subtitle("Agreed" if not e and _receipt_ok(r or {}) else e or _signal(r or {}) or "Agree refused"); refresh(); return False
        threading.Thread(target=mutate,args=(f"{INTERACTABLES_DOOR}/{urllib.parse.quote(ident,safe='')}/run",None,done),daemon=True).start()
    def hide(b,item): b.set_sensitive(False); set_label("hidden" if state.hide(item) else "hide refused"); render_interactables()
    def unhide(b,ident): b.set_sensitive(False); set_label("restored" if state.unhide(ident) else "un-hide refused"); render_interactables()
    def finish_update(r,e): data["busy"]=False; button.set_sensitive(True); ar.set_subtitle("Update complete" if not e and _receipt_ok(r or {}) else e or _signal(r or {}) or "Update refused"); set_label(); refresh(); return False
    def update(_b):
        if data["busy"]: return
        data["busy"]=True; button.set_sensitive(False); set_label("updating"); threading.Thread(target=mutate,args=(UPDATE_DOOR,None,finish_update),daemon=True).start()
    button.connect("clicked",update); refresh(); GLib.timeout_add_seconds(30,periodic_refresh); return page

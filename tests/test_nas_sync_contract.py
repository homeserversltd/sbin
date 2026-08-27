import contextlib, importlib.util, io, json, os, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; MODULE=ROOT/"agathodaimon/storage/backup/nas-sync/index.py"
SPEC=importlib.util.spec_from_file_location("nas_sync_contract",MODULE); nas=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(nas)
class Runner:
 def __init__(self,journal="kernel clean",rsync_code=0): self.calls=[]; self.journal=journal; self.rsync_code=rsync_code
 def __call__(self,a):
  self.calls.append(a)
  if a[0]==nas.FINDMNT: return subprocess.CompletedProcess(a,0,"/dev/source1 /mnt/nas\n" if a[-1]=="/mnt/nas" else "/dev/backup1 /mnt/nas_backup\n","")
  if a[0]==nas.LSBLK:
   out=('NAME="source1" KNAME="source1" PKNAME="source" PATH="/dev/source1" MAJ:MIN="8:1"\nNAME="source" KNAME="source" PKNAME="" PATH="/dev/source" MAJ:MIN="8:0"\n') if a[-1].endswith("source1") else ('NAME="backup1" KNAME="backup1" PKNAME="backup" PATH="/dev/backup1" MAJ:MIN="9:1"\nNAME="backup" KNAME="backup" PKNAME="" PATH="/dev/backup" MAJ:MIN="9:0"\n')
   return subprocess.CompletedProcess(a,0,out,"")
  if a[0]==nas.BLKID: return subprocess.CompletedProcess(a,0,"backup-data\n","")
  if a[0]==nas.JOURNALCTL: return subprocess.CompletedProcess(a,0,self.journal,"")
  if a[0]==nas.RSYNC: return subprocess.CompletedProcess(a,self.rsync_code,"Number of regular files transferred: 4\nTotal transferred file size: 1,024 bytes\n","")
  raise AssertionError(a)
class NasSyncContractTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name); self.old_measure=nas.measure; os.environ.update(CADUCEUS_NAS_STATE_ROOT=str(self.root),CADUCEUS_NAS_RECEIPT_ROOT=str(self.root/"receipts"),CADUCEUS_NAS_LOCK=str(self.root/"lock")); nas.measure=lambda _:(100,1000)
 def tearDown(self):
  nas.measure=self.old_measure
  for k in ("CADUCEUS_NAS_STATE_ROOT","CADUCEUS_NAS_RECEIPT_ROOT","CADUCEUS_NAS_LOCK"): os.environ.pop(k,None)
  self.t.cleanup()
 def state(self,files=100,bytes_=1000): nas.atomic_json(nas.state_file(),{"fileCount":files,"totalBytes":bytes_})
 def test_kernel_error_naming_backing_drive_refuses(self):
  v=nas.sync(runner=Runner("XFS metadata error on backup")); self.assertEqual((v["outcome"],v["reason"]),("refused","current-boot-kernel-error-names-backing-drive")); self.assertTrue(v["receiptPersisted"])
 def test_fifty_percent_shrink_refuses(self):
  self.state(); nas.measure=lambda _:(100,500); v=nas.sync(runner=Runner()); self.assertEqual(v["outcome"],"refused"); self.assertIn("byte-count-shrank-more-than-10-percent",v["reason"])
 def test_mount_and_system_partition_gates_refuse(self):
  class NotMounted(Runner):
   def __call__(self,a):
    v=super().__call__(a)
    if a[0]==nas.FINDMNT and a[-1]=="/mnt/nas": v.stdout="/dev/source1 /\n"
    return v
  self.assertEqual(nas.sync(runner=NotMounted())["reason"],"not-a-real-mountpoint:/mnt/nas")
  class RootTarget(Runner):
   def __call__(self,a):
    v=super().__call__(a)
    if a[0]==nas.FINDMNT and a[-1]=="/mnt/nas_backup": v.stdout="/dev/backup1 /\n"
    return v
  self.assertEqual(nas.sync(runner=RootTarget())["reason"],"backup-target-is-root")
  class SystemPartition(Runner):
   def __call__(self,a):
    v=super().__call__(a)
    if a[0]==nas.BLKID: v.stdout="homeserver-root\n"
    return v
  self.assertEqual(nas.sync(runner=SystemPartition())["reason"],"backup-partlabel-denied:homeserver-root")
 def test_file_count_shrink_over_twenty_percent_refuses(self):
  self.state(files=100,bytes_=1000); nas.measure=lambda _:(79,1000); v=nas.sync(runner=Runner()); self.assertEqual(v["outcome"],"refused"); self.assertIn("file-count-shrank-more-than-20-percent",v["reason"])
 def test_same_device_refuses(self):
  class Same(Runner):
   def __call__(self,a):
    v=super().__call__(a)
    if a[0]==nas.LSBLK: v.stdout='NAME="same1" KNAME="same1" PKNAME="same" PATH="/dev/same1" MAJ:MIN="8:1"\nNAME="same" KNAME="same" PKNAME="" PATH="/dev/same" MAJ:MIN="8:0"\n'
    return v
  v=nas.sync(runner=Same()); self.assertEqual((v["outcome"],v["reason"]),("refused","source-and-destination-share-backing-device"))
 def test_cold_start_cap_stats_and_state(self):
  r=Runner(); v=nas.sync(runner=r); self.assertEqual(v["outcome"],"ok"); self.assertTrue(v["coldStart"]); self.assertIn("COLD START",v["notice"]); self.assertEqual((v["maxDelete"],v["maxDeleteBasis"]),(1000,"cold-start-current-file-count")); self.assertEqual(json.loads(nas.state_file().read_text()),{"fileCount":100,"totalBytes":1000}); call=next(x for x in r.calls if x[0]==nas.RSYNC); self.assertEqual(call[1:6],["-aH","--stats","--delete-delay","--exclude=lost+found","--max-delete=1000"]); self.assertEqual(v["rsyncStats"]["Number of regular files transferred"],"4")
 def test_exit_25_is_failed_critical_and_names_cap(self):
  v=nas.sync(runner=Runner(rsync_code=25)); self.assertEqual((v["outcome"],v["exitCode"]),("failed",25)); self.assertIn("CRITICAL",v["reason"]); self.assertIn("1000",v["reason"])
 def test_success_remeasures_before_state_write(self):
  seq=iter(((100,1000),(101,1010))); nas.measure=lambda _:next(seq); v=nas.sync(runner=Runner()); self.assertEqual(v["outcome"],"ok"); self.assertEqual(json.loads(nas.state_file().read_text()),{"fileCount":101,"totalBytes":1010})
 def test_lock_contention_refuses_and_receipts(self):
  old=nas.acquire_lock; nas.acquire_lock=lambda:(_ for _ in ()).throw(nas.Refusal("single-instance-lock-contended"))
  try: v=nas.sync(runner=Runner())
  finally: nas.acquire_lock=old
  self.assertEqual(v["outcome"],"refused"); self.assertTrue(v["receiptPersisted"])
 def test_accept_shrink_human_only_and_loud(self):
  with self.assertRaises(nas.Refusal): nas.dispatch({"actuator":"nas-sync","metadata":{"action":"sync-now","acceptShrink":True}})
  self.state(); nas.measure=lambda _:(50,500); err=io.StringIO()
  with contextlib.redirect_stderr(err): v=nas.sync(accept_shrink=True,runner=Runner())
  self.assertEqual(v["outcome"],"ok"); self.assertEqual(v["humanOverride"],"--accept-shrink"); self.assertIn("CRITICAL HUMAN OVERRIDE",err.getvalue())
 def test_unreadable_state_refuses(self):
  nas.state_file().write_text("bad"); v=nas.sync(runner=Runner()); self.assertEqual((v["outcome"],v["reason"]),("refused","last-good-state-unreadable-or-malformed"))
 def test_launcher_and_import(self):
  p=ROOT/"caduceus-nas-sync"; self.assertIn('agathodaimon/cli.py" backup nas-sync',p.read_text()); service,_=nas.units(nas.schedule({"enabled":True})); self.assertIn("ExecStart=/usr/local/sbin/caduceus-nas-sync --run",service)
if __name__=="__main__": unittest.main()

"""Privileged Hestia Anchor household certificate primitives.

The nine public primitives are deliberately independently callable.  This module
is the sole Python writer of its disposable-root certificate, proxy and state
surfaces; ``state_commit`` is the sole durable-state writer.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("_house_ca", Path(__file__).with_name("_ca.py"))
if _spec is None or _spec.loader is None:
    raise ImportError("cannot load house-ca primitives")
_ca = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ca)

argparse = _ca.argparse
Sequence = _ca.Sequence
PLATFORMS = _ca.PLATFORMS
_emit = _ca._emit
_json_stdin = _ca._json_stdin
ensure_root = _ca.ensure_root
status = _ca.status
issue_leaf = _ca.issue_leaf
rotate_ca = _ca.rotate_ca
sign_csr = _ca.sign_csr
bundle_export = _ca.bundle_export
bundle_read = _ca.bundle_read
trust_install = _ca.trust_install
apply_nginx = _ca.apply_nginx
constituent_lock = _ca.constituent_lock
state_commit = _ca.state_commit
portal_admit = _ca.portal_admit


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-house-ca")
    sub = parser.add_subparsers(dest="cmd", required=True)
    root = sub.add_parser("ensure-root"); root.add_argument("--dry-run", action="store_true"); root.add_argument("--renewal-authority")
    sub.add_parser("status")
    issue = sub.add_parser("issue-leaf"); issue.add_argument("identity", nargs="?", default="home.arpa"); issue.add_argument("--sans", default=""); issue.add_argument("--ips", default=""); issue.add_argument("--dry-run", action="store_true")
    rotate = sub.add_parser("rotate-ca"); rotate.add_argument("--i-understand-clients-reinstall", action="store_true")
    sub.add_parser("sign-csr")
    legacy_bundle = sub.add_parser("bundle"); legacy_bundle.add_argument("platform", nargs="?", default="linux", choices=sorted(PLATFORMS))
    bundle = sub.add_parser("bundle-export"); bundle.add_argument("platform", choices=sorted(PLATFORMS)); bundle.add_argument("--dry-run", action="store_true")
    reader = sub.add_parser("bundle-read"); reader.add_argument("platform", choices=sorted(PLATFORMS))
    trust = sub.add_parser("trust-install"); trust.add_argument("bundle"); trust.add_argument("--platform", default="linux", choices=sorted(PLATFORMS)); trust.add_argument("--dry-run", action="store_true"); trust.add_argument("--fingerprint"); trust.add_argument("--renew-ring", action="store_true")
    apply = sub.add_parser("apply-nginx"); apply.add_argument("portal"); apply.add_argument("upstream"); apply.add_argument("certificate"); apply.add_argument("key_path"); apply.add_argument("--aliases", default=""); apply.add_argument("--dry-run", action="store_true")
    lock = sub.add_parser("constituent-lock"); lock.add_argument("portal"); lock.add_argument("lan_ip"); lock.add_argument("--aliases", default=""); lock.add_argument("--dry-run", action="store_true")
    commit = sub.add_parser("state-commit"); commit.add_argument("--dry-run", action="store_true")
    admit = sub.add_parser("portal-admit"); admit.add_argument("portal"); admit.add_argument("lan_ip"); admit.add_argument("upstream"); admit.add_argument("--aliases", default=""); admit.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.cmd == "ensure-root": return _emit(lambda: ensure_root(dry_run=args.dry_run, renewal_authority=args.renewal_authority))
    if args.cmd == "status": return _emit(status)
    if args.cmd == "issue-leaf": return _emit(lambda: issue_leaf(args.identity, args.sans.split(",") if args.sans else (), args.ips.split(",") if args.ips else (), dry_run=args.dry_run))
    if args.cmd == "rotate-ca": return _emit(lambda: rotate_ca(args.i_understand_clients_reinstall))
    if args.cmd == "sign-csr": return _emit(lambda: sign_csr(_json_stdin().get("csrPem")))
    if args.cmd == "bundle": return _emit(lambda: bundle_export(args.platform))
    if args.cmd == "bundle-export": return _emit(lambda: bundle_export(args.platform, dry_run=args.dry_run))
    if args.cmd == "bundle-read": return _emit(lambda: bundle_read(args.platform))
    if args.cmd == "trust-install": return _emit(lambda: trust_install(args.bundle, args.platform, dry_run=args.dry_run, fingerprint=args.fingerprint, renew_ring=args.renew_ring))
    if args.cmd == "apply-nginx": return _emit(lambda: apply_nginx(args.portal, args.upstream, args.certificate, args.key_path, args.aliases.split(",") if args.aliases else (), dry_run=args.dry_run))
    if args.cmd == "constituent-lock": return _emit(lambda: constituent_lock(args.portal, args.lan_ip, args.aliases.split(",") if args.aliases else (), dry_run=args.dry_run))
    if args.cmd == "state-commit": return _emit(lambda: state_commit(_json_stdin(), dry_run=args.dry_run))
    if args.cmd == "portal-admit": return _emit(lambda: portal_admit(args.portal, args.lan_ip, args.upstream, args.aliases.split(",") if args.aliases else (), dry_run=args.dry_run))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

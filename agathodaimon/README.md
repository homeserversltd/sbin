# Agathodaimon

The hand form is `cli.py <noun…> <verb> [--field value …] [< envelope]`; long options supply payload fields. Use `--help` at every level and `--version` for the shelf version. A chord is a leaf whose `index.json` carries `serve`.

A stop declares `"hand": "envelope"` in its own `index.json` to receive its request through the envelope with empty argv on every invocation path. A stop declares `"dry-run": true` to accept the GNU `--dry-run` field; undeclared targets refuse it, and legacy argv stops receive the bare flag when the field is true.

## Staff convergence verbs

These receipt-bearing staff verbs expose observation with `--check` and
convergence with `--apply`:

```text
agathodaimon python staff-path --check|--apply
agathodaimon gui launcher-cache --check|--apply
agathodaimon exousia forgejo-credential --check|--apply
```

`--check` writes no receipt. Every `--apply` attempt writes one aggregate
`run.json` below `CADUCEUS_RECEIPT_ROOT` (default
`/var/lib/caduceus/receipts/<run-id>/run.json`) through the Agathodaimon
receipt emitter. Failed attempts are recorded and return nonzero.

Fixture-only path/command overrides are environment variables:

- Staff path: `CADUCEUS_STAFF_VENV` (default `/var/lib/caduceus/venv`).
- Launcher cache: `CADUCEUS_LAUNCHER_HOME`, `CADUCEUS_LAUNCHER_CACHE_DIR`,
  `CADUCEUS_LAUNCHER_REFRESH_SCRIPT`, and
  `CADUCEUS_LAUNCHER_REFRESH_COMMAND`. Production refresh is run as `owner`
  through sudo; setting the command override runs the fixture command directly
  without sudo.
- Forgejo credential mediation: `CADUCEUS_FORGEJO_FULCRUM_ROOT`,
  `CADUCEUS_FORGEJO_ATTACHMENTS_ROOT`, `CADUCEUS_FORGEJO_OWNER_HOME`,
  `CADUCEUS_FORGEJO_CREDENTIAL_STORE`, and Git's `GIT_CONFIG_SYSTEM`.

Forgejo remote/config observations and receipts never include credential
values; the legacy credential-store path is checked and removed without reading
its contents.

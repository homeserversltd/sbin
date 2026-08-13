# Reload

`reload_services` is the staff-only, reload-only service primitive. It preserves caller order, can plan with `dry_run=True`, and accepts optional per-service `FingerprintGate` state to skip unchanged material. Every invocation returns `caduceus.staff.reload.v1` with one ordered entry per service (`service`, `changed`, `reload_outcome`) plus `ok` and `firstMissingSignal`.

The command uses `CADUCEUS_SYSTEMCTL_BIN` when set, otherwise `systemctl`. It never starts, stops, restarts, enables, or disables a service.

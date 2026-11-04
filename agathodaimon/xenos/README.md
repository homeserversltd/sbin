# Xenia staff run boundary

`caduceus-xenos-run install <id>` reads the registered release entry, fetches the exact pinned release or newest release on its branch, checks release.flag against the downloaded binary, seats the binary, renders `<id>.service`, enables and starts it, and requires the guest's single loopback `/health` to identify that release. `uninstall <id>` stops and disables the rendered unit and removes it; the seat is retained. Own-service and clone entries are refused. No checkout or build runs on the appliance. Both verbs return one `appliance.xenia.install.v1` JSON object and exit 0 on success, 1 on failure or 2 on refusal. `--dry-run` reads but writes nothing; `changed` reports whether work would be needed. A converged install does not restart.

The release receipt reports `source: forge|candidate` and `candidate_url` when a GitHub fallback wins; the forge is preferred at each commit, and both roads verify the binary against its checksum and release flag.

The proof-only variables `XENIA_REGISTER`, `XENIA_SEAT_ROOT`, `XENIA_UNIT_ROOT`, `XENIA_CONFIG`, `XENIA_SYSTEMCTL`, `XENIA_LOG`, `XENIA_FORGE_CREDENTIAL`, and `XENIA_PROOF_HEALTH_ENDPOINT` are honored only by a launcher executing from a Cibation ground under `/var/lib/work`, never by the installed root launcher. The production credential is read from `/etc/default/forgejo`; it is sent only to `git.home.arpa` over HTTPS and never on argv. The sibling Harmonia sudoers lane must grant the two exact anchored verb forms; this repo does not own the standing grant.

`caduceus-xenos-run` acts on a seated clone at `/var/lib/xenia/<id>/`. It consumes that clone in place. It never installs the clone, its staff, or its `permissions/xenia` grant table.

The launcher has six verbs:

- `caduceus-xenos-run <id> band <band>` runs `<clone>/staff/cli.py <band>` as `caduceus:caduceus` with the only supplementary group set to `xenia` (the shared clone group that keeps the `0750` seat readable). The guest receives the original stdin, clone cwd, `HOME=/var/lib/caduceus`, and only the declared Xenia environment.
- `caduceus-xenos-run <id> exec <absolute-path> [literal-args...]` remains root only long enough to validate the clone's in-place `permissions/xenia` table, require an exact command-and-arguments grant, and run that one command. Invalid files, sudoers syntax, grantees, paths, wildcards, and argument mismatches refuse; they never warn and continue.
- `caduceus-xenos-run seat <id>` validates the id against `/etc/appliance/xenia.json` `xenoi`, reads the owner only from that entry's `install.owner`, and creates or corrects the real `/var/lib/xenia/<id>` directory to mode `0750` and that non-root passwd account's uid/gid. It takes no owner argument. Its JSON receipt reports `ok`, `id`, `path`, `owner`, and whether state changed; an already-converged seat reports `changed: false`.
- `caduceus-xenos-run census <id>` requires a registered xenos and observes only `<id>.service`'s systemd ControlGroup, its recursive `cgroup.procs`, those processes' socket fd inodes, and matching LISTEN rows in `/proc/net/tcp`, `tcp6`, and `unix`. It returns only loopback listeners with numeric inodes (`port: null` for Unix sockets). A missing unit or non-process xenos returns an empty listener list; a failed observation returns a named `firstMissingSignal` refusal and a nonzero status.
- `caduceus-xenos-run install <id>` installs the declared Release as described above.
- `caduceus-xenos-run uninstall <id>` removes the managed unit and retains the seat.

The POSIX shell entry point remains thin and resolves its adjacent Python launcher from the shelf. For clone execution Python owns bounded sudoers parsing, `lstat` checks, exact argv comparison, process-group timeout, captured output, and the explicit `setgroups`/`setgid`/`setuid` privilege drop. This avoids depending on `setpriv` in an appliance image. `visudo` is resolved at run time from `/usr/sbin/visudo` and then `/usr/bin/visudo`; absence refuses. The clone verbs add no systemd unit or sudoers grant.

## Guest staff kit

`guest/cli.py` and `guest/_envelope.py` are the source of truth for the two files a household copies into a clone's `staff/` directory. The guest CLI seats its own `staff/` directory on `sys.path`, so a guest band can use `from _envelope import read, attach` without an importable `agathodaimon` package.

## Placement and outer boundary

The source shelf sweep carries only `agathodaimon/**` to `/usr/local/sbin/agathodaimon/` with `prune: true`. Therefore the launcher lives at `agathodaimon/caduceus-xenos-run` in this repository and `/usr/local/sbin/agathodaimon/caduceus-xenos-run` on the appliance. A hand-placed copy outside or inside that owned destination is not durable: the next sweep can remove it as undeclared residue.

The Caduceus snake's existing 64 KiB output cap is smaller than a guest band's possible output. That outer cap is unchanged here.

## Sudoers custody

This repository ships no sudoers fragment. The standing invocation grant belongs to Harmonia's sibling `shared/modules/sudoers/` write-set. Its existing anchored lines cover `seat`, `census`, `band`, and `exec`; the sibling install lane adds anchored `^install [a-z0-9][a-z0-9-]{0\,62}$` and `^uninstall [a-z0-9][a-z0-9-]{0\,62}$` lines for `/usr/local/sbin/agathodaimon/caduceus-xenos-run`.

Those grants permit entry to this one root boundary; the launcher's checks still decide whether an individual guest command is permitted.

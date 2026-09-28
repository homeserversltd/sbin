# Xenia staff run boundary

`caduceus-xenos-run` acts on a seated clone at `/var/lib/xenia/<id>/`. It consumes that clone in place. It never installs the clone, its staff, or its `permissions/xenia` grant table.

The launcher has four verbs:

- `caduceus-xenos-run <id> band <band>` runs `<clone>/staff/cli.py <band>` after clearing supplementary groups and dropping to `caduceus:caduceus`. The guest receives the original stdin, clone cwd, `HOME=/var/lib/caduceus`, and only the declared Xenia environment.
- `caduceus-xenos-run <id> exec <absolute-path> [literal-args...]` remains root only long enough to validate the clone's in-place `permissions/xenia` table, require an exact command-and-arguments grant, and run that one command. Invalid files, sudoers syntax, grantees, paths, wildcards, and argument mismatches refuse; they never warn and continue.
- `caduceus-xenos-run seat <id>` validates the id against `/etc/appliance/xenia.json` `xenoi`, reads the owner only from that entry's `install.owner`, and creates or corrects the real `/var/lib/xenia/<id>` directory to mode `0750` and that non-root passwd account's uid/gid. It takes no owner argument. Its JSON receipt reports `ok`, `id`, `path`, `owner`, and whether state changed; an already-converged seat reports `changed: false`.
- `caduceus-xenos-run census <id>` requires a registered xenos and observes only `<id>.service`'s systemd ControlGroup, its recursive `cgroup.procs`, those processes' socket fd inodes, and matching LISTEN rows in `/proc/net/tcp`, `tcp6`, and `unix`. It returns only loopback listeners with numeric inodes (`port: null` for Unix sockets). A missing unit or non-process xenos returns an empty listener list; a failed observation returns a named `firstMissingSignal` refusal and a nonzero status.

The POSIX shell entry point is intentionally thin. Python owns bounded sudoers parsing, `lstat` checks, exact argv comparison, process-group timeout, captured output, and the explicit `setgroups`/`setgid`/`setuid` privilege drop. This avoids depending on `setpriv` in an appliance image. `visudo` is resolved at run time from `/usr/sbin/visudo` and then `/usr/bin/visudo`; absence refuses. The shell entry point remains unchanged; these verbs add no systemd unit or sudoers grant.

## Guest staff kit

`guest/cli.py` and `guest/_envelope.py` are the source of truth for the two files a household copies into a clone's `staff/` directory. The guest CLI seats its own `staff/` directory on `sys.path`, so a guest band can use `from _envelope import read, attach` without an importable `agathodaimon` package.

## Placement and outer boundary

The source shelf sweep carries only `agathodaimon/**` to `/usr/local/sbin/agathodaimon/` with `prune: true`. Therefore the launcher lives at `agathodaimon/caduceus-xenos-run` in this repository and `/usr/local/sbin/agathodaimon/caduceus-xenos-run` on the appliance. A hand-placed copy outside or inside that owned destination is not durable: the next sweep can remove it as undeclared residue.

The Caduceus snake's existing 64 KiB output cap is smaller than a guest band's possible output. That outer cap is unchanged here.

## Sudoers custody

This repository ships no sudoers fragment. The standing invocation grant belongs to Harmonia's sibling `profiles/homeserver/modules/sudoers/` write-set, because that module alone owns `/etc/sudoers.d`, mode `0440`, filename policy, and its `visudo -cf` gate. It must say exactly:

`caduceus ALL=(root) NOPASSWD: /usr/local/sbin/agathodaimon/caduceus-xenos-run * *`

That grant permits entry to this one root boundary; the launcher's in-memory grant-table checks still decide whether an individual guest command is permitted.

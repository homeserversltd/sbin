# Arcadia OS console session subset

This directory contains the Arcadia OS owner-session supervisor, sticky mode
selection, and stable-only branch query. The installed Wayland entry execs
`/usr/local/sbin/agathodaimon/cli.py console session`; that one long-lived owner
process supervises either Steam/Gamescope or Sway. No SDDM configuration write
is needed.

## CLI surface

- `console steam-install --check --json` reads Steam state; the root deed requires `--accept-license` from the owner (exit 0 success/check, 1 observation/privilege/log failure, 6 unsupported manager, 7 already installed, 8 licence not accepted, 9 failed install command).

- Select a mode with the helper argv
  `/usr/local/sbin/agathodaimon/cli.py console session-select desktop|steam`.
  The selector is atomically written to
  `/run/user/<owner-uid>/ARCADIA_CONSOLE_SESSION` and remains sticky for this
  boot; absence selects Steam, and reboot clears `/run`. The supervisor rereads
  the selector whenever it relaunches a child. Consuming it after the first
  read would erase the selected mode, so a later supervisor/child cycle would
  silently fall back to the Steam default.
- A mode change writes the new selector and then stops only the matching owner
  Gamescope or owner Sway session. A failed stop restores the prior selector.
  Steam shutdown uses the existing owner-session command seam; Sway exit uses
  `face/_shared.py` IPC and the verified owner socket. Switching happens in the
  current login session without requiring a relogin.
- `console select-branch -c|-l` accepts either option and prints exactly
  `stable`. It is a locked compatibility response and invokes no external
  branch helper.
- `console session --print` prints the selected session's computed launch argv
  and environment changes without launching a session process.

## Steam session behavior

The Steam argv is exactly `steam -gamepadui -steamos3`. Existing KMS
resolution/refresh selection and the dimensionless Gamescope fallback remain
unchanged. The session environment retains `MANGOHUD=1`, the existing
`SDL_GAMECONTROLLERCONFIG` behavior, and the required power-sentinel interface;
it adds no Gamescope capability exports.

Before each fresh Steam launch, the supervisor removes stale
`STEAMOS_STEAM_SHUTDOWN_SENTINEL` and
`STEAMOS_STEAM_REBOOT_SENTINEL` entries from the owner runtime directory. After
Gamescope returns, it removes any present sentinel before invoking exactly
`loginctl poweroff` or `loginctl reboot`. If both are present, both are consumed
and neither power action runs; Steam restarts under the selected mode. With no
sentinel and Steam still selected, Steam restarts normally.

# Arcadia OS owner console session

This directory contains the Sway owner-session supervisor, bounded Sunshine
and SDDM restart degrees, and stable-only branch query. The installed Wayland
entry execs `/usr/local/sbin/agathodaimon/cli.py console session`; that one
long-lived owner process supervises Sway. No SDDM configuration write is needed.

## CLI surface

- `console session` launches Sway as the owner. A child that exits in less than
  five seconds is relaunched with exponential backoff from one to thirty
  seconds; a longer-lived child resets the delay. The runtime directory must
  be owner-owned and private.
- `console session --print` prints Sway's computed launch argv and environment
  changes without launching a session process.
- `console restart stream` restarts the owner's Sunshine user unit;
  `console restart seat` restarts SDDM. Each degree requires its unit to exist
  and reads its active state back after the restart.
- `console select-branch -c|-l` accepts either option and prints exactly
  `stable`. It is a locked compatibility response and invokes no external
  branch helper.

# Thyrsus

The household forge is always `git.home.arpa`. Enable `thyrsus.enabled` in
`/etc/appliance/config.json`; `thyrsus.forge`, when present, is `git.home.arpa`.
The immutable appliance profile selects HomeServer or HomeSI.

`cli.py thyrsus propose /path/to/repo -m "Describe the change" [--branch name]`
creates the branch, stages everything, commits on it, pushes and opens a pull
request; the branch you stood on never moves. With nothing to propose it puts you
back on your branch and deletes the empty one.
An absent or null branch generates `thyrsus/<UTC yyyymmdd-hhmmss>`. Read `ok`,
`branch`, `pr_url` and `firstMissingSignal`; show the human the pull request URL.
A failed push or pull request never reports success. Earlier local commits,
branches and any successful push remain in place; `attempt` reports the
completed steps. There is no automatic rollback or hidden retry.

Only when the human's words that turn explicitly authorize admission, call
`cli.py thyrsus admit /path/to/repo <pr>`. The PIN gate is not human admission.
This merges through Forgejo and reads its merged state back; read `ok`,
`merged_sha` and `firstMissingSignal`.

`cli.py thyrsus forge-token` reads the HomeServer Forgejo token from stdin on
HomeSI, storing credential `thyrsus_forgejo` through the existing Keyman setter
with username `owner`. Do not put the token in command arguments. HomeServer
has no token field and always authenticates using its own skeleton instead;
the setter never changes that source. A missing or locked vault is never
opened by Thyrsus.

`cli.py thyrsus forge` reads `forge`, `token_present` and `reachable`, without
exporting a key or writing a log. A nonzero HTTP response still establishes
reachability; it does not establish authentication or readiness to merge.

Privileged callers use the declared staff bands `thyrsus/propose`,
`thyrsus/admit`, `thyrsus/forge-token` and `thyrsus/forge`, with the ordinary
staff envelope on stdin. Payloads are respectively `{repo,message,branch?}`,
`{repo,pr}`, `{token}`, and `{}`. Ordinary CLI calls fill their own kernel.
Three writing bands are administrative; the read is not. Credentials are
read within the privileged crossing; Git itself runs as the repository owner.

Secrets stay in the existing Keyman exchange/vault or in memory. The Git
helper consumes an inherited pipe for one Git call; no credential store,
secret environment variable or authenticated URL is written. Each deed emits
one metadata line to `/var/log/appliance/appliance.log`; replies go only home.

`AGATHODAIMON_SCRATCH_ROOT` uses the staff's isolated config/profile coordinate
for labelled scratch observations. It never reads the body's credentials or
writes a scratch credential. Real push, pull request, merge and token-store
proof require the real household forge and vault, not a stand-in API.

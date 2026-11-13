# Thyrsus

The household forge is always `git.home.arpa`. Enable `thyrsus.enabled` in
`/etc/appliance/config.json`; `thyrsus.forge`, when present, is `git.home.arpa`.
The immutable appliance profile selects HomeServer or another profile.

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

`cli.py thyrsus forge-token` reads the Forgejo token from stdin on every profile but HomeServer and
writes `/etc/default/forgejo` and `/home/owner/.ssh/forgejo-token` as mode 0600
env files. Each keeps its existing `FORGEJO_USERNAME`, or defaults to `owner`.
The receipt lists places actually written; a later failure does not roll them
back. Do not put the token in command arguments. HomeServer
has no token field and always authenticates using its own skeleton instead;
the setter never changes that source. A missing or locked vault is never
opened by Thyrsus.

`cli.py thyrsus forge` reads `forge`, `token_present` and `reachable`, without
exporting a key or writing a log. On every profile but HomeServer it also reports
`observed.token_present_by_plane` for `root` and `owner`; `token_present` uses
the root place. A nonzero HTTP response still establishes
reachability; it does not establish authentication or readiness to merge.

`cli.py thyrsus new-tab <id> --into /absolute/directory [--display "Name"]`
creates a private `cartridge-<id>` repository, seeds it from the public Test tab,
and pushes its `main` branch. The directory must already exist and belong to
its repository owner. The id is a lowercase slug of 2–40 letters, digits and
hyphens. Read `repo_url`, `path`, `next`, `firstMissingSignal` and `attempt`.
Activate the repository in Woodpecker and add its `FORGEJO_TOKEN` secret. When
the first Release is ready, add the tab in your HomeServer: press +, choose Make
one, and add `<owner>/cartridge-<id>`. The pipeline does not admit the tab. If a
later step fails, the created repository and any local work remain; inspect
`attempt` before trying again.

Privileged callers use the declared staff bands `thyrsus/propose`,
`thyrsus/admit`, `thyrsus/forge-token`, `thyrsus/new-tab` and `thyrsus/forge`, with the ordinary
staff envelope on stdin. Payloads are respectively `{repo,message,branch?}`,
`{repo,pr}`, `{token}`, `{id,into,display?}` and `{}`. Ordinary CLI calls fill their own kernel.
The four writing bands are administrative; the read is not. Credentials are
read within the privileged crossing; Git itself runs as the repository owner.

Every profile but HomeServer reads the root runtime place for Thyrsus operations; the owner place is
for owner-plane readers. Keyman carries the Forgejo token at birth, not as a
runtime copy for those profiles. The Git helper consumes an inherited pipe for one Git call;
no secret environment variable or authenticated URL is written. Each deed emits
one metadata line to `/var/log/appliance/appliance.log`; replies go only home.

`AGATHODAIMON_SCRATCH_ROOT` uses the staff's isolated config/profile coordinate
for labelled scratch observations. Non-HomeServer token writes and reads use only the
scratch-rooted runtime places. Real push, pull request, merge and live token
storage require the real household and are not established by scratch proof.

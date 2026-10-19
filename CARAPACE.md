# Agathodaimon carapace

`python3 agathodaimon/carapace.py generate` derives the three sold
`appliance.crossings.v1` files from source declarations. It reads
`agathodaimon/sclerites.json`, the three files under `agathodaimon/defconfigs/`,
and each band owner's adjacent `index.json` `sclerite` declaration. It does not
read the generated crossings as inputs. All profiles and output targets are
prepared before writes; absent output files are created, while symlink and
non-regular outputs are rejected. Output arrays are sorted, writes are skipped
when bytes already match, and malformed declarations stop with a source-located
error.

Every `index.py` owner and the metadata-only `gui/update` owner declares one
known `sclerite.name` beside its `features` contribution map in `index.json`;
empty maps remain unpublished owners. A declaration maps feature names to that
owner's `band`, alias `verbs`, `routes`, and optional `administrative`
contributions. Keep read-only observation routes in `all`. The four network
bands (`dhcp`, `dns`, `firewall`, `identity`) contribute their observation band
and existing `network/<name>` verb under `all` in every sold profile. Their
`all` administrative claims remain empty; gated mutation routes and
method-qualified administrative claims stay with `kea` (DHCP), `unbound` (DNS),
or `firewall`. Identity's `/api/v1/network/device/claim` is gated by `kea`;
its `/api/v1/network/device` observer route remains in `all`. Preserve any gated
duplicate band/verb needed for per-claim administrative validation; crossing
unions are idempotent. `lib` is internal and cannot contribute crossing bands
or routes. All ten `face/...` leaves (`app`, `badge`, `bar`, `fetch`, `focus`,
`launch`, `launcher-cache`, `meter`, `volume`, and `workspace`) have feature and
sclerite name `gtk4`; their crossing ownership follows the Caduceus GTK4 leaf,
not the old `sway`, `pactl`, or `desktop` selections.

The defconfigs explicitly select these sold features; declared implications
and prerequisites add derived features without adding profile-band lists:

- `homeserver`: `kea`, `unbound`, `keyman`, `nas`, `linker`, `transmission`,
  `tailscale`; gateway implications add `gateway`, `nft`, `firewall`, and
  `identity`, while NAS derives its `luks` and `xfs` prerequisites.
- `homeconsole`: `sway`, `pactl`, `desktop`, `nmcli`, `steam`.
- `tv`: `sway`, `pactl`, `desktop`, `nmcli`, `gtk4`.

`all` is always on. `kea` and `unbound` each require the derived gateway
capability; selecting both implies `gateway`. Gateway in turn implies `nft`,
`firewall`, and `identity`. This preserves the existing HomeServer gateway
mutation surface without making those mutations profile-table rules. `firewall`
itself requires `kea`, `unbound`, and `nft`. `nas` requires `keyman`, and
`linker` requires `nas`.

`transmission` implies `vpn-namespace`, which requires `transmission` and
implies `pia`. PIA requires exactly one protocol choice, `openvpn` or
`wireguard`; the generator rejects empty or overlapping option memberships and
checks the final closed feature set so explicitly or transitively selecting a
nonchosen protocol is an error. HomeServer selects `openvpn`, matching the
existing `transmission/vpn/pia/index.json` `defaultProtocol`. HomeConsole's
explicit feature list has no `steam-runtime` choice: selected `steam` implies
`console-restart`, which requires any one of the declared features `steam`,
`sunshine`, or `sddm`.

`transmission` and `steam` each imply `games` as an explicit compatibility
policy preserving the existing HomeServer and HomeConsole games crossings;
this is not a claim that either feature is a physical package dependency.

`keyman/key-status` is owned by `keyman`, and `transmission/status` by
`transmission`; neither status is globally selected under `all`. `face/badge`
and `face/meter` are among the ten `gtk4`-owned face leaves, not common `all`
observers. Those key/status bands are available only to profiles selecting
their owning feature (HomeServer here). These observer declarations remain
honest-not-found where dispatch has no implementation; the internal
Transmission bands are not exposed by the crossings. `samba` is likewise
common observer surface. `gui/update` remains a declared, unimplemented
GTK debt for each sold profile that already crossed it. Its metadata-only node
intentionally has no `index.py`, so the staff dispatcher continues to report
not-found rather than fabricating an implementation.
`crossings/lab.json` remains separately owned and is not generated here.

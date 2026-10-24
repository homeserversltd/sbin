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

Every `index.py` owner declares one
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

The defconfigs explicitly select these profile features; declared implications
and prerequisites add derived features without adding profile-band lists:

- `homeserver`: `kea`, `unbound`, `keyman`, `nas`, `linker`, `transmission`,
  `tailscale`; gateway implications add `gateway`, `nft`, `firewall`, and
  `identity`, while NAS derives its `luks` and `xfs` prerequisites.
- `homeconsole`: `sway`, `pactl`, `desktop`, `nmcli`, `games`, `sddm`,
  `console-restart`.
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
existing `transmission/vpn/pia/index.json` `defaultProtocol`. `console-restart`
requires either `sunshine` or `sddm`; HomeConsole selects `sddm` explicitly.

`transmission` implies `games` as an explicit compatibility policy preserving
the existing HomeServer games crossings. HomeConsole selects `games` directly
for its ROM library and artwork. These are not physical package dependencies.

`keyman/key-status` is owned by `keyman`, and `transmission/status` by
`transmission`; neither status is globally selected under `all`. `face/badge`
and `face/meter` are among the ten `gtk4`-owned face leaves, not common `all`
observers. Those key/status bands are available only to profiles selecting
their owning feature (HomeServer here). These observer declarations remain
honest-not-found where dispatch has no implementation; the internal
Transmission bands are not exposed by the crossings. `samba` is likewise
common observer surface.
`crossings/lab.json` remains separately owned and is not generated here.

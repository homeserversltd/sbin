# Agathodaimon carapace

`python3 agathodaimon/carapace.py generate` derives the five generated profile
`appliance.crossings.v1` files from source declarations. It reads
`agathodaimon/sclerites.json`, the five files under `agathodaimon/defconfigs/`,
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
contributions. Keep read-only observation routes in `all`. The network bands `dns` and `firewall` contribute their observation band and existing `network/<name>` verb under `all` in every profile; `dhcp` and `identity` are noun nodes with no band or verb, their act stops carry the bands and routes. The `dhcp` noun keeps two route-only claims, `/api/v1/network/dhcp/reservations` under `all` and `/api/v1/network/dhcp/reservations/:reservation_id` under `kea` (two acts share that path, so the noun owns it). The DNS `all` band is administrative; gated mutation routes and method-qualified administrative claims stay with their act's stop under `kea` (DHCP), `unbound` (DNS), or `firewall`. Identity's `/api/v1/network/device/claim` is claimed by its `claim` stop under `kea`; its `/api/v1/network/device` observer route and `/api/v1/network/status` belong to the `device/list` stop under `all`. Preserve any gated duplicate band/verb needed for per-claim administrative validation; crossing unions are idempotent. `lib` is internal and cannot contribute crossing bands
or routes. All twelve `face/...` leaves (`app`, `badge`, `bar`, `dictate`,
`fetch`, `focus`, `launch`, `launcher-cache`, `meter`, `screenshot`, `volume`,
and `workspace`) have feature and sclerite name `gtk4`; their crossing
ownership follows the Caduceus GTK4 leaf,
not the old `sway`, `pactl`, or `desktop` selections.

The defconfigs explicitly select these profile features; declared implications
and prerequisites add derived features without adding profile-band lists:

- `homeserver`: `thyrsus`, `kea`, `unbound`, `keyman`, `nas`, `pid2-unit`,
  `linker`, `transmission`, `tailscale`; gateway implications add `gateway`,
  `nft`, `firewall`, and `identity`, while NAS derives its `luks` and `xfs`
  prerequisites.
- `homesi`: `thyrsus`, `desktop`, `sway`, `pactl`, `gtk4`, `nmcli`,
  `local-ai`, `pid2-unit`.
- `homeconsole`: `sway`, `pactl`, `desktop`, `nmcli`, `games`, `sddm`,
  `console-restart`.
- `tv`: `sway`, `pactl`, `desktop`, `nmcli`, `gtk4`.

`all` and `settings` are always on. `settings` owns the compositor-free
`settings/datetime` and `settings/region` crossings; session-bound settings
remain under `desktop`. `thyrsus` owns its four stops and is selected on
HomeServer and HomeSI. `kea` and `unbound` each require the derived gateway
capability; selecting both implies `gateway`. Gateway in turn implies `nft`,
`firewall`, and `identity`. This preserves the existing HomeServer gateway
mutation surface without making those mutations profile-table rules. `firewall`
itself requires `kea`, `unbound`, and `nft`. `nas` requires `keyman`, and
`linker` requires `nas`.

`transmission` implies `vpn-namespace`, which requires `transmission` and
implies `pia`. PIA requires exactly one protocol choice, `openvpn` or
`wireguard`; for product profiles the generator rejects empty or overlapping
option memberships and checks the final closed feature set so explicitly or
transitively selecting a nonchosen protocol is an error. Specula is the
all-features exception. HomeServer selects `openvpn`, matching the
existing `transmission/vpn/pia/index.json` `defaultProtocol`. `console-restart`
requires either `sunshine` or `sddm`; HomeConsole selects `sddm` explicitly.

`transmission` implies `games` as an explicit compatibility policy preserving
the existing HomeServer games crossings. HomeConsole selects `games` directly
for its ROM library and artwork. These are not physical package dependencies.

`keyman/key-status` is owned by `keyman`, and `transmission/status` by
`transmission`; neither status is globally selected under `all`. `face/badge`
and `face/meter` are among the twelve `gtk4`-owned face leaves, not common `all`
observers. Those key/status bands are available only to profiles selecting
their owning feature (HomeServer here). These observer declarations remain
honest-not-found where dispatch has no implementation; the internal
Transmission bands are not exposed by the crossings. `samba` is likewise
common observer surface.
`specula` is generated from its defconfig with every declared feature selected;
its protocol choice records HomeServer's default without narrowing the probe.
It is the deliberately un-narrowed probe for unnamed appliances and monadic
profiles, not a grant of private lab authority.

"""Observe and plan one device identity without writing appliance state."""
from __future__ import annotations

import ipaddress
import re
from agathodaimon.network.dhcp._manager import DhcpManager, DhcpError, normalize_mac
from agathodaimon.network.dns._manager import DnsManager, DnsError


def plan_identity(payload, dhcp=None, dns=None):
    if set(('mac', 'hostname', 'ip', 'move', 'settle')) - payload.keys():
        raise DhcpError('identity-plan-input-invalid')
    if not isinstance(payload['mac'], str) or not isinstance(payload['hostname'], str) or type(payload['move']) is not bool or type(payload['settle']) is not bool or (payload['ip'] is not None and not isinstance(payload['ip'], str)):
        raise DhcpError('identity-plan-input-invalid')
    dhcp, dns = dhcp or DhcpManager(), dns or DnsManager()
    mac = normalize_mac(payload['mac'])
    hostname = dns.canonical_name(payload['hostname'])
    requested = payload['ip']
    config = dhcp.get_config()
    dhcp.get_config = lambda: config
    reservations = dhcp.get_reservations()
    leases = dhcp.get_leases()
    records = dns._all_local_records()
    dhcp.get_reservations = lambda: reservations
    dhcp.get_leases = lambda: leases
    dns._all_local_records = lambda: records
    profile, shipped = dns._shipped_records()
    lines = dns._owned_records()
    match = dhcp.reservation_match(reservations, mac)
    lease = next((r for r in leases if r['hw-address'].strip().lower().replace('-', ':') == mac), None)
    reservation = {'ip': match['ip-address'], 'hostname': match['hostname']} if match else None
    observed = {'reservation': reservation, 'lease': lease, 'records': [], 'shipped_profile': profile,
                'shipped': [{'name': name, 'type': kind, 'target': target} for name, kind, target in sorted(shipped)], 'probes': []}
    wanted = {'mac': mac, 'hostname': hostname, 'ip': requested, 'move': payload['move']}
    decision = {'ip': None, 'reason': None, 'reservation': 'refused', 'name': 'refused', 'signal': None}
    considered = set()
    words = []

    def refuse(signal, reason):
        decision.update(signal=signal, reason=reason)

    def probe(address):
        considered.add(address)
        neigh = dhcp._command(['ip', 'neigh', 'show', address], required=False)
        if neigh.returncode != 0:
            raise DhcpError('dhcp-neighbour-probe-failed')
        ping = dhcp._command(['ping', '-c', '1', '-W', '1', address], required=False)
        if ping.returncode not in (0, 1):
            raise DhcpError('dhcp-ping-probe-failed')
        macs = re.findall(r'\blladdr\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b', neigh.stdout)
        foreign = any(value.lower() != mac for value in macs)
        answered = foreign or (ping.returncode == 0 and not macs)
        observed['probes'].append({'address': address, 'answered': answered, 'by': 'neigh' if foreign else 'ping'})
        return answered

    if match:
        considered.add(match['ip-address'])
        if dhcp.reservation_kept(match, requested):
            decision.update(ip=match['ip-address'], reservation='kept', reason='standing-reservation')
            if match['hostname'].lower() != payload['hostname'].lower():
                words.append('reservation-hostname-differs')
        else:
            words.append('reservation-elsewhere')
            refuse('dhcp-reservation-held-elsewhere', 'standing reservation: ' + match['ip-address'])
    else:
        words.append('reservation-absent')
        # Use the writer's taken-address predicate on the one captured roster.
        taken = dhcp.taken_addresses(dns=dns, exempt_name=hostname)
        start, end = dhcp._get_reserved_range()
        if requested is not None:
            considered.add(requested)
            if dhcp._validate_ip_in_pool(requested):
                refuse('dhcp-ip-inside-pool', 'address inside pool')
            elif not dhcp.address_in_range(requested, start, end):
                refuse('dhcp-ip-outside-reserved-range', f'reserved range: {start} - {end}')
            elif requested in taken:
                refuse('dhcp-ip-taken', 'address already taken')
            elif probe(requested):
                refuse('dhcp-ip-answered-probe', 'address answered probe')
            else:
                decision.update(ip=requested, reservation='create', reason='requested-silent-address')
        else:
            for value in range(int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end)) + 1):
                address = str(ipaddress.IPv4Address(value))
                considered.add(address)
                if address in taken:
                    continue
                if len(observed['probes']) >= 5:
                    break
                if not probe(address):
                    decision.update(ip=address, reservation='create', reason='first-silent-reserved-address')
                    break
            if decision['ip'] is None:
                refuse('dhcp-no-silent-address', 'no silent reserved address in probe budget')

    address = decision['ip']
    if address:
        try:
            if hostname == 'home.arpa.':
                apex = {r['target'] for r in records if r['name'] == 'home.arpa' and r['type'] == 'A' and r['source'] == str(dns.root_config)}
                if apex != {address}:
                    raise DnsError('dns-gateway-apex-address-mismatch')
                reverse = dns._reverse_name(address).rstrip('.')
                decision['name'] = 'kept' if any(r['name'] == reverse and r['type'] == 'PTR' and r['target'] in {'home.arpa', 'homeserver.home.arpa'} for r in records) else 'new'
            else:
                state, addresses, reverses = dns.device_name_state(hostname, address, payload['move'], lines)
                decision['name'] = state
                if state != 'kept':
                    retained = [line for line in lines if not (dns._record_parts(line)[0] == hostname and dns._record_parts(line)[1] == 'A' or dns._record_parts(line)[1:3] == ('PTR', hostname))]
                    candidate = retained + [f'{hostname} IN A {address}', f'{dns._reverse_name(address)} IN PTR {hostname}']
                    candidate = dns._migrate_gateway_records(candidate)
                    previous_targets = {o for o, k, _t, marker in map(dns._record_parts, lines) if k == 'A' and marker is None} | dns._alias_bindings(lines).keys()
                    current_targets = {o for o, k, _t, marker in map(dns._record_parts, candidate) if k == 'A' and marker is None} | dns._alias_bindings(candidate).keys()
                    candidate = dns._project_aliases(candidate, removed_targets=previous_targets - current_targets)
                    existing = {dns._record_parts(line)[0].rstrip('.') for line in lines}
                    dns._validate_candidate(candidate, {dns._record_parts(line)[0].rstrip('.') for line in candidate} - existing)
            if decision['name'] == 'new':
                words.append('name-absent')
            elif decision['name'] == 'move':
                words.append('name-elsewhere')
        except DnsError as exc:
            decision['name'] = 'refused'
            decision['signal'] = str(exc)
            words.append('name-elsewhere' if str(exc) == 'dns-name-owned-elsewhere' else 'name-held-not-owned')
    name = hostname.rstrip('.')
    reverse_names = {dns._reverse_name(ip).rstrip('.') for ip in considered if dhcp._validate_ip_address(ip)}
    observed['records'] = [{'name': r['name'], 'type': r['type'], 'target': r['target'], 'where': dns._record_where(r, shipped)} for r in records if r['name'] == name or r['target'] == name or r['target'] in considered or r['name'] in reverse_names]
    return {'observed': observed, 'wanted': wanted, 'diff': {'empty': not words, 'words': words}, 'plan': decision}

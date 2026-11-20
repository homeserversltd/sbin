"""Internal one-shot ARP batch, run by nidus with the staff's CAP_NET_RAW."""

import fcntl
import socket
import struct
import sys
from time import monotonic

_ETH_P_ARP = 0x0806
_ETHERNET_IPV4 = (1, 0x0800, 6, 4)
_REQUEST, _REPLY = 1, 2
_SIOCGIFADDR = 0x8915
_ARP = struct.Struct("!HHBBH6s4s6s4s")


def ask(interface, targets):
    # The runner also bounds this whole child to one second, including startup.
    deadline = monotonic() + 0.9
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as inet:
        # Linux struct ifreq: the primary IPv4 sockaddr starts after IFNAMSIZ;
        # its sin_addr is four bytes into that sockaddr.
        ifreq = struct.pack("256s", interface.encode("ascii"))
        source_ip = fcntl.ioctl(inet, _SIOCGIFADDR, ifreq)[20:24]

    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(_ETH_P_ARP)) as link:
        link.bind((interface, _ETH_P_ARP))
        source_mac = link.getsockname()[4]
        pending = set()
        # Send the whole batch before waiting for any reply: one frame per row.
        for target in targets:
            ip, mac = target.split(",", 1)
            address = socket.inet_pton(socket.AF_INET, ip)
            hardware = bytes.fromhex(mac.replace(":", ""))
            if hardware[0] & 1 or hardware == bytes(6):
                continue  # ARP refresh must not broadcast or multicast.
            remaining = deadline - monotonic()
            if remaining <= 0:
                return
            link.settimeout(remaining)
            packet = _ARP.pack(*_ETHERNET_IPV4, _REQUEST, source_mac, source_ip, hardware, address)
            try:
                link.sendto(packet, (interface, _ETH_P_ARP, 0, 0, hardware))
            except OSError:
                continue
            pending.add((address, hardware))

        # Only receive now. Unanswered or unrelated traffic cannot move the
        # shared deadline, and no response can trigger another transmission.
        while pending:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return
            link.settimeout(remaining)
            try:
                packet, origin = link.recvfrom(_ARP.size)
            except TimeoutError:
                return
            if len(packet) != _ARP.size or origin[2] != socket.PACKET_HOST:
                continue
            header = _ARP.unpack(packet)
            sender_mac, sender_ip, target_mac, target_ip = header[5:]
            if header[:5] == (*_ETHERNET_IPV4, _REPLY) and (target_mac, target_ip) == (source_mac, source_ip):
                pending.discard((sender_ip, sender_mac))


if __name__ == "__main__":
    ask(sys.argv[1], sys.argv[2:])

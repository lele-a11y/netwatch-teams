"""Extract (client, domain) observations from packets: DNS queries and TLS ClientHello SNI."""
from __future__ import annotations

import re
import struct
from typing import Iterator, Optional, Tuple

Observation = Tuple[str, str, str]  # (client_ip, domain, source)


def parse_sni(payload: bytes) -> Optional[str]:
    """Return the SNI host name from a raw TLS ClientHello record, or None."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4          # record header + handshake header
        pos += 2 + 32        # client version + random
        sid_len = payload[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(payload))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000:  # server_name
                p = pos + 2         # skip server_name_list length
                while p + 3 <= pos + ext_len:
                    name_type = payload[p]
                    name_len = struct.unpack("!H", payload[p + 1:p + 3])[0]
                    p += 3
                    if name_type == 0:
                        return payload[p:p + name_len].decode("ascii", "ignore")
                    p += name_len
                return None
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None


def observations_from_packet(pkt) -> Iterator[Observation]:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6

    if IP in pkt:
        src = pkt[IP].src
    elif IPv6 in pkt:
        src = pkt[IPv6].src
    else:
        return

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and pkt.haslayer(DNSQR):
            q = pkt[DNSQR]
            qname = q.qname.decode("ascii", "ignore") if isinstance(q.qname, bytes) else str(q.qname)
            if q.qtype in (1, 28, 65, 5):  # A, AAAA, HTTPS, CNAME
                yield src, qname.rstrip("."), "dns"
        return

    if pkt.haslayer(TCP):
        payload = bytes(pkt[TCP].payload)
        if payload[:1] == b"\x16":
            sni = parse_sni(payload)
            if sni:
                yield src, sni, "sni"


# dnsmasq / Pi-hole:  "Nov  2 10:00:00 dnsmasq[123]: query[A] www.youtube.com from 192.168.1.20"
_DNSMASQ_RE = re.compile(r"query\[(?:A|AAAA|HTTPS|CNAME)\]\s+(\S+)\s+from\s+(\S+)")


def observation_from_line(line: str) -> Optional[Observation]:
    """Parse a dnsmasq/Pi-hole log line or a simple "<domain> [client]" line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _DNSMASQ_RE.search(line)
    if m:
        return m.group(2), m.group(1), "log"
    if "dnsmasq" in line or "pihole" in line:
        return None
    parts = line.split()
    if len(parts) == 1:
        return "unbekannt", parts[0], "log"
    if len(parts) == 2:
        return parts[1], parts[0], "log"
    return None

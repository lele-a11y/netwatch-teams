"""Device identification: which iPad/PC is behind an IP.

Names come from (highest priority first):
  1. names you assign (web UI / CLI / config) to a MAC or IP address
  2. the device's own name, learned passively from DHCP (option 12) and Bonjour/mDNS announcements
  3. DHCP lease files of dnsmasq / Pi-hole
  4. reverse DNS
MAC addresses are taken from sniffed Ethernet frames, DHCP and the system ARP table.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

log = logging.getLogger(__name__)


def _file_sig(path: str) -> tuple:
    """Detects changes even within the filesystem's mtime granularity (os.replace -> new inode)."""
    st = os.stat(path)
    return (st.st_mtime_ns, st.st_ino, st.st_size)

LEASE_FILES = ["/etc/pihole/dhcp.leases", "/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases",
               "/tmp/dhcp.leases"]
_MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$|^[0-9a-f]{12}$")
_ROUTER_IPS = 3     # a MAC seen with more IPv4 sources than this is a router, not a client


def normalize_mac(value: str) -> str:
    v = (value or "").strip().lower()
    if not _MAC_RE.match(v):
        return ""
    v = v.replace("-", "").replace(":", "")
    return ":".join(v[i:i + 2] for i in range(0, 12, 2))


def normalize_key(value: str) -> str:
    """A device key is a MAC address or an IP address."""
    mac = normalize_mac(value)
    if mac:
        return mac
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise ValueError(f"'{value}' ist keine gültige MAC- oder IP-Adresse") from None


def is_random_mac(mac: str) -> bool:
    """Locally administered MAC – e.g. iOS "private Wi-Fi address"."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def clean_hostname(name) -> str:
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    name = str(name or "").strip().rstrip(".").replace("\x00", "")
    for suffix in (".local", ".lan", ".home", ".fritz.box", ".localdomain"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    if not name or name.startswith("_") or name.lower() in ("localhost", "*"):
        return ""
    return name[:63]


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_link_local) and not a.is_loopback and not a.is_unspecified



def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def read_arp_table(path: str = "/proc/net/arp") -> dict[str, str]:
    out = {}
    try:
        with open(path, encoding="ascii", errors="ignore") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != "0x0":
                    mac = normalize_mac(parts[3])
                    if mac and mac != "00:00:00:00:00:00":
                        out[parts[0]] = mac
    except OSError:
        pass
    return out


def read_leases(paths: list[str]) -> dict[str, tuple[str, str]]:
    """dnsmasq/Pi-hole lease files: '<expiry> <mac> <ip> <hostname> <client-id>' -> {ip: (mac, hostname)}"""
    out = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        out[parts[2]] = (normalize_mac(parts[1]), clean_hostname(parts[3]))
        except OSError:
            continue
    return out


def _rrs(field):
    if field is None:
        return []
    if isinstance(field, list):
        return field
    out, rr = [], field          # older scapy: chained DNSRR packets
    while rr is not None and getattr(rr, "rrname", None) is not None:
        out.append(rr)
        rr = rr.payload if rr.payload else None
    return out


@dataclass
class Device:
    ip: str
    mac: str = ""
    name: str = ""         # assigned by you
    hostname: str = ""     # announced by the device / DHCP / reverse DNS
    hostname_source: str = ""

    @property
    def label(self) -> str:
        return self.name or self.hostname

    def display(self) -> str:
        return f"{self.label} ({self.ip})" if self.label else self.ip


class DeviceRegistry:
    def __init__(self, data_dir: Optional[str] = None, names: Optional[dict] = None, resolve_dns: bool = True,
                 lease_files: Optional[list[str]] = None, arp_reader: Callable[[], dict] = read_arp_table,
                 dns_resolver: Callable[[str], str] = reverse_dns):
        self.path = os.path.join(data_dir, "devices.json") if data_dir else None
        self.resolve_dns = resolve_dns
        self.lease_files = LEASE_FILES if lease_files is None else lease_files
        self.arp_reader = arp_reader
        self.dns_resolver = dns_resolver
        self.lock = threading.RLock()
        self.names: dict[str, dict] = {}          # mac|ip -> {"name", "added"}
        self.hosts: dict[str, dict] = {}          # ip -> {"mac", "hostname", "source", "ts"}
        self.mac_hostnames: dict[str, str] = {}   # mac -> hostname (DHCP)
        self._mac_ips: dict[str, set] = {}
        self._dns_cache: dict[str, str] = {}
        self._mtime = 0.0
        self._dirty = False
        self._last_save = 0.0
        self._arp_cache: tuple[float, dict] = (0.0, {})
        self.config_names: dict[str, dict] = {}
        for key, name in (names or {}).items():   # from config.yaml
            try:
                self.config_names[normalize_key(key)] = {"name": str(name), "added": "config"}
            except ValueError as e:
                log.error("devices.names: %s", e)
        self.names.update(self.config_names)
        self._load()

    # ---------- persistence ----------
    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self._mtime = _file_sig(self.path)
        except (OSError, ValueError) as e:
            log.error("Kann %s nicht lesen: %s", self.path, e)
            return
        with self.lock:
            self.names = {**self.config_names,
                          **{k: v for k, v in (data.get("names") or {}).items() if isinstance(v, dict)}}
            for ip, h in (data.get("hosts") or {}).items():
                if h.get("ts", 0) >= self.hosts.get(ip, {}).get("ts", 0):
                    self.hosts[ip] = h
            for mac, hn in (data.get("mac_hostnames") or {}).items():
                self.mac_hostnames.setdefault(mac, hn)

    def refresh(self) -> None:
        """Pick up names saved by another process (e.g. `netwatch web` / `netwatch name`)."""
        if not self.path:
            return
        try:
            mtime = _file_sig(self.path)
        except OSError:
            return
        if mtime != self._mtime:
            self._load()

    def save(self) -> None:
        if not self.path:
            return
        with self.lock:
            self.refresh()
            data = {"names": self.names, "hosts": self.hosts, "mac_hostnames": self.mac_hostnames}
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
            self._mtime = _file_sig(self.path)
            self._dirty = False
            self._last_save = time.monotonic()

    def _maybe_save(self) -> None:
        if self._dirty and time.monotonic() - self._last_save > 30:
            try:
                self.save()
            except OSError as e:
                log.error("Kann Geräte nicht speichern: %s", e)

    # ---------- naming ----------
    def set_name(self, key: str, name: str) -> str:
        key = normalize_key(key)
        name = " ".join((name or "").split())[:80]
        if not name:
            raise ValueError("Bitte einen Namen angeben")
        with self.lock:
            self.refresh()
            self.names[key] = {"name": name, "added": datetime.now().strftime("%Y-%m-%d %H:%M")}
            self.save()
        return key

    def remove_name(self, key: str) -> bool:
        key = normalize_key(key)
        with self.lock:
            self.refresh()
            removed = self.names.pop(key, None) is not None
            if removed:
                self.save()
        return removed

    # ---------- passive learning ----------
    def _note(self, ip: str, mac: str = "", hostname: str = "", source: str = "") -> None:
        if not ip or not _is_private(ip):
            return
        with self.lock:
            h = self.hosts.setdefault(ip, {})
            changed = False
            if mac and h.get("mac") != mac:
                if ":" not in ip:
                    ips = self._mac_ips.setdefault(mac, set())
                    ips.add(ip)
                h["mac"] = mac
                changed = True
            if hostname and h.get("hostname") != hostname:
                h["hostname"], h["source"] = hostname, source
                changed = True
            h["ts"] = int(time.time())
            if changed:
                self._dirty = True
                if hostname:
                    log.info("Gerät erkannt: %s = %s (%s)", ip, hostname, source)

    def observe(self, pkt) -> None:
        """Learn IP -> MAC / device name from a sniffed packet. Never raises."""
        try:
            self._observe(pkt)
        except Exception:
            log.debug("Geräte-Erkennung fehlgeschlagen", exc_info=True)
        self._maybe_save()

    def _observe(self, pkt) -> None:
        from scapy.layers.dhcp import BOOTP, DHCP
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether

        ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else "")
        mac = normalize_mac(pkt[Ether].src) if Ether in pkt else ""

        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            bootp = pkt[BOOTP]
            chaddr = normalize_mac(bytes(bootp.chaddr)[:6].hex())
            opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and len(o) >= 2}
            hostname = clean_hostname(opts.get("hostname", ""))
            if chaddr and hostname:
                with self.lock:
                    if self.mac_hostnames.get(chaddr) != hostname:
                        self.mac_hostnames[chaddr] = hostname
                        self._dirty = True
            if bootp.op == 1:   # client -> server
                addr = opts.get("requested_addr") or (bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else "")
                self._note(str(addr), chaddr, hostname, "dhcp")
            elif opts.get("message-type") in (5, "ack") and bootp.yiaddr != "0.0.0.0":
                self._note(str(bootp.yiaddr), chaddr, self.mac_hostnames.get(chaddr, ""), "dhcp")
            return

        if UDP in pkt and 5353 in (pkt[UDP].sport, pkt[UDP].dport) and pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 1:
                for rr in _rrs(dns.an) + _rrs(dns.ar):
                    if getattr(rr, "type", None) in (1, 28):
                        name = clean_hostname(rr.rrname)
                        if name:
                            self._note(str(rr.rdata), mac if str(rr.rdata) == ip else "", name, "bonjour")
            return

        if ip and mac:
            self._note(ip, mac)

    # ---------- lookup ----------
    def _arp(self) -> dict:
        ts, table = self._arp_cache
        if time.monotonic() - ts > 30:
            table = self.arp_reader()
            self._arp_cache = (time.monotonic(), table)
        return table

    def _client_mac(self, ip: str) -> str:
        mac = self.hosts.get(ip, {}).get("mac", "")
        if mac and len(self._mac_ips.get(mac, ())) > _ROUTER_IPS:
            mac = ""
        return mac or self._arp().get(ip, "")

    def identify(self, ip: str, resolve: bool = True) -> Device:
        self.refresh()
        with self.lock:
            mac = self._client_mac(ip)
            dev = Device(ip=ip, mac=mac)
            entry = (self.names.get(mac) if mac else None) or self.names.get(ip)
            if entry:
                dev.name = entry["name"]
            h = self.hosts.get(ip, {})
            if h.get("hostname"):
                dev.hostname, dev.hostname_source = h["hostname"], h.get("source", "")
            elif mac and self.mac_hostnames.get(mac):
                dev.hostname, dev.hostname_source = self.mac_hostnames[mac], "dhcp"
        if not dev.hostname:
            lease = read_leases(self.lease_files).get(ip) if self.lease_files else None
            if lease and lease[1]:
                dev.mac = dev.mac or lease[0]
                dev.hostname, dev.hostname_source = lease[1], "dhcp-lease"
                if not dev.name and lease[0] in self.names:
                    dev.name = self.names[lease[0]]["name"]
        if not dev.hostname and resolve and self.resolve_dns and ip != "unbekannt":
            if ip not in self._dns_cache:
                if len(self._dns_cache) > 4096:
                    self._dns_cache.clear()
                self._dns_cache[ip] = clean_hostname(self.dns_resolver(ip))
            if self._dns_cache[ip]:
                dev.hostname, dev.hostname_source = self._dns_cache[ip], "dns"
        return dev

    def list(self) -> list[dict]:
        """All known devices (seen or named) for the web UI / API."""
        self.refresh()
        with self.lock:
            hosts = {ip: dict(h) for ip, h in self.hosts.items()}
            names = dict(self.names)
            mac_hn = dict(self.mac_hostnames)
        out, named_seen = [], set()
        for ip, h in hosts.items():
            mac = h.get("mac", "")
            if mac and len(self._mac_ips.get(mac, ())) > _ROUTER_IPS:
                mac = ""
            key = ip if (ip in names and mac not in names) or not mac else mac
            entry = names.get(key)
            if entry:
                named_seen.add(key)
            out.append({"key": key, "ip": ip, "mac": mac, "name": entry["name"] if entry else "",
                        "hostname": h.get("hostname") or mac_hn.get(mac, ""), "source": h.get("source", ""),
                        "random_mac": bool(mac) and is_random_mac(mac),
                        "last_seen": datetime.fromtimestamp(h["ts"]).strftime("%d.%m. %H:%M") if h.get("ts") else ""})
        for key, entry in names.items():
            if key not in named_seen:
                is_mac = bool(normalize_mac(key))
                out.append({"key": key, "ip": "" if is_mac else key, "mac": key if is_mac else "",
                            "name": entry["name"], "hostname": "",
                            "source": "", "random_mac": False, "last_seen": ""})
        out.sort(key=lambda d: (not d["name"], not d["hostname"], d["name"].lower() or d["hostname"].lower(), d["ip"]))
        return out

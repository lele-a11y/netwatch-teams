import json

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from netwatch.devices import DeviceRegistry, clean_hostname, is_random_mac, normalize_key, normalize_mac
from netwatch.main import DEFAULT_CONFIG, Monitor, _merge, build_classifier
from netwatch.notifier import Event, build_card
from netwatch.sniffer import observations_from_packet
from netwatch.web import Signer

IPAD_MAC = "3a:1f:22:aa:bb:01"


class FakeNotifier:
    dry_run = False

    def __init__(self):
        self.sent = []

    def send(self, ev):
        self.sent.append(ev)
        return True


def registry(tmp_path, **kw):
    kw.setdefault("arp_reader", dict)
    kw.setdefault("dns_resolver", lambda ip: "")
    kw.setdefault("lease_files", [])
    return DeviceRegistry(str(tmp_path / "data"), **kw)


def rebuild(pkt):
    return Ether(bytes(pkt))


def dhcp_request(mac, ip, hostname):
    return rebuild(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
                   / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=bytes.fromhex(mac.replace(":", "")))
                   / DHCP(options=[("message-type", "request"), ("requested_addr", ip),
                                   ("hostname", hostname.encode()), "end"]))


def mdns_announce(mac, ip, name):
    return rebuild(Ether(src=mac, dst="01:00:5e:00:00:fb") / IP(src=ip, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
                   / DNS(qr=1, aa=1, an=DNSRR(rrname=name, type="A", rdata=ip)))


def dns_query(mac, ip, qname):
    return rebuild(Ether(src=mac, dst="00:00:5e:00:01:01") / IP(src=ip, dst="192.168.1.1") / UDP(sport=50123, dport=53)
                   / DNS(rd=1, qd=DNSQR(qname=qname)))


def test_helpers():
    assert normalize_mac("3A-1F-22-AA-BB-01") == IPAD_MAC
    assert normalize_mac("3a1f22aabb01") == IPAD_MAC
    assert normalize_mac("nope") == ""
    assert normalize_key("192.168.1.5") == "192.168.1.5"
    assert is_random_mac(IPAD_MAC) and not is_random_mac("00:1b:63:00:00:01")
    assert clean_hostname(b"Leos-iPad.local.") == "Leos-iPad"
    assert clean_hostname("_airplay._tcp.local") == ""


def test_dhcp_hostname_learned(tmp_path):
    r = registry(tmp_path)
    r.observe(dhcp_request(IPAD_MAC, "192.168.1.23", "Leos-iPad"))
    d = r.identify("192.168.1.23")
    assert (d.hostname, d.mac, d.hostname_source) == ("Leos-iPad", IPAD_MAC, "dhcp")
    assert d.display() == "Leos-iPad (192.168.1.23)"


def test_mdns_name_learned_and_not_reported_as_traffic(tmp_path):
    r = registry(tmp_path)
    pkt = mdns_announce(IPAD_MAC, "192.168.1.24", "iPad-von-Mia.local.")
    r.observe(pkt)
    assert r.identify("192.168.1.24").hostname == "iPad-von-Mia"
    assert list(observations_from_packet(pkt)) == []


def test_assigned_name_wins_and_follows_mac(tmp_path):
    r = registry(tmp_path)
    r.observe(dhcp_request(IPAD_MAC, "192.168.1.23", "iPad"))
    r.set_name(IPAD_MAC.upper(), "iPad 07 – Klasse 3a")
    assert r.identify("192.168.1.23").label == "iPad 07 – Klasse 3a"
    r.observe(dns_query(IPAD_MAC, "192.168.1.77", "example.com"))   # new IP, same iPad
    assert r.identify("192.168.1.77").label == "iPad 07 – Klasse 3a"
    # persisted (hosts debounced) + visible to another process
    r.save()
    r2 = registry(tmp_path)
    assert r2.identify("192.168.1.77").label == "iPad 07 – Klasse 3a"
    assert r2.remove_name(IPAD_MAC)
    r.refresh()
    assert r.identify("192.168.1.23").name == ""


def test_name_by_ip_and_config(tmp_path):
    r = registry(tmp_path, names={"192.168.1.50": "Lehrer-PC"})
    assert r.identify("192.168.1.50").label == "Lehrer-PC"
    r.set_name("192.168.1.51", "Beamer")
    assert r.identify("192.168.1.51").label == "Beamer"


def test_router_mac_ignored(tmp_path):
    r = registry(tmp_path)
    router = "00:11:22:33:44:55"
    for i in range(10):
        r.observe(dns_query(router, f"10.0.0.{i + 10}", "example.com"))
    r.set_name(router, "Router")
    assert r.identify("10.0.0.10").name == ""
    assert r.identify("10.0.0.10").mac == ""


def test_arp_lease_and_reverse_dns_fallbacks(tmp_path):
    leases = tmp_path / "dhcp.leases"
    leases.write_text(f"1793600000 {IPAD_MAC} 192.168.1.30 Anna-iPad *\n")
    r = registry(tmp_path, lease_files=[str(leases)], arp_reader=lambda: {"192.168.1.31": "aa:aa:aa:aa:aa:aa"},
                 dns_resolver=lambda ip: "pc-31.lan" if ip == "192.168.1.31" else "")
    assert r.identify("192.168.1.30").hostname == "Anna-iPad"
    d = r.identify("192.168.1.31")
    assert (d.mac, d.hostname, d.hostname_source) == ("aa:aa:aa:aa:aa:aa", "pc-31", "dns")
    r.set_name("aa:aa:aa:aa:aa:aa", "Sekretariat")
    assert r.identify("192.168.1.31").label == "Sekretariat"


def test_list_devices(tmp_path):
    r = registry(tmp_path)
    r.observe(dhcp_request(IPAD_MAC, "192.168.1.23", "Leos-iPad"))
    r.set_name(IPAD_MAC, "Leos iPad")
    r.set_name("aa:bb:cc:00:00:01", "noch nie gesehen")
    devs = {d["key"]: d for d in r.list()}
    assert devs[IPAD_MAC]["name"] == "Leos iPad" and devs[IPAD_MAC]["ip"] == "192.168.1.23"
    assert devs[IPAD_MAC]["random_mac"] is True
    assert devs["aa:bb:cc:00:00:01"]["ip"] == ""
    json.dumps(r.list())


def test_monitor_alert_contains_ipad_name(tmp_path):
    cfg = _merge(DEFAULT_CONFIG, {"learning": {"enabled": False}})
    n = FakeNotifier()
    r = registry(tmp_path)
    m = Monitor(cfg, build_classifier(cfg), n, async_send=False, devices=r)
    m.handle_packet(dhcp_request(IPAD_MAC, "192.168.1.23", "Leos-iPad"))
    m.handle_packet(dns_query(IPAD_MAC, "192.168.1.23", "www.youtube.com"))
    assert n.sent[-1].hostname == "Leos-iPad" and n.sent[-1].mac == IPAD_MAC
    r.set_name(IPAD_MAC, "iPad 07")
    m.handle_packet(dns_query(IPAD_MAC, "192.168.1.23", "browser.lol"))
    ev = n.sent[-1]
    assert ev.device == "iPad 07"
    text = json.dumps(build_card(ev), ensure_ascii=False)
    assert "**iPad 07** hat **browser.lol** geöffnet" in text and IPAD_MAC in text


def test_card_offers_naming_for_unnamed_device():
    ev = Event(client="192.168.1.23", domain="poki.com", category="gaming", site="poki.com", source="sni",
               detected_by="rule", hostname="iPad", mac=IPAD_MAC)
    actions = build_card(ev, "http://nw:8080", Signer("k"))["attachments"][0]["content"]["actions"]
    assert any(a["title"] == "Gerät benennen" and "device=3a%3A1f" in a["url"] for a in actions)
    ev.device = "iPad 07"
    actions = build_card(ev, "http://nw:8080", Signer("k"))["attachments"][0]["content"]["actions"]
    assert not any(a["title"] == "Gerät benennen" for a in actions)

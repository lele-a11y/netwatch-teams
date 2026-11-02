import json
import os
import struct

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from netwatch import classifier as C
from netwatch.main import DEFAULT_CONFIG, Monitor, _merge, build_classifier, main
from netwatch.notifier import Deduplicator, Event, build_card
from netwatch.sniffer import observation_from_line, observations_from_packet, parse_sni


class FakeNotifier:
    dry_run = False

    def __init__(self):
        self.sent = []

    def send(self, ev):
        self.sent.append(ev)
        return True


def make_monitor(**override):
    cfg = _merge(DEFAULT_CONFIG, override)
    cfg["alerts"]["resolve_hostnames"] = False
    n = FakeNotifier()
    return Monitor(cfg, build_classifier(cfg), n, async_send=False), n


def client_hello(host: str) -> bytes:
    name = host.encode()
    sni_list = struct.pack("!BH", 0, len(name)) + name
    sni_ext = struct.pack("!HHH", 0x0000, len(sni_list) + 2, len(sni_list)) + sni_list
    other_ext = struct.pack("!HH", 0x000b, 2) + b"\x01\x00"
    exts = other_ext + sni_ext
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + struct.pack("!H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


@pytest.mark.parametrize("domain,cat", [
    ("www.youtube.com", C.YOUTUBE),
    ("rr3---sn-4g5e6nsz.googlevideo.com", C.YOUTUBE),
    ("youtu.be", C.YOUTUBE),
    ("browser.lol", C.PROXY),
    ("www.browser.lol", C.PROXY),
    ("store.steampowered.com", C.GAMING),
    ("www.roblox.com", C.GAMING),
    ("poki.com", C.GAMING),
    ("unblocked-games-66.example.net", C.GAMING),
    ("my-free-proxy.xyz", C.PROXY),
    ("www.srf.ch", C.NONE),
    ("outlook.office365.com", C.NONE),
    ("www.google.com", C.NONE),
])
def test_classify(domain, cat):
    assert C.Classifier().classify(domain).category == cat


def test_classify_ignores_invalid_and_ptr():
    c = C.Classifier()
    assert not c.classify("1.1.168.192.in-addr.arpa").flagged
    assert not c.classify("localhost").flagged
    assert not c.classify("bad domain!").flagged


def test_ai_classifier_used_and_cached(tmp_path, monkeypatch):
    calls = []

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": '```json\n{"category": "gaming", "reason": "browser games"}\n```'}}]}

    def fake_post(url, headers, json, timeout):
        calls.append(json["messages"][0]["content"])
        return Resp()

    monkeypatch.setattr(C.requests, "post", fake_post)
    cache = tmp_path / "cache.json"
    ai = C.AIClassifier("http://x/v1", "m", cache_file=str(cache))
    c = C.Classifier(ai=ai)
    v = c.classify("cdn.zzzplay.example")
    assert v.category == C.GAMING and v.source == "ai"
    v2 = c.classify("www.zzzplay.example")
    assert v2.source == "cache" and len(calls) == 1
    assert json.loads(cache.read_text())["zzzplay.example"]["category"] == "gaming"
    assert C.AIClassifier("http://x/v1", "m", cache_file=str(cache)).classify("zzzplay.example").source == "cache"


def test_ai_error_does_not_flag(monkeypatch):
    def boom(*a, **k):
        raise C.requests.ConnectionError("down")

    monkeypatch.setattr(C.requests, "post", boom)
    assert C.Classifier(ai=C.AIClassifier("http://x/v1", "m")).classify("unknown-site.example").category == C.NONE


def test_parse_sni():
    assert parse_sni(client_hello("browser.lol")) == "browser.lol"
    assert parse_sni(b"\x16\x03\x01garbage") is None
    assert parse_sni(b"GET / HTTP/1.1\r\n") is None


def test_observations_from_packets():
    dns = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.youtube.com"))
    resp = Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=5353) / DNS(qr=1, qd=DNSQR(qname="www.youtube.com"))
    tls = Ether() / IP(src="10.0.0.6", dst="1.2.3.4") / TCP(sport=50000, dport=443, flags="PA") / client_hello("poki.com")
    assert list(observations_from_packet(dns)) == [("10.0.0.5", "www.youtube.com", "dns")]
    assert list(observations_from_packet(resp)) == []
    assert list(observations_from_packet(tls)) == [("10.0.0.6", "poki.com", "sni")]


def test_dedup_cooldown():
    t = [0.0]
    d = Deduplicator(600, clock=lambda: t[0])
    assert d.should_alert("a", "youtube")
    assert not d.should_alert("a", "youtube")
    assert d.should_alert("b", "youtube")
    t[0] = 601
    assert d.should_alert("a", "youtube")


def test_monitor_alerts_once_per_category_and_respects_allow():
    m, n = make_monitor(rules={"allow": ["chess.com"]})
    m.handle("10.0.0.5", "www.youtube.com", "dns")
    m.handle("10.0.0.5", "i.ytimg.com", "dns")
    m.handle("10.0.0.5", "rr1---sn.googlevideo.com", "sni")
    m.handle("10.0.0.5", "www.srf.ch", "dns")
    m.handle("10.0.0.5", "www.chess.com", "dns")
    m.handle("10.0.0.5", "browser.lol", "sni")
    assert [(e.category, e.site) for e in n.sent] == [("youtube", "youtube.com"), ("proxy", "browser.lol")]


def test_monitor_ignored_clients_and_categories():
    m, n = make_monitor(capture={"ignore_clients": ["10.0.0.1"]}, alerts={"categories": ["proxy"]})
    m.handle("10.0.0.1", "browser.lol", "dns")
    m.handle("10.0.0.2", "www.youtube.com", "dns")
    m.handle("10.0.0.2", "browser.lol", "dns")
    assert [(e.client, e.category) for e in n.sent] == [("10.0.0.2", "proxy")]


def test_log_line_parsing():
    assert observation_from_line("Nov  2 10:00:00 dnsmasq[1]: query[A] www.youtube.com from 192.168.1.20") == \
        ("192.168.1.20", "www.youtube.com", "log")
    assert observation_from_line("Nov  2 10:00:00 dnsmasq[1]: reply www.youtube.com is 1.2.3.4") is None
    assert observation_from_line("poki.com 10.0.0.9") == ("10.0.0.9", "poki.com", "log")


def test_card_payload_shape():
    ev = Event(client="10.0.0.5", domain="www.youtube.com", category="youtube", site="youtube.com",
               source="dns", detected_by="rule", hostname="laptop-anna.lan")
    p = build_card(ev)
    assert p["type"] == "message"
    att = p["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    text = json.dumps(att["content"], ensure_ascii=False)
    assert "**laptop-anna.lan** hat" in text and "10.0.0.5" in text and "YouTube" in text


def test_cli_pcap_end_to_end(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr("netwatch.notifier.TeamsNotifier.send", lambda self, ev: sent.append(ev) or True)
    pkts = [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=1111, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.youtube.com")),
        Ether() / IP(src="10.0.0.6", dst="1.2.3.4") / TCP(sport=50000, dport=443, flags="PA") / client_hello("browser.lol"),
        Ether() / IP(src="10.0.0.7", dst="10.0.0.1") / UDP(sport=1112, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.admin.ch")),
    ]
    f = tmp_path / "t.pcap"
    wrpcap(str(f), pkts)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("teams:\n  webhook_url: https://example.invalid/hook\nalerts:\n  resolve_hostnames: false\n"
                   f"learning:\n  data_dir: {tmp_path / 'data'}\n  fetch_content: false\n")
    assert main(["-c", str(cfg), "pcap", str(f)]) == 0
    assert sorted((e.client, e.category) for e in sent) == [("10.0.0.5", "youtube"), ("10.0.0.6", "proxy")]

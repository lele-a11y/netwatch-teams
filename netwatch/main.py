"""netwatch – watches network traffic and reports YouTube / gaming / proxy sites to Microsoft Teams."""
from __future__ import annotations

import argparse
import functools
import logging
import os
import socket
import sys
import threading
from typing import Iterable, Optional

import yaml

from . import __version__
from .classifier import (AIClassifier, Classifier, DEFAULT_IGNORE, DEFAULT_RULES, NONE,
                         YOUTUBE, _matches, normalize)
from .notifier import Deduplicator, Event, TeamsNotifier
from .sniffer import observation_from_line, observations_from_packet

log = logging.getLogger("netwatch")

DEFAULT_CONFIG = {
    "teams": {"webhook_url": ""},
    "capture": {
        "interface": None,
        "bpf_filter": "udp port 53 or tcp port 53 or tcp port 443",
        "ignore_clients": [],
    },
    "alerts": {
        "categories": ["youtube", "gaming", "proxy"],
        "cooldown_minutes": 10,
        "dedupe_by": "category",
        "resolve_hostnames": True,
    },
    "rules": {"extra": {}, "allow": [], "ignore": [], "keywords": True},
    "ai": {
        "enabled": False,
        "base_url": "http://localhost:11434/v1",
        "model": "llama3.1:8b",
        "api_key": "",
        "cache_file": "ai_cache.json",
    },
    "logging": {"level": "INFO"},
}


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_config(path: Optional[str]) -> dict:
    cfg = DEFAULT_CONFIG
    if path:
        with open(path, encoding="utf-8") as f:
            cfg = _merge(DEFAULT_CONFIG, yaml.safe_load(f) or {})
    cfg = _merge(cfg, {})
    if os.environ.get("TEAMS_WEBHOOK_URL"):
        cfg["teams"]["webhook_url"] = os.environ["TEAMS_WEBHOOK_URL"]
    if os.environ.get("NETWATCH_AI_API_KEY"):
        cfg["ai"]["api_key"] = os.environ["NETWATCH_AI_API_KEY"]
    return cfg


def build_classifier(cfg: dict) -> Classifier:
    rules = {k: list(v) for k, v in DEFAULT_RULES.items()}
    for cat, domains in (cfg["rules"].get("extra") or {}).items():
        rules.setdefault(cat, []).extend(domains or [])
    ai = None
    if cfg["ai"].get("enabled"):
        ai = AIClassifier(cfg["ai"]["base_url"], cfg["ai"]["model"], cfg["ai"].get("api_key", ""),
                          cache_file=cfg["ai"].get("cache_file"))
    return Classifier(rules=rules, ignore=DEFAULT_IGNORE + list(cfg["rules"].get("ignore") or []),
                      use_keywords=cfg["rules"].get("keywords", True), ai=ai)


@functools.lru_cache(maxsize=4096)
def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


class Monitor:
    def __init__(self, cfg: dict, classifier: Classifier, notifier: TeamsNotifier,
                 dedup: Optional[Deduplicator] = None, async_send: bool = True):
        self.cfg = cfg
        self.classifier = classifier
        self.notifier = notifier
        self.dedup = dedup or Deduplicator(int(cfg["alerts"]["cooldown_minutes"] * 60))
        self.categories = set(cfg["alerts"]["categories"])
        self.allow = [normalize(d) for d in cfg["rules"].get("allow") or []]
        self.ignore_clients = set(cfg["capture"].get("ignore_clients") or [])
        self.async_send = async_send
        self._seen_lock = threading.Lock()
        self._seen: dict[str, object] = {}

    def _classify(self, domain: str):
        # Cache verdicts per domain so the AI is not hammered for repeated lookups.
        with self._seen_lock:
            v = self._seen.get(domain)
        if v is None:
            v = self.classifier.classify(domain)
            with self._seen_lock:
                if len(self._seen) > 50000:
                    self._seen.clear()
                self._seen[domain] = v
        return v

    def handle(self, client: str, domain: str, source: str) -> Optional[Event]:
        domain = normalize(domain)
        if client in self.ignore_clients:
            return None
        if any(_matches(domain, a) for a in self.allow):
            return None
        v = self._classify(domain)
        if v.category == NONE or v.category not in self.categories:
            return None
        site = "youtube.com" if v.category == YOUTUBE else v.site
        key = v.category if self.cfg["alerts"].get("dedupe_by", "category") == "category" else site
        if not self.dedup.should_alert(client, key):
            log.debug("unterdrückt (Cooldown): %s %s", client, domain)
            return None
        ev = Event(client=client, domain=domain, category=v.category, site=site,
                   source=source, detected_by=v.source, reason=v.reason)
        log.warning("ALARM %s: %s -> %s [%s via %s/%s]", v.category, client, domain, site, source, v.source)
        if self.async_send:
            threading.Thread(target=self._deliver, args=(ev,), daemon=True).start()
        else:
            self._deliver(ev)
        return ev

    def _deliver(self, ev: Event) -> None:
        if self.cfg["alerts"].get("resolve_hostnames") and ev.client != "unbekannt":
            ev.hostname = resolve_hostname(ev.client)
        self.notifier.send(ev)

    def handle_packet(self, pkt) -> None:
        try:
            for client, domain, source in observations_from_packet(pkt):
                self.handle(client, domain, source)
        except Exception:  # never let one bad packet kill the sniffer
            log.exception("Fehler bei Paketverarbeitung")

    def handle_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            obs = observation_from_line(line)
            if obs:
                self.handle(*obs)


def cmd_run(args, cfg, monitor: Monitor) -> int:
    from scapy.all import sniff
    iface = args.interface or cfg["capture"].get("interface")
    log.info("netwatch %s – lausche auf %s (Filter: %s)", __version__, iface or "Standard-Interface",
             cfg["capture"]["bpf_filter"])
    if monitor.notifier.dry_run:
        log.warning("Kein Teams-Webhook konfiguriert – DRY-RUN, Alarme werden nur geloggt.")
    try:
        sniff(iface=iface, filter=cfg["capture"]["bpf_filter"], prn=monitor.handle_packet, store=False)
    except PermissionError:
        log.error("Keine Berechtigung zum Mitschneiden – mit sudo bzw. CAP_NET_RAW starten.")
        return 1
    return 0


def cmd_pcap(args, cfg, monitor: Monitor) -> int:
    from scapy.utils import PcapReader
    with PcapReader(args.file) as reader:
        for pkt in reader:
            monitor.handle_packet(pkt)
    return 0


def cmd_stdin(args, cfg, monitor: Monitor) -> int:
    monitor.handle_lines(sys.stdin)
    return 0


def cmd_classify(args, cfg, monitor: Monitor) -> int:
    for d in args.domains:
        v = monitor.classifier.classify(d)
        print(f"{d:40} {v.category:8} {v.source:8} {v.site:25} {v.reason}")
    return 0


def cmd_test_webhook(args, cfg, monitor: Monitor) -> int:
    if not cfg["teams"]["webhook_url"]:
        log.error("Kein Webhook konfiguriert (config.yaml teams.webhook_url oder TEAMS_WEBHOOK_URL).")
        return 1
    ev = Event(client="192.168.1.99", domain="www.youtube.com", category=YOUTUBE, site="youtube.com",
               source="test", detected_by="rule", reason="Testnachricht von netwatch")
    return 0 if TeamsNotifier(cfg["teams"]["webhook_url"]).send(ev) else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netwatch", description=__doc__)
    p.add_argument("-c", "--config", default=os.environ.get("NETWATCH_CONFIG"),
                   help="Pfad zur config.yaml")
    p.add_argument("--dry-run", action="store_true", help="Keine Teams-Nachrichten senden, nur loggen")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Live-Traffic mitschneiden (braucht root/CAP_NET_RAW)")
    r.add_argument("-i", "--interface")
    pc = sub.add_parser("pcap", help="pcap-Datei auswerten")
    pc.add_argument("file")
    sub.add_parser("stdin", help="dnsmasq/Pi-hole-Log oder Domains von stdin lesen")
    c = sub.add_parser("classify", help="Domains testweise klassifizieren")
    c.add_argument("domains", nargs="+")
    sub.add_parser("test-webhook", help="Testnachricht an Teams senden")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    level = "DEBUG" if args.verbose else cfg["logging"].get("level", "INFO")
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-7s %(message)s")
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    notifier = TeamsNotifier(cfg["teams"]["webhook_url"], dry_run=args.dry_run)
    monitor = Monitor(cfg, build_classifier(cfg), notifier,
                      async_send=args.cmd == "run")
    handlers = {"run": cmd_run, "pcap": cmd_pcap, "stdin": cmd_stdin,
                "classify": cmd_classify, "test-webhook": cmd_test_webhook}
    try:
        return handlers[args.cmd](args, cfg, monitor)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())

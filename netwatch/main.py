"""netwatch – watches network traffic and reports YouTube / gaming / proxy sites to Microsoft Teams."""
from __future__ import annotations

import argparse
import functools
import logging
import os
import socket
import sys
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

import yaml

from . import __version__
from .classifier import (AIClassifier, Classifier, DEFAULT_IGNORE, DEFAULT_RULES, NONE,
                         YOUTUBE, _matches, normalize)
from .learning import CATEGORIES, LearningStore
from .notifier import Deduplicator, Event, TeamsNotifier
from .sniffer import observation_from_line, observations_from_packet
from .web import App, Signer, load_secret, start_web

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
        "cache_file": "",
    },
    "learning": {
        "enabled": True,
        "data_dir": "data",
        "fetch_content": True,
        "threshold": 0.85,
        "none_threshold": 0.9,
    },
    "web": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 8080,
        "password": "",
        "public_url": "",
        "secret": "",
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
    if os.environ.get("NETWATCH_WEB_PASSWORD"):
        cfg["web"]["password"] = os.environ["NETWATCH_WEB_PASSWORD"]
    return cfg


def build_learner(cfg: dict) -> Optional[LearningStore]:
    lc = cfg["learning"]
    if not lc.get("enabled"):
        return None
    return LearningStore(lc["data_dir"], fetch_content=lc.get("fetch_content", True),
                         threshold=float(lc.get("threshold", 0.85)),
                         none_threshold=float(lc.get("none_threshold", 0.9)))


def build_classifier(cfg: dict, learner: Optional[LearningStore] = None) -> Classifier:
    rules = {k: list(v) for k, v in DEFAULT_RULES.items()}
    for cat, domains in (cfg["rules"].get("extra") or {}).items():
        rules.setdefault(cat, []).extend(domains or [])
    ai = None
    if cfg["ai"].get("enabled"):
        ai = AIClassifier(cfg["ai"]["base_url"], cfg["ai"]["model"], cfg["ai"].get("api_key", ""),
                          cache_file=cfg["ai"].get("cache_file"))
    return Classifier(rules=rules, ignore=DEFAULT_IGNORE + list(cfg["rules"].get("ignore") or []),
                      use_keywords=cfg["rules"].get("keywords", True), ai=ai, learner=learner)


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
        self.recent: deque[Event] = deque(maxlen=200)
        self._seen_lock = threading.Lock()
        self._seen: dict[str, object] = {}
        self._pending: set[str] = set()
        self._version = -1
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="classify") if async_send else None

    def _classify(self, domain: str):
        # Cache verdicts per domain so slow paths (website fetch, LLM) run once per domain.
        learner = self.classifier.learner
        with self._seen_lock:
            if learner is not None and learner.version != self._version:
                self._seen.clear()
                self._version = learner.version
            v = self._seen.get(domain)
            if v is None:
                if domain in self._pending:
                    return None
                self._pending.add(domain)
        if v is None:
            try:
                v = self.classifier.classify(domain)
            finally:
                with self._seen_lock:
                    self._pending.discard(domain)
            with self._seen_lock:
                if len(self._seen) > 50000:
                    self._seen.clear()
                if learner is None or learner.version == self._version:
                    self._seen[domain] = v
        return v

    def handle(self, client: str, domain: str, source: str) -> Optional[Event]:
        domain = normalize(domain)
        if client in self.ignore_clients:
            return None
        if any(_matches(domain, a) for a in self.allow):
            return None
        v = self._classify(domain)
        if v is None or v.category == NONE or v.category not in self.categories:
            return None
        site = "youtube.com" if v.category == YOUTUBE else v.site
        key = v.category if self.cfg["alerts"].get("dedupe_by", "category") == "category" else site
        if not self.dedup.should_alert(client, key):
            log.debug("unterdrückt (Cooldown): %s %s", client, domain)
            return None
        ev = Event(client=client, domain=domain, category=v.category, site=site,
                   source=source, detected_by=v.source, reason=v.reason)
        log.warning("ALARM %s: %s -> %s [%s via %s/%s]", v.category, client, domain, site, source, v.source)
        self.recent.append(ev)
        if self.async_send:
            threading.Thread(target=self._deliver, args=(ev,), daemon=True).start()
        else:
            self._deliver(ev)
        return ev

    def _deliver(self, ev: Event) -> None:
        if self.cfg["alerts"].get("resolve_hostnames") and ev.client != "unbekannt":
            ev.hostname = resolve_hostname(ev.client)
        self.notifier.send(ev)

    def _safe_handle(self, client: str, domain: str, source: str) -> None:
        try:
            self.handle(client, domain, source)
        except Exception:  # never let one bad lookup kill the monitor
            log.exception("Fehler bei Verarbeitung von %s", domain)

    def handle_packet(self, pkt) -> None:
        try:
            observations = list(observations_from_packet(pkt))
        except Exception:
            log.exception("Fehler bei Paketverarbeitung")
            return
        for client, domain, source in observations:
            if self._pool is not None:
                if self._pool._work_queue.qsize() < 5000:
                    self._pool.submit(self._safe_handle, client, domain, source)
            else:
                self._safe_handle(client, domain, source)

    def handle_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            obs = observation_from_line(line)
            if obs:
                self.handle(*obs)


def _web_app(cfg, monitor: Monitor) -> Optional[App]:
    learner = monitor.classifier.learner
    if learner is None:
        return None
    secret = load_secret(cfg["learning"]["data_dir"], cfg["web"].get("secret", ""))
    return App(learner, monitor.classifier, monitor, password=cfg["web"].get("password", ""),
               secret=secret, public_url=cfg["web"].get("public_url", ""))


def cmd_run(args, cfg, monitor: Monitor) -> int:
    from scapy.all import sniff
    if cfg["web"].get("enabled") and not args.no_web:
        app = _web_app(cfg, monitor)
        if app:
            start_web(app, cfg["web"]["host"], int(cfg["web"]["port"]))
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


def cmd_web(args, cfg, monitor: Monitor) -> int:
    app = _web_app(cfg, monitor)
    if app is None:
        log.error("learning.enabled ist aus – Web-Oberfläche braucht den Lernspeicher.")
        return 1
    start_web(app, cfg["web"]["host"], int(cfg["web"]["port"]), background=False)
    return 0


def cmd_add(args, cfg, monitor: Monitor) -> int:
    learner = monitor.classifier.learner
    if learner is None:
        log.error("learning.enabled ist aus.")
        return 1
    for value in args.sites:
        try:
            site = learner.add_site(value, args.category, source="cli", note=args.note or "")
            print(f"{site} -> {args.category}")
        except ValueError as e:
            log.error("%s", e)
            return 1
    return 0


def cmd_remove(args, cfg, monitor: Monitor) -> int:
    learner = monitor.classifier.learner
    if learner is None:
        return 1
    for value in args.sites:
        print(f"{value}: {'entfernt' if learner.remove_site(value) else 'nicht gefunden'}")
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
    return 0 if monitor.notifier.send(ev) else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netwatch", description=__doc__)
    p.add_argument("-c", "--config", default=os.environ.get("NETWATCH_CONFIG"),
                   help="Pfad zur config.yaml")
    p.add_argument("--dry-run", action="store_true", help="Keine Teams-Nachrichten senden, nur loggen")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Live-Traffic mitschneiden (braucht root/CAP_NET_RAW)")
    r.add_argument("-i", "--interface")
    r.add_argument("--no-web", action="store_true", help="Web-Oberfläche nicht starten")
    sub.add_parser("web", help="Nur die Web-Oberfläche starten")
    a = sub.add_parser("add", help="Webseite melden/lernen, z.B.: add gaming neueseite.io")
    a.add_argument("category", choices=CATEGORIES)
    a.add_argument("sites", nargs="+")
    a.add_argument("--note")
    rm = sub.add_parser("remove", help="Gemeldete Webseite entfernen")
    rm.add_argument("sites", nargs="+")
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

    learner = build_learner(cfg)
    signer = Signer(load_secret(cfg["learning"]["data_dir"], cfg["web"].get("secret", ""))) if learner else None
    notifier = TeamsNotifier(cfg["teams"]["webhook_url"], dry_run=args.dry_run,
                             public_url=cfg["web"].get("public_url", "") if cfg["web"].get("enabled") else "",
                             signer=signer)
    monitor = Monitor(cfg, build_classifier(cfg, learner), notifier,
                      async_send=args.cmd == "run")
    handlers = {"run": cmd_run, "pcap": cmd_pcap, "stdin": cmd_stdin, "web": cmd_web, "add": cmd_add,
                "remove": cmd_remove, "classify": cmd_classify, "test-webhook": cmd_test_webhook}
    try:
        return handlers[args.cmd](args, cfg, monitor)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())

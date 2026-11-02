"""Microsoft Teams webhook notifications (Workflows / Power Automate and legacy Incoming Webhooks)."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlencode

import requests

from .classifier import CATEGORY_LABELS

log = logging.getLogger(__name__)


@dataclass
class Event:
    client: str
    domain: str
    category: str
    site: str
    source: str        # dns | sni | log
    detected_by: str   # rule | keyword | ai | cache
    reason: str = ""
    hostname: str = ""   # name announced by the device / DHCP / reverse DNS
    device: str = ""     # name you gave the device (web UI / CLI / config)
    mac: str = ""
    ts: datetime = field(default_factory=datetime.now)


def device_name(ev: Event) -> str:
    return ev.device or ev.hostname


def device_label(ev: Event) -> str:
    name = device_name(ev)
    return f"{name} ({ev.client})" if name else ev.client


def build_card(ev: Event, public_url: str = "", signer=None) -> dict:
    label = CATEGORY_LABELS.get(ev.category, ev.category)
    name = device_name(ev)
    facts = [
        {"title": "Gerät", "value": name or "unbekannt (in der Web-Oberfläche benennen)"},
        {"title": "IP-Adresse", "value": ev.client},
    ]
    if ev.mac:
        facts.append({"title": "MAC-Adresse", "value": ev.mac})
    facts += [
        {"title": "Kategorie", "value": label},
        {"title": "Seite", "value": ev.site},
        {"title": "Domain", "value": ev.domain},
        {"title": "Zeit", "value": ev.ts.strftime("%d.%m.%Y %H:%M:%S")},
        {"title": "Erkannt via", "value": f"{ev.source.upper()} / {ev.detected_by}"
                                           + (f" – {ev.reason}" if ev.reason else "")},
    ]
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "size": "Large", "weight": "Bolder", "color": "Attention",
             "text": f"⚠️ {label} aufgerufen" + (f" – {name}" if name else ""), "wrap": True},
            {"type": "TextBlock", "text": f"**{name or ev.client}** hat **{ev.site}** geöffnet.", "wrap": True},
            {"type": "FactSet", "facts": facts},
        ],
    }
    if public_url and signer is not None:
        card["actions"] = [
            {"type": "Action.OpenUrl", "title": "Falsch-Alarm melden",
             "url": signer.feedback_url(public_url, ev.site)},
            {"type": "Action.OpenUrl", "title": "Webseiten verwalten", "url": public_url.rstrip("/") + "/"},
        ]
        if not ev.device:
            q = urlencode({"device": ev.mac or ev.client})
            card["actions"].append({"type": "Action.OpenUrl", "title": "Gerät benennen",
                                    "url": f"{public_url.rstrip('/')}/?{q}#geraete"})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": card,
        }],
    }


class TeamsNotifier:
    def __init__(self, webhook_url: str, timeout: float = 10.0, retries: int = 3, dry_run: bool = False,
                 public_url: str = "", signer=None):
        self.webhook_url = webhook_url
        self.public_url = public_url
        self.signer = signer
        self.timeout = timeout
        self.retries = retries
        self.dry_run = dry_run or not webhook_url

    def send(self, ev: Event) -> bool:
        payload = build_card(ev, self.public_url, self.signer)
        if self.dry_run:
            log.warning("[DRY-RUN] Alarm: %s -> %s (%s)", device_label(ev), ev.site, ev.category)
            return True
        for attempt in range(1, self.retries + 1):
            try:
                r = requests.post(self.webhook_url, json=payload, timeout=self.timeout)
                if r.status_code < 300:
                    log.info("Teams-Nachricht gesendet: %s -> %s", device_label(ev), ev.site)
                    return True
                if r.status_code == 429:
                    time.sleep(float(r.headers.get("Retry-After", 2 * attempt)))
                    continue
                log.error("Teams-Webhook antwortet %s: %s", r.status_code, r.text[:300])
            except requests.RequestException as e:
                log.error("Teams-Webhook Fehler (Versuch %d): %s", attempt, e)
            time.sleep(2 * attempt)
        return False

    def send_async(self, ev: Event) -> None:
        threading.Thread(target=self.send, args=(ev,), daemon=True).start()


class Deduplicator:
    """Suppresses repeated alerts for the same client + site within a cooldown window."""

    def __init__(self, cooldown_seconds: int = 600, clock=time.monotonic):
        self.cooldown = cooldown_seconds
        self.clock = clock
        self._last: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def should_alert(self, client: str, site: str) -> bool:
        now = self.clock()
        key = (client, site)
        with self._lock:
            last: Optional[float] = self._last.get(key)
            if last is not None and now - last < self.cooldown:
                return False
            self._last[key] = now
            if len(self._last) > 10000:
                cutoff = now - self.cooldown
                self._last = {k: v for k, v in self._last.items() if v >= cutoff}
            return True

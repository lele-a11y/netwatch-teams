"""Self-learning classification.

Two incremental Naive-Bayes models learn continuously:
* a domain model (character n-grams of the domain name)
* a content model (words from title / meta description / text of the website)

They are trained from: user input (web UI / CLI), false-alarm feedback, LLM verdicts and
confident content verdicts. Over time unknown domains get classified locally without the LLM.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import re
import socket
import tempfile
import threading
import time
from collections import defaultdict
from html import unescape
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

import requests

from .classifier import (CATEGORY_LABELS, DEFAULT_RULES, GAMING, NONE, PROXY, YOUTUBE,
                         base_site, is_valid_domain, normalize, _matches)

log = logging.getLogger(__name__)

CATEGORIES = (YOUTUBE, GAMING, PROXY, NONE)

BENIGN_SEED = [
    "srf.ch", "admin.ch", "ch.ch", "sbb.ch", "post.ch", "swisscom.ch", "20min.ch", "nzz.ch",
    "tagesanzeiger.ch", "blick.ch", "watson.ch", "migros.ch", "coop.ch", "digitec.ch", "galaxus.ch",
    "ricardo.ch", "tutti.ch", "ubs.com", "postfinance.ch", "raiffeisen.ch", "ethz.ch", "uzh.ch",
    "wikipedia.org", "wikimedia.org", "github.com", "gitlab.com", "stackoverflow.com",
    "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com", "sharepoint.com",
    "teams.microsoft.com", "zoom.us", "webex.com", "slack.com", "atlassian.net", "notion.so",
    "dropbox.com", "adobe.com", "canva.com", "duden.de", "leo.org", "deepl.com", "linguee.com",
    "amazon.com", "linkedin.com", "salesforce.com", "zendesk.com", "mozilla.org", "ubuntu.com",
    "python.org", "npmjs.com", "docker.com", "openai.com", "anthropic.com", "dell.com", "hp.com",
    "lenovo.com", "brother.com", "weather.com", "meteoswiss.admin.ch", "google-analytics.com",
    "doubleclick.net", "sentry.io", "datadoghq.com", "newrelic.com", "okta.com", "zscaler.net",
    "cloudfront.net", "fastly.net", "jsdelivr.net", "unpkg.com", "fonts.net", "typekit.net",
]

CONTENT_SEED = {
    YOUTUBE: [
        "youtube watch videos subscribe channel playlist shorts trending music video stream creators",
        "video platform watch free videos online clips vlog upload share comments likes",
    ],
    GAMING: [
        "play free online games now browser games action racing shooter puzzle multiplayer io games",
        "unblocked games play at school top games new games high score level arcade",
        "multiplayer survival battle arena kart shooter players leaderboard skins weapons craft build",
        "spiele kostenlos online spielen browserspiele gratis spiele jetzt spielen",
        "game store download games launcher steam epic esports tournament gamer clan",
    ],
    PROXY: [
        "web proxy unblock websites browse anonymously hide your ip free proxy server",
        "cloud browser virtual browser run a browser in the cloud bypass filters unblocker",
        "free vpn anonymous surfing access blocked sites school filter bypass enter url",
    ],
    NONE: [
        "news weather sport politics economy switzerland world latest articles",
        "login sign in account password email calendar documents office productivity",
        "shop online buy products price delivery cart checkout order customer service",
        "documentation api reference developer guide install configure support help center",
        "bank payments credit card mortgage savings account ebanking",
        "school education learning course university students teachers research library",
        "nachrichten wetter sport politik wirtschaft schweiz anmelden konto bestellen",
        "cookies privacy policy terms conditions imprint impressum datenschutz contact jobs careers",
        "company products solutions services customers partners investors press about team",
    ],
}

STOPWORDS = set("""
the and for you your with are this that from our all not can will has have was were its more about
into out over use using get new one also any how what when who why which their they them his her
der die das und ist sind ein eine einer eines mit von für auf den dem des sie wir ihr ihre oder
nicht auch als bei aus zum zur wie was wenn noch nur mehr hier über unter sich man kann werden
les des une pour avec sur dans est
""".split())

_BLOCK_PAGE = re.compile(
    r"(just a moment|attention required|access denied|zugriff verweigert|anfrage wurde blockiert|"
    r"request (was |has been )?blocked|enable javascript and cookies|captcha|are you a robot|"
    r"checking your browser|ddos protection|cf-chl|bot detection|unusual traffic)", re.I)

_TEXT_TOKEN = re.compile(r"[a-zA-ZäöüÄÖÜéèàß0-9]{3,30}")
_TAG_RE = re.compile(r"<[^>]+>")
_DROP_RE = re.compile(r"<(script|style|noscript|svg)\b.*?</\1>", re.S | re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_META_RE = re.compile(
    r"<meta\s+[^>]*(?:name|property)=[\"'](?:description|keywords|og:title|og:description)[\"'][^>]*>",
    re.I)
_CONTENT_ATTR = re.compile(r"content=[\"']([^\"']*)[\"']", re.I)


def domain_features(domain: str) -> list[str]:
    d = normalize(domain)
    if d.startswith("www."):
        d = d[4:]
    parts = d.split(".")
    feats = [f"tld:{parts[-1]}"]
    name = ".".join(parts[:-1]) or d
    for label in re.split(r"[.\-]", name):
        if label:
            feats.append(f"lbl:{label}")
    s = f"^{name}$"
    for n in (3, 4, 5):
        feats += [f"g:{s[i:i + n]}" for i in range(len(s) - n + 1)]
    return feats


def text_features(text: str) -> list[str]:
    return [f"w:{w}" for w in (t.lower() for t in _TEXT_TOKEN.findall(text)) if w not in STOPWORDS][:600]


class NaiveBayes:
    """Multinomial Naive Bayes with incremental updates and tempered (calibrated) probabilities."""

    def __init__(self, temperature: float = 1.0):
        self.temperature = temperature
        self.feat_counts: dict[str, dict[str, int]] = {c: defaultdict(int) for c in CATEGORIES}
        self.total_feats: dict[str, int] = {c: 0 for c in CATEGORIES}
        self.doc_counts: dict[str, int] = {c: 0 for c in CATEGORIES}
        self.vocab: set[str] = set()

    def learn(self, feats: list[str], cls: str, weight: int = 1) -> None:
        if cls not in CATEGORIES or not feats:
            return
        self.doc_counts[cls] += weight
        for f in feats:
            self.feat_counts[cls][f] += weight
            self.total_feats[cls] += weight
            self.vocab.add(f)

    def unlearn(self, feats: list[str], cls: str, weight: int = 1) -> None:
        if cls not in CATEGORIES or not feats:
            return
        self.doc_counts[cls] = max(0, self.doc_counts[cls] - weight)
        for f in feats:
            c = self.feat_counts[cls].get(f, 0)
            if c:
                dec = min(c, weight)
                self.feat_counts[cls][f] = c - dec
                self.total_feats[cls] -= dec

    @property
    def trained(self) -> bool:
        return sum(1 for c in CATEGORIES if self.doc_counts[c] > 0) >= 2

    def predict(self, feats: list[str], min_known: int = 1) -> tuple[str, float, dict[str, float]]:
        known = [f for f in feats if f in self.vocab]
        if not self.trained or not known or len(set(known)) < min_known:
            return NONE, 0.0, {}
        total_docs = sum(self.doc_counts.values())
        v = len(self.vocab)
        scores = {}
        for c in CATEGORIES:
            if self.doc_counts[c] == 0:
                continue
            denom = self.total_feats[c] + v
            ll = sum(math.log((self.feat_counts[c].get(f, 0) + 1) / denom) for f in known)
            # Average per feature so long inputs do not produce absurdly confident posteriors.
            scores[c] = math.log(self.doc_counts[c] / total_docs) / len(known) + ll / len(known)
        m = max(scores.values())
        exp = {c: math.exp((s - m) * self.temperature) for c, s in scores.items()}
        z = sum(exp.values())
        probs = {c: e / z for c, e in exp.items()}
        best = max(probs, key=probs.get)
        return best, probs[best], probs

    def to_dict(self) -> dict:
        return {
            "feat_counts": {c: {f: n for f, n in fc.items() if n} for c, fc in self.feat_counts.items()},
            "doc_counts": self.doc_counts,
        }

    @classmethod
    def from_dict(cls, data: dict, temperature: float = 1.0) -> "NaiveBayes":
        nb = cls(temperature)
        for c in CATEGORIES:
            fc = data.get("feat_counts", {}).get(c, {})
            nb.feat_counts[c] = defaultdict(int, fc)
            nb.total_feats[c] = sum(fc.values())
            nb.doc_counts[c] = data.get("doc_counts", {}).get(c, 0)
            nb.vocab.update(fc)
        return nb


def _is_public_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)


def fetch_page_text(domain: str, timeout: float = 6.0, max_bytes: int = 300_000) -> str:
    """Fetch title/meta/visible text of a public website. Refuses private/internal addresses."""
    url = f"https://{domain}/"
    headers = {"User-Agent": "Mozilla/5.0 (netwatch site classifier)", "Accept-Language": "de,en;q=0.8"}
    for _ in range(4):
        host = urlparse(url).hostname or ""
        if not _is_public_host(host):
            return ""
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False, stream=True)
        except requests.RequestException:
            if url.startswith("https://"):
                url = "http://" + url[8:]
                continue
            return ""
        if r.is_redirect and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        if r.status_code != 200 or "html" not in r.headers.get("Content-Type", "html"):
            r.close()
            return ""
        raw = b""
        for chunk in r.iter_content(16384):
            raw += chunk
            if len(raw) >= max_bytes:
                break
        r.close()
        text = extract_text(raw.decode(r.encoding or "utf-8", "ignore"))
        # Bot-protection / error pages say nothing about the site and contain misleading words.
        return "" if _BLOCK_PAGE.search(text[:3000]) else text
    return ""


def extract_text(html: str) -> str:
    parts = []
    m = _TITLE_RE.search(html)
    if m:
        parts.append(m.group(1))
    for tag in _META_RE.findall(html):
        c = _CONTENT_ATTR.search(tag)
        if c:
            parts.append(c.group(1))
    body = _TAG_RE.sub(" ", _DROP_RE.sub(" ", html))
    parts.append(body[:5000])
    return re.sub(r"\s+", " ", unescape(" ".join(parts))).strip()


def parse_site_input(value: str) -> str:
    """Accept 'https://www.example.com/path', 'example.com', '*.example.com' -> 'example.com'."""
    v = value.strip()
    if "://" not in v:
        v = "http://" + v.lstrip("*.")
    host = normalize(urlparse(v).hostname or "")
    if host.startswith("www."):
        host = host[4:]
    if not is_valid_domain(host):
        raise ValueError(f"Ungültige Domain: {value!r}")
    return host


class LearningStore:
    """Persistent learned sites + self-learning models (JSON files in data_dir)."""

    def __init__(self, data_dir: str, fetch_content: bool = True, threshold: float = 0.85,
                 none_threshold: float = 0.9, fetcher: Callable[[str], str] = fetch_page_text):
        self.data_dir = data_dir
        self.fetch_content = fetch_content
        self.threshold = threshold
        self.none_threshold = none_threshold
        self.fetcher = fetcher
        self.lock = threading.RLock()
        self.version = 0
        self.sites: dict[str, dict] = {}   # authoritative: user input / feedback
        self.auto: dict[str, dict] = {}    # self-learned verdicts (ai/content/ml), cached per site
        self.domain_model = NaiveBayes(temperature=3.0)
        self.content_model = NaiveBayes(temperature=5.0)
        self.stats = defaultdict(int)
        self._mtime = 0.0
        os.makedirs(data_dir, exist_ok=True)
        self._load()

    # ---------- persistence ----------
    @property
    def path(self) -> str:
        return os.path.join(self.data_dir, "learned.json")

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.sites = data.get("sites", {})
            self.auto = data.get("auto", {})
            self.domain_model = NaiveBayes.from_dict(data.get("domain_model", {}), 3.0)
            self.content_model = NaiveBayes.from_dict(data.get("content_model", {}), 5.0)
            self.stats = defaultdict(int, data.get("stats", {}))
            self._mtime = os.path.getmtime(self.path)
            log.info("Lernspeicher geladen: %d Seiten, %d gelernte Verdikte", len(self.sites), len(self.auto))
        except FileNotFoundError:
            self._bootstrap()
            self.save()
        except (OSError, ValueError) as e:
            log.error("Lernspeicher %s unlesbar (%s) – starte neu", self.path, e)
            self._bootstrap()

    def save(self) -> None:
        with self.lock:
            data = {
                "sites": self.sites, "auto": self.auto, "stats": dict(self.stats),
                "domain_model": self.domain_model.to_dict(),
                "content_model": self.content_model.to_dict(),
            }
            fd, tmp = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, self.path)
            self._mtime = os.path.getmtime(self.path)

    def refresh(self) -> None:
        """Reload if another process (CLI `add`, web UI, monitor) changed the file."""
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return
        if mtime != self._mtime:
            with self.lock:
                if mtime != self._mtime:
                    self._load()
                    self.version += 1

    def _bootstrap(self) -> None:
        for cat, domains in DEFAULT_RULES.items():
            for d in domains:
                self.domain_model.learn(domain_features(d), cat)
        for d in BENIGN_SEED:
            self.domain_model.learn(domain_features(d), NONE)
        for cat, texts in CONTENT_SEED.items():
            for t in texts:
                self.content_model.learn(text_features(t), cat)

    # ---------- queries ----------
    def lookup(self, domain: str) -> Optional[tuple[str, dict]]:
        """Return (matched_site, entry) for user-taught sites (most specific match wins)."""
        d = normalize(domain)
        self.refresh()
        with self.lock:
            best = None
            for site, entry in self.sites.items():
                if _matches(d, site) and (best is None or len(site) > len(best[0])):
                    best = (site, entry)
            return best

    def cached(self, site: str) -> Optional[dict]:
        with self.lock:
            return self.auto.get(site)

    def predict(self, domain: str) -> Optional[tuple[str, float, str, str]]:
        """Self-learned prediction -> (category, confidence, source, reason) or None if unsure."""
        site = base_site(normalize(domain))
        with self.lock:
            cat, p, _ = self.domain_model.predict(domain_features(site))
        if p >= (self.none_threshold if cat == NONE else self.threshold):
            self.stats["ml_hits"] += 1
            return cat, p, "ml", f"gelernt aus Domainname ({p:.0%})"

        if not self.fetch_content:
            return None
        text = self.fetcher(site)
        if not text:
            return None
        with self.lock:
            ccat, cp, _ = self.content_model.predict(text_features(text), min_known=5)
        if cp >= (self.none_threshold if ccat == NONE else self.threshold):
            self.stats["content_hits"] += 1
            self.remember(site, ccat, "content", f"Seiteninhalt ({cp:.0%})", text=None, train_content=False)
            return ccat, cp, "content", f"Seiteninhalt ({cp:.0%})"
        self._last_text = (site, text)
        return None

    def last_text_for(self, site: str) -> Optional[str]:
        lt = getattr(self, "_last_text", None)
        return lt[1] if lt and lt[0] == site else None

    # ---------- learning ----------
    def remember(self, site: str, category: str, source: str, reason: str = "",
                 text: Optional[str] = None, train_content: bool = True) -> None:
        """Cache a self-learned verdict and train the models with it."""
        self.refresh()
        with self.lock:
            self.auto[site] = {"category": category, "source": source, "reason": reason, "ts": int(time.time())}
            self.domain_model.learn(domain_features(site), category)
            if text and train_content:
                self.content_model.learn(text_features(text), category)
            self.stats[f"learned_{source}"] += 1
            self.version += 1
        self.save()

    def add_site(self, value: str, category: str, source: str = "user", note: str = "",
                 fetch: Optional[bool] = None) -> str:
        if category not in CATEGORIES:
            raise ValueError(f"Unbekannte Kategorie: {category}")
        site = parse_site_input(value)
        text = ""
        if fetch if fetch is not None else self.fetch_content:
            try:
                text = self.fetcher(site)
            except Exception as e:  # content is optional
                log.info("Inhalt von %s nicht abrufbar: %s", site, e)
        self.refresh()
        with self.lock:
            old = self.sites.get(site)
            if old:
                self.domain_model.unlearn(domain_features(site), old["category"], 3)
            self.sites[site] = {"category": category, "source": source, "note": note[:200],
                                "added": time.strftime("%Y-%m-%d %H:%M"), "has_content": bool(text)}
            # User input is weighted higher than automatic verdicts.
            self.domain_model.learn(domain_features(site), category, 3)
            if text:
                self.content_model.learn(text_features(text), category, 3)
            self.auto.pop(site, None)
            self.stats["learned_user"] += 1
            self.version += 1
        self.save()
        log.info("Gelernt: %s -> %s (%s%s)", site, category, source, ", mit Seiteninhalt" if text else "")
        return site

    def remove_site(self, value: str) -> bool:
        site = parse_site_input(value)
        self.refresh()
        with self.lock:
            entry = self.sites.pop(site, None)
            if entry:
                self.domain_model.unlearn(domain_features(site), entry["category"], 3)
                self.version += 1
        if entry:
            self.save()
        return entry is not None

    def summary(self) -> dict:
        self.refresh()
        with self.lock:
            return {
                "sites": len(self.sites),
                "auto": len(self.auto),
                "domain_docs": dict(self.domain_model.doc_counts),
                "content_docs": dict(self.content_model.doc_counts),
                "vocab": len(self.domain_model.vocab) + len(self.content_model.vocab),
                "stats": dict(self.stats),
                "labels": CATEGORY_LABELS,
            }

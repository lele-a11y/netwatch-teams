"""Domain classification: learned sites + static rules + keyword heuristics + self-learning model + optional LLM."""
from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger(__name__)

YOUTUBE = "youtube"
GAMING = "gaming"
PROXY = "proxy"
NONE = "none"

CATEGORY_LABELS = {
    YOUTUBE: "YouTube / Video",
    GAMING: "Gaming",
    PROXY: "Proxy / Cloud-Browser",
}

DEFAULT_RULES: dict[str, list[str]] = {
    YOUTUBE: [
        "youtube.com", "youtu.be", "youtube-nocookie.com", "youtubei.googleapis.com",
        "youtube.googleapis.com", "googlevideo.com", "ytimg.com", "yt3.ggpht.com",
        "youtubekids.com",
    ],
    GAMING: [
        "steampowered.com", "steamcommunity.com", "steamstatic.com", "epicgames.com",
        "unrealengine.com", "roblox.com", "rbxcdn.com", "minecraft.net", "mojang.com",
        "twitch.tv", "ttvnw.net", "riotgames.com", "leagueoflegends.com",
        "playvalorant.com", "ea.com", "origin.com", "battle.net", "blizzard.com",
        "xbox.com", "xboxlive.com", "playstation.com", "playstation.net",
        "nintendo.com", "ubisoft.com", "gog.com", "itch.io", "miniclip.com",
        "poki.com", "crazygames.com", "coolmathgames.com", "friv.com", "y8.com",
        "kongregate.com", "agame.com", "addictinggames.com", "armorgames.com",
        "krunker.io", "slither.io", "agar.io", "diep.io", "shellshock.io",
        "geforcenow.com", "nvidiagrid.net", "xcloud.xbox.com", "fortnite.com",
        "chess.com", "lichess.org", "gameflare.com", "kizi.com", "silvergames.com",
        "1001spiele.de", "spielaffe.de", "jetztspielen.de", "gamepix.com",
        "geforcenow.nvidia.com", "now.gg", "bloxd.io", "moomoo.io", "smashkarts.io",
        "1v1.lol", "zombsroyale.io", "surviv.io", "skribbl.io", "gartic.io", "venge.io",
    ],
    PROXY: [
        "browser.lol", "hyperbeam.com", "neverinstall.com", "browserling.com",
        "croxyproxy.com", "croxyproxy.rocks", "proxysite.com", "hide.me",
        "hidester.com", "kproxy.com", "proxyium.com", "blockaway.net",
        "4everproxy.com", "megaproxy.com", "proxyscrape.com", "whoer.net",
        "vpnbook.com", "hidemyass.com", "ultrasurf.us", "psiphon.ca",
        "torproject.org", "holyunblocker.com", "titaniumnetwork.org",
        "rammerhead.org", "interstellar.network", "nebulaservices.org",
        "unblockit.ca", "proxyfree.com", "plainproxies.com",
    ],
}

KEYWORDS: dict[str, list[str]] = {
    YOUTUBE: ["youtube", "ytimg", "googlevideo"],
    GAMING: [
        "game", "games", "gaming", "spiele", "spielen", "unblockedgames",
        "unblocked-games", "steam", "roblox", "minecraft", "fortnite", "epicgames",
        "esport", "arcade", "slither", "krunker", ".io-games", "1v1lol", "1v1.lol",
    ],
    PROXY: [
        "proxy", "unblock", "unblocker", "webproxy", "croxy", "cloudbrowser",
        "virtualbrowser", "browserling", "hyperbeam", "rammerhead", "ultraviolet",
        "holyub", "titanium",
    ],
}

# Sites that should never raise an alert (allow-list). Unlike DEFAULT_IGNORE this wins even over
# rules/keywords and user-taught categories, so an explicitly allowed site is truly never reported.
DEFAULT_ALLOW = [
    "dungeongame.ch",
]

# Infrastructure that should never trigger (CDNs, OS telemetry, etc.).
DEFAULT_IGNORE = [
    "in-addr.arpa", "ip6.arpa", "local", "localhost", "lan", "home.arpa",
    "microsoft.com", "windowsupdate.com", "apple.com", "icloud.com",
    "gstatic.com", "google.com", "googleapis.com", "cloudflare.com",
    "akamaiedge.net", "akamai.net", "msftconnecttest.com",
]

_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")


@dataclass(frozen=True)
class Verdict:
    category: str
    source: str  # allow | rule | keyword | ai | cache | ignore
    site: str    # registrable-ish domain used for grouping alerts
    reason: str = ""

    @property
    def flagged(self) -> bool:
        return self.category != NONE


def normalize(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    return d


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    return all(_LABEL_RE.match(p) for p in domain.split("."))


def _matches(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def base_site(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class Classifier:
    def __init__(
        self,
        rules: Optional[dict[str, list[str]]] = None,
        ignore: Optional[list[str]] = None,
        use_keywords: bool = True,
        ai: Optional["AIClassifier"] = None,
        learner=None,
        allow: Optional[list[str]] = None,
    ):
        self.rules = {k: [normalize(s) for s in v] for k, v in (rules or DEFAULT_RULES).items()}
        self.ignore = [normalize(s) for s in (ignore if ignore is not None else DEFAULT_IGNORE)]
        self.allow = [normalize(s) for s in (allow if allow is not None else DEFAULT_ALLOW)]
        self.use_keywords = use_keywords
        self.ai = ai
        self.learner = learner

    def classify(self, domain: str) -> Verdict:
        d = normalize(domain)
        if not is_valid_domain(d):
            return Verdict(NONE, "ignore", d, "invalid domain")

        for s in self.allow:
            if _matches(d, s):
                return Verdict(NONE, "allow", base_site(d), f"ausgeschlossen ({s})")

        if self.learner is not None:
            hit = self.learner.lookup(d)
            if hit:
                site, entry = hit
                return Verdict(entry["category"], "learned", site, entry.get("note") or "von Hand gemeldet")

        for category, suffixes in self.rules.items():
            for s in suffixes:
                if _matches(d, s):
                    return Verdict(category, "rule", s, f"matches {s}")

        for s in self.ignore:
            if _matches(d, s):
                return Verdict(NONE, "ignore", base_site(d), f"ignored ({s})")

        if self.use_keywords:
            hits = [(len(kw), cat, kw) for cat, kws in KEYWORDS.items() for kw in kws if kw in d]
            if hits:
                _, category, kw = max(hits)
                return Verdict(category, "keyword", base_site(d), f"keyword '{kw}'")

        site = base_site(d)
        if self.learner is not None:
            cached = self.learner.cached(site)
            if cached:
                return Verdict(cached["category"], "cache", site, cached.get("reason", ""))
            pred = self.learner.predict(d)
            if pred:
                cat, _, source, reason = pred
                if source == "ml":
                    self.learner.remember(site, cat, "ml", reason, train_content=False)
                return Verdict(cat, source, site, reason)

        if self.ai is not None:
            v = self.ai.classify(d)
            if self.learner is not None and v.source == "ai" and v.reason != "ai error":
                self.learner.remember(site, v.category, "ai", v.reason, text=self.learner.last_text_for(site))
            return v

        return Verdict(NONE, "default", site)


AI_PROMPT = """You classify internet domains seen in network traffic of a school/office network.
Categories:
- "youtube": YouTube or YouTube mirrors/frontends (e.g. invidious, piped)
- "gaming": online games, browser game portals, game stores/launchers, game streaming
- "proxy": web proxies, unblockers, cloud/virtual browsers (like browser.lol, hyperbeam), VPN sites used to bypass filters
- "none": anything else, including CDNs, APIs, ads, telemetry and generic infrastructure
Answer ONLY with JSON: {"category": "<youtube|gaming|proxy|none>", "reason": "<max 10 words>"}
Domain: """


class AIClassifier:
    """Classifies unknown domains via an OpenAI-compatible chat API (OpenAI, Ollama, LM Studio...).

    Results are cached per registrable site so each site is asked about only once.
    """

    def __init__(self, base_url: str, model: str, api_key: str = "", timeout: float = 15.0,
                 cache_file: Optional[str] = None):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.cache_file = cache_file
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        if cache_file:
            try:
                with open(cache_file, encoding="utf-8") as f:
                    self._cache = json.load(f)
            except FileNotFoundError:
                pass
            except (OSError, ValueError) as e:
                log.warning("Could not read AI cache %s: %s", cache_file, e)

    def _save(self) -> None:
        if not self.cache_file:
            return
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=1, sort_keys=True)
        except OSError as e:
            log.warning("Could not write AI cache: %s", e)

    def _ask(self, domain: str) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "user", "content": AI_PROMPT + domain}],
        }
        r = requests.post(self.url, headers=headers, json=body, timeout=self.timeout)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", text, re.S)
        data = json.loads(m.group(0) if m else text)
        cat = str(data.get("category", NONE)).lower()
        if cat not in (YOUTUBE, GAMING, PROXY, NONE):
            cat = NONE
        return {"category": cat, "reason": str(data.get("reason", ""))[:120]}

    def classify(self, domain: str) -> Verdict:
        site = base_site(domain)
        with self._lock:
            cached = self._cache.get(site)
        if cached is not None:
            return Verdict(cached["category"], "cache", site, cached.get("reason", ""))
        try:
            result = self._ask(site)
        except Exception as e:  # network/parse errors must never stop monitoring
            log.warning("AI classification failed for %s: %s", site, e)
            return Verdict(NONE, "ai", site, "ai error")
        with self._lock:
            self._cache[site] = result
            self._save()
        log.info("AI: %s -> %s (%s)", site, result["category"], result["reason"])
        return Verdict(result["category"], "ai", site, result["reason"])

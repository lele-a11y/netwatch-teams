"""Small web UI + JSON API: teach new websites, mark false alarms, test domains, see alerts."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

from .classifier import CATEGORY_LABELS, NONE
from .learning import CATEGORIES, LearningStore, parse_site_input

log = logging.getLogger(__name__)

LABELS = {**CATEGORY_LABELS, NONE: "Erlaubt (kein Alarm)"}


def load_secret(data_dir: str, configured: str = "") -> str:
    if configured:
        return configured
    path = os.path.join(data_dir, "secret.key")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        s = secrets.token_hex(32)
        os.makedirs(data_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(s)
        os.chmod(path, 0o600)
        return s


class Signer:
    def __init__(self, secret: str):
        self.key = secret.encode()

    def sign(self, *parts: str) -> str:
        return hmac.new(self.key, "|".join(parts).encode(), hashlib.sha256).hexdigest()[:32]

    def verify(self, sig: str, *parts: str) -> bool:
        return hmac.compare_digest(sig or "", self.sign(*parts))

    def feedback_url(self, public_url: str, site: str, category: str = NONE) -> str:
        q = urlencode({"site": site, "cat": category, "sig": self.sign("feedback", site, category)})
        return f"{public_url.rstrip('/')}/feedback?{q}"


CSS = """
body{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#f4f5f7;color:#222}
header{background:#464eb8;color:#fff;padding:14px 24px}header h1{margin:0;font-size:20px}
main{max-width:1100px;margin:0 auto;padding:16px}
section{background:#fff;border-radius:8px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 3px #0002}
h2{margin-top:0;font-size:17px}
input,select,button{font-size:14px;padding:7px 9px;border:1px solid #bbb;border-radius:5px}
input[name=site],input[name=domain]{width:320px}button{background:#464eb8;color:#fff;border:0;cursor:pointer}
button.ghost{background:#eee;color:#333}button.danger{background:#c4314b}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;color:#fff}
.youtube{background:#c4314b}.gaming{background:#7a3eb1}.proxy{background:#d67f00}.none{background:#2e8540}
.msg{padding:10px 14px;border-radius:6px;margin-bottom:12px}.ok{background:#e3f4e8}.err{background:#fbe3e6}
.muted{color:#777;font-size:13px}form.inline{display:inline}
"""


def tag(cat: str) -> str:
    return f'<span class="tag {escape(cat)}">{escape(LABELS.get(cat, cat))}</span>'


class App:
    def __init__(self, store: LearningStore, classifier, monitor=None, password: str = "",
                 secret: str = "", public_url: str = ""):
        self.store = store
        self.classifier = classifier
        self.monitor = monitor
        self.password = password
        self.signer = Signer(secret or secrets.token_hex(32))
        self.public_url = public_url
        self.csrf = self.signer.sign("csrf")

    # ---------------- rendering ----------------
    def page(self, body: str, title: str = "netwatch") -> str:
        return (f"<!doctype html><html lang=de><head><meta charset=utf-8><title>{escape(title)}</title>"
                f"<meta name=viewport content='width=device-width,initial-scale=1'><style>{CSS}</style></head>"
                f"<body><header><h1>netwatch – Webseiten-Überwachung</h1></header><main>{body}</main></body></html>")

    def options(self, selected: str = "") -> str:
        return "".join(f'<option value="{c}"{" selected" if c == selected else ""}>{escape(LABELS[c])}</option>'
                       for c in CATEGORIES)

    def dashboard(self, msg: str = "", ok: bool = True, test: Optional[str] = None) -> str:
        csrf = f'<input type=hidden name=csrf value="{self.csrf}">'
        out = []
        if msg:
            out.append(f'<div class="msg {"ok" if ok else "err"}">{escape(msg)}</div>')

        out.append(f"""<section><h2>Neue Webseite melden</h2>
<form method=post action="/sites">{csrf}
<input name=site placeholder="z.B. https://www.coolmathgames.com oder neueseite.io" required>
<select name=category>{self.options("gaming")}</select>
<input name=note placeholder="Notiz (optional)">
<button>Hinzufügen &amp; lernen</button></form>
<p class=muted>Die Domain wird ab sofort erkannt (inkl. Subdomains). Zusätzlich lernt die KI aus
Domainname und Seiteninhalt und erkennt dadurch ähnliche, unbekannte Seiten selbst.</p></section>""")

        test_html = ""
        if test is not None:
            try:
                v = self.classifier.classify(test)
                test_html = (f"<p><b>{escape(test)}</b> → {tag(v.category)} "
                             f"<span class=muted>via {escape(v.source)} · {escape(v.reason)}</span></p>")
            except Exception as e:
                test_html = f"<p class=err>{escape(str(e))}</p>"
        out.append(f"""<section><h2>Domain testen</h2><form method=get action="/">
<input name=domain placeholder="z.B. krunker.io" value="{escape(test or '')}"> <button>Prüfen</button></form>
{test_html}</section>""")

        if self.monitor is not None:
            rows = []
            for ev in list(self.monitor.recent)[::-1][:50]:
                client = f"{ev.hostname} ({ev.client})" if ev.hostname else ev.client
                rows.append(
                    f"<tr><td>{ev.ts:%d.%m. %H:%M:%S}</td><td>{escape(client)}</td><td>{escape(ev.domain)}</td>"
                    f"<td>{tag(ev.category)}</td><td class=muted>{escape(ev.detected_by)}</td><td>"
                    f'<form class=inline method=post action="/sites">{csrf}'
                    f'<input type=hidden name=site value="{escape(ev.site)}"><input type=hidden name=category value=none>'
                    f'<input type=hidden name=note value="Falsch-Alarm"><button class=ghost>Falsch-Alarm</button></form>'
                    f"</td></tr>")
            out.append("<section><h2>Letzte Alarme</h2>" + (
                "<table><tr><th>Zeit</th><th>Gerät</th><th>Domain</th><th>Kategorie</th><th>Erkannt</th><th></th></tr>"
                + "".join(rows) + "</table>" if rows else "<p class=muted>Noch keine Alarme.</p>") + "</section>")

        with self.store.lock:
            sites = sorted(self.store.sites.items(), key=lambda kv: kv[1].get("added", ""), reverse=True)
            auto = sorted(self.store.auto.items(), key=lambda kv: kv[1].get("ts", 0), reverse=True)[:100]
        rows = "".join(
            f"<tr><td>{escape(s)}</td><td>{tag(e['category'])}</td><td class=muted>{escape(e.get('source', ''))}</td>"
            f"<td class=muted>{escape(e.get('note', ''))}</td><td class=muted>{escape(e.get('added', ''))}</td><td>"
            f'<form class=inline method=post action="/sites/delete">{csrf}<input type=hidden name=site value="{escape(s)}">'
            f"<button class=danger>Löschen</button></form></td></tr>" for s, e in sites)
        out.append("<section><h2>Gemeldete Webseiten</h2>" + (
            "<table><tr><th>Domain</th><th>Kategorie</th><th>Quelle</th><th>Notiz</th><th>Hinzugefügt</th><th></th></tr>"
            + rows + "</table>" if rows else "<p class=muted>Noch keine.</p>") + "</section>")

        arows = "".join(
            f"<tr><td>{escape(s)}</td><td>{tag(e['category'])}</td><td class=muted>{escape(e.get('source', ''))}</td>"
            f"<td class=muted>{escape(e.get('reason', ''))}</td><td>"
            + ("" if e["category"] == NONE else
               f'<form class=inline method=post action="/sites">{csrf}<input type=hidden name=site value="{escape(s)}">'
               f'<input type=hidden name=category value=none><input type=hidden name=note value="Korrektur">'
               f"<button class=ghost>Falsch</button></form>")
            + "</td></tr>" for s, e in auto)
        out.append("<section><h2>Von der KI selbst gelernt</h2>" + (
            "<table><tr><th>Seite</th><th>Kategorie</th><th>Quelle</th><th>Begründung</th><th></th></tr>"
            + arows + "</table>" if arows else "<p class=muted>Noch nichts – die KI lernt, sobald unbekannte Seiten auftauchen.</p>")
            + "</section>")

        s = self.store.summary()
        out.append(f"""<section><h2>KI-Status</h2><p class=muted>
Trainingsbeispiele Domain-Modell: {sum(s['domain_docs'].values())} · Inhalts-Modell: {sum(s['content_docs'].values())} ·
Merkmale: {s['vocab']} · lokal erkannt (ohne LLM): {s['stats'].get('ml_hits', 0) + s['stats'].get('content_hits', 0)} ·
vom LLM gelernt: {s['stats'].get('learned_ai', 0)}</p>
<p class=muted>API: <code>curl -u admin:PASSWORT -X POST -H 'Content-Type: application/json'
-d '{{"site":"neueseite.io","category":"gaming"}}' {escape(self.public_url or 'http://host:8080')}/api/sites</code></p></section>""")
        return self.page("".join(out))

    def feedback_page(self, site: str, cat: str, sig: str, done: bool = False) -> str:
        if done:
            return self.page(f'<section><div class="msg ok">Danke! <b>{escape(site)}</b> ist jetzt als '
                             f'{tag(cat)} gespeichert – die KI hat daraus gelernt.</div></section>')
        return self.page(f"""<section><h2>Rückmeldung</h2><p><b>{escape(site)}</b> als {tag(cat)} markieren?</p>
<form method=post action="/feedback"><input type=hidden name=site value="{escape(site)}">
<input type=hidden name=cat value="{escape(cat)}"><input type=hidden name=sig value="{escape(sig)}">
<button>Bestätigen</button></form></section>""")


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "netwatch"

        def log_message(self, fmt, *args):
            log.debug("web: " + fmt, *args)

        # ---------- helpers ----------
        def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8", headers=None):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False, default=str), "application/json; charset=utf-8")

        def _redirect(self, location: str) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _authorized(self) -> bool:
            if not app.password:
                return True
            h = self.headers.get("Authorization", "")
            if h.startswith("Basic "):
                try:
                    user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
                except (ValueError, UnicodeDecodeError):
                    return False
                return hmac.compare_digest(pw.encode(), app.password.encode())
            return False

        def _deny(self) -> None:
            self._send(401, "Login erforderlich", "text/plain; charset=utf-8",
                       {"WWW-Authenticate": 'Basic realm="netwatch"'})

        def _body(self) -> dict:
            n = min(int(self.headers.get("Content-Length") or 0), 65536)
            raw = self.rfile.read(n).decode("utf-8", "ignore")
            if "json" in self.headers.get("Content-Type", ""):
                try:
                    data = json.loads(raw or "{}")
                    return data if isinstance(data, dict) else {}
                except ValueError:
                    return {}
            return {k: v[0] for k, v in parse_qs(raw).items()}

        # ---------- routing ----------
        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/healthz":
                return self._send(200, "ok", "text/plain")
            if u.path == "/feedback":
                site, cat, sig = q.get("site", ""), q.get("cat", NONE), q.get("sig", "")
                if cat not in CATEGORIES or not app.signer.verify(sig, "feedback", site, cat):
                    return self._send(403, app.page("<section>Ungültiger Link.</section>"))
                return self._send(200, app.feedback_page(site, cat, sig))
            if not self._authorized():
                return self._deny()
            if u.path == "/":
                return self._send(200, app.dashboard(q.get("msg", ""), q.get("ok", "1") == "1",
                                                     test=q.get("domain") or None))
            if u.path == "/api/sites":
                with app.store.lock:
                    return self._json(200, app.store.sites)
            if u.path == "/api/learned":
                with app.store.lock:
                    return self._json(200, app.store.auto)
            if u.path == "/api/classify":
                v = app.classifier.classify(q.get("domain", ""))
                return self._json(200, {"domain": q.get("domain", ""), "category": v.category,
                                        "source": v.source, "site": v.site, "reason": v.reason})
            if u.path == "/api/alerts" and app.monitor is not None:
                return self._json(200, [ev.__dict__ for ev in list(app.monitor.recent)[::-1]])
            if u.path == "/api/status":
                return self._json(200, app.store.summary())
            self._send(404, "nicht gefunden", "text/plain")

        def do_POST(self):
            u = urlparse(self.path)
            data = self._body()
            if u.path == "/feedback":
                site, cat, sig = data.get("site", ""), data.get("cat", NONE), data.get("sig", "")
                if cat not in CATEGORIES or not app.signer.verify(sig, "feedback", site, cat):
                    return self._send(403, app.page("<section>Ungültiger Link.</section>"))
                app.store.add_site(site, cat, source="feedback", note="Teams-Rückmeldung")
                return self._send(200, app.feedback_page(site, cat, sig, done=True))
            if not self._authorized():
                return self._deny()

            if u.path == "/api/sites":
                try:
                    site = app.store.add_site(str(data.get("site", "")), str(data.get("category", "")),
                                              source="api", note=str(data.get("note", "")))
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                return self._json(201, {"site": site, **app.store.sites[site]})

            if not hmac.compare_digest(data.get("csrf", ""), app.csrf):
                return self._send(403, "CSRF-Token ungültig", "text/plain; charset=utf-8")
            try:
                if u.path == "/sites":
                    site = app.store.add_site(data.get("site", ""), data.get("category", ""),
                                              source="user", note=data.get("note", ""))
                    label = LABELS.get(app.store.sites[site]["category"])
                    return self._redirect("/?" + urlencode({"msg": f"{site} gespeichert als {label}"}))
                if u.path == "/sites/delete":
                    site = parse_site_input(data.get("site", ""))
                    app.store.remove_site(site)
                    return self._redirect("/?" + urlencode({"msg": f"{site} entfernt"}))
            except ValueError as e:
                return self._redirect("/?" + urlencode({"msg": str(e), "ok": "0"}))
            self._send(404, "nicht gefunden", "text/plain")

        def do_DELETE(self):
            if not self._authorized():
                return self._deny()
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/api/sites":
                try:
                    removed = app.store.remove_site(q.get("site", ""))
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                return self._json(200 if removed else 404, {"removed": removed})
            self._send(404, "nicht gefunden", "text/plain")

    return Handler


def start_web(app: App, host: str, port: int, background: bool = True) -> ThreadingHTTPServer:
    if not app.password and host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Kein web.password gesetzt – Web-Oberfläche nur auf 127.0.0.1 erreichbar.")
        host = "127.0.0.1"
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    log.info("Web-Oberfläche: http://%s:%d/", host, port)
    if background:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    else:
        httpd.serve_forever()
    return httpd

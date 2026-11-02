import base64
import json
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from netwatch import classifier as C
from netwatch.devices import DeviceRegistry
from netwatch.learning import (LearningStore, NaiveBayes, domain_features, extract_text,
                               parse_site_input, text_features)
from netwatch.main import DEFAULT_CONFIG, Monitor, _merge, build_classifier
from netwatch.notifier import Event, build_card
from netwatch.web import App, Signer, make_handler
from http.server import ThreadingHTTPServer


class FakeNotifier:
    dry_run = False

    def __init__(self):
        self.sent = []

    def send(self, ev):
        self.sent.append(ev)
        return True


def store(tmp_path, pages=None, **kw):
    pages = pages or {}
    return LearningStore(str(tmp_path / "data"), fetcher=lambda site: pages.get(site, ""), **kw)


@pytest.mark.parametrize("value,expected", [
    ("https://www.Example.com/path?x=1", "example.com"),
    ("example.com", "example.com"),
    ("*.games.example.org", "games.example.org"),
    ("sub.site.io:8080", "sub.site.io"),
])
def test_parse_site_input(value, expected):
    assert parse_site_input(value) == expected


@pytest.mark.parametrize("bad", ["", "nodot", "http://", "bad host.com"])
def test_parse_site_input_rejects(bad):
    with pytest.raises(ValueError):
        parse_site_input(bad)


def test_naive_bayes_learns_and_roundtrips():
    nb = NaiveBayes(temperature=3.0)
    for d in ["playgames.com", "freegames.net", "gamezone.io"]:
        nb.learn(domain_features(d), C.GAMING)
    for d in ["bank.ch", "news.ch", "weather.ch"]:
        nb.learn(domain_features(d), C.NONE)
    cat, p, _ = nb.predict(domain_features("supergames.com"))
    assert cat == C.GAMING and p > 0.5
    nb2 = NaiveBayes.from_dict(json.loads(json.dumps(nb.to_dict())), 3.0)
    assert nb2.predict(domain_features("supergames.com"))[0] == C.GAMING


def test_extract_text():
    html = ("<html><head><title>Play Free Games</title><meta name='description' content='Best io games'>"
            "<script>var x='nope'</script></head><body><h1>Hello</h1></body></html>")
    t = extract_text(html)
    assert "Play Free Games" in t and "Best io games" in t and "Hello" in t and "nope" not in t


def test_user_site_overrides_rules_and_persists(tmp_path):
    s = store(tmp_path, fetch_content=False)
    c = C.Classifier(learner=s)
    assert c.classify("www.chess.com").category == C.GAMING
    s.add_site("https://www.chess.com/play", C.NONE, note="Schach erlaubt")
    v = c.classify("www.chess.com")
    assert (v.category, v.source) == (C.NONE, "learned")
    s.add_site("my-new-site.example", C.PROXY)
    assert c.classify("cdn.my-new-site.example").category == C.PROXY

    s2 = store(tmp_path, fetch_content=False)
    assert s2.lookup("my-new-site.example")[1]["category"] == C.PROXY
    assert s2.remove_site("my-new-site.example")
    assert s2.lookup("my-new-site.example") is None


def test_add_site_learns_from_content(tmp_path):
    page = "Totally Free Browser Shooter – play multiplayer io games online, unblocked, new levels high score"
    s = store(tmp_path, pages={"zqxw.example": page})
    s.add_site("zqxw.example", C.GAMING)
    assert s.sites["zqxw.example"]["has_content"]
    cat, p, _ = s.content_model.predict(text_features("multiplayer shooter games high score"))
    assert cat == C.GAMING


def test_content_model_classifies_unknown_site(tmp_path):
    pages = {"blorptastic.example": "<title>Play free online games</title> unblocked games at school, arcade, "
                                    "racing, shooter, multiplayer io games, play now, high score"}
    s = store(tmp_path, pages={k: extract_text(v) for k, v in pages.items()})
    c = C.Classifier(learner=s)
    v = c.classify("www.blorptastic.example")
    assert (v.category, v.source) == (C.GAMING, "content")
    # self-learned and cached afterwards
    assert s.auto["blorptastic.example"]["category"] == C.GAMING
    assert c.classify("blorptastic.example").source == "cache"


def test_ai_verdicts_are_learned(tmp_path, monkeypatch):
    calls = []

    class FakeAI:
        def classify(self, d):
            calls.append(d)
            return C.Verdict(C.PROXY, "ai", C.base_site(d), "cloud browser")

    s = store(tmp_path, pages={"qqvv.example": "flimflam zorbotron quaxel"})
    c = C.Classifier(learner=s, ai=FakeAI())
    assert c.classify("qqvv.example").category == C.PROXY
    assert c.classify("www.qqvv.example").source == "cache"
    assert len(calls) == 1
    assert s.stats["learned_ai"] == 1
    assert s.content_model.feat_counts[C.PROXY]["w:flimflam"] >= 1


def test_monitor_cache_invalidated_after_teaching(tmp_path):
    cfg = _merge(DEFAULT_CONFIG, {"alerts": {"resolve_hostnames": False}})
    s = store(tmp_path, fetch_content=False)
    n = FakeNotifier()
    m = Monitor(cfg, build_classifier(cfg, s), n, async_send=False)
    m.handle("10.0.0.1", "www.zzz-site.ch", "dns")
    assert n.sent == []
    s.add_site("zzz-site.ch", C.GAMING)
    m.handle("10.0.0.1", "www.zzz-site.ch", "dns")
    assert [e.category for e in n.sent] == [C.GAMING]
    assert list(m.recent)[0].site == "zzz-site.ch"


def test_card_has_feedback_buttons():
    signer = Signer("k")
    ev = Event(client="10.0.0.5", domain="poki.com", category="gaming", site="poki.com", source="dns", detected_by="rule")
    card = build_card(ev, "http://netwatch.lan:8080", signer)["attachments"][0]["content"]
    url = card["actions"][0]["url"]
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    assert q["site"] == "poki.com" and q["cat"] == "none" and signer.verify(q["sig"], "feedback", "poki.com", "none")
    assert "actions" not in build_card(ev)["attachments"][0]["content"]


@pytest.fixture
def web(tmp_path):
    s = store(tmp_path, fetch_content=False)
    cfg = _merge(DEFAULT_CONFIG, {"alerts": {"resolve_hostnames": False}})
    devices = DeviceRegistry(str(tmp_path / "data"), arp_reader=dict, dns_resolver=lambda ip: "", lease_files=[])
    m = Monitor(cfg, build_classifier(cfg, s), FakeNotifier(), async_send=False, devices=devices)
    app = App(s, m.classifier, m, password="geheim", secret="testsecret", public_url="http://x", devices=devices)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", app, m
    httpd.shutdown()


def req(url, data=None, auth=True, json_body=None, method=None):
    headers = {}
    body = None
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(b"admin:geheim").decode()
    if json_body is not None:
        body = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(urllib.request.Request(url, data=body, headers=headers, method=method))
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def test_web_requires_auth(web):
    base, _, _ = web
    assert req(base + "/", auth=False)[0] == 401
    assert req(base + "/healthz", auth=False)[0] == 200
    code, body, _ = req(base + "/")
    assert code == 200 and "Neue Webseite melden" in body


def test_web_form_add_and_delete(web):
    base, app, _ = web
    assert req(base + "/sites", {"site": "https://www.neueseite.io/x", "category": "gaming"})[0] == 403  # no csrf
    code, _, h = req(base + "/sites", {"site": "https://www.neueseite.io/x", "category": "gaming", "csrf": app.csrf})
    assert code == 303 and "neueseite.io" in urllib.parse.unquote_plus(h["Location"])
    assert app.store.sites["neueseite.io"]["category"] == "gaming"
    code, body, _ = req(base + "/?domain=play.neueseite.io")
    assert "neueseite.io" in body and "learned" in body
    req(base + "/sites/delete", {"site": "neueseite.io", "csrf": app.csrf})
    assert "neueseite.io" not in app.store.sites


def test_web_api(web):
    base, app, _ = web
    code, body, _ = req(base + "/api/sites", json_body={"site": "browsr.example", "category": "proxy"})
    assert code == 201 and json.loads(body)["site"] == "browsr.example"
    code, body, _ = req(base + "/api/classify?domain=www.browsr.example")
    assert json.loads(body)["category"] == "proxy"
    assert req(base + "/api/sites", json_body={"site": "x.example", "category": "bogus"})[0] == 400
    assert req(base + "/api/sites?site=browsr.example", method="DELETE")[0] == 200
    assert req(base + "/api/sites", auth=False, json_body={"site": "a.example", "category": "none"})[0] == 401


def test_web_feedback_link(web):
    base, app, m = web
    url = app.signer.feedback_url(base, "poki.com")
    code, body, _ = req(url, auth=False)
    assert code == 200 and "Bestätigen" in body
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    assert req(base + "/feedback", {**q, "sig": "0" * 32}, auth=False)[0] == 403
    code, body, _ = req(base + "/feedback", q, auth=False)
    assert code == 200 and app.store.sites["poki.com"]["category"] == "none"
    assert m.classifier.classify("poki.com").category == "none"


def test_web_devices(web):
    base, app, m = web
    m.handle("192.168.1.23", "www.youtube.com", "dns")
    code, body, _ = req(base + "/")
    assert "Geräte" in body and "benennen" in body
    code, body, _ = req(base + "/?device=192.168.1.23")
    assert 'value="192.168.1.23"' in body
    assert req(base + "/devices", {"device": "192.168.1.23", "name": "iPad 07"})[0] == 403  # no csrf
    code, _, h = req(base + "/devices", {"device": "192.168.1.23", "name": "iPad 07", "csrf": app.csrf})
    assert code == 303 and app.devices.identify("192.168.1.23").label == "iPad 07"
    code, body, _ = req(base + "/api/devices", json_body={"device": "AA-BB-CC-DD-EE-01", "name": "iPad 08"})
    assert code == 201 and json.loads(body)["device"] == "aa:bb:cc:dd:ee:01"
    assert req(base + "/api/devices", json_body={"device": "kaputt", "name": "x"})[0] == 400
    names = {d["key"]: d["name"] for d in json.loads(req(base + "/api/devices")[1])}
    assert names == {"192.168.1.23": "iPad 07", "aa:bb:cc:dd:ee:01": "iPad 08"}
    assert req(base + "/api/devices?device=aa:bb:cc:dd:ee:01", method="DELETE")[0] == 200
    req(base + "/devices/delete", {"device": "192.168.1.23", "csrf": app.csrf})
    assert app.devices.identify("192.168.1.23").name == ""

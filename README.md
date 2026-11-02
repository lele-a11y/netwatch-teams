# netwatch – Teams-Alarm bei YouTube, Gaming & Proxy-Seiten

`netwatch` schneidet den Netzwerkverkehr mit, erkennt aufgerufene Domains und schickt eine
Nachricht (Adaptive Card) in einen Microsoft-Teams-Kanal, wenn ein Gerät

* **YouTube** (inkl. `googlevideo.com`, `ytimg.com`, `youtu.be` …),
* eine **Gaming-Seite** (Steam, Roblox, Epic, Poki, CrazyGames, Twitch, `*.io`-Games …) oder
* einen **Proxy / Cloud-Browser** wie **browser.lol**, Hyperbeam, CroxyProxy, Unblocker …

öffnet.

## Wie es erkennt

1. **Quellen** – DNS-Anfragen (UDP/TCP 53) und der Hostname aus dem TLS-Handshake (SNI, TCP 443).
   HTTPS-Inhalte werden *nicht* entschlüsselt.
2. **Regeln** – kuratierte Domainlisten pro Kategorie (`netwatch/classifier.py`, erweiterbar in der Config).
3. **Heuristik** – Schlüsselwörter im Domainnamen (`proxy`, `unblock`, `unblocked-games`, `spiele` …).
4. **KI** (optional) – unbekannte Domains klassifiziert ein LLM (OpenAI-kompatible API: lokal mit
   **Ollama** oder OpenAI). Ergebnisse werden pro Seite gecacht, jede Seite wird nur einmal gefragt.
   Fällt die KI aus, läuft die Überwachung weiter.
5. **Cooldown** – pro Gerät und Kategorie max. eine Meldung alle 10 Minuten (einstellbar),
   damit ein YouTube-Video nicht 50 Nachrichten erzeugt.

## Wo muss es laufen?

Das Tool sieht nur Traffic, der an der Netzwerkkarte des Rechners vorbeikommt. Für ein ganzes Netz:

* auf dem **Router/Gateway/Firewall** (Linux, z.B. Raspberry Pi als Gateway), **oder**
* an einem **Mirror-/SPAN-Port** des Switches, **oder**
* auf dem **DNS-Server** des Netzes (z.B. Pi-hole) – dann reicht sogar dessen Log (siehe unten).

## Installation

```bash
git clone <repo> /opt/netwatch && cd /opt/netwatch
python3 -m venv .venv && .venv/bin/pip install .
cp config.example.yaml config.yaml   # Webhook-URL eintragen
```

### Teams-Webhook erstellen

Teams-Kanal → `…` → **Workflows** → Vorlage **„Post to a channel when a webhook request is received“**
(„Beim Empfang einer Webhookanforderung in einem Kanal posten“) → URL kopieren → in `config.yaml`
unter `teams.webhook_url` eintragen (oder Umgebungsvariable `TEAMS_WEBHOOK_URL`).
Der alte „Incoming Webhook“-Connector funktioniert auch, wird von Microsoft aber abgekündigt.

```bash
.venv/bin/netwatch -c config.yaml test-webhook       # Testnachricht in Teams
```

## Benutzung

```bash
sudo .venv/bin/netwatch -c config.yaml run -i eth0   # Live-Überwachung
.venv/bin/netwatch -c config.yaml --dry-run run      # nur loggen, nichts senden
.venv/bin/netwatch classify browser.lol poki.com www.srf.ch   # Klassifizierung testen
.venv/bin/netwatch -c config.yaml pcap mitschnitt.pcap       # pcap auswerten

# Pi-hole / dnsmasq: Log statt Mitschnitt (kein root nötig)
tail -F /var/log/pihole/pihole.log | .venv/bin/netwatch -c config.yaml stdin
```

### Als Dienst (systemd)

```bash
sudo cp netwatch.service /etc/systemd/system/
sudo systemctl enable --now netwatch
journalctl -u netwatch -f
```
Bei aktivierter KI im Dienst `ai.cache_file: /var/lib/netwatch/ai_cache.json` setzen.

### Docker

```bash
cp config.example.yaml config.yaml   # bei KI: ai.cache_file: /data/ai_cache.json
docker compose up -d --build
```

### KI aktivieren (lokal mit Ollama)

```bash
curl -fsSL https://ollama.com/install.sh | sh && ollama pull llama3.1:8b
```
```yaml
ai:
  enabled: true
  base_url: "http://localhost:11434/v1"
  model: "llama3.1:8b"
```
Für OpenAI: `base_url: https://api.openai.com/v1`, `model: gpt-4o-mini`, Key via `NETWATCH_AI_API_KEY`.
Achtung: dann gehen die unbekannten Domainnamen an OpenAI.

## Grenzen

* **DNS-over-HTTPS / Private DNS** im Browser umgeht die DNS-Erkennung. SNI greift dann meist
  trotzdem, ausser bei **Encrypted Client Hello (ECH)** oder **QUIC/HTTP3** (UDP 443).
  Empfehlung: bekannte DoH-Resolver und ggf. UDP 443 in der Firewall sperren (Browser fallen dann auf TCP zurück).
* **VPNs** verbergen alles – erkannt wird höchstens der Aufruf der VPN-/Proxy-Webseite.
* Geräte werden per IP (+ Reverse-DNS-Name) gemeldet; für die Zuordnung zu Personen DHCP-Reservationen nutzen.

## Rechtliches (CH)

Überwachung des Surfverhaltens von Mitarbeitenden/Schüler:innen ist nur mit vorgängiger, transparenter
Information (Nutzungsreglement) und verhältnismässig zulässig (DSG, Art. 26 ArGV 3). Im Zweifel mit dem
Datenschutz abklären.

## Tests

```bash
.venv/bin/pip install -e '.[dev]' && .venv/bin/pytest
```

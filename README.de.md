<div align="center">

# netsa

**Open-Source-Plattform für die Lagebeurteilung der Netzwerksicherheit und die Analyse der Angriffsfläche**

Macht aus nginx-, Firewall- / IDS-, Host-Authentifizierungs- und DNS-Logs ein Sicherheitslagebild, das rückverfolgbar und handlungsfähig ist und ständig dazulernt.<br>
Eine einzige Binärdatei, sofort einsetzbar, auch offline in internen Netzen.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md) · **Deutsch** · [Русский](README.ru.md)

[Schnellstart](#schnellstart) · [Screenshots](#screenshots) · [Kernfunktionen](#kernfunktionen) · [Funktionsweise](#funktionsweise) · [Unterstützte Logs](#unterstützte-logs) · [Dokumentation](#dokumentation)

</div>

![Lageübersicht: Angriffskarte, Echtzeit-Alarme und Bedrohungsindex](docs/images/overview.png)

## Warum netsa

- **Keine Abhängigkeiten, Bereitstellung in einem Schritt**: eine einzige Go-Binärdatei mit eingebauter Weboberfläche, Karten der Welt sowie der chinesischen Provinzen und Städte und Offline-Geolokalisierungsdatenbanken. Elasticsearch, Kafka oder eine Datenbank sind nicht nötig. Docker-Images gibt es für amd64 und arm64, und bei deaktivierter Online-Rückverfolgung läuft netsa in isolierten Netzen vollständig offline.
- **Logs müssen nicht vorab angepasst werden**: erkennt automatisch mehr als 40 Formate, darunter nginx / Apache / IIS / Caddy, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, Linux- und Windows-Authentifizierung, gängige DNS-Server sowie Wrapper-Formate von Collectors wie Docker und Filebeat.
- **Genaue Erkennung, verlässliche Alarme**: 69 Signaturregeln plus Verhaltenserkennung; Antworten, Sitzungsbelege und Schwachstellen der Assets dienen zur Nachprüfung von „scheinbarem Erfolg“. Der Schweregrad wird zentral entschieden: Blockierte Angriffe werden nie als „kritisch“ markiert, und erfolgreiche Ausnutzung wird nicht übersehen.
- **Rückverfolgung bis zur Stadt, Zuordnung bis zur Gruppe**: ermittelt die echte IP hinter CDNs und Proxys und erkennt XFF-Fälschungen sowie Direktverbindungen, die das CDN umgehen. Mehrere Geolokalisierungsquellen werden abgeglichen und mit einem Vertrauensgrad versehen. Die Korrelation gleicher Herkunft findet weitere IPs, die vermutlich zum selben Angreifer gehören.
- **Wird mit der Nutzung genauer**: lernt aus den Entscheidungen der Analysten. Regeln und Endpunkte mit wiederholten Fehlalarmen werden automatisch herabgestuft, bestätigte Angreifer bei ihrer Rückkehr automatisch hochgestuft. Die KI-Triage unterstützt die APIs von OpenAI und Anthropic, sodass sich internes vLLM ebenso wie Cloud-Modelle anbinden lassen. Sie passt sich automatisch an Modellunterschiede an und bewertet die Vertrauenswürdigkeit der Modelle anhand der Analystenentscheidungen.
- **Geschlossener Kreislauf für den Sicherheitsbetrieb**: Bündelung von Vorfällen mit Bearbeitungsfristen, Unterdrückung von Fehlalarmen, Benachrichtigungen über DingTalk / WeCom / Feishu, Verknüpfung von Assets und Schwachstellen, Aufbewahrung von Rohlogs und Forensik, Wochen- und Monatsberichte, MLPS-2.0-Selbstprüfung (chinesisches mehrstufiges Schutzsystem) und eine manipulationssichere Audit-Kette.
- **Schnell auf einer einzigen Maschine**: etwa 460.000 Ereignisse pro Sekunde durchgängig auf einem Entwicklungsrechner (i7-10700, 16 Threads). Dank Aho-Corasick-Vorfilterung müssen normale Anfragen kaum reguläre Ausdrücke ausführen, die Erkennung dauert etwa 3 µs pro Ereignis.

## Schnellstart

### Mit einem Befehl ausprobieren (simulierte Angriffslogs inklusive)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Öffne <http://localhost:8080> und melde dich mit dem Benutzer `admin` und dem Passwort `Netsa@demo2026` an. Der Simulator erzeugt fortlaufend Angriffslogs, und das Dashboard aktualisiert sich in Echtzeit.

### Produktivbereitstellung

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Rufe `http://<Server-IP>:8080` auf. Das Anfangspasswort steht in den Logs: `docker compose logs netsa | grep 初始密码` (`初始密码` ist der wörtliche Logtext und bedeutet „Anfangspasswort“). Es muss bei der ersten Anmeldung geändert werden.
- Standardmäßig werden `/var/log/nginx` und `/var/log` auf dem Host gelesen. Syslog von Netzwerkgeräten geht an `<Server-IP>:5514` (UDP / TCP).
- Um eine Version festzulegen, Ports zu ändern oder die Alarmarchivierung zu aktivieren, führe zuerst `cp .env.example .env` aus und bearbeite die Datei gemäß den Kommentaren.
- Windows PowerShell 5.1 unterstützt weder `&&` noch `grep`: Führe Befehle zeilenweise aus und verwende `Select-String` statt `grep`.

Upgrades und Rollback, Offline-Bereitstellung und häufige Probleme findest du im [Bereitstellungsleitfaden](docs/deployment.md).

### Vorhandene Logs ohne Bereitstellung analysieren

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # öffnet nach der Analyse das Dashboard
```

## Screenshots

| Sicherheitsbewertung und Empfehlungen | Analyse der Angriffsfläche |
|---|---|
| ![Sicherheitsbewertung](docs/images/assess.png) | ![Analyse der Angriffsfläche](docs/images/surface.png) |
| **Vorfallbearbeitung und Fristen** | **Selbstlernen und automatische Kalibrierung** |
| ![Vorfallbearbeitung](docs/images/incidents.png) | ![Selbstlernen](docs/images/learn.png) |

Die Screenshots zeigen die Weboberfläche, die auf Chinesisch ist, mit Demodaten des eingebauten Simulators. Alle IPs und Websites darin sind simuliert. Du kannst es mit der obigen Demo-Umgebung selbst ausprobieren.

## Kernfunktionen

| Modul | Funktionen |
|---|---|
| [Log-Erfassung](docs/log-sources.md) | Dateien in Echtzeit verfolgen (Platzhalter, logrotate-Rotation), Stapelanalyse (auch `.gz`), Syslog über UDP / TCP / TLS (gegenseitige Authentifizierung möglich); Absendererkennung, Positivliste, Ratenbegrenzung und Alarme bei ausbleibenden Logs |
| [Angriffserkennung](docs/detection.md) | Signaturregeln für SQL-Injection, XSS, Befehlsausführung, Log4Shell, SSRF, XXE, Deserialisierung, WebShell, Ausnutzung bekannter Schwachstellen und mehr; Verhaltenserkennung von CC-Angriffen, Brute Force, Credential Stuffing, API-Enumeration, Portscans und mehr; mehrstufige Dekodierung gegen gängige Umgehungen |
| [Ergebnisprüfung](docs/detection.md#研判复核用证据排除表面成功) | Unterscheidet anhand von Antworten und Sitzungsbelegen blockiert, fehlgeschlagen, nicht blockiert und vermuteten Erfolg; schließt Scheinbefunde wie Fallback-Seiten von Single-Page-Apps, einheitliche Fehlerseiten und „erlaubten“ Verkehr aus, der nie einen Dienst erreicht hat |
| [Host- und DNS-Erkennung](docs/log-sources.md#主机认证日志与-dns-日志) | SSH- / RDP- / VPN-Brute-Force und erfolgreiche Kompromittierung, Password Spraying, gelöschte Logs, neue Konten und Rechteausweitung; DNSLog-Out-of-Band-Rückrufe, DNS-Tunnel, DGA, Mining-Pool-Domains |
| [Rückverfolgung der Angriffsquelle](docs/traceability.md) | Kombiniert ip2region, MaxMind, ip-api, rDNS und RDAP / WHOIS, mit Standortzuordnung für eigene interne Subnetze; die Korrelation gleicher Herkunft findet über Subnetz, Werkzeug-Fingerabdruck und Angriffstechnik vermutliche Mitglieder derselben Gruppe |
| [Lage-Dashboard](docs/deployment.md#演示环境) | Angriffskarten der Welt und Chinas mit Drill-down bis zu Provinz und Stadt; Angriffslinien und Alarme in Echtzeit; KPIs, Trends und Verteilungsdiagramme führen per Drill-down zu Angriffsquellen oder Alarmen |
| [Analyse der Angriffsfläche](docs/log-sources.md#未做-dnat-映射的端口探测) | Erfasst exponierte Dienste und findet offengelegten Quellcode, Schlüssel und Backups sowie exponierte Verwaltungsschnittstellen; filtert mithilfe von DNAT-Zuordnungen und Firewall-Sitzungsbelegen Hintergrundscans heraus, die keinen Dienst erreichen können |
| [Sicherheitsbewertung und Kompromittierungsanalyse](docs/detection.md#安全评估与失陷研判) | Bewertet sieben Dimensionen mit einer Gesamtnote von A bis E und Empfehlungen P0–P3; interne Hosts, die Adressen aus Threat Intelligence kontaktieren, Erkennung von C2-Beacons; MITRE-ATT&CK-Matrix |
| [Selbstlernen und KI-Triage](docs/self-learning.md) | Automatische Kalibrierung auf Regel- und Zielebene, Hochstufung zurückkehrender bestätigter Angreifer, Lernfenster, Richtlinie in der Weboberfläche anpassbar; die KI-Triage unterstützt OpenAI- / Anthropic-APIs und vLLM, passt sich automatisch an Modellunterschiede an, fügt ähnliche Fälle aus der eigenen Organisation hinzu und misst die Übereinstimmung des Modells mit den Analysten |
| [Vorfallbearbeitung und Benachrichtigungen](docs/operations.md#事件处置与误报抑制) | Alarme werden automatisch zu Vorfällen gebündelt, mit Zuweisung, Bearbeitungsfristen und Erinnerungen bei Überschreitung; Unterdrückung von Fehlalarmen; [Benachrichtigungen über DingTalk / WeCom / Feishu](docs/operations.md#告警推送钉钉--企业微信--飞书) mit Deduplizierung, Zusammenführung und Ratenbegrenzung; Export von Sperrlisten für nginx, iptables, ipset und mehr |
| [Aufbewahrung, Compliance und Audit](docs/operations.md#原始日志留存与检索) | Rohlogs in stündlich komprimierten Segmenten mit manipulationssicherer Hash-Kette; [langfristige PostgreSQL-Archivierung](docs/operations.md#告警归档可选postgresql) (optional); Wochen- und Monatsberichte, MLPS-2.0-Selbstprüfung; [drei Rollen, Zwei-Faktor-Authentifizierung und manipulationssichere Audit-Kette](docs/operations.md#登录账号与审计); Prometheus-Metriken |

## Funktionsweise

```text
Log-Quellen          nginx · Firewall / IDS · Host-Authentifizierung · DNS · Container und Collectors
   │                 Dateiverfolgung / Stapelanalyse / Syslog (UDP · TCP · TLS)
   ▼
Formaterkennung      Format und Zeitzone werden je Quelle und je Absender getrennt erkannt
   ▼
Echte IP             ermittelt die Quelle über vertrauenswürdige Proxys, markiert XFF-Fälschung und CDN-Umgehung
   ▼
Bedrohungserkennung  Signaturregeln (AC-Vorfilter + Regex) + Verhaltenserkennung (Zeitfenster, begrenzter Speicher)
   ▼
Belegfilter          Sitzungsbelege und DNAT-Zuordnungen entfernen Proben ohne erreichten Dienst; Unterdrückung wird angewendet
   ▼
Gelernte Anpassung   stuft wiederholte Fehlalarme gemäß Analysten herab, bestätigte Quellen hoch (learn)
   ▼
Schweregrad          Kategorie-Untergrenze, Hochstufung bei Erfolg und Ergebnis-Obergrenze bestimmen das Endergebnis (risk)
   ▼
Zustandsspeicher     Angreiferprofile · Alarme · Vorfälle · Angriffsfläche · Zeitreihen · Snapshot-Persistenz
   │
   ├── Web-Dashboard und REST-API (SSE-Echtzeitübertragung)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Aufbewahrung von Rohlogs · PostgreSQL-Archiv (optional)
   └── KI-Triage (optional, Ergebnisse werden in den Vorfall geschrieben)
```

Wichtige Designentscheidungen:

- **Der Schweregrad wird an einer einzigen Stelle entschieden**: Der in einer Regel angegebene Schweregrad ist nur ein Vorschlag. So rechnet nicht jede Stufe eigenständig hoch und herunter, und gleichartige Ereignisse erhalten keine unterschiedlichen Schweregrade. Siehe [Schweregrad-Entscheidung](docs/detection.md#威胁等级判定).
- **Belege vor Anschein**: Ein „Erlauben“ der Firewall, eine 200-Antwort oder eine erfolgreiche Anmeldung nach mehreren Fehlversuchen werden anhand von Sitzungen, Antwort-Baselines und Kontohinweisen nachgeprüft.
- **Lernen hat Grenzen**: Es wird nur aus menschlichen Entscheidungen gelernt. Automatische Anpassungen ändern höchstens eine Stufe auf einmal, und erfolgreiche Ausnutzung bleibt kritisch. Die Unterdrückung von Fehlalarmen, die Alarme ausblendet, muss von einer Person übernommen werden. KI-Ergebnisse dienen nicht als Lernbeispiele und lösen keine automatische Bearbeitung aus.
- **Unter Last unter Kontrolle**: Parsing und Erkennung laufen parallel und werden stapelweise gespeichert, Profilanzahl und Erkennungsfenster haben feste Obergrenzen, und eine einzelne fehlerhafte Logzeile beeinträchtigt den Dienst nicht. Für Warteschlangenstau und Verwerfungen gibt es Überwachungsmetriken.

## Unterstützte Logs

| Typ | Formate |
|---|---|
| **Web** | nginx / Apache (combined, main, vhost), beliebiges eigenes `log_format`, nginx JSON, Caddy, Traefik, Elastic ECS, IIS W3C |
| **Firewall** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Windows-Firewall, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, Bedrohungslogs von Geräten wie FortiGate IPS / UTM |
| **Host- und VPN-Authentifizierung** | Linux `auth.log` / `secure`, Windows-Sicherheitsereignisse (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, SQL-Server-Anmeldungen |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Container und Collectors** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O; werden automatisch entpackt, um das Originallog zu erkennen |

Die Einrichtung ist unter [Log-Anbindung](docs/log-sources.md) beschrieben. Nach dem Anbinden einer Quelle kannst du auf der Datenquellen-Seite des Dashboards die Erkennungsergebnisse und Beispiele für Parsing-Fehler prüfen.

## Dokumentation

Die folgenden ausführlichen Dokumente sind in vereinfachtem Chinesisch verfasst.

| Dokument | Inhalt |
|---|---|
| [Bereitstellungsleitfaden](docs/deployment.md) | Produktivbereitstellung, `.env`-Variablen, Upgrades und Rollback, Offline-Netze, Demo-Umgebung, Ausführung aus dem Quellcode |
| [Log-Anbindung](docs/log-sources.md) | Anbindung von Web, Firewall, Authentifizierung und DNS, Verwaltung von Syslog-Absendern, Zeitzonen, DNAT und Sitzungsbelege |
| [Erkennung und Prüfung](docs/detection.md) | Schweregrad-Entscheidung, Ergebnisprüfung, Bedrohungsbewertung, Sicherheitsbewertung und Kompromittierungsanalyse |
| [Rückverfolgung der Angriffsquelle](docs/traceability.md) | Geolokalisierung aus mehreren Quellen, interne Subnetze, Hot Reload der Geodatenbanken, Korrelation gleicher Herkunft |
| [Selbstlernen und KI-Triage](docs/self-learning.md) | Was automatisch angewendet wird und seine Grenzen, Verhaltens-Baselines, Compliance-Selbstprüfungen, Konfiguration und Anpassung externer Modelle |
| [Sicherheitsbetrieb](docs/operations.md) | Vorfallbearbeitung, Benachrichtigungen, Rohlogs, Assets und Schwachstellen, Berichte und Compliance, Konten und Audit, Metriken, Alarmarchivierung |
| [Konfigurationsreferenz](docs/configuration.md) | Häufige Einstellungen und Betriebshinweise |
| [API](docs/api.md) | Überblick über die REST-API |
| [Entwicklung und Veröffentlichung](docs/development.md) | Lokale Tests, Codestruktur, Erstellung und Veröffentlichung von Images |

## Entwicklung

Erfordert Go 1.25 oder neuer (veröffentlichte Versionen werden mit Go 1.27 erstellt). Reines Go, kein CGO.

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # darf nichts ausgeben
go vet ./...
go test ./...
```

Race-Tests benötigen einen C-Compiler. Ohne gcc auf deinem Rechner kannst du sie in einem Container ausführen:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

Codestruktur und Veröffentlichungsablauf findest du unter [Entwicklung und Veröffentlichung](docs/development.md).

## Mitwirken

Issues und Pull Requests sind willkommen, besonders:

- Beispiele neuer Logformate (bitte vorher anonymisieren) sowie Meldungen zu Erkennungs- oder Parsing-Fehlern;
- neue Erkennungsregeln sowie Meldungen zu Fehlalarmen oder übersehenen Angriffen mit Beispielen;
- Verbesserungen der Dokumentation und Erfahrungen aus realen Bereitstellungen.

Bitte bestehe vor dem Einreichen von Code die obigen Prüfungen. Die CI führt zusätzlich Race-Tests und `govulncheck` aus.

Wenn netsa dir nützt, vergib bitte einen **Star**, damit mehr Menschen, die es brauchen, es finden.

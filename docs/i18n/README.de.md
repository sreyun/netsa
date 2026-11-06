<div align="center">

# netsa

**Open-Source-Plattform für Netzwerksicherheits-Lagebild und Angriffsflächenanalyse**

Macht aus Web-, Firewall- / IDS-, Netzwerkfluss-, Host-Authentifizierungs- und Prozess- sowie DNS-Logs ein Sicherheitslagebild, das sich zurückverfolgen und bearbeiten lässt und ständig dazulernt.<br>
Eine einzige Binärdatei, sofort einsatzbereit, auch in isolierten Netzen.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md) · **Deutsch** · [Русский](README.ru.md)

[Schnellstart](#schnellstart) · [Screenshots](#screenshots) · [Kernfunktionen](#kernfunktionen) · [Funktionsweise](#funktionsweise) · [Unterstützte Logs](#unterstützte-logs) · [Dokumentation](#dokumentation)

</div>

![Lageübersicht: Angriffskarte, Echtzeit-Alarme und Bedrohungsindex](../images/overview.png)

## Warum netsa

- **Keine Abhängigkeiten, Bereitstellung in einem Schritt**: eine einzige Go-Binärdatei mit eingebauter Weboberfläche, Welt- sowie chinesischen Provinz- und Städtekarten und Offline-Geolokalisierungsdatenbanken. Weder Elasticsearch noch Kafka noch eine Datenbank nötig. Docker-Images gibt es für amd64 und arm64, und mit abgeschalteter Online-Rückverfolgung läuft es vollständig offline in isolierten Netzen.
- **Keine Vorab-Anpassung der Logs**: erkennt automatisch mehr als 50 Formate, darunter nginx / Tengine / OpenResty / APISIX / Kong / Apache / IIS / Caddy, WAFs wie ModSecurity, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, Linux- und Windows-Authentifizierung, gängige DNS-Server, Zeek, NetFlow / sFlow / IPFIX, Host-Logs von Sysmon / auditd / Wazuh, Anmelde-Logs von Anwendungen sowie die Hüllformate von Kollektoren wie Docker und Filebeat.
- **Präzise Erkennung, vertrauenswürdige Alarme**: 87 Signaturregeln (teils aus dem OWASP CRS übernommen), Syntaxanalyse mit libinjection und Verhaltenserkennung; Antworten, Sitzungsnachweise und Schwachstellen der Assets dienen zur erneuten Prüfung des „scheinbaren Erfolgs“. Der Schweregrad entsteht aus einer zentralen Entscheidung: Blockierte Angriffe werden nie als „kritisch“ eingestuft, und erfolgreiche Ausnutzung wird nicht übersehen.
- **Kennt chinesische OA-Systeme und Middleware**: 261 eingebaute Signaturen verwundbarer Endpunkte für 42 Produkte, darunter die OA-Systeme von Seeyon, Weaver, Yonyou, Tongda, Landray und Wanhu, FanRuan, Esafenet, RuoYi, Nacos, APISIX, Nginx UI sowie Geräte von Sangfor, Ruijie, Hikvision und Dahua. Alarme nennen das Produkt und die CVE- / CNVD-Kennung; verwundbare Endpunkte, die der normale Geschäftsbetrieb nutzt, werden automatisch gelernt und lösen keine Dauer-Alarme mehr aus.
- **Bedrohungsdaten: genau statt nur viel**: Threat Intelligence zu IPs, Domains, TLS-Fingerabdrücken und Datei-Hashes (STIX / TAXII / MISP / Textlisten), nach Kategorie eingestuft (C2, Malware, Phishing, Mining, Angriffsquelle), missbrauchte öffentliche Plattformen werden automatisch herausgefiltert. Die Genauigkeit jeder Quelle wird anhand der Urteile der Analysten gemessen, Quellen mit anhaltenden Fehlalarmen werden automatisch herabgestuft.
- **Firewall- und Web-Logs verknüpft**: Ein interner Host, der sich nach einem Web-Angriff mit dem Angreifer oder einer in der Angriffsnutzlast genannten Rückrufadresse verbindet, wird als kompromittiert markiert; eine Verbindung zu einer Adresse aus der Nutzlast beweist, dass die Nutzlast ausgeführt wurde.
- **Bis zur Stadt zurückverfolgen, bis zur Gruppe verknüpfen**: ermittelt die echte IP hinter CDNs und Proxys und erkennt XFF-Fälschung sowie direkte Verbindungen zum Ursprungsserver, die das CDN umgehen. Mehrere Geolokalisierungsquellen werden abgeglichen und mit einem Vertrauensgrad versehen. Die Korrelation gleicher Herkunft und die Gruppierung zu Kampagnen finden die wechselnden Ausgangsadressen eines Angreifers (gleicher Werkzeug-Fingerabdruck, gleiche OAST-Korrelations-ID, TLS-Fingerabdruck, gleiches Köder-Token). Ein Treffer auf einen [Köder](../detection.md#诱饵) (Köderpfad, -token, -konto oder Honeypot) identifiziert einen Angreifer mit hoher Sicherheit. Die Asset-Angriffskette zeigt in zeitlicher Reihenfolge, wie ein Server gescannt, ausgenutzt, übernommen und für laterale Bewegung genutzt wurde.
- **Wird mit der Nutzung genauer**: lernt aus den Urteilen der Analysten. Regeln und Endpunkte mit wiederholten Fehlalarmen werden automatisch herabgestuft, bestätigte Angreifer bei ihrer Rückkehr automatisch hochgestuft. Keine manuell gepflegten Allowlists: Aus normalem Verkehr lernt es die üblichen Werte jedes Parameters und erkennt passiv die Produkte und Frontend-Frameworks jeder Website, sodass normaler Text in einem Suchfeld oder Sondierungen nach einem Produkt, das die Website gar nicht nutzt, keine schwerwiegenden Alarme mehr auslösen. Die KI-Triage unterstützt die APIs von OpenAI und Anthropic, sodass sich lokales vLLM wie Cloud-Modelle anbinden lassen. Sie passt sich automatisch an Modellunterschiede an und bewertet anhand der Analystenurteile, wie weit jedem Modell zu trauen ist.
- **Ein vollständiger Kreislauf für den Sicherheitsbetrieb**: Bündelung zu Vorfällen mit Bearbeitungsfristen, Unterdrückung von Fehlalarmen, Benachrichtigungen über DingTalk / WeCom / Feishu, Verknüpfung von Assets und Schwachstellen, Aufbewahrung der Rohlogs mit Beweispaket per Klick, Wochen- und Monatsberichte, Selbstbewertung nach MLPS 2.0 (Chinas mehrstufigem Schutzsystem) und eine manipulationssichere Audit-Kette.
- **Schnell auf einer einzigen Maschine**: rund 460.000 Ereignisse pro Sekunde Ende-zu-Ende auf einem Entwicklungsrechner (i7-10700, 16 Threads). Dank Aho-Corasick-Vorfilterung brauchen normale Anfragen kaum je einen regulären Ausdruck, etwa 3 µs pro Ereignis.

## Schnellstart

### Mit einem Befehl ausprobieren (simulierte Angriffslogs inklusive)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Öffne <http://localhost:8080> und melde dich als `admin` mit dem Passwort `Netsa@demo2026` an. Der Simulator erzeugt fortlaufend Angriffslogs, und das Dashboard aktualisiert sich in Echtzeit.

### Produktivbereitstellung

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Rufe `http://<Server-IP>:8080` auf. Das Anfangspasswort steht in den Logs: `docker compose logs netsa | grep 初始密码` (`初始密码` ist der wörtliche Logtext und bedeutet „Anfangspasswort“). Es muss bei der ersten Anmeldung geändert werden.
- Standardmäßig werden `/var/log/nginx` und `/var/log` des Hosts gelesen; sende Syslog von Netzwerkgeräten an `<Server-IP>:5514` (UDP / TCP).
- Um eine Version festzulegen, Ports zu ändern oder das Alarmarchiv zu aktivieren, führe zuerst `cp .env.example .env` aus und passe die Datei gemäß den Kommentaren an.
- Windows PowerShell 5.1 unterstützt weder `&&` noch `grep`: Führe die Befehle einzeln aus und verwende `Select-String` statt `grep`.

Upgrades und Rollback, Offline-Bereitstellung und häufige Fragen findest du im [Bereitstellungsleitfaden](../deployment.md).

### Vorhandene Logs ohne Bereitstellung analysieren

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # öffnet nach der Analyse das Dashboard
```

## Screenshots

| Sicherheitsbewertung und empfohlene Maßnahmen | Angriffsflächenanalyse |
|---|---|
| ![Sicherheitsbewertung](../images/assess.png) | ![Angriffsflächenanalyse](../images/surface.png) |
| **Vorfallbearbeitung und Fristen** | **Selbstlernen und automatische Kalibrierung** |
| ![Vorfallbearbeitung](../images/incidents.png) | ![Selbstlernen](../images/learn.png) |

Die Screenshots zeigen die chinesischsprachige Weboberfläche mit Demodaten des eingebauten Simulators. Alle IPs und Websites sind simuliert. Mit der obigen Demoumgebung kannst du es selbst ausprobieren.

## Kernfunktionen

| Modul | Funktionen |
|---|---|
| [Log-Erfassung](../log-sources.md) | Echtzeit-Verfolgung von Dateien (Platzhalter, logrotate-Rotation), Stapelanalyse (einschließlich `.gz`), Syslog über UDP / TCP / TLS (optional mit gegenseitiger Authentifizierung), [Erfassung von NetFlow / sFlow / IPFIX](../log-sources.md#流量日志zeeknetflow--sflow-与云抗-d-服务); Erkennung der Absender, Allowlists, Ratenbegrenzung und Alarme bei verstummten Quellen |
| [Angriffserkennung](../detection.md) | Signaturregeln für SQL-Injection, XSS, Befehlsausführung, Log4Shell, SSRF, XXE, Deserialisierung, WebShells, bekannte Exploits und mehr, einige Befehls-, Code- und Java-Klassen-Regeln aus dem OWASP CRS übernommen; die [Syntaxanalyse mit libinjection](../detection.md#语法分析libinjection) prüft Injection-Treffer erneut und findet Varianten, die reguläre Ausdrücke übersehen; [Signaturen verwundbarer Endpunkte chinesischer OA-Systeme und Middleware](../detection.md#国产-oa中间件漏洞接口签名) (261 Signaturen, 42 Produkte); Verhaltenserkennung von CC, Brute Force, Credential Stuffing, Endpunkt-Enumeration, Portscans, WebShell-Verhalten, Datenabfluss, lateraler Bewegung und volumetrischem DDoS; wenn der Anfragekörper protokolliert wird, werden auch POST-Nutzlasten geprüft; mehrstufige Dekodierung vereitelt gängige Umgehungen |
| [Ergebnisprüfung](../detection.md#研判复核用证据排除表面成功) | Unterscheidet anhand von Antworten und Sitzungsnachweisen zwischen blockierten, fehlgeschlagenen, nicht blockierten und vermutlich erfolgreichen Angriffen; schließt scheinbare Erfolge wie Fallback-Seiten von Single-Page-Apps, einheitliche Fehlerseiten und „erlaubten“ Verkehr aus, der nie einen Dienst erreichte |
| [Host- und DNS-Erkennung](../log-sources.md#主机认证日志与-dns-日志) | Brute Force auf SSH / RDP / VPN und erfolgreiche Einbrüche, Password Spraying, gelöschte Logs, neue Konten und Rechteausweitung, [Kontoübernahme](../detection.md#账号盗用) (unmögliche Reisen, Anmeldungen aus einem neuen Land, gleichzeitige Anmeldungen von mehreren Orten); [Erkennung von Host-Prozessen](../detection.md#主机进程检测) (Webserver-Prozesse, die Befehle ausführen, Reverse Shells, Diebstahl von Anmeldedaten, Persistenz); DNSLog-Out-of-Band-Rückrufe, DNS-Tunneling, DGA, Mining-Pool-Domains sowie durch Threat Intelligence markierte C2-, Malware- und Phishing-Domains |
| [Rückverfolgung der Angriffsquelle](../traceability.md) | Kombiniert ip2region, MaxMind, ip-api, rDNS und RDAP / WHOIS, mit eigenen Standorten für interne Subnetze; die Korrelation gleicher Herkunft nutzt Subnetze, Werkzeug-Fingerabdrücke und Angriffstechniken, um mutmaßliche Mitglieder derselben Gruppe zu finden |
| [Asset-Angriffskette](../detection.md#资产攻击链路) | Stellt eine Website oder einen Host in den Mittelpunkt und verknüpft Aufklärung, Ausnutzung, Einbruch, Einnistung, Kontrolle, laterale Bewegung, Sammlung und Auswirkung, mit Nachweis, Quelle und ATT&CK-Technik für jeden Schritt; Websites und die Server dahinter werden automatisch zusammengeführt, mit einem Urteil zur Kompromittierung und empfohlenen Maßnahmen |
| [Lage-Dashboard](../deployment.md#演示环境) | Angriffskarten für die Welt und China mit Drilldown bis zu Provinzen und Städten; Angriffslinien und Alarme in Echtzeit; KPIs, Trends und Verteilungsdiagramme führen per Drilldown zu Angriffsquellen oder Alarmen |
| [Angriffsflächenanalyse](../log-sources.md#未做-dnat-映射的端口探测) | Erfasst die nach außen angebotenen Dienste und findet geleakten Quellcode, Schlüssel und Backups sowie offene Verwaltungsoberflächen; kombiniert DNAT-Zuordnungen mit den Sitzungsnachweisen der Firewall, um Hintergrund-Scans herauszufiltern, die keinen Dienst erreichen können |
| [Sicherheitsbewertung und Kompromittierungsanalyse](../detection.md#安全评估与失陷研判) | Bewertet sieben Dimensionen mit einer Gesamtnote von A bis E und Empfehlungen von P0 bis P3; erkennt interne Hosts, die sich mit von Threat Intelligence markierten Adressen verbinden, C2-Beacons, bösartige TLS-Fingerabdrücke und auf Hosts gelandete Nutzlasten; die [Verknüpfung von Firewall- und Web-Logs](../detection.md#防火墙与-web-日志联动被攻击后回连) findet Hosts, die sich zu ihrem Angreifer zurückverbunden haben; MITRE-ATT&CK-Matrix |
| [Selbstlernen und KI-Triage](../self-learning.md) | Automatische Kalibrierung der Genauigkeit je Regel, je Ziel und je Threat-Intelligence-Quelle, Hochstufung bei Rückkehr bestätigter Quellen, Lernfenster, Richtlinien in der Oberfläche anpassbar; lernt aus den Logs interne Subnetze, Angriffsquellen, Kampagnen sowie die [normalen Parameterwerte und Produkte jeder Website](../self-learning.md#参数的正常取值与站点产品); die KI-Triage unterstützt die APIs von OpenAI / Anthropic und vLLM, passt sich automatisch an Modellunterschiede an, fügt ähnliche Fälle aus der eigenen Organisation bei und misst, wie oft das Modell mit den Analysten übereinstimmt |
| [Vorfallbearbeitung und Benachrichtigungen](../operations.md#事件处置与误报抑制) | Alarme werden automatisch zu Vorfällen gebündelt, mit Zuweisung, Bearbeitungsfristen und Erinnerungen bei Überschreitung; Unterdrückung von Fehlalarmen; [Registrierung autorisierter Scans](../detection.md#授权扫描登记) (während eines Tests nur aufzeichnen, ohne zu alarmieren, danach automatisch wiederhergestellt); [Benachrichtigungen über DingTalk / WeCom / Feishu](../operations.md#告警推送钉钉--企业微信--飞书) mit Deduplizierung, Zusammenfassung und Ratenbegrenzung; Export von Sperrlisten für nginx, iptables, ipset und mehr |
| [Aufbewahrung, Compliance und Audit](../operations.md#原始日志留存与检索) | Rohlogs stündlich komprimiert aufbewahrt, mit einer Hash-Kette gegen Manipulation; [Langzeitarchiv in PostgreSQL](../operations.md#告警归档可选postgresql) (optional); Wochen- und Monatsberichte, Selbstbewertung nach MLPS 2.0; [drei Rollen, Zwei-Faktor-Authentifizierung und eine manipulationssichere Audit-Kette](../operations.md#登录账号与审计); Prometheus-Metriken |

## Funktionsweise

```text
Logquellen           nginx · Firewall / IDS · Zeek · Host-Authentifizierung und -Prozesse · App-Anmeldungen · DNS · Container und Kollektoren
   │                 Dateiverfolgung / Stapelanalyse / Syslog (UDP · TCP · TLS) / Flusserfassung (NetFlow · IPFIX · sFlow)
   ▼
Formaterkennung      Format und Zeitzone je Quelle und je Absender getrennt erkannt
   ▼
Echte IP             ermittelt die Quelle über vertrauenswürdige Proxys, markiert XFF-Fälschung und CDN-Umgehung
   ▼
Bedrohungserkennung  Signaturregeln (AC-Vorfilter + Regex) + Syntaxanalyse (libinjection) + Regeln für Host-Prozesse + Verhaltenserkennung (Zeitfenster, begrenzter Speicher)
   ▼
Threat Intel und Köder  Threat Intelligence zu IP / Domain / TLS-Fingerabdruck / Datei-Hash; Treffer auf Köderpfade, -token, -konten und Honeypots bestätigen den Angreifer
   ▼
Nachweisfilter       Sitzungsnachweise und DNAT-Zuordnungen verwerfen Sondierungen, die keinen Dienst erreichten; Unterdrückung wird angewendet
   ▼
Gelernte Anpassung   normale Parameterwerte und Website-Produkte prüfen Treffer erneut; wiederholte Fehlalarme werden gemäß Analystenurteilen herabgestuft, bestätigte Quellen hochgestuft (learn)
   ▼
Verknüpfung          verbindet frühere Web-Angriffe: Rückrufe und Nutzlast-Downloads nach einem Angriff; spätere laterale Verbindungen kompromittierter Hosts
   ▼
Schweregrad          Kategorie-Untergrenze, Hochstufung bei Erfolg und Obergrenze nach Ergebnis bestimmen den endgültigen Schweregrad (risk)
   ▼
Zustandsspeicher     Angreiferprofile · Alarme · Vorfälle · Kampagnen · Asset-Angriffsketten · Angriffsfläche · Zeitreihen · Persistenz per Snapshot
   │
   ├── Web-Dashboard und REST-API (Live-Push per SSE)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Aufbewahrung der Rohlogs · PostgreSQL-Archiv (optional)
   └── KI-Triage (optional, Ergebnisse werden in die Vorfallakte geschrieben)
```

Wichtige Gestaltungsprinzipien:

- **Der Schweregrad wird an einer Stelle entschieden**: Der von einer Regel angegebene Schweregrad ist nur ein Vorschlag. So addiert und subtrahiert nicht jede Stufe für sich, und ähnliche Ereignisse erhalten keine unterschiedlichen Schweregrade. Siehe [Schweregrad-Entscheidungen](../detection.md#威胁等级判定).
- **Nachweise vor Anschein**: Ein „Erlaubt“ der Firewall, eine 200-Antwort oder eine erfolgreiche Anmeldung nach wiederholten Fehlversuchen werden anhand von Sitzungen, Antwort-Referenzwerten und Kontohinweisen erneut geprüft.
- **Lernen hat Grenzen**: Die Regelkalibrierung lernt nur aus menschlichen Urteilen. Automatische Anpassungen bewegen sich höchstens um eine Stufe, und erfolgreiche Ausnutzung bleibt kritisch. Aus dem Verkehr gelernte normale Parameterwerte und Website-Produkte stufen einen Treffer nur herab, wenn zwei unabhängige Bedingungen zugleich erfüllt sind (der Parameter ist normalerweise gewöhnlicher Text und die Syntaxanalyse findet keine Injection; die Website nutzt das Produkt nicht und die Anfrage war nicht erfolgreich), und nur bis zu niedrigem Schweregrad, ohne den Alarm je zu verbergen. Die Unterdrückung von Fehlalarmen, die Alarme verbirgt, muss von einem Menschen übernommen werden. KI-Ergebnisse dienen nicht als Lernbeispiele und lösen nie eine automatische Bearbeitung aus.
- **Bleibt unter Last beherrschbar**: Parsing und Erkennung laufen parallel und werden stapelweise gespeichert, Profilanzahl und Erkennungsfenster haben feste Obergrenzen, und eine einzelne fehlerhafte Logzeile beeinträchtigt den Dienst nicht. Rückstaus und verworfene Einträge in Warteschlangen haben Überwachungsmetriken.

## Unterstützte Logs

| Typ | Formate |
|---|---|
| **Web** | nginx / Tengine / OpenResty / Apache (combined, main, vhost), beliebiges eigenes `log_format`, nginx JSON, APISIX, Kong, Nginx Proxy Manager, Caddy, Traefik, Elastic ECS, IIS W3C |
| **WAF** | Blockierungen und Ratenbegrenzungen von ModSecurity und naxsi in den Fehlerlogs von nginx / Tengine / OpenResty, JSON-Audit-Logs von ModSecurity, OpenResty Lua WAF |
| **Firewall** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Windows-Firewall, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone sowie die Angriffsabwehr-Logs von Huawei, H3C und Sangfor |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, Bedrohungslogs von Geräten wie FortiGate IPS / UTM |
| **Host- und VPN-Authentifizierung** | Linux `auth.log` / `secure`, Windows-Sicherheitsereignisse (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, SQL-Server-Anmeldungen |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Netzwerkflüsse** | Zeek (conn / http / ssl / files, TSV oder JSON), NetFlow v5 / v9, IPFIX, sFlow v5 (Erfassung per UDP), Angriffsereignisse von Cloud-Anti-DDoS-Diensten |
| **Host-Prozesse (EDR / HIDS)** | Sysmon (Winlogbeat / NXLog / Elastic Agent), Windows 4688, Elastic Defend (ECS), Linux auditd, Wazuh-Alarme |
| **App-Anmeldungen und Honeypots** | JSON-Anmelde-Logs von Geschäftsanwendungen und Identitäts- / SSO-Plattformen, Logs des Honeypots OpenCanary |
| **Container und Kollektoren** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O, automatisch entpackt, um das ursprüngliche Log zu erkennen |

Die Einrichtung beschreibt die [Log-Anbindung](../log-sources.md). Nach dem Anbinden einer Quelle findest du Erkennungsergebnisse und Beispiele fehlgeschlagener Analysen auf der Datenquellen-Seite des Dashboards.

## Dokumentation

Die folgenden ausführlichen Dokumente sind in vereinfachtem Chinesisch verfasst.

| Dokument | Inhalt |
|---|---|
| [Bereitstellungsleitfaden](../deployment.md) | Produktivbereitstellung, `.env`-Variablen, Upgrade und Rollback, Offline-Netze, Demoumgebung, Ausführung aus dem Quellcode |
| [Log-Anbindung](../log-sources.md) | Anbindung von Web-, Firewall-, Authentifizierungs-, DNS-, Netzwerkfluss- (Zeek, NetFlow / sFlow, Cloud-Anti-DDoS), Host-Prozess- und App-Anmelde-Logs, Verwaltung der Syslog-Absender, Zeitzonen, DNAT und Sitzungsnachweise |
| [Erkennung und Prüfung](../detection.md) | Schweregrad-Entscheidungen, Ergebnisprüfung, Kampagnen und Asset-Angriffsketten, Datendiebstahl und laterale Bewegung, Köder, Erkennung von Host-Prozessen, Kontoübernahme, Bedrohungsbewertung, Sicherheitsbewertung und Kompromittierungsanalyse |
| [Rückverfolgung der Angriffsquelle](../traceability.md) | Geolokalisierung aus mehreren Quellen, interne Subnetze, Hot-Reload der Geolokalisierungsdatenbanken, Korrelation gleicher Herkunft |
| [Selbstlernen und KI-Triage](../self-learning.md) | Was automatisch angewendet wird und seine Grenzen, Verhaltens-Referenzwerte, Compliance-Selbstprüfung, Konfiguration externer Modelle und Modellanpassung |
| [Sicherheitsbetrieb](../operations.md) | Vorfallbearbeitung, Benachrichtigungen, Rohlogs, Assets und Schwachstellen, Berichte und Compliance, Konten und Audit, Überwachungsmetriken, Alarmarchiv |
| [Konfigurationsreferenz](../configuration.md) | Gängige Einstellungen und Betriebshinweise |
| [API](../api.md) | Überblick über die REST-API |
| [Externe Integrationen](../integrations.md) | Single Sign-on per LDAP / OIDC, Weiterleitung an SIEM, automatisches Sperren, Tickets und Playbooks, Threat Intelligence über STIX / TAXII / MISP und Text (IP, Domain, TLS-Fingerabdruck, Datei-Hash, mit Kategorien), Sigma und signierte Regelpakete |
| [Entwicklung und Release](../development.md) | Lokale Tests, Codestruktur, Image-Build und Release |
| [Fähigkeitsbewertung und Roadmap](../roadmap.md) | Erkennungs-, Ortungs- und Rückverfolgungsfähigkeiten entlang der Angriffskette bewertet, mit Lücken und einem Stufenplan |
| [Änderungsprotokoll](../CHANGELOG.md) | Änderungen, die die Nutzung betreffen |

## Entwicklung

Benötigt Go 1.25 oder neuer (Release-Builds verwenden Go 1.27). Reines Go, kein CGO.

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # darf nichts ausgeben
go vet ./...
go test ./...
```

Race-Tests benötigen einen C-Compiler. Ohne gcc auf deinem Rechner führe sie in einem Container aus:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

Codestruktur und Release-Ablauf beschreibt [Entwicklung und Release](../development.md).

## Mitwirken

Issues und Pull Requests sind willkommen, besonders:

- Beispiele neuer Logformate (bitte vorher anonymisieren) sowie Berichte über fehlgeschlagene Erkennung oder Analyse;
- neue Erkennungsregeln sowie Berichte über Fehlalarme oder übersehene Angriffe mit Beispielen;
- Verbesserungen der Dokumentation und Erfahrungen aus realen Bereitstellungen.

Bitte bestehe vor dem Einreichen von Code die obigen Prüfungen. Die CI führt außerdem Race-Tests und `govulncheck` aus.

Wenn dir netsa hilft, gib ihm einen **Star**, damit mehr Menschen, die es brauchen, es finden.

## Lizenz

Dieses Projekt wird unter der [Apache License 2.0](../../LICENSE) veröffentlicht: Du darfst es kommerziell nutzen, verändern und weiterverbreiten, sofern du den Urheberrechtshinweis, den Lizenztext und die Datei [NOTICE](../../NOTICE) beibehältst.

- Die Software wird „wie besehen“ bereitgestellt, ohne ausdrückliche oder stillschweigende Gewährleistung;
- Die Lizenz gewährt keine Markenrechte; Name und Logo von `netsa` sind nicht umfasst;
- Abhängigkeiten von Drittanbietern unterliegen ihren eigenen Lizenzen, vollständig aufgeführt in `go.mod` und `go.sum`. Einige Erkennungsregeln sind aus dem [OWASP Core Rule Set](https://coreruleset.org) (Apache-2.0) übernommen, und die Signaturen verwundbarer Endpunkte chinesischer OA-Systeme und Middleware stammen aus [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT); siehe [NOTICE](../../NOTICE).

Kommerzielle Leistungen wie Regel- und Threat-Intelligence-Abonnements, Bereitstellung und Auslieferung sowie Unterstützung bei MLPS-Prüfungen bieten die Maintainer gesondert an; deine Nutzungsrechte an der Open-Source-Ausgabe unter Apache-2.0 bleiben davon unberührt.

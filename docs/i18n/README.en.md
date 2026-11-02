<div align="center">

# netsa

**Open-source network security situational awareness and attack surface analysis platform**

Turn nginx, firewall / IDS, host authentication and DNS logs into a security picture you can trace, act on, and that keeps learning.<br>
A single binary that works out of the box, including on isolated networks.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · **English** · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[Quick start](#quick-start) · [Screenshots](#screenshots) · [Core capabilities](#core-capabilities) · [How it works](#how-it-works) · [Supported logs](#supported-logs) · [Documentation](#documentation)

</div>

![Situation overview: attack map, live alerts and threat index](../images/overview.png)

## Why netsa

- **No dependencies, one-step deployment**: a single Go binary with the web UI, world and China province/city maps, and offline geolocation databases built in. No Elasticsearch, Kafka or database required. Docker images are available for amd64 and arm64, and with online tracing turned off it runs fully offline on isolated networks.
- **No log adaptation needed up front**: automatically recognizes more than 40 formats, covering nginx / Apache / IIS / Caddy, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, Linux and Windows authentication, mainstream DNS servers, and wrapper formats from collectors such as Docker and Filebeat.
- **Accurate detection, alerts you can trust**: 69 signature rules plus behavioral detection, with responses, session evidence and asset vulnerabilities used to re-check "apparent success". Severity comes from one central decision: blocked attacks are never labeled "critical", and successful exploitation is not missed.
- **Trace to the city, link to the group**: recovers the real IP behind CDNs and proxies, and detects XFF spoofing and direct-to-origin connections that bypass the CDN. Multiple geolocation sources are cross-checked and given a confidence level. Same-origin correlation finds other IPs likely to belong to the same attacker.
- **Gets more accurate with use**: learns from analysts' verdicts. Rules and endpoints with repeated false positives are downgraded automatically, and confirmed attackers are escalated automatically when they return. AI triage supports both OpenAI and Anthropic APIs, so on-premises vLLM and cloud models can both connect. It adapts to model differences automatically and uses analysts' verdicts to assess how far each model can be trusted.
- **A complete security operations loop**: incident aggregation with handling deadlines, false-positive suppression, DingTalk / WeCom / Feishu notifications, asset and vulnerability correlation, raw log retention and forensics, weekly and monthly reports, MLPS 2.0 (China's Multi-Level Protection Scheme) self-assessment, and a tamper-evident audit chain.
- **Fast on a single machine**: about 460,000 events per second end to end on a development machine (i7-10700, 16 threads). Aho-Corasick prefiltering means normal requests rarely need a regex, at about 3µs per event.

## Quick start

### Try it with one command (simulated attack logs included)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Open <http://localhost:8080> and sign in with username `admin` and password `Netsa@demo2026`. The simulator keeps generating attack logs, and the dashboard updates in real time.

### Production deployment

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Visit `http://<server-ip>:8080`. The initial password is in the logs: `docker compose logs netsa | grep 初始密码` (`初始密码` is the literal log text, meaning "initial password"). You must change it at first login.
- By default it reads `/var/log/nginx` and `/var/log` on the host. Send syslog from network devices to `<server-ip>:5514` (UDP / TCP).
- To pin a version, change ports or enable alert archiving, run `cp .env.example .env` first and edit it following the comments.
- Windows PowerShell 5.1 does not support `&&` or `grep`: run commands one line at a time, and use `Select-String` instead of `grep`.

For upgrades and rollback, offline deployment and common problems, see the [deployment guide](../deployment.md).

### Analyze existing logs without deploying

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # open the dashboard after analysis
```

## Screenshots

| Security assessment and recommendations | Attack surface analysis |
|---|---|
| ![Security assessment](../images/assess.png) | ![Attack surface analysis](../images/surface.png) |
| **Incident handling and deadlines** | **Self-learning and auto-calibration** |
| ![Incident handling](../images/incidents.png) | ![Self-learning](../images/learn.png) |

The screenshots show the web UI, which is in Chinese, using demo data from the built-in simulator. All IPs and sites in them are simulated. You can try it yourself with the demo environment above.

## Core capabilities

| Module | Capabilities |
|---|---|
| [Log collection](../log-sources.md) | Live file tailing (wildcards, logrotate rotation), batch analysis (including `.gz`), syslog over UDP / TCP / TLS (mutual authentication optional); sender identification, allowlist, rate limiting and silent-source alerts |
| [Attack detection](../detection.md) | Signature rules for SQL injection, XSS, command execution, Log4Shell, SSRF, XXE, deserialization, WebShell, known vulnerability exploitation and more; behavioral detection of CC attacks, brute force, credential stuffing, API enumeration, port scanning and more; multi-round decoding against common evasion |
| [Result verification](../detection.md#研判复核用证据排除表面成功) | Uses responses and session evidence to distinguish blocked, failed, not blocked and suspected success; rules out appearances such as single-page app fallback pages, unified error pages, and "allowed" traffic that never reached a service |
| [Host and DNS detection](../log-sources.md#主机认证日志与-dns-日志) | SSH / RDP / VPN brute force and successful compromise, password spraying, cleared logs, new accounts and privilege escalation; DNSLog out-of-band callbacks, DNS tunneling, DGA, mining pool domains |
| [Attack source tracing](../traceability.md) | Combines ip2region, MaxMind, ip-api, rDNS and RDAP / WHOIS, with custom internal subnet locations; same-origin correlation by subnet, tool fingerprint and attack technique finds likely members of the same group |
| [Situation dashboard](../deployment.md#演示环境) | World / China attack maps with drill-down to province and city; live attack lines and alert push; KPIs, trends and distribution charts all drill down to attack sources or alerts |
| [Attack surface analysis](../log-sources.md#未做-dnat-映射的端口探测) | Maps exposed services and finds leaked source code, keys and backups, and exposed admin interfaces; uses DNAT mappings and firewall session evidence to filter out background scans that cannot reach any service |
| [Security assessment and compromise analysis](../detection.md#安全评估与失陷研判) | Scores seven dimensions with an A–E overall grade and P0–P3 recommendations; internal hosts connecting to threat-intelligence addresses, C2 beacon detection; MITRE ATT&CK matrix |
| [Self-learning and AI triage](../self-learning.md) | Rule-level and target-level auto-calibration, escalation of returning confirmed attackers, a learning window, with policy adjustable in the web UI; AI triage supports OpenAI / Anthropic APIs and vLLM, adapts to model differences automatically, includes similar cases from your own organization, and tracks how often the model agrees with analysts |
| [Incident handling and notifications](../operations.md#事件处置与误报抑制) | Alerts aggregate into incidents automatically, with assignment, handling deadlines and overdue reminders; false-positive suppression; [DingTalk / WeCom / Feishu notifications](../operations.md#告警推送钉钉--企业微信--飞书) with deduplication, merging and rate limiting; blocklist export for nginx, iptables, ipset and more |
| [Retention, compliance and audit](../operations.md#原始日志留存与检索) | Raw logs retained in hourly compressed segments with a tamper-evident hash chain; [long-term PostgreSQL archiving](../operations.md#告警归档可选postgresql) (optional); weekly and monthly reports, MLPS 2.0 self-assessment; [three roles, two-factor authentication and a tamper-evident audit chain](../operations.md#登录账号与审计); Prometheus metrics |

## How it works

```text
Log sources       nginx · firewall / IDS · host authentication · DNS · containers and collectors
   │              file tailing / batch analysis / syslog (UDP · TCP · TLS)
   ▼
Format detection  format and time zone detected separately per source and per sender
   ▼
Real IP           recovers the source via trusted proxies, flags XFF spoofing and CDN bypass
   ▼
Threat detection  signature rules (AC prefilter + regex) + behavioral detection (time windows, bounded memory)
   ▼
Evidence filter   session evidence and DNAT mappings drop probes that reached no service; suppression applied
   ▼
Learned tuning    downgrades repeated false positives per analyst verdicts, escalates confirmed sources (learn)
   ▼
Severity decision category floor, success escalation, result cap decide the final severity (risk)
   ▼
State store       attacker profiles · alerts · incidents · attack surface · time series · snapshot persistence
   │
   ├── Web dashboard and REST API (SSE live push)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Raw log retention · PostgreSQL archive (optional)
   └── AI triage (optional, conclusions written to the incident record)
```

Key design points:

- **Severity is decided in one place**: the severity declared by a rule is only a suggestion, which prevents each stage from adding and subtracting on its own and leaving similar events with different severities. See [severity decisions](../detection.md#威胁等级判定).
- **Evidence over appearances**: a firewall "allow", a 200 response, or a successful login after repeated failures are all re-checked against sessions, response baselines and account clues.
- **Learning has limits**: it learns only from human verdicts. Automatic adjustments move at most one level at a time, and successful exploitation is still critical. False-positive suppression, which hides alerts, must be adopted by a person. AI conclusions are not used as learning samples and never trigger automatic handling.
- **Stays in control under pressure**: parsing and detection run in parallel and are stored in batches, profile counts and detection windows have hard limits, and a single malformed log line does not affect the service. Queue backlogs and drops all have monitoring metrics.

## Supported logs

| Type | Formats |
|---|---|
| **Web** | nginx / Apache (combined, main, vhost), any custom `log_format`, nginx JSON, Caddy, Traefik, Elastic ECS, IIS W3C |
| **Firewall** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Windows Firewall, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, device threat logs such as FortiGate IPS / UTM |
| **Host and VPN authentication** | Linux `auth.log` / `secure`, Windows security events (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, SQL Server logins |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Containers and collectors** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O, unwrapped automatically to recognize the original log |

See [log onboarding](../log-sources.md) for setup. After connecting a source, check the recognition results and parse-failure samples on the dashboard's data source page.

## Documentation

The detailed documents below are written in Simplified Chinese.

| Document | Contents |
|---|---|
| [Deployment guide](../deployment.md) | Production deployment, `.env` variables, upgrades and rollback, offline networks, demo environment, running from source |
| [Log onboarding](../log-sources.md) | Web, firewall, authentication and DNS onboarding, syslog sender management, time zones, DNAT and session evidence |
| [Detection and verification](../detection.md) | Severity decisions, result verification, threat scoring, security assessment and compromise analysis |
| [Attack source tracing](../traceability.md) | Multi-source geolocation, internal subnets, hot reload of geolocation databases, same-origin correlation |
| [Self-learning and AI triage](../self-learning.md) | What is applied automatically and its limits, behavior baselines, compliance self-checks, external model configuration and adaptation |
| [Security operations](../operations.md) | Incident handling, notifications, raw logs, assets and vulnerabilities, reports and compliance, accounts and audit, metrics, alert archiving |
| [Configuration reference](../configuration.md) | Common settings and operational notes |
| [API](../api.md) | REST API overview |
| [Development and release](../development.md) | Local testing, code structure, image build and release |

## Development

Requires Go 1.25 or later (release builds use Go 1.27). Pure Go, no CGO.

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # must print nothing
go vet ./...
go test ./...
```

Race tests need a C compiler. Without gcc on your machine, run them in a container:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

See [development and release](../development.md) for code structure and the release process.

## Contributing

Issues and pull requests are welcome, especially:

- samples of new log formats (please anonymize them first), and reports of recognition or parsing failures;
- new detection rules, and false-positive or false-negative reports with samples;
- documentation improvements and real-world deployment experience.

Please pass the checks above before submitting code. CI also runs race tests and `govulncheck`.

If netsa is useful to you, please give it a **Star** so more people who need it can find it.

<div align="center">

# netsa

**Open-source network security situational awareness and attack surface analysis platform**

**One binary turns web, firewall / IDS, flow, host and DNS logs into a security picture you can trace, act on — and that corrects its own mistakes.**<br>
No Elasticsearch, Kafka or database required. Works fully offline. Up and running in 5 minutes.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release&color=36cfc9)](https://github.com/sreyun/netsa/tags)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../../LICENSE)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)
[![Stars](https://img.shields.io/github/stars/sreyun/netsa?style=flat&logo=github&color=yellow)](https://github.com/sreyun/netsa/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/sreyun/netsa)](https://github.com/sreyun/netsa/commits/master)

[简体中文](../../README.md) · **English** · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[Quick start](#quick-start) · [Screenshots](#screenshots) · [Core capabilities](#core-capabilities) · [How it works](#how-it-works) · [Supported logs](#supported-logs) · [Documentation](#documentation)

</div>

![Situation overview: attack map, live alerts and threat index](../images/overview.png)

<div align="center">

| 50+ | 87 + libinjection | 261 | ~460k events/s | 0 |
|:---:|:---:|:---:|:---:|:---:|
| log formats auto-detected | signature rules + syntax analysis | Chinese OA / middleware vulnerability signatures | end-to-end on one machine | external components |

</div>

## Why netsa

- **No dependencies, one-step deployment**: a single Go binary with the web UI, world and China province/city maps, and offline geolocation databases built in. No Elasticsearch, Kafka or database required. Docker images are available for amd64 and arm64, and with online tracing turned off it runs fully offline on isolated networks.
- **No log adaptation needed up front**: automatically recognizes more than 50 formats, covering nginx / Tengine / OpenResty / APISIX / Kong / Apache / IIS / Caddy, WAFs such as ModSecurity, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, Linux and Windows authentication, mainstream DNS servers, Zeek, NetFlow / sFlow / IPFIX, Sysmon / auditd / Wazuh host logs, application login logs, and wrapper formats from collectors such as Docker and Filebeat.
- **Accurate detection, alerts you can trust**: 87 signature rules (some adapted from the OWASP CRS), libinjection syntax analysis plus behavioral detection, with responses, session evidence and asset vulnerabilities used to re-check "apparent success". Severity comes from one central decision: blocked attacks are never labeled "critical", and successful exploitation is not missed.
- **Knows Chinese OA systems and middleware**: 261 built-in vulnerable-endpoint signatures covering 42 products, including Seeyon, Weaver, Yonyou, Tongda, Landray and Wanhu OA, FanRuan, Esafenet, RuoYi, Nacos, APISIX, Nginx UI, and Sangfor, Ruijie, Hikvision and Dahua devices. Alerts name the product and the CVE / CNVD ID; vulnerable endpoints used by normal business traffic are learned automatically so they stop raising alerts.
- **Intelligence that is accurate, not just large**: IP, domain, TLS fingerprint and file hash intelligence (STIX / TAXII / MISP / text lists), graded by category (C2, malware, phishing, mining, attack source), with abused public platforms filtered out automatically. Each feed's accuracy is measured against analysts' verdicts, and feeds with persistent false positives are downgraded automatically.
- **Firewall and web logs linked together**: an internal host that, after a web attack, connects to the attacker or to a callback address written in the attack payload is flagged as compromised; a connection to an address from the payload proves the payload was executed.
- **Trace to the city, link to the group**: recovers the real IP behind CDNs and proxies, and detects XFF spoofing and direct-to-origin connections that bypass the CDN. Multiple geolocation sources are cross-checked and given a confidence level. Same-origin correlation and campaign grouping find the rotating exit addresses of one attacker (same tool fingerprint, same OAST correlation ID, TLS fingerprint, same decoy token). A hit on a [decoy](../detection.md#诱饵) (decoy path, token, account or honeypot) identifies an attacker with high confidence. The asset attack chain lays out, in time order, how a server was scanned, exploited, controlled and used for lateral movement.
- **Gets more accurate with use — and corrects itself**: learns from analysts' verdicts. Without any analyst verdict it also checks its own and the AI model's conclusions against objective evidence (proven exploitation, call-backs after an attack, decoy hits, registered authorized scans): what it learned wrong is revoked automatically, incidents it already produced are re-graded (and restored if the correction itself turns out wrong), and finished low-risk incidents are archived so the queue only holds what needs attention. Rules and endpoints with repeated false positives are downgraded automatically, and confirmed attackers are escalated automatically when they return. No manual allowlist curation: it learns each parameter's normal values from normal traffic and passively identifies the products and frontend frameworks each site uses, so plain text typed into a search box, or probes for a product the site does not run, no longer raise high-severity alerts. AI triage supports both OpenAI and Anthropic APIs, so on-premises vLLM and cloud models can both connect. It adapts to model differences automatically and uses analysts' verdicts to assess how far each model can be trusted.
- **A complete security operations loop**: incident aggregation with handling deadlines, false-positive suppression, DingTalk / WeCom / Feishu notifications, asset and vulnerability correlation, raw log retention with one-click evidence packages, weekly and monthly reports, MLPS 2.0 (China's Multi-Level Protection Scheme) self-assessment, and a tamper-evident audit chain.
- **One search box for everything**: press `Ctrl+K` and type an IP, incident number, asset, site, rule or attack type; results are grouped by category and open the attacker profile, incident, attack chain or campaign straight from the keyboard, with one-step fallbacks to alert and raw-log search.
- **Fast on a single machine**: about 460,000 events per second end to end on a development machine (i7-10700, 16 threads). Aho-Corasick prefiltering means normal requests rarely need a regex, at about 3µs per event.

## Quick start

### Try it with one command (simulated attack logs included)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Open <http://localhost:8080> and sign in as `admin` with password `Netsa@demo2026`. The simulator keeps generating attack logs and the dashboard updates live.

### Production deployment

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Open `http://<server IP>:8080`. The initial password is in the log: `docker compose logs netsa | grep 初始密码`. You must change it after the first sign-in.
- By default the host's `/var/log/nginx` and `/var/log` are read; send syslog from network devices to `<server IP>:5514` (UDP / TCP).
- To pin a version, change ports or enable the alert archive, run `cp .env.example .env` first and edit it as the comments describe.
- Windows PowerShell 5.1 does not support `&&` or `grep`: run the commands one at a time and use `Select-String` instead of `grep`.

See the [deployment guide](../deployment.md) for upgrades and rollback, offline deployment and common questions.

### Analyze existing logs without deploying

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # open the dashboard after analysis
```

## Screenshots

| Security assessment and recommended actions | Attack surface analysis |
|---|---|
| ![Security assessment](../images/assess.png) | ![Attack surface analysis](../images/surface.png) |
| **Incident handling and deadlines** | **Self-learning and automatic tuning** |
| ![Incident handling](../images/incidents.png) | ![Self-learning](../images/learn.png) |

Screenshots use demo data from the built-in simulator; all IPs and sites are simulated. Try it yourself with the demo environment above.

## Core capabilities

| Module | Capabilities |
|---|---|
| [Log collection](../log-sources.md) | Live file tailing (wildcards, logrotate rotation), batch analysis (including `.gz`), syslog over UDP / TCP / TLS (optionally mutual TLS), [NetFlow / sFlow / IPFIX collection](../log-sources.md#流量日志zeeknetflow--sflow-与云抗-d-服务); sender identification, allowlists, rate limits and source-silence alerts |
| [Attack detection](../detection.md) | Signature rules for SQL injection, XSS, command execution, Log4Shell, SSRF, XXE, deserialization, WebShells, known exploits and more, with some command, code and Java class rules adapted from the OWASP CRS; [libinjection syntax analysis](../detection.md#语法分析libinjection) re-checks injection hits and catches variants the regexes miss; [vulnerable-endpoint signatures for Chinese OA and middleware](../detection.md#国产-oa中间件漏洞接口签名) (261 signatures, 42 products); behavioral detection of CC, brute force, credential stuffing, endpoint enumeration, port scanning, WebShell behavior, data exfiltration, lateral movement and bandwidth DDoS; POST payloads are checked too when the request body is logged; multi-round decoding defeats common evasion |
| [Result verification](../detection.md#研判复核用证据排除表面成功) | Uses responses and session evidence to separate blocked, failed, not blocked and likely successful attacks; rules out apparent success such as single-page-app fallback pages, uniform error pages and "allowed" traffic that never reached a service |
| [Host and DNS detection](../log-sources.md#主机认证日志与-dns-日志) | SSH / RDP / VPN brute force and successful cracks, password spraying, cleared logs, new accounts and privilege escalation, [account takeover](../detection.md#账号盗用) (impossible travel, new-country logins, concurrent logins from many places); [host process detection](../detection.md#主机进程检测) (web server processes running commands, reverse shells, credential theft, persistence); DNSLog out-of-band callbacks, DNS tunneling, DGA, mining pool domains, and C2, malware and phishing domains flagged by intelligence |
| [Attack source tracing](../traceability.md) | Combines ip2region, MaxMind, ip-api, rDNS and RDAP / WHOIS, with custom internal subnet locations; same-origin correlation uses subnets, tool fingerprints and attack techniques to find likely members of the same group |
| [Asset attack chain](../detection.md#资产攻击链路) | Centers on a site or host and links reconnaissance, exploitation, breach, implant, control, lateral movement, collection and impact, with evidence, source and ATT&CK technique for every step; sites and the servers behind them are merged automatically, with a compromise verdict and recommended actions |
| [Situation dashboard](../deployment.md#演示环境) | World / China attack maps with drill-down to provinces and cities; live attack lines and alert push; KPIs, trends and distribution charts all drill down to attack sources or alerts |
| [Attack surface analysis](../log-sources.md#未做-dnat-映射的端口探测) | Maps exposed services and finds leaked source code, keys and backups, and exposed admin interfaces; combines DNAT mappings with firewall session evidence to filter out background scanning that cannot reach any service |
| [Security assessment and compromise analysis](../detection.md#安全评估与失陷研判) | Scores seven dimensions with an A–E overall grade and P0–P3 recommendations; detects internal hosts connecting to intelligence-listed addresses, C2 beacons, malicious TLS fingerprints and payloads landing on hosts; [firewall and web log correlation](../detection.md#防火墙与-web-日志联动被攻击后回连) finds hosts that connected back to their attacker; MITRE ATT&CK matrix |
| [Self-learning and AI triage](../self-learning.md) | Rule-level, target-level and intelligence-feed accuracy calibrated automatically, escalation when confirmed sources return, learning windows, with policies adjustable in the UI; learns internal subnets, attack sources, campaigns, and [normal parameter values and site products](../self-learning.md#参数的正常取值与站点产品) from logs; AI triage supports OpenAI / Anthropic APIs and vLLM, adapts to model differences automatically, includes similar cases from your own organization, and tracks how often the model agrees with analysts |
| [Incident handling and notifications](../operations.md#事件处置与误报抑制) | Alerts are aggregated into incidents automatically, with assignment, handling deadlines and overdue reminders; false-positive suppression; [authorized scan registration](../detection.md#授权扫描登记) (record without alerting during a test, restored automatically when it ends); [DingTalk / WeCom / Feishu notifications](../operations.md#告警推送钉钉--企业微信--飞书) with deduplication, merging and rate limiting; blocklist export for nginx, iptables, ipset and more |
| [Retention, compliance and audit](../operations.md#原始日志留存与检索) | Raw logs compressed and retained by hour, with a hash chain against tampering; [PostgreSQL long-term archive](../operations.md#告警归档可选postgresql) (optional); weekly and monthly reports, MLPS 2.0 self-assessment; [three roles, two-factor authentication and a tamper-evident audit chain](../operations.md#登录账号与审计); Prometheus metrics |

## How it works

```text
Log sources       nginx · firewall / IDS · Zeek · host authentication and processes · app logins · DNS · containers and collectors
   │              file tailing / batch analysis / syslog (UDP · TCP · TLS) / flow collection (NetFlow · IPFIX · sFlow)
   ▼
Format detection  format and time zone detected separately per source and per sender
   ▼
Real IP           recovers the source via trusted proxies, flags XFF spoofing and CDN bypass
   ▼
Threat detection  signature rules (AC prefilter + regex) + syntax analysis (libinjection) + host process rules + behavioral detection (time windows, bounded memory)
   ▼
Intel and decoys  IP / domain / TLS fingerprint / file hash intelligence; hits on decoy paths, tokens, accounts and honeypots confirm the attacker
   ▼
Evidence filter   session evidence and DNAT mappings drop probes that reached no service; suppression applied
   ▼
Learned tuning    normal parameter values and site products re-check hits; repeated false positives downgraded per analyst verdicts, confirmed sources escalated (learn)
   ▼
Correlation       links earlier web attacks: callbacks and payload downloads after an attack; later lateral connections from compromised hosts
   ▼
Severity decision category floor, success escalation, result cap decide the final severity (risk)
   ▼
State store       attacker profiles · alerts · incidents · campaigns · asset attack chains · attack surface · time series · snapshot persistence
   │
   ├── Web dashboard and REST API (SSE live push)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Raw log retention · PostgreSQL archive (optional)
   └── AI triage (optional, conclusions written to the incident record)
```

Key design points:

- **Severity is decided in one place**: the severity declared by a rule is only a suggestion, which prevents each stage from adding and subtracting on its own and leaving similar events with different severities. See [severity decisions](../detection.md#威胁等级判定).
- **Evidence over appearances**: a firewall "allow", a 200 response, or a successful login after repeated failures are all re-checked against sessions, response baselines and account clues.
- **Learning has limits**: rule calibration learns only from human verdicts. Automatic adjustments move at most one level at a time, and successful exploitation is still critical. Normal parameter values and site products learned from traffic downgrade a hit only when two independent conditions both hold (the parameter is normally plain text and syntax analysis finds no injection; the site does not run the product and the request did not succeed), and only to low severity, never hiding the alert. False-positive suppression, which hides alerts, must be adopted by a person. AI conclusions are not used as learning samples and never trigger automatic handling.
- **Stays in control under pressure**: parsing and detection run in parallel and are stored in batches, profile counts and detection windows have hard limits, and a single malformed log line does not affect the service. Queue backlogs and drops all have monitoring metrics.

## Supported logs

| Type | Formats |
|---|---|
| **Web** | nginx / Tengine / OpenResty / Apache (combined, main, vhost), any custom `log_format`, nginx JSON, APISIX, Kong, Nginx Proxy Manager, Caddy, Traefik, Elastic ECS, IIS W3C |
| **WAF** | ModSecurity and naxsi blocks and rate limiting in nginx / Tengine / OpenResty error logs, ModSecurity JSON audit logs, OpenResty Lua WAF |
| **Firewall** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Windows Firewall, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone, plus attack-defense logs from Huawei, H3C and Sangfor |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, device threat logs such as FortiGate IPS / UTM |
| **Host and VPN authentication** | Linux `auth.log` / `secure`, Windows security events (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, SQL Server logins |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Network flows** | Zeek (conn / http / ssl / files, TSV or JSON), NetFlow v5 / v9, IPFIX, sFlow v5 (UDP collection), attack events from cloud anti-DDoS services |
| **Host processes (EDR / HIDS)** | Sysmon (Winlogbeat / NXLog / Elastic Agent), Windows 4688, Elastic Defend (ECS), Linux auditd, Wazuh alerts |
| **App logins and honeypots** | JSON login logs from business systems and identity / SSO platforms, OpenCanary honeypot logs |
| **Containers and collectors** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O, unwrapped automatically to recognize the original log |

See [log onboarding](../log-sources.md) for setup. After connecting a source, check the recognition results and parse-failure samples on the dashboard's data source page.

## Documentation

The detailed documentation is in Simplified Chinese.

| Document | Contents |
|---|---|
| [Deployment guide](../deployment.md) | Production deployment, `.env` variables, upgrade and rollback, offline networks, demo environment, running from source |
| [Log onboarding](../log-sources.md) | Web, firewall, authentication, DNS, network flow (Zeek, NetFlow / sFlow, cloud anti-DDoS), host process and app login onboarding, syslog sender management, time zones, DNAT and session evidence |
| [Detection and verification](../detection.md) | Severity decisions, result verification, campaigns and asset attack chains, data theft and lateral movement, decoys, host process detection, account takeover, threat scoring, security assessment and compromise analysis |
| [Attack source tracing](../traceability.md) | Multi-source geolocation, internal subnets, hot reload of geolocation databases, same-origin correlation |
| [Self-learning and AI triage](../self-learning.md) | What is applied automatically and its limits, behavior baselines, compliance self-check, external model configuration and model adaptation |
| [Security operations](../operations.md) | Incident handling, notifications, raw logs, assets and vulnerabilities, reports and compliance, accounts and audit, monitoring metrics, alert archive |
| [Configuration reference](../configuration.md) | Common settings and operational notes |
| [API](../api.md) | REST API overview |
| [External integrations](../integrations.md) | LDAP / OIDC single sign-on, SIEM forwarding, automated blocking, tickets and playbooks, STIX / TAXII / MISP and text intelligence (IP, domain, TLS fingerprint, file hash, with categories), Sigma and signed rule packs |
| [Development and release](../development.md) | Local testing, code structure, image build and release |
| [Capability assessment and roadmap](../roadmap.md) | Detection, location and tracing capabilities assessed along the attack chain, with gaps and a phased plan |
| [Changelog](../CHANGELOG.md) | Changes that affect usage |

## Development

Requires Go 1.26 or later (release builds use Go 1.27). Pure Go, no CGO.

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

If netsa helped you catch a real attack — or saved you running a whole log platform — please give it a **Star** so more people who need it can find it.

[![Star History Chart](https://api.star-history.com/svg?repos=sreyun/netsa&type=Date)](https://star-history.com/#sreyun/netsa&Date)

## License

This project is released under the [Apache License 2.0](../../LICENSE): you may use it commercially, modify it and redistribute it, provided you keep the copyright notice, the license text and the [NOTICE](../../NOTICE) file.

- The software is provided "as is", without warranties of any kind, express or implied;
- The license does not grant trademark rights; the `netsa` name and logo are not covered;
- Third-party dependencies follow their own licenses, listed in full in `go.mod` and `go.sum`. Some detection rules are adapted from the [OWASP Core Rule Set](https://coreruleset.org) (Apache-2.0), and the Chinese OA and middleware vulnerable-endpoint signatures are extracted from [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT); see [NOTICE](../../NOTICE).

Commercial services such as rule and intelligence subscriptions, deployment and delivery, and MLPS assessment support are provided separately by the maintainers and do not affect your rights to use the open-source edition under Apache-2.0.

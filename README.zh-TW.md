<div align="center">

# netsa

**開源的網路安全態勢感知與攻擊面分析平台**

把 nginx、防火牆 / IDS、主機認證與 DNS 日誌，變成可溯源、可處置、會持續學習的安全態勢。<br>
單一執行檔，開箱即用，支援內網離線執行。

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](README.md) · [English](README.en.md) · **繁體中文** · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[快速開始](#快速開始) · [介面預覽](#介面預覽) · [核心能力](#核心能力) · [運作原理](#運作原理) · [支援的日誌](#支援的日誌) · [文件](#文件)

</div>

![態勢總覽：攻擊地圖、即時告警與威脅指數](docs/images/overview.png)

## 為什麼是 netsa

- **零相依，一鍵部署**：Go 單一執行檔，前端、世界與中國省市地圖、離線定位資料庫全部內建，不需要 Elasticsearch、Kafka 或資料庫。Docker 映像同時提供 amd64 與 arm64，關閉線上溯源後可在隔離網路中完全離線執行。
- **日誌不用先適配**：自動識別 40 餘種格式，涵蓋 nginx / Apache / IIS / Caddy、iptables、華為、H3C、FortiGate、Palo Alto、Suricata、Linux 與 Windows 認證、主流 DNS，以及 Docker、Filebeat 等採集器的包裝格式。
- **偵測準，告警可信**：69 條特徵規則加行為偵測，用回應、工作階段證據和資產弱點複核「表面成功」。等級由統一裁決決定：已攔截的攻擊不會被標成「嚴重」，真正利用成功的不會被漏掉。
- **能溯源到城市，能關聯到團夥**：還原 CDN 與代理背後的真實 IP，識別 XFF 偽造和繞過 CDN 直連；多來源定位交叉比對並給出信賴度；同源關聯分析找出疑似同一攻擊者的其他 IP。
- **越用越準**：從分析師的處置結論中學習，反覆誤報的規則和介面自動降級，已確認的攻擊者再次出現自動升級。AI 研判同時支援 OpenAI 與 Anthropic 介面，內網 vLLM、雲端模型都能接入，自動適配模型差異，並用分析師的結論評估模型可信度。
- **安全維運閉環**：事件聚合與處置時限、誤報抑制、釘釘 / 企業微信 / 飛書推播、資產弱點關聯、原始日誌留存與取證、週報月報、等保 2.0 自查、防竄改稽核鏈。
- **單機就夠快**：開發機（i7-10700，16 執行緒）端到端約 46 萬條/秒；Aho-Corasick 預篩讓正常請求基本不必執行正規表示式，偵測約 3µs/條。

## 快速開始

### 一條指令體驗（內建模擬攻擊日誌）

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

瀏覽器開啟 <http://localhost:8080>，帳號 `admin`，密碼 `Netsa@demo2026`。模擬器會持續產生攻擊日誌，大螢幕即時更新。

### 正式環境部署

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- 造訪 `http://<伺服器IP>:8080`，初始密碼在日誌中：`docker compose logs netsa | grep 初始密码`（`初始密码` 是日誌中的簡體原文），首次登入後須修改。
- 預設讀取主機的 `/var/log/nginx` 與 `/var/log`；網路設備的 syslog 傳送到 `<伺服器IP>:5514`（UDP / TCP）。
- 需要固定版本、修改連接埠或啟用告警歸檔時，先執行 `cp .env.example .env` 再依註解修改。
- Windows PowerShell 5.1 不支援 `&&` 和 `grep`：請逐行執行指令，並用 `Select-String` 代替 `grep`。

升級回滾、內網離線部署和常見問題見[部署指南](docs/deployment.md)。

### 不部署，直接分析現有日誌

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # 分析後開啟大螢幕
```

## 介面預覽

| 安全評估與處置建議 | 攻擊面分析 |
|---|---|
| ![安全評估](docs/images/assess.png) | ![攻擊面分析](docs/images/surface.png) |
| **事件處置與處置時限** | **自學習與自動校準** |
| ![事件處置](docs/images/incidents.png) | ![自學習](docs/images/learn.png) |

截圖為簡體中文介面，來自內建模擬器產生的示範資料，其中的 IP 與站點均為模擬，可用上面的示範環境自行體驗。

## 核心能力

| 模組 | 能力 |
|---|---|
| [日誌採集](docs/log-sources.md) | 即時追蹤檔案（萬用字元、logrotate 輪替）、批次分析（含 `.gz`）、Syslog UDP / TCP / TLS（可雙向認證）；傳送端識別、白名單、限速與斷流告警 |
| [攻擊偵測](docs/detection.md) | SQL 注入、XSS、命令執行、Log4Shell、SSRF、XXE、反序列化、WebShell、已知弱點利用等特徵規則；CC、暴力破解、撞庫、介面遍歷、連接埠掃描等行為偵測；多輪解碼對抗常見繞過 |
| [結果研判](docs/detection.md#研判复核用证据排除表面成功) | 依回應與工作階段證據區分已攔截、失敗、未攔截、疑似成功；排除單頁應用程式兜底頁、統一錯誤頁、未到達服務的「放行」等表面現象 |
| [主機與 DNS 偵測](docs/log-sources.md#主机认证日志与-dns-日志) | SSH / RDP / VPN 暴力破解與破解成功、密碼噴灑、日誌被清除、新建帳號與提權；DNSLog 帶外回連、DNS 隧道、DGA、礦池網域 |
| [攻擊來源溯源](docs/traceability.md) | 融合 ip2region、MaxMind、ip-api、rDNS、RDAP / WHOIS，支援內網自訂網段定位；同源關聯依網段、工具指紋、攻擊手法找出疑似同一團夥 |
| [態勢大螢幕](docs/deployment.md#演示环境) | 世界 / 中國雙視圖攻擊地圖，可下鑽到省和地市；即時飛線與告警推播；KPI、趨勢、分布圖均可點擊下鑽到攻擊來源或告警 |
| [攻擊面分析](docs/log-sources.md#未做-dnat-映射的端口探测) | 梳理對外服務，發現原始碼、金鑰、備份洩露與管理介面暴露；結合 DNAT 映射與防火牆工作階段證據，過濾打不到任何服務的背景掃描 |
| [安全評估與失陷研判](docs/detection.md#安全评估与失陷研判) | 七個維度評分並給出 A~E 總評與 P0~P3 處置建議；內網主機外連情報位址、C2 心跳偵測；MITRE ATT&CK 矩陣 |
| [自學習與 AI 研判](docs/self-learning.md) | 規則級與目標級自動校準、確認攻擊來源復現升級、學習視窗，策略可在頁面調整；AI 研判支援 OpenAI / Anthropic 介面與 vLLM，自動適配模型差異，附帶本單位相似案例，並統計模型與分析師結論的一致率 |
| [事件處置與推播](docs/operations.md#事件处置与误报抑制) | 告警自動聚合為事件，支援指派、處置時限與逾時提醒；誤報抑制；[釘釘 / 企業微信 / 飛書推播](docs/operations.md#告警推送钉钉--企业微信--飞书)，去重、合併、限速；匯出 nginx、iptables、ipset 等封鎖清單 |
| [留存、合規與稽核](docs/operations.md#原始日志留存与检索) | 原始日誌按小時壓縮留存，雜湊鏈防竄改；[PostgreSQL 長期歸檔](docs/operations.md#告警归档可选postgresql)（可選）；週報月報、等保 2.0 自查；[三種角色、雙因素認證與防竄改稽核鏈](docs/operations.md#登录账号与审计)；Prometheus 指標 |

## 運作原理

```text
日誌來源    nginx · 防火牆 / IDS · 主機認證 · DNS · 容器與採集器
   │        檔案追蹤 / 批次分析 / Syslog（UDP · TCP · TLS）
   ▼
格式識別    每個資料來源、每個傳送端獨立識別格式與時區
   ▼
真實 IP     依可信代理還原來源，標記 XFF 偽造與繞過 CDN
   ▼
威脅偵測    特徵規則（AC 預篩 + 正規表示式）+ 行為偵測（時間視窗，記憶體有上限）
   ▼
證據過濾    工作階段證據與 DNAT 映射排除未到達服務的探測，套用誤報抑制
   ▼
學習校準    依分析師結論下調反覆誤報的命中，升級已確認攻擊來源（learn）
   ▼
等級裁決    分類底線、成功升級、結果封頂，統一決定最終等級（risk）
   ▼
狀態庫      攻擊者畫像 · 告警 · 安全事件 · 攻擊面 · 時間序列 · 快照持久化
   │
   ├── Web 大螢幕與 REST API（SSE 即時推播）
   ├── 釘釘 / 企業微信 / 飛書 / Webhook
   ├── 原始日誌留存 · PostgreSQL 歸檔（可選）
   └── AI 研判（可選，結論寫入事件處置紀錄）
```

幾個關鍵設計：

- **等級只在一處裁決**：規則宣告的等級只是建議值，避免各環節各自加減造成同類事件等級不一致。詳見[威脅等級判定](docs/detection.md#威胁等级判定)。
- **證據優先於表象**：防火牆「放行」、回應 200、多次失敗後登入成功，都要再用工作階段、回應基線和帳號線索複核。
- **學習有邊界**：只從人的結論學習；自動調整每次最多一級，利用成功仍判嚴重；會隱藏告警的誤報抑制必須人工採納。AI 結論不作為學習樣本，也不會自動處置。
- **壓力下不失控**：解析與偵測並行、分批入庫，畫像數和偵測視窗都有硬上限，單條畸形日誌不影響服務；佇列積壓和丟棄都有監控指標。

## 支援的日誌

| 類型 | 格式 |
|---|---|
| **Web** | nginx / Apache（combined、main、vhost）、任意自訂 `log_format`、nginx JSON、Caddy、Traefik、Elastic ECS、IIS W3C |
| **防火牆** | iptables、UFW、firewalld、nftables、pfSense / OPNsense、Windows 防火牆、Cisco ASA / FTD、Palo Alto、FortiGate、華為 USG、H3C、深信服、山石 |
| **IDS / IPS** | Suricata EVE JSON、Snort fast alert、FortiGate IPS / UTM 等設備威脅日誌 |
| **主機與 VPN 認證** | Linux `auth.log` / `secure`、Windows 安全事件（NXLog、Winlogbeat、Snare）、FortiGate / Cisco / OpenVPN、SQL Server 登入 |
| **DNS** | BIND、dnsmasq、CoreDNS、Windows DNS、Zeek、Suricata DNS |
| **容器與採集器** | Docker json-file、Fluent Bit / Fluentd、Filebeat / Logstash / Vector、containerd / CRI-O，自動拆開後識別原始日誌 |

接入方法見[日誌接入](docs/log-sources.md)；接入後在大螢幕「資料來源」頁檢視識別結果和解析失敗範例。

## 文件

以下詳細文件為簡體中文。

| 文件 | 內容 |
|---|---|
| [部署指南](docs/deployment.md) | 正式環境部署、`.env` 變數、升級回滾、內網離線、示範環境、從原始碼執行 |
| [日誌接入](docs/log-sources.md) | Web、防火牆、認證、DNS 接入，syslog 傳送端管理，時區，DNAT 與工作階段證據 |
| [偵測與研判](docs/detection.md) | 威脅等級判定、研判複核、威脅評分、安全評估與失陷研判 |
| [攻擊來源溯源](docs/traceability.md) | 多來源定位、內網網段、定位資料庫熱更新、同源關聯分析 |
| [自學習與 AI 研判](docs/self-learning.md) | 自動生效的範圍與邊界、行為基線、合規自檢、外部模型設定與模型適配 |
| [安全維運](docs/operations.md) | 事件處置、告警推播、原始日誌、資產弱點、報表合規、帳號稽核、監控指標、告警歸檔 |
| [設定參考](docs/configuration.md) | 常用設定項與執行注意事項 |
| [API](docs/api.md) | REST 介面一覽 |
| [開發與發布](docs/development.md) | 本機測試、程式碼結構、映像建置與發布 |

## 開發

需要 Go 1.25 及以上（發布版本使用 Go 1.27 建置），純 Go 實作，無 CGO。

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # 必須沒有輸出
go vet ./...
go test ./...
```

競態測試依賴 C 編譯器，本機沒有 gcc 時可以在容器裡執行：

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

程式碼結構和發布流程見[開發與發布](docs/development.md)。

## 參與貢獻

歡迎提交 Issue 和 Pull Request，尤其歡迎：

- 新的日誌格式範例（請先去識別化），以及識別失敗或解析錯誤的回饋；
- 新的偵測規則，以及附範例的誤報、漏報回報；
- 文件改進和實際部署經驗。

提交程式碼前請先通過上面的檢查，CI 還會執行競態測試和 `govulncheck`。

如果 netsa 對你有幫助，請點一個 **Star**，讓更多需要它的人看到。

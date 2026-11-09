<div align="center">

# netsa

**開源的網路安全態勢感知與攻擊面分析平台**

把 Web、防火牆 / IDS、流量、主機認證與處理程序、DNS 日誌，變成可溯源、可處置、會持續學習的安全態勢。<br>
單一執行檔，開箱即用，支援內網離線執行。

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · **繁體中文** · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[快速開始](#快速開始) · [介面預覽](#介面預覽) · [核心能力](#核心能力) · [運作原理](#運作原理) · [支援的日誌](#支援的日誌) · [文件](#文件)

</div>

![態勢總覽：攻擊地圖、即時告警與威脅指數](../images/overview.png)

## 為什麼是 netsa

- **零相依，一鍵部署**：Go 單一執行檔，前端、世界與中國省市地圖、離線定位資料庫全部內建，不需要 Elasticsearch、Kafka 或資料庫。Docker 映像同時提供 amd64 與 arm64，關閉線上溯源後可在隔離網路中完全離線執行。
- **日誌不用先適配**：自動識別 50 餘種格式，涵蓋 nginx / Tengine / OpenResty / APISIX / Kong / Apache / IIS / Caddy、ModSecurity 等 WAF、iptables、華為、H3C、FortiGate、Palo Alto、Suricata、Linux 與 Windows 認證、主流 DNS、Zeek、NetFlow / sFlow / IPFIX、Sysmon / auditd / Wazuh 主機日誌、應用程式登入日誌，以及 Docker、Filebeat 等採集器的包裝格式。
- **偵測準，告警可信**：87 條特徵規則（部分改編自 OWASP CRS）、libinjection 語法分析加行為偵測，用回應、工作階段證據和資產弱點複核「表面成功」。等級由統一裁決決定：已攔截的攻擊不會被標成「嚴重」，真正利用成功的不會被漏掉。
- **認得中國的 OA 與中介軟體**：內建 261 條弱點介面特徵，涵蓋致遠、泛微、用友、通達、藍凌、萬戶 OA，帆軟、億賽通、若依、Nacos、APISIX、Nginx UI，以及深信服、銳捷、海康、大華等 42 個產品，告警直接註明產品與 CVE / CNVD 編號；正常業務在用的弱點介面自動學習，不會一直刷告警。
- **情資在準不在多**：IP、網域、TLS 指紋與檔案雜湊情資（STIX / TAXII / MISP / 文字清單），依遠控、惡意軟體、釣魚、礦池、攻擊來源分類定級，自動過濾被濫用的公共平台；每個情資來源的準確率依分析師結論自動統計，長期誤報的自動降級。
- **防火牆與 Web 日誌聯動**：Web 攻擊之後內網主機連線攻擊者、或連線攻擊載荷裡寫著的回連位址，直接判為入侵跡象；載荷中的位址被連線即證明載荷已被執行。
- **能溯源到城市，能關聯到團夥**：還原 CDN 與代理背後的真實 IP，識別 XFF 偽造和繞過 CDN 直連；多來源定位交叉比對並給出信賴度；同源關聯與攻擊活動歸併找出同一攻擊者輪換的出口（同一工具指紋、同一 OAST 關聯標識、TLS 指紋、同一誘餌線索）；[誘餌](../detection.md#诱饵)（誘餌路徑、線索、帳號、蜜罐）命中即高信賴攻擊者；資產攻擊鏈路把一台伺服器從被掃描、被利用到被控制、橫向移動的全過程依時間串起來。
- **越用越準**：從分析師的處置結論中學習，反覆誤報的規則和介面自動降級，已確認的攻擊者再次出現自動升級；不需要人工整理白名單，自動從正常流量學習每個參數平時的取值、被動識別每個網站使用的產品與前端框架，搜尋框裡的普通文字、網站上根本不存在的產品的弱點探測不再刷出高風險。AI 研判同時支援 OpenAI 與 Anthropic 介面，內網 vLLM、雲端模型都能接入，自動適配模型差異，並用分析師的結論評估模型可信度。
- **安全維運閉環**：事件聚合與處置時限、誤報抑制、釘釘 / 企業微信 / 飛書推播、資產弱點關聯、原始日誌留存與一鍵取證包、週報月報、等保 2.0 自查、防竄改稽核鏈。
- **一個搜尋框直達一切**：`Ctrl+K` 輸入 IP、事件編號、資產、站點、規則或攻擊類型，依類別分組，用鍵盤直達攻擊源畫像、事件、攻擊鏈路與攻擊活動；搜不到時一鍵轉到告警與原始日誌檢索。
- **內外雙向都看得見**：攻擊地圖同時畫出外部對內的攻擊，以及內網主機對外的攻擊與異常連線（外連威脅情資位址、木馬回連、資料外洩、對外掃描；正常的出站存取不畫線）；飛線可在「重點 / 全部 / 關閉」間調整密度，地圖可全螢幕投到大螢幕上。
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

- 存取 `http://<伺服器IP>:8080`，初始密碼在日誌中：`docker compose logs netsa | grep 初始密码`，首次登入後須修改。
- 預設讀取主機的 `/var/log/nginx` 與 `/var/log`；網路設備的 syslog 傳送到 `<伺服器IP>:5514`（UDP / TCP）。
- 需要固定版本、修改連接埠或啟用告警歸檔時，先執行 `cp .env.example .env` 再依註解修改。
- Windows PowerShell 5.1 不支援 `&&` 和 `grep`：請逐行執行指令，並用 `Select-String` 代替 `grep`。

升級回復、內網離線部署和常見問題見[部署指南](../deployment.md)。

### 不部署，直接分析現有日誌

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # 分析後開啟大螢幕
```

## 介面預覽

| 安全評估與處置建議 | 攻擊面分析 |
|---|---|
| ![安全評估](../images/assess.png) | ![攻擊面分析](../images/surface.png) |
| **事件處置與處置時限** | **自學習與自動校準** |
| ![事件處置](../images/incidents.png) | ![自學習](../images/learn.png) |

截圖來自內建模擬器產生的示範資料，其中的 IP 與網站均為模擬，可用上面的示範環境自行體驗。

## 核心能力

| 模組 | 能力 |
|---|---|
| [日誌採集](../log-sources.md) | 即時追蹤檔案（萬用字元、logrotate 輪替）、批次分析（含 `.gz`）、Syslog UDP / TCP / TLS（可雙向認證）、[NetFlow / sFlow / IPFIX 採集](../log-sources.md#流量日志zeeknetflow--sflow-与云抗-d-服务)；傳送端識別、白名單、限速與斷流告警 |
| [攻擊偵測](../detection.md) | SQL 注入、XSS、命令執行、Log4Shell、SSRF、XXE、反序列化、WebShell、已知弱點利用等特徵規則，部分命令、程式碼、Java 類別規則改編自 OWASP CRS；[libinjection 語法分析](../detection.md#语法分析libinjection)複核注入命中並補上正規表示式漏掉的變形；[中國 OA、中介軟體弱點介面特徵](../detection.md#国产-oa中间件漏洞接口签名)（261 條，42 個產品）；CC、暴力破解、撞庫、介面遍歷、連接埠掃描、WebShell 行為畫像、資料外傳、橫向移動、頻寬型 DDoS 等行為偵測；記錄了請求本文時同樣偵測 POST 載荷；多輪解碼對抗常見繞過 |
| [結果研判](../detection.md#研判复核用证据排除表面成功) | 依回應與工作階段證據區分已攔截、失敗、未攔截、疑似成功；排除單頁應用程式兜底頁、統一錯誤頁、未到達服務的「放行」等表面現象 |
| [主機與 DNS 偵測](../log-sources.md#主机认证日志与-dns-日志) | SSH / RDP / VPN 暴力破解與破解成功、密碼噴灑、日誌被清除、新建帳號與提權、[帳號盜用](../detection.md#账号盗用)（不可能的旅行、新國家登入、多地並發）；[主機處理程序偵測](../detection.md#主机进程检测)（Web 處理程序執行命令、反彈 Shell、憑證竊取、持久化）；DNSLog 帶外回連、DNS 通道、DGA、礦池網域，以及情資標記的遠控、惡意軟體、釣魚網域 |
| [攻擊來源溯源](../traceability.md) | 融合 ip2region、MaxMind、ip-api、rDNS、RDAP / WHOIS，支援內網自訂網段定位；同源關聯依網段、工具指紋、攻擊手法找出疑似同一團夥 |
| [資產攻擊鏈路](../detection.md#资产攻击链路) | 以網站 / 主機為中心串起偵察、利用、突破、植入、控制、橫向、竊取、影響，每一步註明證據、來源與 ATT&CK 技術；網站與背後的伺服器自動合併，研判是否遭入侵並給出處置建議 |
| [態勢大螢幕](../deployment.md#演示环境) | 世界 / 中國雙視圖攻擊地圖，可下鑽到省和地市；即時飛線與告警推播；KPI、趨勢、分布圖均可點擊下鑽到攻擊來源或告警 |
| [攻擊面分析](../log-sources.md#未做-dnat-映射的端口探测) | 梳理對外服務，發現原始碼、金鑰、備份洩漏與管理介面暴露；結合 DNAT 對應與防火牆工作階段證據，過濾打不到任何服務的背景掃描 |
| [安全評估與入侵研判](../detection.md#安全评估与失陷研判) | 七個維度評分並給出 A~E 總評與 P0~P3 處置建議；內網主機外連情資位址、C2 心跳偵測、惡意 TLS 指紋、攻擊載荷落地；[防火牆與 Web 日誌聯動](../detection.md#防火墙与-web-日志联动被攻击后回连)發現被攻擊後回連攻擊者的主機；MITRE ATT&CK 矩陣 |
| [自學習與 AI 研判](../self-learning.md) | 規則級、目標級與威脅情資來源準確率自動校準、確認攻擊來源再現升級、學習視窗，策略可在頁面調整；從日誌自動學習內網網段、攻擊來源、攻擊活動、[參數正常取值與網站產品](../self-learning.md#参数的正常取值与站点产品)；AI 研判支援 OpenAI / Anthropic 介面與 vLLM，自動適配模型差異，附帶本單位相似案例，並統計模型與分析師結論的一致率 |
| [事件處置與推播](../operations.md#事件处置与误报抑制) | 告警自動聚合為事件，支援指派、處置時限與逾時提醒；誤報抑制；[授權掃描登記](../detection.md#授权扫描登记)（測試期間只記錄不告警，到期自動恢復）；[釘釘 / 企業微信 / 飛書推播](../operations.md#告警推送钉钉--企业微信--飞书)，去重、合併、限速；匯出 nginx、iptables、ipset 等封鎖清單 |
| [留存、合規與稽核](../operations.md#原始日志留存与检索) | 原始日誌依小時壓縮留存，雜湊鏈防竄改；[PostgreSQL 長期歸檔](../operations.md#告警归档可选postgresql)（選用）；週報月報、等保 2.0 自查；[三種角色、雙因素認證與防竄改稽核鏈](../operations.md#登录账号与审计)；Prometheus 指標 |

## 運作原理

```text
日誌來源    nginx · 防火牆 / IDS · Zeek · 主機認證與處理程序 · 應用程式登入 · DNS · 容器與採集器
   │        檔案追蹤 / 批次分析 / Syslog（UDP · TCP · TLS）/ 流量採集（NetFlow · IPFIX · sFlow）
   ▼
格式識別    每個資料來源、每個傳送端獨立識別格式與時區
   ▼
真實 IP     依可信代理還原來源，標記 XFF 偽造與繞過 CDN
   ▼
威脅偵測    特徵規則（AC 預篩 + 正規表示式）+ 語法分析（libinjection）+ 主機處理程序規則 + 行為偵測（時間視窗，記憶體有上限）
   ▼
情資與誘餌  IP / 網域 / TLS 指紋 / 檔案雜湊情資；誘餌路徑、線索、帳號與蜜罐命中即確認攻擊來源
   ▼
證據過濾    工作階段證據與 DNAT 對應排除未到達服務的探測，套用誤報抑制
   ▼
學習校準    參數正常取值、網站產品複核命中；依分析師結論下調反覆誤報的命中，升級已確認攻擊來源（learn）
   ▼
聯動分析    關聯先前的 Web 攻擊：被攻擊後回連、下載載荷；遭入侵主機事後的橫向連線
   ▼
等級裁決    分類底線、成功升級、結果封頂，統一決定最終等級（risk）
   ▼
狀態庫      攻擊者畫像 · 告警 · 安全事件 · 攻擊活動 · 資產攻擊鏈路 · 攻擊面 · 時間序列 · 快照持久化
   │
   ├── Web 大螢幕與 REST API（SSE 即時推播）
   ├── 釘釘 / 企業微信 / 飛書 / Webhook
   ├── 原始日誌留存 · PostgreSQL 歸檔（選用）
   └── AI 研判（選用，結論寫入事件處置紀錄）
```

幾個關鍵設計：

- **等級只在一處裁決**：規則宣告的等級只是建議值，避免各環節各自加減造成同類事件等級不一致。詳見[威脅等級判定](../detection.md#威胁等级判定)。
- **證據優先於表象**：防火牆「放行」、回應 200、多次失敗後登入成功，都要再用工作階段、回應基線和帳號線索複核。
- **學習有邊界**：規則校準只從人的結論學習，自動調整每次最多一級，利用成功仍判嚴重；從正常流量學到的參數取值與網站產品，要兩個相互獨立的依據同時成立才降級（參數平時就是普通文字 + 語法分析不構成注入；網站沒有該產品 + 請求沒有成功），只降到低風險、不隱藏告警；會隱藏告警的誤報抑制必須人工採納。AI 結論不作為學習樣本，也不會自動處置。
- **壓力下不失控**：解析與偵測並行、分批入庫，畫像數和偵測視窗都有硬上限，單條畸形日誌不影響服務；佇列積壓和丟棄都有監控指標。

## 支援的日誌

| 類型 | 格式 |
|---|---|
| **Web** | nginx / Tengine / OpenResty / Apache（combined、main、vhost）、任意自訂 `log_format`、nginx JSON、APISIX、Kong、Nginx Proxy Manager、Caddy、Traefik、Elastic ECS、IIS W3C |
| **WAF** | nginx / Tengine / OpenResty 錯誤日誌中的 ModSecurity、naxsi 攔截與限流，ModSecurity JSON 稽核日誌，OpenResty Lua WAF |
| **防火牆** | iptables、UFW、firewalld、nftables、pfSense / OPNsense、Windows 防火牆、Cisco ASA / FTD、Palo Alto、FortiGate、華為 USG、H3C、深信服、山石，以及華為、H3C、深信服的攻擊防範日誌 |
| **IDS / IPS** | Suricata EVE JSON、Snort fast alert、FortiGate IPS / UTM 等設備威脅日誌 |
| **主機與 VPN 認證** | Linux `auth.log` / `secure`、Windows 安全性事件（NXLog、Winlogbeat、Snare）、FortiGate / Cisco / OpenVPN、SQL Server 登入 |
| **DNS** | BIND、dnsmasq、CoreDNS、Windows DNS、Zeek、Suricata DNS |
| **流量** | Zeek（conn / http / ssl / files，TSV 或 JSON）、NetFlow v5 / v9、IPFIX、sFlow v5（UDP 採集）、雲端抗 DDoS 服務的攻擊事件 |
| **主機處理程序（EDR / HIDS）** | Sysmon（Winlogbeat / NXLog / Elastic Agent）、Windows 4688、Elastic Defend（ECS）、Linux auditd、Wazuh 告警 |
| **應用程式登入與蜜罐** | 業務系統、統一身分認證 / SSO 的 JSON 登入日誌，OpenCanary 蜜罐日誌 |
| **容器與採集器** | Docker json-file、Fluent Bit / Fluentd、Filebeat / Logstash / Vector、containerd / CRI-O，自動拆開後識別原始日誌 |

接入方法見[日誌接入](../log-sources.md)；接入後在大螢幕「資料來源」頁查看識別結果和解析失敗範例。

## 文件

以下詳細文件為簡體中文。

| 文件 | 內容 |
|---|---|
| [部署指南](../deployment.md) | 正式環境部署、`.env` 變數、升級回復、內網離線、示範環境、從原始碼執行 |
| [日誌接入](../log-sources.md) | Web、防火牆、認證、DNS、流量（Zeek、NetFlow / sFlow、雲端抗 DDoS）、主機處理程序、應用程式登入接入，syslog 傳送端管理，時區，DNAT 與工作階段證據 |
| [偵測與研判](../detection.md) | 威脅等級判定、研判複核、攻擊活動與資產攻擊鏈路、資料竊取與橫向移動、誘餌、主機處理程序偵測、帳號盜用、威脅評分、安全評估與入侵研判 |
| [攻擊來源溯源](../traceability.md) | 多來源定位、內網網段、定位資料庫熱更新、同源關聯分析 |
| [自學習與 AI 研判](../self-learning.md) | 自動生效的範圍與邊界、行為基線、合規自檢、外部模型設定與模型適配 |
| [安全維運](../operations.md) | 事件處置、告警推播、原始日誌、資產弱點、報表合規、帳號稽核、監控指標、告警歸檔 |
| [設定參考](../configuration.md) | 常用設定項與執行注意事項 |
| [API](../api.md) | REST 介面一覽 |
| [對接外部系統](../integrations.md) | LDAP / OIDC 單一登入、SIEM 轉送、聯動封鎖、工單與處置劇本、STIX / TAXII / MISP 與文字情資（IP、網域、TLS 指紋、檔案雜湊，情資類別）、Sigma 與特徵規則包 |
| [開發與發布](../development.md) | 本機測試、程式碼結構、映像建置與發布 |
| [能力評估與路線圖](../roadmap.md) | 依攻擊鏈路評估識別、定位、溯源能力，缺口與分步計畫 |
| [更新紀錄](../CHANGELOG.md) | 影響使用的變化 |

## 開發

需要 Go 1.26 以上（發布版本使用 Go 1.27 建置），純 Go 實作，無 CGO。

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

程式碼結構和發布流程見[開發與發布](../development.md)。

## 參與貢獻

歡迎提交 Issue 和 Pull Request，尤其歡迎：

- 新的日誌格式範例（請先去識別化），以及識別失敗或解析錯誤的回饋；
- 新的偵測規則，以及附範例的誤報、漏報回報；
- 文件改進和實際部署經驗。

提交程式碼前請先通過上面的檢查，CI 還會執行競態測試和 `govulncheck`。

如果 netsa 對你有幫助，請點一個 **Star**，讓更多需要它的人看到。

## 授權條款

本專案採用 [Apache License 2.0](../../LICENSE) 發布：可以自由地用於商業目的、修改與再散布，只需保留版權聲明、授權文本與 [NOTICE](../../NOTICE) 檔案。

- 軟體依「現狀」提供，不附帶任何明示或暗示的擔保；
- 授權不授予商標使用權，`netsa` 名稱與標識不包含在授權範圍內；
- 第三方相依套件遵循各自授權，完整清單見 `go.mod` 與 `go.sum`；部分偵測規則改編自 [OWASP Core Rule Set](https://coreruleset.org)（Apache-2.0），中國 OA、中介軟體弱點介面特徵擷取自 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)（MIT），見 [NOTICE](../../NOTICE)。

規則與情資訂閱、部署交付、等保測評支援等商業服務由維護方另行提供，不影響開源版依據 Apache-2.0 的使用權利。

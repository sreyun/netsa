<div align="center">

# netsa

**오픈소스 네트워크 보안 상황 인식 및 공격 표면 분석 플랫폼**

Web, 방화벽 / IDS, 네트워크 플로, 호스트 인증과 프로세스, DNS 로그를 추적하고 대응할 수 있으며 계속 학습하는 보안 상황으로 바꿔 줍니다.<br>
단일 바이너리로 바로 사용할 수 있고, 내부망 오프라인 운영도 지원합니다.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · **한국어** · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[빠른 시작](#빠른-시작) · [화면 미리보기](#화면-미리보기) · [핵심 기능](#핵심-기능) · [동작 방식](#동작-방식) · [지원 로그](#지원-로그) · [문서](#문서)

</div>

![상황 개요: 공격 지도, 실시간 경보, 위협 지수](../images/overview.png)

## netsa를 선택하는 이유

- **의존성 없음, 한 번에 배포**: Go 단일 바이너리에 프런트엔드, 세계 지도와 중국 성·시 지도, 오프라인 위치 데이터베이스가 모두 내장되어 있습니다. Elasticsearch, Kafka, 데이터베이스가 필요 없습니다. Docker 이미지는 amd64와 arm64를 제공하며, 온라인 추적을 끄면 격리된 네트워크에서 완전히 오프라인으로 운영할 수 있습니다.
- **로그를 미리 맞출 필요 없음**: 50가지 이상의 형식을 자동으로 인식합니다. nginx / Tengine / OpenResty / APISIX / Kong / Apache / IIS / Caddy, ModSecurity 등의 WAF, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, Linux와 Windows 인증, 주요 DNS, Zeek, NetFlow / sFlow / IPFIX, Sysmon / auditd / Wazuh 호스트 로그, 애플리케이션 로그인 로그, 그리고 Docker, Filebeat 등 수집기의 래핑 형식을 지원합니다.
- **정확한 탐지, 믿을 수 있는 경보**: 87개의 시그니처 규칙(일부는 OWASP CRS를 개작), libinjection 구문 분석, 행위 탐지를 결합하고, 응답, 세션 증거, 자산 취약점으로 "겉보기 성공"을 다시 확인합니다. 심각도는 하나의 통합 판정으로 결정됩니다. 차단된 공격이 "심각"으로 표시되지 않고, 실제로 성공한 공격도 놓치지 않습니다.
- **중국산 OA와 미들웨어를 인식**: 취약한 엔드포인트 시그니처 261개를 내장해 Seeyon(致遠), Weaver(泛微), Yonyou(用友), Tongda(通達), Landray(藍凌), Wanhu(萬戶) OA, FanRuan(帆軟), Esafenet(億賽通), RuoYi(若依), Nacos, APISIX, Nginx UI, 그리고 Sangfor(深信服), Ruijie(銳捷), Hikvision, Dahua 등 42개 제품을 다룹니다. 경보에는 제품명과 CVE / CNVD 번호가 바로 표시되며, 정상 업무에서 쓰이는 취약 엔드포인트는 자동으로 학습되어 경보가 계속 나오지 않습니다.
- **위협 인텔리전스는 양보다 정확성**: IP, 도메인, TLS 핑거프린트, 파일 해시 인텔리전스(STIX / TAXII / MISP / 텍스트 목록)를 C2, 악성코드, 피싱, 채굴 풀, 공격 출처로 분류해 등급을 매기고, 악용되는 공용 플랫폼은 자동으로 걸러 냅니다. 각 피드의 정확도는 분석가의 판정으로 자동 집계하며, 오탐이 지속되는 피드는 자동으로 등급을 낮춥니다.
- **방화벽과 Web 로그 연계**: Web 공격 이후 내부 호스트가 공격자나 공격 페이로드에 적힌 콜백 주소에 접속하면 침해 징후로 판정합니다. 페이로드 속 주소로의 접속은 페이로드가 실행되었다는 증거입니다.
- **도시 단위까지 추적하고 그룹까지 연관**: CDN과 프록시 뒤의 실제 IP를 복원하고, XFF 위조와 CDN을 우회한 원본 서버 직접 접속을 탐지합니다. 여러 위치 정보 출처를 교차 검증해 신뢰도를 제시합니다. 동일 출처 연관 분석과 공격 캠페인 병합으로 같은 공격자가 바꿔 가며 쓰는 출구 주소(같은 도구 핑거프린트, 같은 OAST 상관 ID, TLS 핑거프린트, 같은 미끼 토큰)를 찾습니다. [미끼](../detection.md#诱饵)(미끼 경로, 토큰, 계정, 허니팟)에 걸리면 높은 신뢰도로 공격자로 판단합니다. 자산 공격 체인은 서버 한 대가 스캔되고, 악용되고, 제어되고, 측면 이동에 쓰이기까지의 전 과정을 시간순으로 연결합니다.
- **쓸수록 정확해짐**: 분석가의 처리 결론에서 학습해, 오탐을 반복하는 규칙과 엔드포인트는 자동으로 등급을 낮추고, 확인된 공격자가 다시 나타나면 자동으로 등급을 올립니다. 허용 목록을 수작업으로 정리할 필요 없이, 정상 트래픽에서 각 매개변수의 평소 값을 학습하고 각 사이트가 쓰는 제품과 프런트엔드 프레임워크를 수동적으로 식별합니다. 검색창에 입력한 평범한 문자열이나 사이트에 없는 제품에 대한 취약점 탐색이 더 이상 고위험 경보를 일으키지 않습니다. AI 판정은 OpenAI와 Anthropic API를 모두 지원해 내부망 vLLM과 클라우드 모델을 모두 연결할 수 있고, 모델 차이에 자동으로 적응하며 분석가의 결론으로 모델의 신뢰도를 평가합니다.
- **보안 운영의 전 과정**: 인시던트 집계와 처리 기한, 오탐 억제, DingTalk / WeCom / Feishu 알림, 자산·취약점 연관, 원본 로그 보존과 원클릭 증거 패키지, 주간·월간 보고서, MLPS 2.0(중국 등급 보호 제도) 자체 점검, 위변조 탐지 감사 체인을 갖추고 있습니다.
- **검색창 하나로 모든 것을**: `Ctrl+K`를 누르고 IP, 인시던트 번호, 자산, 사이트, 규칙, 공격 유형을 입력하면 유형별로 묶어 보여 주고, 키보드만으로 공격원 프로필, 인시던트, 공격 체인, 공격 캠페인을 열 수 있습니다. 찾지 못하면 알림 검색이나 원시 로그 검색으로 바로 넘어갑니다.
- **안팎 양방향을 모두 표시**: 공격 지도에 외부에서 내부로의 공격뿐 아니라 내부 호스트에서 외부로의 공격과 비정상 연결(위협 인텔리전스에 등록된 주소로의 연결, 트로이 목마 콜백, 데이터 유출, 외부 스캔. 정상적인 외부 통신은 선을 그리지 않음)도 표시합니다. 공격선 밀도는 '중점 / 전체 / 끄기'로 바꿀 수 있고, 지도는 전체 화면으로 대형 화면에 띄울 수 있습니다.
- **한 대로도 충분히 빠름**: 개발 장비(i7-10700, 16스레드)에서 엔드투엔드 초당 약 46만 건. Aho-Corasick 사전 필터 덕분에 정상 요청은 거의 정규식을 실행할 필요가 없으며, 탐지는 건당 약 3µs입니다.

## 빠른 시작

### 명령 하나로 체험(공격 로그 시뮬레이터 포함)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

브라우저에서 <http://localhost:8080>을 열고 계정 `admin`, 비밀번호 `Netsa@demo2026`으로 로그인합니다. 시뮬레이터가 공격 로그를 계속 생성하고 대시보드가 실시간으로 갱신됩니다.

### 운영 환경 배포

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- `http://<서버IP>:8080`에 접속합니다. 초기 비밀번호는 로그에 있습니다: `docker compose logs netsa | grep 初始密码`(`初始密码`는 로그에 출력되는 문자열로 "초기 비밀번호"라는 뜻입니다). 첫 로그인 후 변경해야 합니다.
- 기본적으로 호스트의 `/var/log/nginx`와 `/var/log`를 읽습니다. 네트워크 장비의 syslog는 `<서버IP>:5514`(UDP / TCP)로 보냅니다.
- 버전 고정, 포트 변경, 경보 보관이 필요하면 먼저 `cp .env.example .env`를 실행한 뒤 주석에 따라 수정합니다.
- Windows PowerShell 5.1은 `&&`와 `grep`을 지원하지 않습니다. 명령을 한 줄씩 실행하고 `grep` 대신 `Select-String`을 사용하세요.

업그레이드와 롤백, 오프라인 배포, 자주 묻는 문제는 [배포 가이드](../deployment.md)를 참고하세요.

### 배포 없이 기존 로그 분석

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # 분석 후 대시보드 열기
```

## 화면 미리보기

| 보안 평가와 조치 권고 | 공격 표면 분석 |
|---|---|
| ![보안 평가](../images/assess.png) | ![공격 표면 분석](../images/surface.png) |
| **인시던트 처리와 처리 기한** | **자가 학습과 자동 보정** |
| ![인시던트 처리](../images/incidents.png) | ![자가 학습](../images/learn.png) |

스크린샷은 중국어 웹 화면이며, 내장 시뮬레이터가 생성한 데모 데이터를 보여 줍니다. IP와 사이트는 모두 가상입니다. 위의 데모 환경으로 직접 체험할 수 있습니다.

## 핵심 기능

| 모듈 | 기능 |
|---|---|
| [로그 수집](../log-sources.md) | 파일 실시간 추적(와일드카드, logrotate 순환), 일괄 분석(`.gz` 포함), syslog UDP / TCP / TLS(상호 인증 가능), [NetFlow / sFlow / IPFIX 수집](../log-sources.md#流量日志zeeknetflow--sflow-与云抗-d-服务). 발신 장비 식별, 허용 목록, 속도 제한, 로그 끊김 경보 |
| [공격 탐지](../detection.md) | SQL 인젝션, XSS, 명령 실행, Log4Shell, SSRF, XXE, 역직렬화, WebShell, 알려진 취약점 악용 등의 시그니처 규칙(명령, 코드, Java 클래스 규칙 일부는 OWASP CRS를 개작). [libinjection 구문 분석](../detection.md#语法分析libinjection)으로 인젝션 탐지를 다시 확인하고 정규식이 놓친 변형을 잡아냅니다. [중국산 OA·미들웨어 취약 엔드포인트 시그니처](../detection.md#国产-oa中间件漏洞接口签名)(261개, 42개 제품). CC, 무차별 대입, 크리덴셜 스터핑, 엔드포인트 열거, 포트 스캔, WebShell 행위, 데이터 유출, 측면 이동, 대역폭형 DDoS 행위 탐지. 요청 본문이 기록되어 있으면 POST 페이로드도 검사하며, 다단계 디코딩으로 일반적인 우회 기법에 대응합니다 |
| [결과 판정](../detection.md#研判复核用证据排除表面成功) | 응답과 세션 증거로 차단, 실패, 미차단, 성공 의심을 구분합니다. 단일 페이지 앱의 대체 페이지, 공통 오류 페이지, 서비스에 닿지 않은 "허용" 등 겉보기 성공을 배제합니다 |
| [호스트와 DNS 탐지](../log-sources.md#主机认证日志与-dns-日志) | SSH / RDP / VPN 무차별 대입과 침투 성공, 패스워드 스프레이, 로그 삭제, 계정 생성과 권한 상승, [계정 탈취](../detection.md#账号盗用)(불가능한 이동, 새로운 국가에서의 로그인, 여러 지역 동시 로그인). [호스트 프로세스 탐지](../detection.md#主机进程检测)(Web 서버 프로세스의 명령 실행, 리버스 셸, 자격 증명 탈취, 지속성 확보). DNSLog 대역 외 콜백, DNS 터널링, DGA, 채굴 풀 도메인, 인텔리전스가 표시한 C2·악성코드·피싱 도메인 |
| [공격 출처 추적](../traceability.md) | ip2region, MaxMind, ip-api, rDNS, RDAP / WHOIS를 통합하고 내부망 사용자 정의 대역 위치도 지원합니다. 동일 출처 연관 분석은 대역, 도구 핑거프린트, 공격 기법으로 같은 그룹으로 의심되는 출처를 찾습니다 |
| [자산 공격 체인](../detection.md#资产攻击链路) | 사이트나 호스트를 중심으로 정찰, 악용, 돌파, 설치, 제어, 측면 이동, 탈취, 영향을 연결하고, 단계마다 증거, 출처, ATT&CK 기법을 표시합니다. 사이트와 그 뒤의 서버를 자동으로 병합하고, 침해 여부 판정과 조치 권고를 제시합니다 |
| [상황 대시보드](../deployment.md#演示环境) | 세계 / 중국 이중 공격 지도(성·시 단위로 드릴다운 가능), 실시간 공격 궤적과 경보 알림. KPI, 추이, 분포 차트에서 공격 출처나 경보로 드릴다운할 수 있습니다 |
| [공격 표면 분석](../log-sources.md#未做-dnat-映射的端口探测) | 외부 공개 서비스를 정리하고 소스 코드, 키, 백업 유출과 관리 인터페이스 노출을 찾습니다. DNAT 매핑과 방화벽 세션 증거를 결합해 어떤 서비스에도 닿지 않는 배경 스캔을 걸러 냅니다 |
| [보안 평가와 침해 판정](../detection.md#安全评估与失陷研判) | 7개 차원으로 점수를 매겨 A~E 종합 등급과 P0~P3 조치 권고를 제시합니다. 인텔리전스에 등록된 주소로의 내부 호스트 접속, C2 비컨, 악성 TLS 핑거프린트, 공격 페이로드 안착을 탐지합니다. [방화벽과 Web 로그 연계](../detection.md#防火墙与-web-日志联动被攻击后回连)로 공격받은 뒤 공격자에게 되접속한 호스트를 찾습니다. MITRE ATT&CK 매트릭스 |
| [자가 학습과 AI 판정](../self-learning.md) | 규칙 단위·대상 단위·위협 인텔리전스 피드의 정확도를 자동 보정하고, 확인된 공격 출처가 다시 나타나면 등급을 올리며, 학습 기간을 둡니다(정책은 화면에서 조정 가능). 로그에서 내부망 대역, 공격 출처, 공격 캠페인, [매개변수의 정상 값과 사이트 제품](../self-learning.md#参数的正常取值与站点产品)을 자동으로 학습합니다. AI 판정은 OpenAI / Anthropic API와 vLLM을 지원하고, 모델 차이에 자동으로 적응하며, 자체 조직의 유사 사례를 첨부하고, 모델과 분석가 결론의 일치율을 집계합니다 |
| [인시던트 처리와 알림](../operations.md#事件处置与误报抑制) | 경보를 인시던트로 자동 집계하고 담당자 지정, 처리 기한, 기한 초과 알림을 지원합니다. 오탐 억제. [승인된 스캔 등록](../detection.md#授权扫描登记)(테스트 기간에는 기록만 하고 경보를 내지 않으며, 기한이 지나면 자동 복구). [DingTalk / WeCom / Feishu 알림](../operations.md#告警推送钉钉--企业微信--飞书)(중복 제거, 병합, 속도 제한). nginx, iptables, ipset 등의 차단 목록 내보내기 |
| [보존, 규정 준수, 감사](../operations.md#原始日志留存与检索) | 원본 로그를 시간 단위로 압축 보존하고 해시 체인으로 위변조를 방지합니다. [PostgreSQL 장기 보관](../operations.md#告警归档可选postgresql)(선택). 주간·월간 보고서, MLPS 2.0 자체 점검. [세 가지 역할, 이중 인증, 위변조 탐지 감사 체인](../operations.md#登录账号与审计). Prometheus 지표 |

## 동작 방식

```text
로그 소스        nginx · 방화벽 / IDS · Zeek · 호스트 인증과 프로세스 · 앱 로그인 · DNS · 컨테이너와 수집기
   │             파일 추적 / 일괄 분석 / syslog(UDP · TCP · TLS) / 플로 수집(NetFlow · IPFIX · sFlow)
   ▼
형식 인식        데이터 소스별, 발신 장비별로 형식과 시간대를 따로 인식
   ▼
실제 IP          신뢰할 수 있는 프록시에 따라 출처를 복원하고 XFF 위조와 CDN 우회를 표시
   ▼
위협 탐지        시그니처 규칙(AC 사전 필터 + 정규식) + 구문 분석(libinjection) + 호스트 프로세스 규칙 + 행위 탐지(시간 창, 메모리 상한)
   ▼
인텔리전스와 미끼  IP / 도메인 / TLS 핑거프린트 / 파일 해시 인텔리전스, 미끼 경로·토큰·계정·허니팟에 걸리면 공격 출처로 확정
   ▼
증거 필터        세션 증거와 DNAT 매핑으로 서비스에 닿지 않은 탐색을 배제하고 오탐 억제를 적용
   ▼
학습 보정        매개변수 정상 값과 사이트 제품으로 탐지를 다시 확인, 분석가 결론에 따라 반복 오탐을 낮추고 확인된 공격 출처를 올림(learn)
   ▼
연계 분석        이전 Web 공격과 연관: 공격 후 콜백, 페이로드 다운로드, 침해된 호스트의 이후 측면 이동 연결
   ▼
심각도 판정      분류 하한, 성공 시 상향, 결과에 따른 상한으로 최종 심각도를 통합 결정(risk)
   ▼
상태 저장소      공격자 프로필 · 경보 · 인시던트 · 공격 캠페인 · 자산 공격 체인 · 공격 표면 · 시계열 · 스냅숏 영속화
   │
   ├── Web 대시보드와 REST API(SSE 실시간 푸시)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── 원본 로그 보존 · PostgreSQL 보관(선택)
   └── AI 판정(선택, 결론은 인시던트 처리 기록에 기록)
```

주요 설계:

- **심각도는 한 곳에서만 판정**: 규칙이 선언한 심각도는 제안값일 뿐이며, 각 단계가 제각각 더하고 빼서 같은 종류의 이벤트 심각도가 달라지는 것을 막습니다. 자세한 내용은 [위협 심각도 판정](../detection.md#威胁等级判定)을 참고하세요.
- **겉모습보다 증거**: 방화벽의 "허용", 200 응답, 여러 번 실패한 뒤의 로그인 성공은 모두 세션, 응답 기준선, 계정 단서로 다시 확인합니다.
- **학습에는 경계가 있음**: 규칙 보정은 사람의 결론에서만 학습하고, 자동 조정은 한 번에 최대 한 단계이며, 악용 성공은 여전히 심각으로 판정합니다. 정상 트래픽에서 학습한 매개변수 값과 사이트 제품은 서로 독립적인 두 근거가 동시에 성립할 때만 등급을 낮추며(매개변수가 평소 평범한 문자열이고 구문 분석에서도 인젝션이 아님, 사이트에 해당 제품이 없고 요청도 성공하지 않음), 저위험까지만 낮추고 경보를 숨기지 않습니다. 경보를 숨기는 오탐 억제는 사람이 채택해야 합니다. AI 결론은 학습 데이터로 쓰지 않고 자동 처리도 하지 않습니다.
- **부하에도 통제를 잃지 않음**: 파싱과 탐지는 병렬로 처리하고 일괄 저장합니다. 프로필 수와 탐지 시간 창에는 엄격한 상한이 있어 잘못된 형식의 로그 한 줄이 서비스에 영향을 주지 않습니다. 대기열 적체와 폐기에는 모니터링 지표가 있습니다.

## 지원 로그

| 유형 | 형식 |
|---|---|
| **Web** | nginx / Tengine / OpenResty / Apache(combined, main, vhost), 임의의 사용자 정의 `log_format`, nginx JSON, APISIX, Kong, Nginx Proxy Manager, Caddy, Traefik, Elastic ECS, IIS W3C |
| **WAF** | nginx / Tengine / OpenResty 오류 로그의 ModSecurity·naxsi 차단과 속도 제한, ModSecurity JSON 감사 로그, OpenResty Lua WAF |
| **방화벽** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Windows 방화벽, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone, 그리고 Huawei, H3C, Sangfor의 공격 방어 로그 |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, FortiGate IPS / UTM 등 장비 위협 로그 |
| **호스트와 VPN 인증** | Linux `auth.log` / `secure`, Windows 보안 이벤트(NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, SQL Server 로그인 |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **네트워크 플로** | Zeek(conn / http / ssl / files, TSV 또는 JSON), NetFlow v5 / v9, IPFIX, sFlow v5(UDP 수집), 클라우드 DDoS 방어 서비스의 공격 이벤트 |
| **호스트 프로세스(EDR / HIDS)** | Sysmon(Winlogbeat / NXLog / Elastic Agent), Windows 4688, Elastic Defend(ECS), Linux auditd, Wazuh 경보 |
| **앱 로그인과 허니팟** | 업무 시스템과 통합 인증 / SSO의 JSON 로그인 로그, OpenCanary 허니팟 로그 |
| **컨테이너와 수집기** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O. 래핑을 자동으로 풀어 원본 로그를 인식합니다 |

연결 방법은 [로그 연결](../log-sources.md)을 참고하세요. 연결 후 대시보드의 "데이터 소스" 페이지에서 인식 결과와 파싱 실패 샘플을 확인할 수 있습니다.

## 문서

아래 상세 문서는 중국어 간체로 작성되어 있습니다.

| 문서 | 내용 |
|---|---|
| [배포 가이드](../deployment.md) | 운영 환경 배포, `.env` 변수, 업그레이드와 롤백, 내부망 오프라인, 데모 환경, 소스에서 실행 |
| [로그 연결](../log-sources.md) | Web, 방화벽, 인증, DNS, 네트워크 플로(Zeek, NetFlow / sFlow, 클라우드 DDoS 방어), 호스트 프로세스, 앱 로그인 연결, syslog 발신 장비 관리, 시간대, DNAT와 세션 증거 |
| [탐지와 판정](../detection.md) | 위협 심각도 판정, 결과 재확인, 공격 캠페인과 자산 공격 체인, 데이터 탈취와 측면 이동, 미끼, 호스트 프로세스 탐지, 계정 탈취, 위협 점수, 보안 평가와 침해 판정 |
| [공격 출처 추적](../traceability.md) | 다중 출처 위치 확인, 내부망 대역, 위치 데이터베이스 핫 리로드, 동일 출처 연관 분석 |
| [자가 학습과 AI 판정](../self-learning.md) | 자동 적용 범위와 경계, 행위 기준선, 규정 준수 자체 점검, 외부 모델 설정과 모델 적응 |
| [보안 운영](../operations.md) | 인시던트 처리, 알림, 원본 로그, 자산과 취약점, 보고서와 규정 준수, 계정과 감사, 모니터링 지표, 경보 보관 |
| [설정 참조](../configuration.md) | 자주 쓰는 설정 항목과 운영 시 주의 사항 |
| [API](../api.md) | REST API 목록 |
| [외부 시스템 연동](../integrations.md) | LDAP / OIDC 통합 로그인, SIEM 전달, 연동 차단, 티켓과 처리 플레이북, STIX / TAXII / MISP와 텍스트 인텔리전스(IP, 도메인, TLS 핑거프린트, 파일 해시, 분류 포함), Sigma와 서명된 규칙 팩 |
| [개발과 릴리스](../development.md) | 로컬 테스트, 코드 구조, 이미지 빌드와 릴리스 |
| [역량 평가와 로드맵](../roadmap.md) | 공격 체인에 따른 탐지·위치 확인·추적 역량 평가, 부족한 점과 단계별 계획 |
| [변경 이력](../CHANGELOG.md) | 사용에 영향을 주는 변경 |

## 개발

Go 1.26 이상이 필요합니다(릴리스 버전은 Go 1.27로 빌드). 순수 Go 구현이며 CGO를 사용하지 않습니다.

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # 출력이 없어야 함
go vet ./...
go test ./...
```

경쟁 상태 테스트에는 C 컴파일러가 필요합니다. 로컬에 gcc가 없으면 컨테이너에서 실행할 수 있습니다:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

코드 구조와 릴리스 절차는 [개발과 릴리스](../development.md)를 참고하세요.

## 기여하기

Issue와 Pull Request를 환영합니다. 특히 다음을 환영합니다:

- 새로운 로그 형식 샘플(먼저 민감 정보를 제거해 주세요), 인식 실패나 파싱 오류 피드백
- 새로운 탐지 규칙, 샘플이 포함된 오탐·미탐 보고
- 문서 개선과 실제 배포 경험

코드를 제출하기 전에 위의 검사를 통과해 주세요. CI에서는 경쟁 상태 테스트와 `govulncheck`도 실행합니다.

netsa가 도움이 되었다면 **Star**를 눌러 필요한 사람들이 찾을 수 있게 해 주세요.

## 라이선스

이 프로젝트는 [Apache License 2.0](../../LICENSE)으로 배포됩니다. 저작권 고지, 라이선스 전문, [NOTICE](../../NOTICE) 파일을 유지하면 상업적 사용, 수정, 재배포를 자유롭게 할 수 있습니다.

- 소프트웨어는 "있는 그대로" 제공되며, 명시적이든 묵시적이든 어떠한 보증도 하지 않습니다
- 라이선스는 상표 사용권을 부여하지 않으며, `netsa` 이름과 로고는 허가 범위에 포함되지 않습니다
- 서드파티 의존성은 각자의 라이선스를 따르며, 전체 목록은 `go.mod`와 `go.sum`에 있습니다. 일부 탐지 규칙은 [OWASP Core Rule Set](https://coreruleset.org)(Apache-2.0)을 개작했고, 중국산 OA·미들웨어 취약 엔드포인트 시그니처는 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)(MIT)에서 추출했습니다. [NOTICE](../../NOTICE)를 참고하세요

규칙과 인텔리전스 구독, 배포 지원, 등급 보호 평가 지원 등의 상용 서비스는 관리자가 별도로 제공하며, Apache-2.0에 따른 오픈소스 버전의 사용 권리에는 영향을 주지 않습니다.

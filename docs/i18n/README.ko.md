<div align="center">

# netsa

**오픈소스 네트워크 보안 상황 인식 및 공격 표면 분석 플랫폼**

nginx, 방화벽 / IDS, 호스트 인증, DNS 로그를 추적하고 대응할 수 있으며 계속 학습하는 보안 상황으로 바꿔 줍니다.<br>
단일 바이너리로 바로 사용할 수 있고, 내부망 오프라인 운영도 지원합니다.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · **한국어** · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[빠른 시작](#빠른-시작) · [화면 미리보기](#화면-미리보기) · [핵심 기능](#핵심-기능) · [동작 방식](#동작-방식) · [지원 로그](#지원-로그) · [문서](#문서)

</div>

![상황 개요: 공격 지도, 실시간 경보, 위협 지수](../images/overview.png)

## netsa를 선택하는 이유

- **의존성 없이 한 번에 배포**: Go 단일 바이너리에 프런트엔드, 세계 지도와 중국 성·시 지도, 오프라인 위치 정보 데이터베이스가 모두 내장되어 있어 Elasticsearch, Kafka, 데이터베이스가 필요 없습니다. Docker 이미지는 amd64와 arm64를 제공하며, 온라인 추적을 끄면 격리된 네트워크에서 완전히 오프라인으로 동작합니다.
- **로그를 미리 맞출 필요 없음**: 40가지 이상의 형식을 자동으로 인식합니다. nginx / Apache / IIS / Caddy, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, Linux와 Windows 인증, 주요 DNS, Docker와 Filebeat 등 수집기의 래핑 형식을 지원합니다.
- **정확한 탐지, 믿을 수 있는 경보**: 79개의 시그니처 규칙(일부는 OWASP CRS에서 차용), libinjection 구문 분석과 행위 탐지를 갖추고, 응답, 세션 증거, 자산 취약점으로 "겉보기 성공"을 재검증합니다. 등급은 한곳에서 통합 판정하므로 차단된 공격이 "심각"으로 표시되지 않고, 실제로 성공한 악용을 놓치지 않습니다.
- **도시까지 추적하고 그룹까지 연결**: CDN과 프록시 뒤의 실제 IP를 복원하고 XFF 위조와 CDN 우회 직접 연결을 식별합니다. 여러 위치 정보 소스를 교차 비교해 신뢰도를 제시하고, 동일 출처 연관 분석으로 같은 공격자로 의심되는 다른 IP를 찾아냅니다.
- **쓸수록 정확해짐**: 분석가의 처리 결론에서 학습합니다. 오탐이 반복되는 규칙과 엔드포인트는 자동으로 등급이 낮아지고, 확인된 공격자가 다시 나타나면 자동으로 등급이 올라갑니다. AI 분석은 OpenAI와 Anthropic API를 모두 지원하여 내부 vLLM과 클라우드 모델을 모두 연결할 수 있으며, 모델 차이에 자동으로 적응하고 분석가의 결론으로 모델의 신뢰도를 평가합니다.
- **완결된 보안 운영 흐름**: 인시던트 집계와 처리 기한, 오탐 억제, DingTalk / WeCom / Feishu 알림, 자산·취약점 연관, 원본 로그 보관과 포렌식, 주간·월간 보고서, MLPS 2.0(중국 등급 보호 제도) 자가 점검, 위변조 방지 감사 체인을 제공합니다.
- **단일 서버로도 충분히 빠름**: 개발 장비(i7-10700, 16스레드)에서 엔드투엔드 약 46만 건/초를 처리합니다. Aho-Corasick 사전 필터 덕분에 정상 요청은 대부분 정규식을 실행하지 않으며, 탐지는 건당 약 3µs입니다.

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

| 보안 평가와 처리 권고 | 공격 표면 분석 |
|---|---|
| ![보안 평가](../images/assess.png) | ![공격 표면 분석](../images/surface.png) |
| **인시던트 처리와 처리 기한** | **자가 학습과 자동 보정** |
| ![인시던트 처리](../images/incidents.png) | ![자가 학습](../images/learn.png) |

스크린샷은 중국어 웹 화면이며, 내장 시뮬레이터가 생성한 데모 데이터를 보여 줍니다. IP와 사이트는 모두 가상입니다. 위의 데모 환경으로 직접 체험할 수 있습니다.

## 핵심 기능

| 모듈 | 기능 |
|---|---|
| [로그 수집](../log-sources.md) | 파일 실시간 추적(와일드카드, logrotate 순환), 일괄 분석(`.gz` 포함), Syslog UDP / TCP / TLS(상호 인증 가능), 송신 측 식별, 허용 목록, 속도 제한, 로그 끊김 경보 |
| [공격 탐지](../detection.md) | SQL 인젝션, XSS, 명령 실행, Log4Shell, SSRF, XXE, 역직렬화, WebShell, 알려진 취약점 악용 등의 시그니처 규칙; CC, 무차별 대입, 크리덴셜 스터핑, API 열거, 포트 스캔 등의 행위 탐지; 다단계 디코딩으로 일반적인 우회에 대응 |
| [결과 판정](../detection.md#研判复核用证据排除表面成功) | 응답과 세션 증거로 차단됨, 실패, 차단되지 않음, 성공 의심을 구분; 단일 페이지 앱의 대체 페이지, 통합 오류 페이지, 서비스에 도달하지 않은 "허용" 같은 겉보기 현상을 배제 |
| [호스트 및 DNS 탐지](../log-sources.md#主机认证日志与-dns-日志) | SSH / RDP / VPN 무차별 대입과 침입 성공, 패스워드 스프레이, 로그 삭제, 계정 생성과 권한 상승; DNSLog 대역 외 콜백, DNS 터널, DGA, 채굴 풀 도메인 |
| [공격원 추적](../traceability.md) | ip2region, MaxMind, ip-api, rDNS, RDAP / WHOIS를 통합하고 내부 사용자 정의 서브넷 위치를 지원; 동일 출처 연관으로 서브넷, 도구 지문, 공격 기법에 따라 같은 그룹으로 의심되는 대상을 발견 |
| [상황 대시보드](../deployment.md#演示环境) | 세계 / 중국 이중 공격 지도, 성과 시 단위까지 드릴다운; 실시간 공격선과 경보 알림; KPI, 추세, 분포 차트를 클릭해 공격원이나 경보로 드릴다운 |
| [공격 표면 분석](../log-sources.md#未做-dnat-映射的端口探测) | 외부 공개 서비스를 정리하고 소스 코드, 키, 백업 유출과 관리 인터페이스 노출을 발견; DNAT 매핑과 방화벽 세션 증거로 어떤 서비스에도 닿지 않는 배경 스캔을 걸러냄 |
| [보안 평가와 침해 판정](../detection.md#安全评估与失陷研判) | 7개 차원으로 점수를 매겨 A~E 종합 등급과 P0~P3 처리 권고를 제시; 내부 호스트의 위협 인텔리전스 주소 접속, C2 비콘 탐지; MITRE ATT&CK 매트릭스 |
| [자가 학습과 AI 분석](../self-learning.md) | 규칙 단위와 대상 단위 자동 보정, 확인된 공격원 재출현 시 등급 상향, 학습 기간(정책은 화면에서 조정 가능); AI 분석은 OpenAI / Anthropic API와 vLLM을 지원하고 모델 차이에 자동 적응하며, 자사 유사 사례를 첨부하고 모델과 분석가 결론의 일치율을 집계 |
| [인시던트 처리와 알림](../operations.md#事件处置与误报抑制) | 경보를 인시던트로 자동 집계하고 담당자 지정, 처리 기한, 기한 초과 알림을 지원; 오탐 억제; [DingTalk / WeCom / Feishu 알림](../operations.md#告警推送钉钉--企业微信--飞书)(중복 제거, 병합, 속도 제한); nginx, iptables, ipset 등의 차단 목록 내보내기 |
| [보관, 규정 준수, 감사](../operations.md#原始日志留存与检索) | 원본 로그를 시간 단위로 압축 보관하고 해시 체인으로 위변조 방지; [PostgreSQL 장기 보관](../operations.md#告警归档可选postgresql)(선택); 주간·월간 보고서, MLPS 2.0 자가 점검; [세 가지 역할, 이중 인증, 위변조 방지 감사 체인](../operations.md#登录账号与审计); Prometheus 지표 |

## 동작 방식

```text
로그 소스      nginx · 방화벽 / IDS · 호스트 인증 · DNS · 컨테이너와 수집기
   │           파일 추적 / 일괄 분석 / Syslog(UDP · TCP · TLS)
   ▼
형식 인식      데이터 소스와 송신 측별로 형식과 시간대를 독립적으로 인식
   ▼
실제 IP        신뢰할 수 있는 프록시 기준으로 출처를 복원, XFF 위조와 CDN 우회를 표시
   ▼
위협 탐지      시그니처 규칙(AC 사전 필터 + 정규식) + 행위 탐지(시간 창, 메모리 상한 있음)
   ▼
증거 필터      세션 증거와 DNAT 매핑으로 서비스에 도달하지 않은 탐색을 제외, 오탐 억제 적용
   ▼
학습 보정      분석가 결론에 따라 반복 오탐 적중을 하향, 확인된 공격원을 상향(learn)
   ▼
등급 판정      분류 하한, 성공 시 상향, 결과별 상한으로 최종 등급을 통합 결정(risk)
   ▼
상태 저장소    공격자 프로필 · 경보 · 보안 인시던트 · 공격 표면 · 시계열 · 스냅샷 영속화
   │
   ├── 웹 대시보드와 REST API(SSE 실시간 알림)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── 원본 로그 보관 · PostgreSQL 보관(선택)
   └── AI 분석(선택, 결론을 인시던트 처리 기록에 기록)
```

핵심 설계:

- **등급은 한곳에서만 판정**: 규칙에 선언한 등급은 권장값일 뿐이며, 각 단계가 제각각 가감해 같은 종류의 이벤트 등급이 달라지는 것을 막습니다. 자세한 내용은 [위협 등급 판정](../detection.md#威胁等级判定)을 참고하세요.
- **겉모습보다 증거 우선**: 방화벽 "허용", 응답 200, 여러 번 실패한 뒤의 로그인 성공은 모두 세션, 응답 기준선, 계정 단서로 재검증합니다.
- **학습에는 경계가 있음**: 사람의 결론에서만 학습합니다. 자동 조정은 한 번에 최대 한 단계이며, 악용에 성공하면 여전히 심각으로 판정합니다. 경보를 숨기는 오탐 억제는 사람이 채택해야 합니다. AI 결론은 학습 샘플로 쓰이지 않으며 자동 처리도 하지 않습니다.
- **부하에도 통제 유지**: 파싱과 탐지를 병렬로 수행해 일괄 저장하고, 프로필 수와 탐지 창에는 엄격한 상한이 있습니다. 비정상 로그 한 줄이 서비스에 영향을 주지 않으며, 대기열 적체와 폐기는 모두 모니터링 지표로 확인할 수 있습니다.

## 지원 로그

| 유형 | 형식 |
|---|---|
| **Web** | nginx / Apache(combined, main, vhost), 임의의 사용자 정의 `log_format`, nginx JSON, Caddy, Traefik, Elastic ECS, IIS W3C |
| **방화벽** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Windows 방화벽, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, FortiGate IPS / UTM 등 장비의 위협 로그 |
| **호스트 및 VPN 인증** | Linux `auth.log` / `secure`, Windows 보안 이벤트(NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, SQL Server 로그인 |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **컨테이너와 수집기** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O(자동으로 풀어 원본 로그를 인식) |

연동 방법은 [로그 연동](../log-sources.md)을 참고하세요. 연동 후 대시보드의 "데이터 소스" 페이지에서 인식 결과와 파싱 실패 샘플을 확인할 수 있습니다.

## 문서

아래 상세 문서는 중국어 간체로 작성되어 있습니다.

| 문서 | 내용 |
|---|---|
| [배포 가이드](../deployment.md) | 운영 환경 배포, `.env` 변수, 업그레이드와 롤백, 오프라인 환경, 데모 환경, 소스에서 실행 |
| [로그 연동](../log-sources.md) | Web, 방화벽, 인증, DNS 연동, syslog 송신 측 관리, 시간대, DNAT와 세션 증거 |
| [탐지와 판정](../detection.md) | 위협 등급 판정, 결과 재검증, 위협 점수, 보안 평가와 침해 판정 |
| [공격원 추적](../traceability.md) | 다중 소스 위치 정보, 내부 서브넷, 위치 정보 데이터베이스 핫 리로드, 동일 출처 연관 분석 |
| [자가 학습과 AI 분석](../self-learning.md) | 자동 적용 범위와 경계, 행위 기준선, 규정 준수 자가 점검, 외부 모델 설정과 적응 |
| [보안 운영](../operations.md) | 인시던트 처리, 경보 알림, 원본 로그, 자산과 취약점, 보고서와 규정 준수, 계정과 감사, 모니터링 지표, 경보 보관 |
| [설정 참고](../configuration.md) | 자주 쓰는 설정 항목과 운영 시 주의 사항 |
| [API](../api.md) | REST API 목록 |
| [외부 시스템 연동](../integrations.md) | LDAP / OIDC 싱글 사인온, SIEM 전달, 방화벽 연동 차단, 티켓과 플레이북, STIX / TAXII / MISP 인텔리전스, Sigma 및 서명된 규칙 팩 |
| [개발과 릴리스](../development.md) | 로컬 테스트, 코드 구조, 이미지 빌드와 릴리스 |

## 개발

Go 1.25 이상이 필요합니다(릴리스 버전은 Go 1.27로 빌드). 순수 Go 구현이며 CGO를 사용하지 않습니다.

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

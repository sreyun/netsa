<div align="center">

# netsa

**Plataforma de código abierto para la conciencia situacional de seguridad de red y el análisis de la superficie de ataque**

Convierte los registros web, de cortafuegos / IDS, de flujos de red, de autenticación y procesos de los hosts y de DNS en una visión de seguridad que puedes rastrear, sobre la que puedes actuar y que sigue aprendiendo.<br>
Un único binario listo para usar, también en redes aisladas.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · **Español** · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[Inicio rápido](#inicio-rápido) · [Capturas de pantalla](#capturas-de-pantalla) · [Capacidades principales](#capacidades-principales) · [Cómo funciona](#cómo-funciona) · [Registros compatibles](#registros-compatibles) · [Documentación](#documentación)

</div>

![Vista general: mapa de ataques, alertas en tiempo real e índice de amenaza](../images/overview.png)

## Por qué netsa

- **Sin dependencias, despliegue en un paso**: un único binario de Go con la interfaz web, mapas del mundo y de provincias y ciudades de China, y bases de geolocalización sin conexión integradas. No necesita Elasticsearch, Kafka ni base de datos. Hay imágenes Docker para amd64 y arm64 y, con el rastreo en línea desactivado, funciona totalmente sin conexión en redes aisladas.
- **Sin adaptar los registros de antemano**: reconoce automáticamente más de 50 formatos: nginx / Tengine / OpenResty / APISIX / Kong / Apache / IIS / Caddy, WAF como ModSecurity, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, autenticación de Linux y Windows, los principales servidores DNS, Zeek, NetFlow / sFlow / IPFIX, registros de host de Sysmon / auditd / Wazuh, registros de inicio de sesión de aplicaciones y los formatos de envoltura de recolectores como Docker y Filebeat.
- **Detección precisa, alertas fiables**: 87 reglas de firmas (algunas adaptadas del OWASP CRS), análisis sintáctico con libinjection y detección por comportamiento, usando respuestas, evidencias de sesión y vulnerabilidades de los activos para volver a comprobar el «éxito aparente». La gravedad la fija una única decisión central: un ataque bloqueado nunca se marca como «crítico» y una explotación con éxito no se pasa por alto.
- **Conoce los sistemas OA y el middleware chinos**: 261 firmas integradas de endpoints vulnerables que cubren 42 productos, entre ellos los OA de Seeyon, Weaver, Yonyou, Tongda, Landray y Wanhu, FanRuan, Esafenet, RuoYi, Nacos, APISIX, Nginx UI y equipos de Sangfor, Ruijie, Hikvision y Dahua. Las alertas indican el producto y el identificador CVE / CNVD; los endpoints vulnerables que usa el tráfico normal del negocio se aprenden automáticamente para que dejen de generar alertas.
- **Inteligencia precisa, no solo abundante**: inteligencia de IP, dominios, huellas TLS y hashes de archivos (STIX / TAXII / MISP / listas de texto), clasificada por categoría (C2, malware, phishing, minería, origen de ataques), con las plataformas públicas abusadas filtradas automáticamente. La precisión de cada fuente se mide con los veredictos de los analistas, y las fuentes con falsos positivos persistentes se rebajan automáticamente.
- **Registros del cortafuegos y de la web relacionados**: un host interno que, tras un ataque web, se conecta al atacante o a una dirección de retorno escrita en la carga útil se marca como comprometido; conectarse a una dirección de la carga útil demuestra que la carga se ejecutó.
- **Rastreo hasta la ciudad, vínculo con el grupo**: recupera la IP real detrás de CDN y proxies, y detecta la falsificación de XFF y las conexiones directas al origen que eluden la CDN. Varias fuentes de geolocalización se contrastan y se les asigna un nivel de confianza. La correlación de mismo origen y la agrupación en campañas encuentran las direcciones de salida que va rotando un mismo atacante (misma huella de herramienta, mismo identificador de correlación OAST, huella TLS, mismo token señuelo). Un acierto en un [señuelo](../detection.md#诱饵) (ruta, token, cuenta señuelo o honeypot) identifica a un atacante con alta confianza. La cadena de ataque al activo muestra en orden cronológico cómo se escaneó, explotó y controló un servidor y cómo se usó para el movimiento lateral.
- **Más preciso con el uso**: aprende de los veredictos de los analistas. Las reglas y endpoints con falsos positivos repetidos se rebajan automáticamente y los atacantes confirmados se elevan automáticamente cuando vuelven. Sin mantener listas de permitidos a mano: aprende del tráfico normal los valores habituales de cada parámetro e identifica de forma pasiva los productos y frameworks de frontend de cada sitio, de modo que el texto normal de un buscador o las sondas de un producto que el sitio no usa ya no generan alertas de alta gravedad. El triaje con IA admite las API de OpenAI y de Anthropic, así que se pueden conectar tanto vLLM local como modelos en la nube. Se adapta automáticamente a las diferencias entre modelos y usa los veredictos de los analistas para evaluar cuánto se puede confiar en cada modelo.
- **Un ciclo completo de operaciones de seguridad**: agregación de incidentes con plazos de atención, supresión de falsos positivos, notificaciones por DingTalk / WeCom / Feishu, correlación de activos y vulnerabilidades, conservación de registros sin procesar con paquetes de evidencias en un clic, informes semanales y mensuales, autoevaluación MLPS 2.0 (el esquema chino de protección multinivel) y una cadena de auditoría a prueba de manipulaciones.
- **Rápido en una sola máquina**: unos 460 000 eventos por segundo de extremo a extremo en un equipo de desarrollo (i7-10700, 16 hilos). El prefiltrado Aho-Corasick hace que las peticiones normales casi nunca necesiten una expresión regular, con unos 3 µs por evento.

## Inicio rápido

### Pruébalo con un comando (incluye registros de ataques simulados)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Abre <http://localhost:8080> e inicia sesión como `admin` con la contraseña `Netsa@demo2026`. El simulador genera registros de ataques de forma continua y el panel se actualiza en tiempo real.

### Despliegue en producción

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Visita `http://<IP-del-servidor>:8080`. La contraseña inicial está en los registros: `docker compose logs netsa | grep 初始密码` (`初始密码` es el texto literal del registro y significa «contraseña inicial»). Debes cambiarla en el primer inicio de sesión.
- De forma predeterminada se leen `/var/log/nginx` y `/var/log` del host; envía el syslog de los equipos de red a `<IP-del-servidor>:5514` (UDP / TCP).
- Para fijar una versión, cambiar puertos o activar el archivo de alertas, ejecuta primero `cp .env.example .env` y edítalo según los comentarios.
- Windows PowerShell 5.1 no admite `&&` ni `grep`: ejecuta los comandos de uno en uno y usa `Select-String` en lugar de `grep`.

Consulta la [guía de despliegue](../deployment.md) para actualizaciones y reversiones, despliegue sin conexión y preguntas frecuentes.

### Analiza registros existentes sin desplegar

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # abre el panel tras el análisis
```

## Capturas de pantalla

| Evaluación de seguridad y acciones recomendadas | Análisis de la superficie de ataque |
|---|---|
| ![Evaluación de seguridad](../images/assess.png) | ![Análisis de la superficie de ataque](../images/surface.png) |
| **Gestión de incidentes y plazos** | **Autoaprendizaje y ajuste automático** |
| ![Gestión de incidentes](../images/incidents.png) | ![Autoaprendizaje](../images/learn.png) |

Las capturas muestran la interfaz web, que está en chino, con datos de demostración del simulador integrado. Todas las IP y los sitios son simulados. Puedes probarlo con el entorno de demostración de arriba.

## Capacidades principales

| Módulo | Capacidades |
|---|---|
| [Recopilación de registros](../log-sources.md) | Seguimiento de archivos en tiempo real (comodines, rotación de logrotate), análisis por lotes (incluido `.gz`), syslog por UDP / TCP / TLS (con TLS mutuo opcional), [recopilación de NetFlow / sFlow / IPFIX](../log-sources.md#流量日志zeeknetflow--sflow-与云抗-d-服务); identificación de emisores, listas de permitidos, límites de velocidad y alertas por silencio de la fuente |
| [Detección de ataques](../detection.md) | Reglas de firmas para inyección SQL, XSS, ejecución de comandos, Log4Shell, SSRF, XXE, deserialización, WebShell, exploits conocidos y más, con algunas reglas de comandos, código y clases Java adaptadas del OWASP CRS; el [análisis sintáctico con libinjection](../detection.md#语法分析libinjection) vuelve a comprobar las inyecciones y detecta variantes que las expresiones regulares no ven; [firmas de endpoints vulnerables de OA y middleware chinos](../detection.md#国产-oa中间件漏洞接口签名) (261 firmas, 42 productos); detección por comportamiento de CC, fuerza bruta, relleno de credenciales, enumeración de endpoints, escaneo de puertos, comportamiento de WebShell, exfiltración de datos, movimiento lateral y DDoS volumétrico; cuando se registra el cuerpo de la petición también se analizan las cargas POST; la decodificación en varias rondas frustra las evasiones habituales |
| [Verificación de resultados](../detection.md#研判复核用证据排除表面成功) | Usa las respuestas y la evidencia de sesión para distinguir ataques bloqueados, fallidos, no bloqueados y probablemente exitosos; descarta éxitos aparentes como páginas de respaldo de aplicaciones de una sola página, páginas de error uniformes y tráfico «permitido» que nunca llegó a un servicio |
| [Detección en hosts y DNS](../log-sources.md#主机认证日志与-dns-日志) | Fuerza bruta en SSH / RDP / VPN y accesos conseguidos, password spraying, borrado de registros, nuevas cuentas y escalada de privilegios, [robo de cuentas](../detection.md#账号盗用) (viajes imposibles, inicios de sesión desde un país nuevo, sesiones simultáneas desde varios lugares); [detección de procesos del host](../detection.md#主机进程检测) (procesos del servidor web que ejecutan comandos, reverse shells, robo de credenciales, persistencia); retornos fuera de banda de DNSLog, túneles DNS, DGA, dominios de pools de minería y dominios de C2, malware y phishing señalados por la inteligencia |
| [Rastreo del origen del ataque](../traceability.md) | Combina ip2region, MaxMind, ip-api, rDNS y RDAP / WHOIS, con ubicaciones personalizadas para subredes internas; la correlación de mismo origen usa subredes, huellas de herramientas y técnicas de ataque para encontrar probables miembros del mismo grupo |
| [Cadena de ataque al activo](../detection.md#资产攻击链路) | Se centra en un sitio o host y enlaza reconocimiento, explotación, intrusión, implantación, control, movimiento lateral, recolección e impacto, con la evidencia, el origen y la técnica ATT&CK de cada paso; los sitios y los servidores que hay detrás se fusionan automáticamente, con un veredicto de compromiso y acciones recomendadas |
| [Panel de situación](../deployment.md#演示环境) | Mapas de ataques del mundo y de China con desglose a provincias y ciudades; líneas de ataque y alertas en tiempo real; los KPI, tendencias y gráficos de distribución permiten profundizar hasta los orígenes o las alertas |
| [Análisis de la superficie de ataque](../log-sources.md#未做-dnat-映射的端口探测) | Inventaría los servicios expuestos y detecta fugas de código fuente, claves y copias de seguridad, así como interfaces de administración expuestas; combina las asignaciones DNAT con la evidencia de sesión del cortafuegos para filtrar el escaneo de fondo que no puede llegar a ningún servicio |
| [Evaluación de seguridad y análisis de compromiso](../detection.md#安全评估与失陷研判) | Puntúa siete dimensiones con una nota global de A a E y recomendaciones de P0 a P3; detecta hosts internos que se conectan a direcciones señaladas por la inteligencia, balizas de C2, huellas TLS maliciosas y cargas útiles que llegan a los hosts; la [correlación de registros del cortafuegos y de la web](../detection.md#防火墙与-web-日志联动被攻击后回连) encuentra los hosts que se conectaron de vuelta a su atacante; matriz MITRE ATT&CK |
| [Autoaprendizaje y triaje con IA](../self-learning.md) | Calibración automática de la precisión por regla, por objetivo y por fuente de inteligencia, elevación cuando vuelven orígenes confirmados, ventanas de aprendizaje y políticas ajustables en la interfaz; aprende de los registros las subredes internas, los orígenes de ataque, las campañas y los [valores normales de los parámetros y los productos de cada sitio](../self-learning.md#参数的正常取值与站点产品); el triaje con IA admite las API de OpenAI / Anthropic y vLLM, se adapta automáticamente a las diferencias entre modelos, incluye casos similares de tu propia organización y mide con qué frecuencia el modelo coincide con los analistas |
| [Gestión de incidentes y notificaciones](../operations.md#事件处置与误报抑制) | Las alertas se agrupan automáticamente en incidentes, con asignación, plazos de atención y recordatorios de vencimiento; supresión de falsos positivos; [registro de escaneos autorizados](../detection.md#授权扫描登记) (solo se registra sin alertar durante una prueba y se restablece automáticamente al terminar); [notificaciones por DingTalk / WeCom / Feishu](../operations.md#告警推送钉钉--企业微信--飞书) con deduplicación, fusión y límite de velocidad; exportación de listas de bloqueo para nginx, iptables, ipset y más |
| [Conservación, cumplimiento y auditoría](../operations.md#原始日志留存与检索) | Registros sin procesar comprimidos y conservados por horas, con una cadena de hashes contra manipulaciones; [archivo a largo plazo en PostgreSQL](../operations.md#告警归档可选postgresql) (opcional); informes semanales y mensuales, autoevaluación MLPS 2.0; [tres roles, autenticación de dos factores y una cadena de auditoría a prueba de manipulaciones](../operations.md#登录账号与审计); métricas de Prometheus |

## Cómo funciona

```text
Fuentes de registro    nginx · cortafuegos / IDS · Zeek · autenticación y procesos de hosts · inicios de sesión de aplicaciones · DNS · contenedores y recolectores
   │                   seguimiento de archivos / análisis por lotes / syslog (UDP · TCP · TLS) / recopilación de flujos (NetFlow · IPFIX · sFlow)
   ▼
Detección del formato  formato y zona horaria detectados por separado para cada fuente y cada emisor
   ▼
IP real                recupera el origen mediante proxies de confianza, marca la falsificación de XFF y la elusión de la CDN
   ▼
Detección de amenazas  reglas de firmas (prefiltro AC + regex) + análisis sintáctico (libinjection) + reglas de procesos del host + detección por comportamiento (ventanas de tiempo, memoria acotada)
   ▼
Inteligencia y señuelos  inteligencia de IP / dominios / huellas TLS / hashes de archivos; los aciertos en rutas, tokens, cuentas señuelo y honeypots confirman al atacante
   ▼
Filtro de evidencias   la evidencia de sesión y las asignaciones DNAT descartan sondas que no llegaron a ningún servicio; se aplica la supresión
   ▼
Ajuste aprendido       los valores normales de los parámetros y los productos de cada sitio revisan los aciertos; los falsos positivos repetidos se rebajan según los veredictos de los analistas y se elevan los orígenes confirmados (learn)
   ▼
Correlación            enlaza ataques web anteriores: retornos y descargas de cargas útiles tras un ataque; conexiones laterales posteriores de hosts comprometidos
   ▼
Decisión de gravedad   el mínimo por categoría, la elevación por éxito y el tope por resultado fijan la gravedad final (risk)
   ▼
Almacén de estado      perfiles de atacantes · alertas · incidentes · campañas · cadenas de ataque a activos · superficie de ataque · series temporales · persistencia por instantáneas
   │
   ├── Panel web y API REST (envío en vivo por SSE)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Conservación de registros sin procesar · archivo en PostgreSQL (opcional)
   └── Triaje con IA (opcional, las conclusiones se escriben en el registro del incidente)
```

Puntos clave del diseño:

- **La gravedad se decide en un solo lugar**: la gravedad que declara una regla es solo una sugerencia, lo que evita que cada etapa sume y reste por su cuenta y que eventos similares acaben con gravedades distintas. Consulta las [decisiones de gravedad](../detection.md#威胁等级判定).
- **La evidencia por encima de las apariencias**: un «permitido» del cortafuegos, una respuesta 200 o un inicio de sesión correcto tras fallos repetidos se vuelven a comprobar con sesiones, líneas base de respuesta y pistas de cuentas.
- **El aprendizaje tiene límites**: la calibración de reglas solo aprende de los veredictos humanos. Los ajustes automáticos mueven como mucho un nivel cada vez y una explotación con éxito sigue siendo crítica. Los valores normales de los parámetros y los productos del sitio aprendidos del tráfico solo rebajan un acierto cuando se cumplen a la vez dos condiciones independientes (el parámetro suele ser texto normal y el análisis sintáctico no encuentra inyección; el sitio no usa el producto y la petición no tuvo éxito), y solo hasta gravedad baja, sin ocultar nunca la alerta. La supresión de falsos positivos, que sí oculta alertas, debe adoptarla una persona. Las conclusiones de la IA no se usan como muestras de aprendizaje y nunca desencadenan acciones automáticas.
- **Bajo control incluso bajo presión**: el análisis y la detección se ejecutan en paralelo y se almacenan por lotes, el número de perfiles y las ventanas de detección tienen límites estrictos, y una sola línea de registro mal formada no afecta al servicio. Las colas acumuladas y los descartes tienen métricas de supervisión.

## Registros compatibles

| Tipo | Formatos |
|---|---|
| **Web** | nginx / Tengine / OpenResty / Apache (combined, main, vhost), cualquier `log_format` personalizado, nginx JSON, APISIX, Kong, Nginx Proxy Manager, Caddy, Traefik, Elastic ECS, IIS W3C |
| **WAF** | Bloqueos y limitación de velocidad de ModSecurity y naxsi en los registros de error de nginx / Tengine / OpenResty, registros de auditoría JSON de ModSecurity, OpenResty Lua WAF |
| **Cortafuegos** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Firewall de Windows, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone, además de los registros de defensa contra ataques de Huawei, H3C y Sangfor |
| **IDS / IPS** | Suricata EVE JSON, alertas fast de Snort, registros de amenazas de equipos como FortiGate IPS / UTM |
| **Autenticación de hosts y VPN** | `auth.log` / `secure` de Linux, eventos de seguridad de Windows (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, inicios de sesión de SQL Server |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Flujos de red** | Zeek (conn / http / ssl / files, TSV o JSON), NetFlow v5 / v9, IPFIX, sFlow v5 (recopilación por UDP), eventos de ataque de servicios anti-DDoS en la nube |
| **Procesos del host (EDR / HIDS)** | Sysmon (Winlogbeat / NXLog / Elastic Agent), Windows 4688, Elastic Defend (ECS), auditd de Linux, alertas de Wazuh |
| **Inicios de sesión de aplicaciones y honeypots** | Registros JSON de inicio de sesión de sistemas de negocio y plataformas de identidad / SSO, registros del honeypot OpenCanary |
| **Contenedores y recolectores** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O, desenvueltos automáticamente para reconocer el registro original |

Consulta la [incorporación de registros](../log-sources.md) para configurarlos. Tras conectar una fuente, revisa los resultados del reconocimiento y las muestras de fallos de análisis en la página de fuentes de datos del panel.

## Documentación

Los documentos detallados siguientes están escritos en chino simplificado.

| Documento | Contenido |
|---|---|
| [Guía de despliegue](../deployment.md) | Despliegue en producción, variables de `.env`, actualización y reversión, redes sin conexión, entorno de demostración, ejecución desde el código fuente |
| [Incorporación de registros](../log-sources.md) | Incorporación de registros web, de cortafuegos, de autenticación, DNS, flujos de red (Zeek, NetFlow / sFlow, anti-DDoS en la nube), procesos del host e inicios de sesión de aplicaciones, gestión de emisores de syslog, zonas horarias, DNAT y evidencia de sesión |
| [Detección y verificación](../detection.md) | Decisiones de gravedad, verificación de resultados, campañas y cadenas de ataque a activos, robo de datos y movimiento lateral, señuelos, detección de procesos del host, robo de cuentas, puntuación de amenazas, evaluación de seguridad y análisis de compromiso |
| [Rastreo del origen del ataque](../traceability.md) | Geolocalización con varias fuentes, subredes internas, recarga en caliente de las bases de geolocalización, correlación de mismo origen |
| [Autoaprendizaje y triaje con IA](../self-learning.md) | Qué se aplica automáticamente y sus límites, líneas base de comportamiento, autoverificación de cumplimiento, configuración de modelos externos y adaptación a cada modelo |
| [Operaciones de seguridad](../operations.md) | Gestión de incidentes, notificaciones, registros sin procesar, activos y vulnerabilidades, informes y cumplimiento, cuentas y auditoría, métricas de supervisión, archivo de alertas |
| [Referencia de configuración](../configuration.md) | Ajustes habituales y notas de operación |
| [API](../api.md) | Resumen de la API REST |
| [Integraciones externas](../integrations.md) | Inicio de sesión único LDAP / OIDC, reenvío a SIEM, bloqueo automatizado, tickets y playbooks, inteligencia STIX / TAXII / MISP y en texto (IP, dominios, huellas TLS, hashes de archivos, con categorías), Sigma y paquetes de reglas firmados |
| [Desarrollo y publicación](../development.md) | Pruebas locales, estructura del código, construcción y publicación de imágenes |
| [Evaluación de capacidades y hoja de ruta](../roadmap.md) | Capacidades de detección, localización y rastreo evaluadas a lo largo de la cadena de ataque, con carencias y un plan por fases |
| [Registro de cambios](../CHANGELOG.md) | Cambios que afectan al uso |

## Desarrollo

Requiere Go 1.26 o posterior (las versiones publicadas se compilan con Go 1.27). Go puro, sin CGO.

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # no debe imprimir nada
go vet ./...
go test ./...
```

Las pruebas de condiciones de carrera necesitan un compilador de C. Si no tienes gcc, ejecútalas en un contenedor:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

Consulta [desarrollo y publicación](../development.md) para la estructura del código y el proceso de publicación.

## Contribuir

Las issues y pull requests son bienvenidas, en especial:

- muestras de nuevos formatos de registro (anonimízalas antes) e informes de fallos de reconocimiento o de análisis;
- nuevas reglas de detección e informes de falsos positivos o falsos negativos con muestras;
- mejoras de la documentación y experiencias reales de despliegue.

Pasa las comprobaciones anteriores antes de enviar código. La CI también ejecuta pruebas de condiciones de carrera y `govulncheck`.

Si netsa te resulta útil, dale una **Star** para que más personas que lo necesitan puedan encontrarlo.

## Licencia

Este proyecto se publica bajo la [Apache License 2.0](../../LICENSE): puedes usarlo con fines comerciales, modificarlo y redistribuirlo, siempre que conserves el aviso de copyright, el texto de la licencia y el archivo [NOTICE](../../NOTICE).

- El software se ofrece «tal cual», sin garantías de ningún tipo, ni expresas ni implícitas;
- La licencia no concede derechos de marca; el nombre y el logotipo de `netsa` no están incluidos;
- Las dependencias de terceros siguen sus propias licencias, listadas por completo en `go.mod` y `go.sum`. Algunas reglas de detección están adaptadas del [OWASP Core Rule Set](https://coreruleset.org) (Apache-2.0) y las firmas de endpoints vulnerables de OA y middleware chinos proceden de [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT); consulta [NOTICE](../../NOTICE).

Los servicios comerciales, como las suscripciones de reglas e inteligencia, el despliegue y la entrega, y el apoyo a evaluaciones MLPS, los prestan aparte los mantenedores y no afectan a tus derechos de uso de la edición de código abierto bajo Apache-2.0.

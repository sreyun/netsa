<div align="center">

# netsa

**Plataforma de código abierto para la conciencia situacional de seguridad de red y el análisis de la superficie de ataque**

Convierte los registros de nginx, firewall / IDS, autenticación de hosts y DNS en una visión de seguridad rastreable, accionable y que sigue aprendiendo.<br>
Un único binario listo para usar, también en redes internas sin conexión.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · **Español** · [Français](README.fr.md) · [Deutsch](README.de.md) · [Русский](README.ru.md)

[Inicio rápido](#inicio-rápido) · [Capturas de pantalla](#capturas-de-pantalla) · [Capacidades principales](#capacidades-principales) · [Cómo funciona](#cómo-funciona) · [Registros compatibles](#registros-compatibles) · [Documentación](#documentación)

</div>

![Vista general: mapa de ataques, alertas en tiempo real e índice de amenazas](../images/overview.png)

## Por qué netsa

- **Sin dependencias, despliegue en un paso**: un único binario de Go con la interfaz web, los mapas del mundo y de provincias y ciudades de China, y las bases de datos de geolocalización sin conexión integrados. No necesita Elasticsearch, Kafka ni base de datos. Hay imágenes Docker para amd64 y arm64 y, con el rastreo en línea desactivado, funciona totalmente sin conexión en redes aisladas.
- **No hay que adaptar los registros antes**: reconoce automáticamente más de 40 formatos: nginx / Apache / IIS / Caddy, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, autenticación de Linux y Windows, los principales servidores DNS y los formatos envueltos por recopiladores como Docker y Filebeat.
- **Detección precisa, alertas fiables**: 79 reglas de firmas (algunas adaptadas de OWASP CRS), análisis sintáctico con libinjection más detección de comportamiento, con respuestas, evidencias de sesión y vulnerabilidades de activos para volver a comprobar el «éxito aparente». La gravedad se decide de forma centralizada: los ataques bloqueados nunca se marcan como «críticos» y las explotaciones realmente exitosas no se pasan por alto.
- **Rastreo hasta la ciudad, correlación hasta el grupo**: recupera la IP real detrás de CDN y proxies, y detecta la falsificación de XFF y las conexiones directas que evitan la CDN. Compara varias fuentes de geolocalización y asigna un nivel de confianza. La correlación de mismo origen encuentra otras IP que probablemente pertenecen al mismo atacante.
- **Más preciso con el uso**: aprende de las conclusiones de los analistas. Las reglas y los endpoints con falsos positivos repetidos bajan de nivel automáticamente, y los atacantes confirmados suben de nivel automáticamente cuando reaparecen. El triaje con IA admite las API de OpenAI y Anthropic, de modo que se pueden conectar tanto vLLM en red interna como modelos en la nube. Se adapta automáticamente a las diferencias entre modelos y usa las conclusiones de los analistas para evaluar su fiabilidad.
- **Ciclo completo de operaciones de seguridad**: agregación de incidentes con plazos de gestión, supresión de falsos positivos, notificaciones por DingTalk / WeCom / Feishu, correlación de activos y vulnerabilidades, conservación de registros sin procesar y análisis forense, informes semanales y mensuales, autoevaluación MLPS 2.0 (esquema chino de protección multinivel) y cadena de auditoría a prueba de manipulaciones.
- **Rápido en una sola máquina**: unos 460 000 eventos por segundo de extremo a extremo en una máquina de desarrollo (i7-10700, 16 hilos). El prefiltrado Aho-Corasick hace que las solicitudes normales casi nunca necesiten ejecutar expresiones regulares, con unos 3 µs por evento.

## Inicio rápido

### Pruébalo con un comando (incluye registros de ataques simulados)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Abre <http://localhost:8080> e inicia sesión con el usuario `admin` y la contraseña `Netsa@demo2026`. El simulador genera registros de ataques de forma continua y el panel se actualiza en tiempo real.

### Despliegue en producción

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Visita `http://<IP-del-servidor>:8080`. La contraseña inicial está en los registros: `docker compose logs netsa | grep 初始密码` (`初始密码` es el texto literal del registro y significa «contraseña inicial»). Debes cambiarla en el primer inicio de sesión.
- De forma predeterminada lee `/var/log/nginx` y `/var/log` del host. Envía el syslog de los dispositivos de red a `<IP-del-servidor>:5514` (UDP / TCP).
- Para fijar una versión, cambiar puertos o activar el archivado de alertas, ejecuta primero `cp .env.example .env` y edítalo siguiendo los comentarios.
- Windows PowerShell 5.1 no admite `&&` ni `grep`: ejecuta los comandos línea a línea y usa `Select-String` en lugar de `grep`.

Para actualizaciones y reversiones, despliegue sin conexión y problemas comunes, consulta la [guía de despliegue](../deployment.md).

### Analiza registros existentes sin desplegar

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # abre el panel tras el análisis
```

## Capturas de pantalla

| Evaluación de seguridad y recomendaciones | Análisis de la superficie de ataque |
|---|---|
| ![Evaluación de seguridad](../images/assess.png) | ![Análisis de la superficie de ataque](../images/surface.png) |
| **Gestión de incidentes y plazos** | **Autoaprendizaje y calibración automática** |
| ![Gestión de incidentes](../images/incidents.png) | ![Autoaprendizaje](../images/learn.png) |

Las capturas muestran la interfaz web, que está en chino, con datos de demostración del simulador integrado. Todas las IP y los sitios son simulados. Puedes probarlo con el entorno de demostración de arriba.

## Capacidades principales

| Módulo | Capacidades |
|---|---|
| [Recopilación de registros](../log-sources.md) | Seguimiento de archivos en tiempo real (comodines, rotación con logrotate), análisis por lotes (incluido `.gz`), syslog por UDP / TCP / TLS (autenticación mutua opcional); identificación de emisores, lista de permitidos, limitación de velocidad y alertas de fuentes silenciosas |
| [Detección de ataques](../detection.md) | Reglas de firmas para inyección SQL, XSS, ejecución de comandos, Log4Shell, SSRF, XXE, deserialización, WebShell, explotación de vulnerabilidades conocidas y más; detección de comportamiento de ataques CC, fuerza bruta, relleno de credenciales, enumeración de API, escaneo de puertos y más; decodificación en varias rondas contra las evasiones habituales |
| [Verificación de resultados](../detection.md#研判复核用证据排除表面成功) | Usa respuestas y evidencias de sesión para distinguir bloqueado, fallido, no bloqueado y posible éxito; descarta apariencias como páginas de respaldo de aplicaciones de una sola página, páginas de error unificadas y tráfico «permitido» que nunca llegó a un servicio |
| [Detección en hosts y DNS](../log-sources.md#主机认证日志与-dns-日志) | Fuerza bruta SSH / RDP / VPN y compromisos exitosos, rociado de contraseñas, borrado de registros, cuentas nuevas y escalada de privilegios; retrollamadas fuera de banda DNSLog, túneles DNS, DGA, dominios de minería |
| [Rastreo del origen de ataques](../traceability.md) | Combina ip2region, MaxMind, ip-api, rDNS y RDAP / WHOIS, con ubicación de subredes internas personalizadas; la correlación de mismo origen por subred, huella de herramienta y técnica de ataque encuentra posibles miembros del mismo grupo |
| [Panel de situación](../deployment.md#演示环境) | Mapas de ataques del mundo y de China con desglose hasta provincia y ciudad; líneas de ataque y alertas en tiempo real; los KPI, las tendencias y los gráficos de distribución permiten desglosar hasta orígenes de ataque o alertas |
| [Análisis de la superficie de ataque](../log-sources.md#未做-dnat-映射的端口探测) | Inventaría los servicios expuestos y encuentra filtraciones de código fuente, claves y copias de seguridad, e interfaces de administración expuestas; usa mapeos DNAT y evidencias de sesión del firewall para filtrar los escaneos de fondo que no alcanzan ningún servicio |
| [Evaluación de seguridad y análisis de compromiso](../detection.md#安全评估与失陷研判) | Puntúa siete dimensiones con una nota global de A a E y recomendaciones P0–P3; hosts internos que conectan a direcciones de inteligencia de amenazas, detección de balizas C2; matriz MITRE ATT&CK |
| [Autoaprendizaje y triaje con IA](../self-learning.md) | Calibración automática por regla y por objetivo, escalado de atacantes confirmados que reaparecen, ventana de aprendizaje, con política ajustable en la interfaz web; el triaje con IA admite las API de OpenAI / Anthropic y vLLM, se adapta automáticamente a las diferencias entre modelos, incluye casos similares de tu propia organización y mide la coincidencia del modelo con los analistas |
| [Gestión de incidentes y notificaciones](../operations.md#事件处置与误报抑制) | Las alertas se agregan automáticamente en incidentes, con asignación, plazos de gestión y avisos de vencimiento; supresión de falsos positivos; [notificaciones por DingTalk / WeCom / Feishu](../operations.md#告警推送钉钉--企业微信--飞书) con deduplicación, fusión y limitación de velocidad; exportación de listas de bloqueo para nginx, iptables, ipset y más |
| [Conservación, cumplimiento y auditoría](../operations.md#原始日志留存与检索) | Registros sin procesar conservados en segmentos comprimidos por hora con cadena de hash a prueba de manipulaciones; [archivado a largo plazo en PostgreSQL](../operations.md#告警归档可选postgresql) (opcional); informes semanales y mensuales, autoevaluación MLPS 2.0; [tres roles, autenticación de dos factores y cadena de auditoría a prueba de manipulaciones](../operations.md#登录账号与审计); métricas de Prometheus |

## Cómo funciona

```text
Fuentes de registros  nginx · firewall / IDS · autenticación de hosts · DNS · contenedores y recopiladores
   │                  seguimiento de archivos / análisis por lotes / syslog (UDP · TCP · TLS)
   ▼
Detección de formato  formato y zona horaria detectados por separado para cada fuente y emisor
   ▼
IP real               recupera el origen mediante proxies de confianza, marca falsificación de XFF y evasión de CDN
   ▼
Detección de amenazas reglas de firmas (prefiltro AC + regex) + comportamiento (ventanas de tiempo, memoria limitada)
   ▼
Filtro de evidencias  evidencias de sesión y mapeos DNAT descartan sondeos que no llegaron a un servicio; aplica supresión
   ▼
Ajuste aprendido      baja de nivel los falsos positivos repetidos según los analistas, sube orígenes confirmados (learn)
   ▼
Decisión de gravedad  mínimo por categoría, escalado por éxito y tope por resultado deciden la gravedad final (risk)
   ▼
Almacén de estado     perfiles de atacantes · alertas · incidentes · superficie de ataque · series temporales · instantáneas
   │
   ├── Panel web y API REST (envío en tiempo real por SSE)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Conservación de registros sin procesar · archivo PostgreSQL (opcional)
   └── Triaje con IA (opcional, las conclusiones se escriben en el registro del incidente)
```

Decisiones clave de diseño:

- **La gravedad se decide en un solo lugar**: la gravedad que declara una regla es solo una sugerencia, lo que evita que cada etapa sume y reste por su cuenta y que eventos similares acaben con gravedades distintas. Consulta las [decisiones de gravedad](../detection.md#威胁等级判定).
- **Las evidencias por encima de las apariencias**: un «permitir» del firewall, una respuesta 200 o un inicio de sesión exitoso tras varios fallos se vuelven a comprobar con sesiones, líneas base de respuesta e indicios de la cuenta.
- **El aprendizaje tiene límites**: solo aprende de conclusiones humanas. Los ajustes automáticos cambian como máximo un nivel cada vez, y una explotación exitosa sigue siendo crítica. La supresión de falsos positivos, que oculta alertas, debe adoptarla una persona. Las conclusiones de la IA no se usan como muestras de aprendizaje ni desencadenan gestión automática.
- **Bajo control incluso con carga**: el análisis y la detección se ejecutan en paralelo y se almacenan por lotes, el número de perfiles y las ventanas de detección tienen límites estrictos, y una sola línea de registro malformada no afecta al servicio. Las colas acumuladas y los descartes tienen métricas de monitorización.

## Registros compatibles

| Tipo | Formatos |
|---|---|
| **Web** | nginx / Apache (combined, main, vhost), cualquier `log_format` personalizado, nginx JSON, Caddy, Traefik, Elastic ECS, IIS W3C |
| **Firewall** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Firewall de Windows, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, registros de amenazas de dispositivos como FortiGate IPS / UTM |
| **Autenticación de hosts y VPN** | Linux `auth.log` / `secure`, eventos de seguridad de Windows (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, inicios de sesión de SQL Server |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Contenedores y recopiladores** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O; se desenvuelven automáticamente para reconocer el registro original |

Consulta la [incorporación de registros](../log-sources.md) para la configuración. Después de conectar una fuente, revisa los resultados del reconocimiento y las muestras de errores de análisis en la página de fuentes de datos del panel.

## Documentación

Los documentos detallados siguientes están escritos en chino simplificado.

| Documento | Contenido |
|---|---|
| [Guía de despliegue](../deployment.md) | Despliegue en producción, variables de `.env`, actualizaciones y reversiones, redes sin conexión, entorno de demostración, ejecución desde el código fuente |
| [Incorporación de registros](../log-sources.md) | Incorporación de web, firewall, autenticación y DNS, gestión de emisores syslog, zonas horarias, DNAT y evidencias de sesión |
| [Detección y verificación](../detection.md) | Decisiones de gravedad, verificación de resultados, puntuación de amenazas, evaluación de seguridad y análisis de compromiso |
| [Rastreo del origen de ataques](../traceability.md) | Geolocalización multifuente, subredes internas, recarga en caliente de las bases de geolocalización, correlación de mismo origen |
| [Autoaprendizaje y triaje con IA](../self-learning.md) | Qué se aplica automáticamente y sus límites, líneas base de comportamiento, autocomprobaciones de cumplimiento, configuración y adaptación de modelos externos |
| [Operaciones de seguridad](../operations.md) | Gestión de incidentes, notificaciones, registros sin procesar, activos y vulnerabilidades, informes y cumplimiento, cuentas y auditoría, métricas, archivado de alertas |
| [Referencia de configuración](../configuration.md) | Ajustes comunes y notas de operación |
| [API](../api.md) | Resumen de la API REST |
| [Integraciones externas](../integrations.md) | Inicio de sesión único LDAP / OIDC, reenvío a SIEM, bloqueo en firewall, tickets y playbooks, inteligencia STIX / TAXII / MISP, Sigma y paquetes de reglas firmados |
| [Desarrollo y publicación](../development.md) | Pruebas locales, estructura del código, compilación y publicación de imágenes |

## Desarrollo

Requiere Go 1.25 o posterior (las versiones publicadas se compilan con Go 1.27). Go puro, sin CGO.

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # no debe mostrar nada
go vet ./...
go test ./...
```

Las pruebas de condiciones de carrera necesitan un compilador de C. Si no tienes gcc en tu máquina, ejecútalas en un contenedor:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

Consulta [desarrollo y publicación](../development.md) para ver la estructura del código y el proceso de publicación.

## Contribuir

Los Issues y Pull Requests son bienvenidos, en especial:

- muestras de nuevos formatos de registro (anonimízalas antes), e informes de fallos de reconocimiento o análisis;
- nuevas reglas de detección, e informes de falsos positivos o falsos negativos con muestras;
- mejoras de la documentación y experiencia real de despliegue.

Antes de enviar código, supera las comprobaciones anteriores. La CI también ejecuta pruebas de condiciones de carrera y `govulncheck`.

Si netsa te resulta útil, dale una **Star** para que más personas que lo necesitan puedan encontrarlo.

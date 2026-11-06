<div align="center">

# netsa

**Plateforme open source de connaissance de la situation de sécurité réseau et d'analyse de la surface d'attaque**

Transforme les journaux web, de pare-feu / IDS, de flux réseau, d'authentification et de processus des hôtes, et DNS en une vision de la sécurité traçable, actionnable et qui continue d'apprendre.<br>
Un seul binaire, prêt à l'emploi, y compris sur des réseaux isolés.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · **Français** · [Deutsch](README.de.md) · [Русский](README.ru.md)

[Démarrage rapide](#démarrage-rapide) · [Aperçu](#aperçu) · [Fonctionnalités principales](#fonctionnalités-principales) · [Fonctionnement](#fonctionnement) · [Journaux pris en charge](#journaux-pris-en-charge) · [Documentation](#documentation)

</div>

![Vue d'ensemble : carte des attaques, alertes en temps réel et indice de menace](../images/overview.png)

## Pourquoi netsa

- **Aucune dépendance, déploiement en une étape** : un seul binaire Go qui embarque l'interface web, les cartes du monde et des provinces et villes de Chine, ainsi que des bases de géolocalisation hors ligne. Ni Elasticsearch, ni Kafka, ni base de données. Des images Docker sont disponibles pour amd64 et arm64 et, avec le traçage en ligne désactivé, il fonctionne entièrement hors ligne sur des réseaux isolés.
- **Aucune adaptation préalable des journaux** : reconnaît automatiquement plus de 50 formats, dont nginx / Tengine / OpenResty / APISIX / Kong / Apache / IIS / Caddy, des WAF comme ModSecurity, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, l'authentification Linux et Windows, les principaux serveurs DNS, Zeek, NetFlow / sFlow / IPFIX, les journaux d'hôte Sysmon / auditd / Wazuh, les journaux de connexion des applications, ainsi que les formats d'encapsulation de collecteurs comme Docker et Filebeat.
- **Une détection précise, des alertes fiables** : 87 règles de signatures (certaines adaptées de l'OWASP CRS), l'analyse syntaxique libinjection et la détection comportementale, avec les réponses, les preuves de session et les vulnérabilités des actifs pour revérifier les « réussites apparentes ». La gravité découle d'une décision centrale unique : une attaque bloquée n'est jamais classée « critique » et une exploitation réussie n'est pas manquée.
- **Connaît les OA et middlewares chinois** : 261 signatures intégrées de points d'accès vulnérables couvrant 42 produits, dont les OA de Seeyon, Weaver, Yonyou, Tongda, Landray et Wanhu, FanRuan, Esafenet, RuoYi, Nacos, APISIX, Nginx UI et les équipements Sangfor, Ruijie, Hikvision et Dahua. Les alertes indiquent le produit et l'identifiant CVE / CNVD ; les points d'accès vulnérables utilisés par le trafic métier normal sont appris automatiquement pour qu'ils cessent de déclencher des alertes.
- **Un renseignement précis plutôt que volumineux** : renseignement sur les IP, domaines, empreintes TLS et empreintes de fichiers (STIX / TAXII / MISP / listes texte), classé par catégorie (C2, logiciel malveillant, hameçonnage, minage, source d'attaque), en écartant automatiquement les plateformes publiques détournées. La précision de chaque flux est mesurée d'après les verdicts des analystes, et les flux aux faux positifs persistants sont automatiquement rétrogradés.
- **Journaux du pare-feu et du web reliés** : un hôte interne qui, après une attaque web, se connecte à l'attaquant ou à une adresse de rappel écrite dans la charge utile est signalé comme compromis ; une connexion vers une adresse de la charge utile prouve que celle-ci a été exécutée.
- **Tracer jusqu'à la ville, relier au groupe** : retrouve l'IP réelle derrière les CDN et les proxies, et détecte l'usurpation de XFF et les connexions directes à l'origine qui contournent le CDN. Plusieurs sources de géolocalisation sont recoupées et assorties d'un niveau de confiance. La corrélation de même origine et le regroupement en campagnes retrouvent les adresses de sortie qu'un même attaquant fait tourner (même empreinte d'outil, même identifiant de corrélation OAST, empreinte TLS, même jeton leurre). Un accès à un [leurre](../detection.md#诱饵) (chemin, jeton, compte leurre ou honeypot) identifie un attaquant avec une forte confiance. La chaîne d'attaque de l'actif retrace dans l'ordre chronologique comment un serveur a été scanné, exploité, contrôlé puis utilisé pour un mouvement latéral.
- **De plus en plus précis à l'usage** : apprend des verdicts des analystes. Les règles et points d'accès aux faux positifs répétés sont rétrogradés automatiquement, et les attaquants confirmés sont escaladés automatiquement à leur retour. Pas de listes d'autorisation à entretenir à la main : il apprend du trafic normal les valeurs habituelles de chaque paramètre et identifie passivement les produits et frameworks front-end de chaque site, si bien que du texte ordinaire saisi dans un champ de recherche ou des sondes visant un produit absent du site ne déclenchent plus d'alertes graves. Le tri par IA prend en charge les API d'OpenAI et d'Anthropic, ce qui permet de connecter un vLLM local comme des modèles cloud. Il s'adapte automatiquement aux différences entre modèles et utilise les verdicts des analystes pour évaluer la confiance à accorder à chacun.
- **Une boucle complète d'opérations de sécurité** : agrégation des incidents avec délais de traitement, suppression des faux positifs, notifications DingTalk / WeCom / Feishu, corrélation des actifs et des vulnérabilités, conservation des journaux bruts avec paquet de preuves en un clic, rapports hebdomadaires et mensuels, auto-évaluation MLPS 2.0 (le dispositif chinois de protection à plusieurs niveaux) et chaîne d'audit inviolable.
- **Rapide sur une seule machine** : environ 460 000 événements par seconde de bout en bout sur une machine de développement (i7-10700, 16 threads). Le préfiltrage Aho-Corasick évite presque toujours une expression régulière pour les requêtes normales, soit environ 3 µs par événement.

## Démarrage rapide

### Essayez avec une seule commande (journaux d'attaque simulés inclus)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Ouvrez <http://localhost:8080> et connectez-vous en tant qu'`admin` avec le mot de passe `Netsa@demo2026`. Le simulateur génère des journaux d'attaque en continu et le tableau de bord se met à jour en temps réel.

### Déploiement en production

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Rendez-vous sur `http://<IP-du-serveur>:8080`. Le mot de passe initial se trouve dans les journaux : `docker compose logs netsa | grep 初始密码` (`初始密码` est le texte exact du journal et signifie « mot de passe initial »). Il doit être changé à la première connexion.
- Par défaut, les répertoires `/var/log/nginx` et `/var/log` de l'hôte sont lus ; envoyez le syslog des équipements réseau vers `<IP-du-serveur>:5514` (UDP / TCP).
- Pour figer une version, changer les ports ou activer l'archivage des alertes, exécutez d'abord `cp .env.example .env`, puis modifiez-le selon les commentaires.
- Windows PowerShell 5.1 ne prend pas en charge `&&` ni `grep` : exécutez les commandes une par une et utilisez `Select-String` à la place de `grep`.

Consultez le [guide de déploiement](../deployment.md) pour les mises à jour et retours arrière, le déploiement hors ligne et les questions fréquentes.

### Analyser des journaux existants sans déployer

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # ouvre le tableau de bord après l'analyse
```

## Aperçu

| Évaluation de sécurité et actions recommandées | Analyse de la surface d'attaque |
|---|---|
| ![Évaluation de sécurité](../images/assess.png) | ![Analyse de la surface d'attaque](../images/surface.png) |
| **Traitement des incidents et délais** | **Auto-apprentissage et réglage automatique** |
| ![Traitement des incidents](../images/incidents.png) | ![Auto-apprentissage](../images/learn.png) |

Les captures montrent l'interface web, en chinois, avec les données de démonstration du simulateur intégré. Toutes les IP et tous les sites sont simulés. Vous pouvez l'essayer avec l'environnement de démonstration ci-dessus.

## Fonctionnalités principales

| Module | Fonctionnalités |
|---|---|
| [Collecte des journaux](../log-sources.md) | Suivi des fichiers en temps réel (jokers, rotation logrotate), analyse par lots (y compris `.gz`), syslog en UDP / TCP / TLS (TLS mutuel possible), [collecte NetFlow / sFlow / IPFIX](../log-sources.md#流量日志zeeknetflow--sflow-与云抗-d-服务) ; identification des émetteurs, listes d'autorisation, limitation de débit et alertes de silence d'une source |
| [Détection des attaques](../detection.md) | Règles de signatures pour l'injection SQL, le XSS, l'exécution de commandes, Log4Shell, SSRF, XXE, la désérialisation, les WebShells, les exploits connus et plus encore, certaines règles de commandes, de code et de classes Java étant adaptées de l'OWASP CRS ; l'[analyse syntaxique libinjection](../detection.md#语法分析libinjection) revérifie les injections et repère les variantes que les regex manquent ; [signatures de points d'accès vulnérables des OA et middlewares chinois](../detection.md#国产-oa中间件漏洞接口签名) (261 signatures, 42 produits) ; détection comportementale du CC, de la force brute, du credential stuffing, de l'énumération de points d'accès, du scan de ports, du comportement des WebShells, de l'exfiltration de données, du mouvement latéral et du DDoS volumétrique ; les charges POST sont aussi analysées quand le corps de la requête est journalisé ; le décodage en plusieurs passes déjoue les contournements courants |
| [Vérification des résultats](../detection.md#研判复核用证据排除表面成功) | Utilise les réponses et les preuves de session pour distinguer les attaques bloquées, échouées, non bloquées et probablement réussies ; écarte les réussites apparentes comme les pages de repli des applications monopages, les pages d'erreur uniformes et le trafic « autorisé » qui n'a jamais atteint de service |
| [Détection sur les hôtes et le DNS](../log-sources.md#主机认证日志与-dns-日志) | Force brute SSH / RDP / VPN et accès obtenus, password spraying, effacement des journaux, nouveaux comptes et élévation de privilèges, [usurpation de compte](../detection.md#账号盗用) (voyages impossibles, connexions depuis un nouveau pays, connexions simultanées depuis plusieurs lieux) ; [détection des processus des hôtes](../detection.md#主机进程检测) (processus du serveur web qui exécutent des commandes, reverse shells, vol d'identifiants, persistance) ; rappels hors bande DNSLog, tunnels DNS, DGA, domaines de pools de minage et domaines C2, malveillants et d'hameçonnage signalés par le renseignement |
| [Traçage de la source des attaques](../traceability.md) | Combine ip2region, MaxMind, ip-api, rDNS et RDAP / WHOIS, avec des emplacements personnalisés pour les sous-réseaux internes ; la corrélation de même origine s'appuie sur les sous-réseaux, les empreintes d'outils et les techniques d'attaque pour retrouver les membres probables d'un même groupe |
| [Chaîne d'attaque de l'actif](../detection.md#资产攻击链路) | Centrée sur un site ou un hôte, elle relie reconnaissance, exploitation, intrusion, implantation, contrôle, mouvement latéral, collecte et impact, avec la preuve, la source et la technique ATT&CK de chaque étape ; les sites et les serveurs qui les hébergent sont fusionnés automatiquement, avec un verdict de compromission et des actions recommandées |
| [Tableau de bord de situation](../deployment.md#演示环境) | Cartes des attaques du monde et de la Chine avec zoom jusqu'aux provinces et aux villes ; lignes d'attaque et alertes en temps réel ; les KPI, tendances et graphiques de répartition permettent de remonter aux sources d'attaque ou aux alertes |
| [Analyse de la surface d'attaque](../log-sources.md#未做-dnat-映射的端口探测) | Recense les services exposés et détecte les fuites de code source, de clés et de sauvegardes ainsi que les interfaces d'administration exposées ; combine les correspondances DNAT et les preuves de session du pare-feu pour filtrer le scan de fond qui ne peut atteindre aucun service |
| [Évaluation de sécurité et analyse de compromission](../detection.md#安全评估与失陷研判) | Note sept dimensions avec une note globale de A à E et des recommandations de P0 à P3 ; détecte les hôtes internes qui se connectent à des adresses signalées par le renseignement, les balises C2, les empreintes TLS malveillantes et les charges utiles déposées sur les hôtes ; la [corrélation des journaux du pare-feu et du web](../detection.md#防火墙与-web-日志联动被攻击后回连) retrouve les hôtes qui se sont reconnectés à leur attaquant ; matrice MITRE ATT&CK |
| [Auto-apprentissage et tri par IA](../self-learning.md) | Calibrage automatique de la précision par règle, par cible et par flux de renseignement, escalade au retour d'une source confirmée, fenêtres d'apprentissage, politiques réglables dans l'interface ; apprend des journaux les sous-réseaux internes, les sources d'attaque, les campagnes ainsi que les [valeurs normales des paramètres et les produits de chaque site](../self-learning.md#参数的正常取值与站点产品) ; le tri par IA prend en charge les API OpenAI / Anthropic et vLLM, s'adapte automatiquement aux différences entre modèles, joint des cas similaires de votre organisation et mesure à quelle fréquence le modèle s'accorde avec les analystes |
| [Traitement des incidents et notifications](../operations.md#事件处置与误报抑制) | Les alertes sont agrégées automatiquement en incidents, avec affectation, délais de traitement et rappels de dépassement ; suppression des faux positifs ; [déclaration des scans autorisés](../detection.md#授权扫描登记) (enregistrement sans alerte pendant un test, rétabli automatiquement à la fin) ; [notifications DingTalk / WeCom / Feishu](../operations.md#告警推送钉钉--企业微信--飞书) avec déduplication, regroupement et limitation de débit ; export de listes de blocage pour nginx, iptables, ipset et autres |
| [Conservation, conformité et audit](../operations.md#原始日志留存与检索) | Journaux bruts compressés et conservés par heure, avec une chaîne de hachage contre la falsification ; [archivage à long terme dans PostgreSQL](../operations.md#告警归档可选postgresql) (facultatif) ; rapports hebdomadaires et mensuels, auto-évaluation MLPS 2.0 ; [trois rôles, authentification à deux facteurs et chaîne d'audit inviolable](../operations.md#登录账号与审计) ; métriques Prometheus |

## Fonctionnement

```text
Sources de journaux    nginx · pare-feu / IDS · Zeek · authentification et processus des hôtes · connexions aux applications · DNS · conteneurs et collecteurs
   │                   suivi de fichiers / analyse par lots / syslog (UDP · TCP · TLS) / collecte de flux (NetFlow · IPFIX · sFlow)
   ▼
Détection du format    format et fuseau horaire détectés séparément pour chaque source et chaque émetteur
   ▼
IP réelle              retrouve la source via les proxies de confiance, signale l'usurpation de XFF et le contournement du CDN
   ▼
Détection des menaces  règles de signatures (préfiltre AC + regex) + analyse syntaxique (libinjection) + règles sur les processus des hôtes + détection comportementale (fenêtres temporelles, mémoire bornée)
   ▼
Renseignement et leurres  renseignement IP / domaine / empreinte TLS / empreinte de fichier ; un accès aux chemins, jetons, comptes leurres et honeypots confirme l'attaquant
   ▼
Filtre de preuves      les preuves de session et les correspondances DNAT écartent les sondes qui n'ont atteint aucun service ; la suppression est appliquée
   ▼
Réglage appris         les valeurs normales des paramètres et les produits des sites revérifient les détections ; les faux positifs répétés sont rétrogradés selon les verdicts des analystes, les sources confirmées escaladées (learn)
   ▼
Corrélation            relie les attaques web antérieures : rappels et téléchargements de charges utiles après une attaque ; connexions latérales ultérieures des hôtes compromis
   ▼
Décision de gravité    le plancher par catégorie, l'escalade en cas de réussite et le plafond selon le résultat fixent la gravité finale (risk)
   ▼
Stockage d'état        profils d'attaquants · alertes · incidents · campagnes · chaînes d'attaque des actifs · surface d'attaque · séries temporelles · persistance par instantanés
   │
   ├── Tableau de bord web et API REST (diffusion en direct par SSE)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Conservation des journaux bruts · archivage PostgreSQL (facultatif)
   └── Tri par IA (facultatif, les conclusions sont inscrites dans le dossier de l'incident)
```

Points clés de la conception :

- **La gravité est décidée en un seul endroit** : la gravité déclarée par une règle n'est qu'une suggestion, ce qui empêche chaque étape d'ajouter et de retrancher de son côté et d'attribuer des gravités différentes à des événements similaires. Voir les [décisions de gravité](../detection.md#威胁等级判定).
- **Les preuves avant les apparences** : un « autorisé » du pare-feu, une réponse 200 ou une connexion réussie après des échecs répétés sont tous revérifiés à l'aide des sessions, des références de réponse et des indices liés aux comptes.
- **L'apprentissage a des limites** : le calibrage des règles n'apprend que des verdicts humains. Les ajustements automatiques ne bougent que d'un niveau à la fois et une exploitation réussie reste critique. Les valeurs normales des paramètres et les produits des sites appris du trafic ne rétrogradent une détection que lorsque deux conditions indépendantes sont réunies (le paramètre est habituellement du texte ordinaire et l'analyse syntaxique ne trouve pas d'injection ; le site n'utilise pas le produit et la requête n'a pas abouti), et seulement jusqu'à une gravité faible, sans jamais masquer l'alerte. La suppression des faux positifs, qui masque des alertes, doit être adoptée par une personne. Les conclusions de l'IA ne servent pas d'échantillons d'apprentissage et ne déclenchent jamais de traitement automatique.
- **Reste maîtrisé sous la charge** : l'analyse et la détection s'exécutent en parallèle et sont stockées par lots, le nombre de profils et les fenêtres de détection ont des limites strictes, et une seule ligne de journal malformée n'affecte pas le service. Les files d'attente en retard et les rejets disposent de métriques de surveillance.

## Journaux pris en charge

| Type | Formats |
|---|---|
| **Web** | nginx / Tengine / OpenResty / Apache (combined, main, vhost), tout `log_format` personnalisé, nginx JSON, APISIX, Kong, Nginx Proxy Manager, Caddy, Traefik, Elastic ECS, IIS W3C |
| **WAF** | Blocages et limitations de débit ModSecurity et naxsi dans les journaux d'erreurs nginx / Tengine / OpenResty, journaux d'audit JSON de ModSecurity, OpenResty Lua WAF |
| **Pare-feu** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Pare-feu Windows, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone, ainsi que les journaux de défense contre les attaques de Huawei, H3C et Sangfor |
| **IDS / IPS** | Suricata EVE JSON, alertes fast de Snort, journaux de menaces d'équipements comme FortiGate IPS / UTM |
| **Authentification des hôtes et VPN** | `auth.log` / `secure` de Linux, événements de sécurité Windows (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, connexions SQL Server |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Flux réseau** | Zeek (conn / http / ssl / files, TSV ou JSON), NetFlow v5 / v9, IPFIX, sFlow v5 (collecte UDP), événements d'attaque des services anti-DDoS cloud |
| **Processus des hôtes (EDR / HIDS)** | Sysmon (Winlogbeat / NXLog / Elastic Agent), Windows 4688, Elastic Defend (ECS), auditd sous Linux, alertes Wazuh |
| **Connexions aux applications et honeypots** | Journaux de connexion JSON des applications métier et des plateformes d'identité / SSO, journaux du honeypot OpenCanary |
| **Conteneurs et collecteurs** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O, désencapsulés automatiquement pour reconnaître le journal d'origine |

Voir l'[intégration des journaux](../log-sources.md) pour la configuration. Après avoir connecté une source, consultez les résultats de reconnaissance et les exemples d'échecs d'analyse sur la page des sources de données du tableau de bord.

## Documentation

Les documents détaillés ci-dessous sont rédigés en chinois simplifié.

| Document | Contenu |
|---|---|
| [Guide de déploiement](../deployment.md) | Déploiement en production, variables `.env`, mise à jour et retour arrière, réseaux hors ligne, environnement de démonstration, exécution depuis les sources |
| [Intégration des journaux](../log-sources.md) | Intégration des journaux web, de pare-feu, d'authentification, DNS, de flux réseau (Zeek, NetFlow / sFlow, anti-DDoS cloud), de processus des hôtes et de connexion aux applications, gestion des émetteurs syslog, fuseaux horaires, DNAT et preuves de session |
| [Détection et vérification](../detection.md) | Décisions de gravité, vérification des résultats, campagnes et chaînes d'attaque des actifs, vol de données et mouvement latéral, leurres, détection des processus des hôtes, usurpation de compte, score de menace, évaluation de sécurité et analyse de compromission |
| [Traçage de la source des attaques](../traceability.md) | Géolocalisation multi-sources, sous-réseaux internes, rechargement à chaud des bases de géolocalisation, corrélation de même origine |
| [Auto-apprentissage et tri par IA](../self-learning.md) | Ce qui s'applique automatiquement et ses limites, références de comportement, auto-contrôle de conformité, configuration des modèles externes et adaptation aux modèles |
| [Opérations de sécurité](../operations.md) | Traitement des incidents, notifications, journaux bruts, actifs et vulnérabilités, rapports et conformité, comptes et audit, métriques de surveillance, archivage des alertes |
| [Référence de configuration](../configuration.md) | Paramètres courants et remarques d'exploitation |
| [API](../api.md) | Vue d'ensemble de l'API REST |
| [Intégrations externes](../integrations.md) | Authentification unique LDAP / OIDC, transfert vers un SIEM, blocage automatisé, tickets et playbooks, renseignement STIX / TAXII / MISP et texte (IP, domaines, empreintes TLS, empreintes de fichiers, avec catégories), Sigma et paquets de règles signés |
| [Développement et publication](../development.md) | Tests locaux, structure du code, construction et publication des images |
| [Évaluation des capacités et feuille de route](../roadmap.md) | Capacités de détection, de localisation et de traçage évaluées le long de la chaîne d'attaque, avec les lacunes et un plan par étapes |
| [Journal des modifications](../CHANGELOG.md) | Changements qui affectent l'utilisation |

## Développement

Nécessite Go 1.25 ou plus récent (les versions publiées sont compilées avec Go 1.27). Go pur, sans CGO.

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # ne doit rien afficher
go vet ./...
go test ./...
```

Les tests de concurrence nécessitent un compilateur C. Sans gcc sur votre machine, exécutez-les dans un conteneur :

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

Voir [développement et publication](../development.md) pour la structure du code et le processus de publication.

## Contribuer

Les issues et pull requests sont les bienvenues, en particulier :

- des exemples de nouveaux formats de journaux (anonymisez-les d'abord) et des signalements d'échecs de reconnaissance ou d'analyse ;
- de nouvelles règles de détection et des signalements de faux positifs ou de faux négatifs avec exemples ;
- des améliorations de la documentation et des retours d'expérience de déploiement réels.

Merci de passer les vérifications ci-dessus avant de soumettre du code. La CI exécute aussi les tests de concurrence et `govulncheck`.

Si netsa vous est utile, mettez-lui une **Star** pour que davantage de personnes qui en ont besoin puissent le trouver.

## Licence

Ce projet est publié sous [Apache License 2.0](../../LICENSE) : vous pouvez l'utiliser à des fins commerciales, le modifier et le redistribuer, à condition de conserver la mention de copyright, le texte de la licence et le fichier [NOTICE](../../NOTICE).

- Le logiciel est fourni « en l'état », sans garantie d'aucune sorte, expresse ou implicite ;
- La licence n'accorde aucun droit sur les marques ; le nom et le logo `netsa` ne sont pas couverts ;
- Les dépendances tierces suivent leurs propres licences, listées intégralement dans `go.mod` et `go.sum`. Certaines règles de détection sont adaptées de l'[OWASP Core Rule Set](https://coreruleset.org) (Apache-2.0), et les signatures de points d'accès vulnérables des OA et middlewares chinois sont extraites de [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT) ; voir [NOTICE](../../NOTICE).

Les services commerciaux, comme les abonnements aux règles et au renseignement, le déploiement et la livraison ou l'accompagnement des évaluations MLPS, sont proposés séparément par les mainteneurs et n'affectent pas vos droits d'utilisation de l'édition open source sous Apache-2.0.

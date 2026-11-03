<div align="center">

# netsa

**Plateforme open source de connaissance de la situation de sécurité réseau et d'analyse de la surface d'attaque**

Transforme les journaux nginx, pare-feu / IDS, d'authentification d'hôtes et DNS en une vision de la sécurité traçable, exploitable et qui continue d'apprendre.<br>
Un seul binaire prêt à l'emploi, y compris sur des réseaux internes hors ligne.

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[简体中文](../../README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · **Français** · [Deutsch](README.de.md) · [Русский](README.ru.md)

[Démarrage rapide](#démarrage-rapide) · [Aperçu](#aperçu) · [Fonctionnalités principales](#fonctionnalités-principales) · [Fonctionnement](#fonctionnement) · [Journaux pris en charge](#journaux-pris-en-charge) · [Documentation](#documentation)

</div>

![Vue d'ensemble : carte des attaques, alertes en temps réel et indice de menace](../images/overview.png)

## Pourquoi netsa

- **Aucune dépendance, déploiement en une étape** : un seul binaire Go avec l'interface web, les cartes du monde et des provinces et villes de Chine, et les bases de géolocalisation hors ligne intégrées. Ni Elasticsearch, ni Kafka, ni base de données. Des images Docker sont fournies pour amd64 et arm64 et, une fois le traçage en ligne désactivé, il fonctionne entièrement hors ligne sur des réseaux isolés.
- **Aucune adaptation préalable des journaux** : reconnaît automatiquement plus de 40 formats, dont nginx / Apache / IIS / Caddy, iptables, Huawei, H3C, FortiGate, Palo Alto, Suricata, l'authentification Linux et Windows, les principaux serveurs DNS et les formats encapsulés par des collecteurs comme Docker et Filebeat.
- **Détection précise, alertes fiables** : 79 règles de signatures (certaines adaptées de l'OWASP CRS), une analyse syntaxique libinjection et une détection comportementale, avec les réponses, les preuves de session et les vulnérabilités des actifs pour revérifier les « succès apparents ». La gravité est décidée de façon centralisée : une attaque bloquée n'est jamais marquée « critique » et une exploitation réussie n'est pas manquée.
- **Traçage jusqu'à la ville, corrélation jusqu'au groupe** : retrouve l'IP réelle derrière les CDN et les proxys, et détecte l'usurpation de XFF et les connexions directes qui contournent le CDN. Plusieurs sources de géolocalisation sont recoupées avec un niveau de confiance. La corrélation de même origine trouve d'autres IP susceptibles d'appartenir au même attaquant.
- **Plus précis à l'usage** : apprend des conclusions des analystes. Les règles et les points de terminaison aux faux positifs répétés sont automatiquement rétrogradés, et les attaquants confirmés sont automatiquement relevés lorsqu'ils reviennent. Le triage par IA prend en charge les API OpenAI et Anthropic, ce qui permet de connecter aussi bien un vLLM interne que des modèles cloud. Il s'adapte automatiquement aux différences entre modèles et utilise les conclusions des analystes pour évaluer leur fiabilité.
- **Un cycle complet d'opérations de sécurité** : agrégation des incidents avec délais de traitement, suppression des faux positifs, notifications DingTalk / WeCom / Feishu, corrélation des actifs et des vulnérabilités, conservation des journaux bruts et investigation, rapports hebdomadaires et mensuels, auto-évaluation MLPS 2.0 (schéma chinois de protection à plusieurs niveaux) et chaîne d'audit inviolable.
- **Rapide sur une seule machine** : environ 460 000 événements par seconde de bout en bout sur une machine de développement (i7-10700, 16 threads). Grâce au préfiltrage Aho-Corasick, les requêtes normales n'exécutent presque jamais d'expression régulière, soit environ 3 µs par événement.

## Démarrage rapide

### Essayez avec une seule commande (journaux d'attaque simulés inclus)

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

Ouvrez <http://localhost:8080> et connectez-vous avec le compte `admin` et le mot de passe `Netsa@demo2026`. Le simulateur génère des journaux d'attaque en continu et le tableau de bord se met à jour en temps réel.

### Déploiement en production

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- Rendez-vous sur `http://<IP-du-serveur>:8080`. Le mot de passe initial se trouve dans les journaux : `docker compose logs netsa | grep 初始密码` (`初始密码` est le texte exact du journal et signifie « mot de passe initial »). Vous devez le changer à la première connexion.
- Par défaut, il lit `/var/log/nginx` et `/var/log` sur l'hôte. Envoyez le syslog des équipements réseau vers `<IP-du-serveur>:5514` (UDP / TCP).
- Pour figer une version, changer les ports ou activer l'archivage des alertes, exécutez d'abord `cp .env.example .env`, puis modifiez le fichier en suivant les commentaires.
- Windows PowerShell 5.1 ne prend pas en charge `&&` ni `grep` : exécutez les commandes ligne par ligne et utilisez `Select-String` à la place de `grep`.

Pour les mises à niveau et les retours arrière, le déploiement hors ligne et les problèmes courants, consultez le [guide de déploiement](../deployment.md).

### Analyser des journaux existants sans déployer

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # ouvre le tableau de bord après l'analyse
```

## Aperçu

| Évaluation de la sécurité et recommandations | Analyse de la surface d'attaque |
|---|---|
| ![Évaluation de la sécurité](../images/assess.png) | ![Analyse de la surface d'attaque](../images/surface.png) |
| **Traitement des incidents et délais** | **Auto-apprentissage et calibration automatique** |
| ![Traitement des incidents](../images/incidents.png) | ![Auto-apprentissage](../images/learn.png) |

Les captures montrent l'interface web, qui est en chinois, avec des données de démonstration du simulateur intégré. Toutes les IP et tous les sites sont simulés. Vous pouvez l'essayer avec l'environnement de démonstration ci-dessus.

## Fonctionnalités principales

| Module | Fonctionnalités |
|---|---|
| [Collecte des journaux](../log-sources.md) | Suivi de fichiers en temps réel (caractères génériques, rotation logrotate), analyse par lots (y compris `.gz`), syslog UDP / TCP / TLS (authentification mutuelle possible) ; identification des émetteurs, liste d'autorisation, limitation de débit et alertes de source muette |
| [Détection des attaques](../detection.md) | Règles de signatures pour l'injection SQL, XSS, l'exécution de commandes, Log4Shell, SSRF, XXE, la désérialisation, WebShell, l'exploitation de vulnérabilités connues, etc. ; détection comportementale des attaques CC, de la force brute, du bourrage d'identifiants, de l'énumération d'API, du scan de ports, etc. ; décodage en plusieurs passes contre les contournements courants |
| [Vérification des résultats](../detection.md#研判复核用证据排除表面成功) | Utilise les réponses et les preuves de session pour distinguer bloqué, échoué, non bloqué et succès suspecté ; écarte les apparences comme les pages de repli des applications monopages, les pages d'erreur unifiées et le trafic « autorisé » qui n'a jamais atteint de service |
| [Détection hôtes et DNS](../log-sources.md#主机认证日志与-dns-日志) | Force brute SSH / RDP / VPN et compromissions réussies, pulvérisation de mots de passe, effacement de journaux, création de comptes et élévation de privilèges ; rappels hors bande DNSLog, tunnels DNS, DGA, domaines de minage |
| [Traçage de l'origine des attaques](../traceability.md) | Combine ip2region, MaxMind, ip-api, rDNS et RDAP / WHOIS, avec localisation de sous-réseaux internes personnalisés ; la corrélation de même origine par sous-réseau, empreinte d'outil et technique d'attaque trouve les membres probables d'un même groupe |
| [Tableau de bord de situation](../deployment.md#演示环境) | Cartes des attaques du monde et de la Chine avec exploration jusqu'à la province et la ville ; lignes d'attaque et alertes en temps réel ; les KPI, tendances et graphiques de répartition permettent d'explorer jusqu'aux sources d'attaque ou aux alertes |
| [Analyse de la surface d'attaque](../log-sources.md#未做-dnat-映射的端口探测) | Recense les services exposés et détecte les fuites de code source, de clés et de sauvegardes, ainsi que les interfaces d'administration exposées ; utilise les mappages DNAT et les preuves de session du pare-feu pour filtrer les scans de fond qui n'atteignent aucun service |
| [Évaluation de la sécurité et analyse de compromission](../detection.md#安全评估与失陷研判) | Note sept dimensions avec une évaluation globale de A à E et des recommandations P0–P3 ; hôtes internes contactant des adresses de renseignement sur les menaces, détection de balises C2 ; matrice MITRE ATT&CK |
| [Auto-apprentissage et triage par IA](../self-learning.md) | Calibration automatique par règle et par cible, relèvement des attaquants confirmés qui reviennent, fenêtre d'apprentissage, politique réglable dans l'interface web ; le triage par IA prend en charge les API OpenAI / Anthropic et vLLM, s'adapte automatiquement aux différences entre modèles, joint des cas similaires de votre organisation et mesure la concordance du modèle avec les analystes |
| [Traitement des incidents et notifications](../operations.md#事件处置与误报抑制) | Les alertes sont agrégées automatiquement en incidents, avec affectation, délais de traitement et rappels de dépassement ; suppression des faux positifs ; [notifications DingTalk / WeCom / Feishu](../operations.md#告警推送钉钉--企业微信--飞书) avec déduplication, fusion et limitation de débit ; export de listes de blocage pour nginx, iptables, ipset, etc. |
| [Conservation, conformité et audit](../operations.md#原始日志留存与检索) | Journaux bruts conservés par segments horaires compressés avec chaîne de hachage inviolable ; [archivage PostgreSQL à long terme](../operations.md#告警归档可选postgresql) (facultatif) ; rapports hebdomadaires et mensuels, auto-évaluation MLPS 2.0 ; [trois rôles, authentification à deux facteurs et chaîne d'audit inviolable](../operations.md#登录账号与审计) ; métriques Prometheus |

## Fonctionnement

```text
Sources de journaux   nginx · pare-feu / IDS · authentification d'hôtes · DNS · conteneurs et collecteurs
   │                  suivi de fichiers / analyse par lots / syslog (UDP · TCP · TLS)
   ▼
Détection du format   format et fuseau horaire détectés séparément pour chaque source et chaque émetteur
   ▼
IP réelle             retrouve l'origine via les proxys de confiance, signale l'usurpation de XFF et le contournement du CDN
   ▼
Détection des menaces règles de signatures (préfiltre AC + regex) + comportement (fenêtres de temps, mémoire bornée)
   ▼
Filtre de preuves     preuves de session et mappages DNAT écartent les sondes sans service atteint ; suppression appliquée
   ▼
Ajustement appris     rétrograde les faux positifs répétés selon les analystes, relève les origines confirmées (learn)
   ▼
Décision de gravité   plancher par catégorie, relèvement en cas de succès et plafond par résultat fixent la gravité (risk)
   ▼
Magasin d'état        profils d'attaquants · alertes · incidents · surface d'attaque · séries temporelles · instantanés
   │
   ├── Tableau de bord web et API REST (diffusion SSE en temps réel)
   ├── DingTalk / WeCom / Feishu / Webhook
   ├── Conservation des journaux bruts · archive PostgreSQL (facultatif)
   └── Triage par IA (facultatif, conclusions écrites dans le dossier de l'incident)
```

Principaux choix de conception :

- **La gravité est décidée à un seul endroit** : la gravité déclarée par une règle n'est qu'une suggestion, ce qui évite que chaque étape ajoute et retire des niveaux de son côté et que des événements similaires aient des gravités différentes. Voir les [décisions de gravité](../detection.md#威胁等级判定).
- **Les preuves avant les apparences** : un « autoriser » du pare-feu, une réponse 200 ou une connexion réussie après plusieurs échecs sont revérifiés à l'aide des sessions, des références de réponse et des indices liés au compte.
- **L'apprentissage a des limites** : il n'apprend que des conclusions humaines. Les ajustements automatiques changent d'un niveau au plus à la fois, et une exploitation réussie reste critique. La suppression des faux positifs, qui masque des alertes, doit être adoptée par une personne. Les conclusions de l'IA ne servent pas d'échantillons d'apprentissage et ne déclenchent aucun traitement automatique.
- **Sous contrôle même sous charge** : l'analyse et la détection s'exécutent en parallèle et sont stockées par lots, le nombre de profils et les fenêtres de détection ont des limites strictes, et une seule ligne de journal malformée n'affecte pas le service. Les files d'attente en retard et les pertes disposent de métriques de supervision.

## Journaux pris en charge

| Type | Formats |
|---|---|
| **Web** | nginx / Apache (combined, main, vhost), tout `log_format` personnalisé, nginx JSON, Caddy, Traefik, Elastic ECS, IIS W3C |
| **Pare-feu** | iptables, UFW, firewalld, nftables, pfSense / OPNsense, Pare-feu Windows, Cisco ASA / FTD, Palo Alto, FortiGate, Huawei USG, H3C, Sangfor, Hillstone |
| **IDS / IPS** | Suricata EVE JSON, Snort fast alert, journaux de menaces d'équipements comme FortiGate IPS / UTM |
| **Authentification d'hôtes et VPN** | Linux `auth.log` / `secure`, événements de sécurité Windows (NXLog, Winlogbeat, Snare), FortiGate / Cisco / OpenVPN, connexions SQL Server |
| **DNS** | BIND, dnsmasq, CoreDNS, Windows DNS, Zeek, Suricata DNS |
| **Conteneurs et collecteurs** | Docker json-file, Fluent Bit / Fluentd, Filebeat / Logstash / Vector, containerd / CRI-O ; désencapsulés automatiquement pour reconnaître le journal d'origine |

Consultez la [connexion des journaux](../log-sources.md) pour la mise en place. Après avoir connecté une source, vérifiez les résultats de reconnaissance et les exemples d'échecs d'analyse sur la page des sources de données du tableau de bord.

## Documentation

Les documents détaillés ci-dessous sont rédigés en chinois simplifié.

| Document | Contenu |
|---|---|
| [Guide de déploiement](../deployment.md) | Déploiement en production, variables `.env`, mises à niveau et retours arrière, réseaux hors ligne, environnement de démonstration, exécution depuis les sources |
| [Connexion des journaux](../log-sources.md) | Connexion web, pare-feu, authentification et DNS, gestion des émetteurs syslog, fuseaux horaires, DNAT et preuves de session |
| [Détection et vérification](../detection.md) | Décisions de gravité, vérification des résultats, score de menace, évaluation de la sécurité et analyse de compromission |
| [Traçage de l'origine des attaques](../traceability.md) | Géolocalisation multisource, sous-réseaux internes, rechargement à chaud des bases de géolocalisation, corrélation de même origine |
| [Auto-apprentissage et triage par IA](../self-learning.md) | Ce qui s'applique automatiquement et ses limites, références de comportement, auto-contrôles de conformité, configuration et adaptation des modèles externes |
| [Opérations de sécurité](../operations.md) | Traitement des incidents, notifications, journaux bruts, actifs et vulnérabilités, rapports et conformité, comptes et audit, métriques, archivage des alertes |
| [Référence de configuration](../configuration.md) | Paramètres courants et remarques d'exploitation |
| [API](../api.md) | Présentation de l'API REST |
| [Intégrations externes](../integrations.md) | Authentification unique LDAP / OIDC, transfert vers SIEM, blocage sur pare-feu, tickets et playbooks, renseignement STIX / TAXII / MISP, Sigma et packs de règles signés |
| [Développement et publication](../development.md) | Tests locaux, structure du code, construction et publication des images |

## Développement

Nécessite Go 1.25 ou ultérieur (les versions publiées sont construites avec Go 1.27). Go pur, sans CGO.

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

Consultez [développement et publication](../development.md) pour la structure du code et le processus de publication.

## Contribuer

Les Issues et les Pull Requests sont les bienvenues, en particulier :

- des exemples de nouveaux formats de journaux (anonymisez-les d'abord), et des signalements d'échecs de reconnaissance ou d'analyse ;
- de nouvelles règles de détection, et des signalements de faux positifs ou de faux négatifs avec exemples ;
- des améliorations de la documentation et des retours d'expérience de déploiement.

Avant de soumettre du code, passez les vérifications ci-dessus. La CI exécute aussi les tests de concurrence et `govulncheck`.

Si netsa vous est utile, mettez-lui une **Star** pour que davantage de personnes qui en ont besoin puissent le trouver.

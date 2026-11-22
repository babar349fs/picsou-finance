# Audit de sécurité — Picsou

| | |
|---|---|
| Dépôt audité | `babar349fs/picsou-finance` (fork). Aucune modification n'a été proposée sur le dépôt amont `Cloeille/picsou-finance`. |
| Commit | `93ea2b9e` (`main`, « ci(docker): publish ghcr.io/cloeille/picsou-finance/demo ») |
| Date | 22 novembre 2026 |
| Périmètre | Code applicatif (Java 21 / Spring Boot, React, sidecars Python), configuration Docker / Helm / CI, historique git, dépendances résolues. |
| Méthode | Lecture statique. Aucun exploit n'a été exécuté, aucune instance n'a été démarrée. Les numéros de ligne cités sont ceux de ce commit. |
| Sévérité | Critique, Élevée, Moyenne, Faible, Info. Aucun constat Critique n'a été vérifié. |

Ce document est un rapport de lecture. Il ne modifie pas le comportement de l'application.

## Synthèse

Picsou est une application d'auto-hébergement qui manipule des identifiants bancaires, des soldes et des transactions. Le socle d'authentification est nettement au-dessus d'un projet personnel moyen : cookies JWT `HttpOnly`, version de jeton (`tv`) contrôlée en base, mots de passe bcrypt coût 12, MFA TOTP, révocation des sessions « Remember Me », CSRF sans jeton mais basé sur `Sec-Fetch-Site` / `Origin`, CORS fermé par défaut, chiffrement AES-GCM des secrets de connecteurs, et un filtrage `member_id` largement systématique.

Les écarts qui comptent vraiment sont des défauts de **déploiement par défaut** et quelques **actions sensibles insuffisamment liées à la session ou au second facteur** :

1. Au premier démarrage, l'assistant est anonyme et Docker publie le port 8080 sur toutes les interfaces. La première personne qui joint l'instance en devient l'administrateur, ou peut la verrouiller.
2. Le mot de passe PostgreSQL par défaut est `picsou`. Le port 5432 n'est pas publié sur l'hôte par Compose, mais tout conteneur du réseau Docker par défaut peut s'y connecter avec ce mot de passe.
3. Le chemin Docker documenté est du HTTP clair. L'assistant désactive alors le drapeau `Secure` des cookies de session. Un observateur sur le réseau local voit la session et les données financières.
4. Plusieurs bibliothèques du classpath (Tomcat 10.1.55, pilote JDBC 42.7.11, Jackson 2.21.4, Netty 4.1.135) sont en dessous de versions corrigées annoncées par OSV. L'exploitabilité dans *cette* configuration n'a pas été rejouée.
5. Le changement de mot de passe et le reset d'un membre ne reprennent pas toutes les précautions déjà présentes sur l'export de données (re-authentification, révocation immédiate).

Aucun secret de production (clé privée réelle, jeton d'API, fichier `.env` vivant) n'a été trouvé dans l'arbre ni dans l'historique des 1 264 commits. Les recherches SQL, commandes, XSS et désérialisation Java n'ont pas produit de faille exploitable confirmée. `pip-audit` sur les sidecars Python n'a rien remonté.

## Tableau des constats

Tri du plus grave au plus faible. Les identifiants sont stables pour la discussion.

| ID | Sévérité | Sujet |
|----|----------|--------|
| SEC-01 | Élevée | Assistant de premier démarrage anonyme, publié sur `0.0.0.0:8080` |
| SEC-02 | Élevée | Mot de passe PostgreSQL par défaut `picsou` |
| SEC-03 | Élevée | HTTP clair par défaut et cookies de session sans `Secure` |
| SEC-04 | Moyenne | Bibliothèques Java en dessous d'un correctif OSV (Tomcat, JDBC, Jackson, Netty) |
| SEC-05 | Moyenne | Changement de mot de passe sans second facteur |
| SEC-06 | Moyenne | Reset d'un membre : les sessions restent valides jusqu'à l'activation du lien |
| SEC-07 | Moyenne | Fin de connexion bancaire : le `state` OAuth n'est pas lié à l'appelant |
| SEC-08 | Moyenne | Export CSV : formules de tableur non neutralisées |
| SEC-09 | Moyenne | URL de base du fournisseur d'IA : SSRF depuis le serveur |
| SEC-10 | Moyenne | Recovery admin : l'URL d'activation, jeton inclus, est écrite dans les logs |
| SEC-11 | Moyenne | SSO : un membre du groupe admin est provisionné administrateur sans invitation |
| SEC-12 | Moyenne | Clé de chiffrement colocalisée, AES-128 accepté, pas de rotation |
| SEC-13 | Moyenne | Helm : la NetworkPolicy n'isole pas l'application si `appIngressFrom` est vide |
| SEC-14 | Faible | Jeton de rafraîchissement de session réutilisable jusqu'à expiration |
| SEC-15 | Faible | Changement de nom d'utilisateur sans incrément de `tokenVersion` |
| SEC-16 | Faible | Oracle d'expiration sur le jeton d'activation |
| SEC-17 | Faible | SDK MCP Java 0.18.3 : avis de DNS rebinding |
| SEC-18 | Faible | CSP `style-src 'unsafe-inline'` et CSS injectée dans le graphique |
| SEC-19 | Faible | Serveur MCP activé par défaut |
| SEC-20 | Faible | Artefacts de debug Fortuneo et conteneur `chown` root |
| SEC-21 | Info | Historique git : pas de secret réel ; seulement des marqueurs |
| SEC-22 | Info | IBAN, transactions et soldes stockés en clair (choix documenté) |
| SEC-23 | Info | Enregistrement OAuth anonyme (`POST /oauth2/register`) |
| SEC-24 | Info | HSTS désactivé, actuator réduit, dépendances de dev npm |
| SEC-25 | Info | `pip-audit` : aucune vulnérabilité connue sur les sidecars |

## SEC-01 — Assistant de premier démarrage anonyme, publié partout

**Sévérité :** Élevée

**Description.** Tant que `setup.state` n'est pas `COMPLETE`, `SetupFilter` laisse passer `/api/setup/**` et Spring Security le marque `permitAll`. `POST /api/setup/admin` crée le compte administrateur avec le mot de passe choisi par l'appelant. `POST /api/setup/complete` passe l'instance à `COMPLETE` sans exiger qu'un administrateur existe. Compose publie `8080` sur toutes les interfaces IPv4 et IPv6. La limite est de 10 requêtes mutantes par minute et par adresse : une seule requête suffit.

**Preuve.**

- `backend/src/main/java/com/picsou/config/SecurityConfig.java` lignes 157-158 : `requestMatchers("/api/setup/**").permitAll()`.
- `backend/src/main/java/com/picsou/config/SetupFilter.java` lignes 34-42 et 54-56 : avant la fin du setup, `/api/setup/` est autorisé ; le reste de l'API répond 503.
- `backend/src/main/java/com/picsou/controller/SetupController.java` lignes 98-119 (`POST /admin`) et 277-284 (`POST /complete`). `complete` appelle `setupService.markComplete()` après le rate-limit et `requireNotComplete()`, sans contrôle « un admin existe ».
- `backend/src/main/java/com/picsou/service/SetupService.java` lignes 107-114 et 172-186 : l'isolation `SERIALIZABLE` empêche deux créations concurrentes, elle ne réserve pas la création au propriétaire de la machine.
- `docker/docker-compose.yml` lignes 11-26 : `"8080:8080"`, commentaire explicite sur le bind `0.0.0.0` et `[::]`.

**Scénario.** Une instance vient d'être démarrée sur un NAS ou un réseau local, l'assistant n'est pas encore terminé. Une autre machine du même réseau envoie `POST /api/setup/admin` et choisit le mot de passe administrateur. Elle se connecte ensuite et lit tout ce que l'instance synchronisera. Variante : `POST /api/setup/complete` avant toute création de compte. L'assistant répond ensuite 410, `SetupFilter` ouvre l'API, et aucun compte utilisable n'existe. Reprendre la main demande une intervention en base.

**Correctif.** Lier l'assistant au réseau local de confiance (`127.0.0.1:8080` par défaut, publication large opt-in) ou exiger un jeton de premier démarrage affiché une seule fois dans les logs du conteneur. Refuser `POST /complete` tant qu'aucun administrateur activé n'existe. Le rate-limit actuel ne couvre pas cette course.

## SEC-02 — Mot de passe PostgreSQL par défaut `picsou`

**Sévérité :** Élevée

**Description.** Si `POSTGRES_PASSWORD` est absent ou vide, l'application et le conteneur `db` utilisent le mot de passe `picsou`, utilisateur `picsou`, base `picsou`. Les fichiers d'exemple le présentent comme le comportement normal. Compose ne publie pas le port 5432 vers l'hôte : le risque n'est pas « Internet voit Postgres ». Le risque est tout conteneur joint au réseau Docker par défaut, y compris un sidecar de connecteur bancaire (profils optionnels) qui partage ce réseau. Le chart Helm, lui, génère un mot de passe aléatoire.

**Preuve.**

- `backend/src/main/resources/application.yml` ligne 8 : `password: ${SPRING_DATASOURCE_PASSWORD:${POSTGRES_PASSWORD:picsou}}`.
- `backend/src/main/java/com/picsou/config/SecretBootstrap.java` lignes 72-73 : `DEFAULT_DATASOURCE_PASSWORD = "picsou"`. Les lignes 53-59 expliquent que le mot de passe n'est jamais généré.
- `docker/docker-compose.yml` ligne 41 et lignes 406-410 : même repli pour l'application et pour `postgres:16-alpine`. Le service `db` n'a pas de clé `ports`.
- `.env.example` lignes 16-25 : « unset → picsou ».
- `charts/picsou/templates/secret.yaml` ligne 7 : `randAlphaNum 32` lorsque aucune valeur n'est fournie. Ce repli sûr ne s'applique pas à Compose.

**Scénario.** L'opérateur lance Compose sans définir `POSTGRES_PASSWORD`, ce que l'exemple autorise. Un sidecar compromis (automatisation navigateur qui charge du JavaScript bancaire) ouvre une connexion vers `db:5432` avec `picsou` / `picsou` et lit transactions, IBAN et secrets chiffrés. Sans la clé de chiffrement (SEC-12) il n'obtient pas les mots de passe bancaires en clair, mais il obtient l'historique financier.

**Correctif.** Refuser le démarrage Compose et bare-metal lorsque le mot de passe est vide ou égal à `picsou`, sur le même modèle que `CRYPTO_ENCRYPTION_KEY`. Générer le mot de passe au premier `up` et le conserver dans le volume de secrets, ou échouer avec un message qui demande `openssl rand -base64 24`.

## SEC-03 — HTTP clair et cookies de session sans drapeau Secure

**Sévérité :** Élevée

**Description.** Le déploiement Compose par défaut sert l'interface et l'API en HTTP sur le port 8080. Le profil TLS (Caddy) est opt-in. L'assistant pré-coche `secureCookies` à faux dès que la page est ouverte en `http:`. Les cookies `access_token`, `refresh_token`, `persistent_token` et `reauth_proof` partent alors sans `Secure`. Le trafic qui suit (soldes, transactions, identifiants saisis vers les sidecars) est en clair sur le chemin réseau.

**Preuve.**

- `docker/docker-compose.yml` lignes 11-26 (HTTP publié) et 73-76 (profil `tls` optionnel, ports 80/443).
- `frontend/src/pages/setup/SetupStepSecurity.tsx` lignes 14-19 et 27-33 : `secureCookies` vaut `location.protocol === 'https:'`.
- `backend/src/main/resources/application.yml` ligne 218 : défaut `SECURE_COOKIES` vrai, écrasé ensuite par le réglage d'assistant stocké en base.
- `docs/features/security-cors-cookies.md` lignes 90-98 et `docs/decisions/2026-04-26-totp-2fa-and-persistent-sessions.md` : le projet documente ce choix pour le LAN. Le documenter ne retire pas l'exposition du défaut.

**Scénario.** L'instance est jointe depuis un autre appareil du domicile ou d'un réseau d'entreprise, en HTTP, parce que c'est le chemin que Compose ouvre. Un équipement sur le même segment (ou un proxy transparent) observe le cookie de session et les réponses JSON. Le cookie est `HttpOnly`, ce qui bloque sa lecture par du JavaScript de page, pas sa capture sur le fil.

**Correctif.** Faire du profil TLS le chemin documenté par défaut pour tout accès non loopback. Tant que l'origine est `http` et que l'hôte n'est pas loopback, afficher un blocage dans l'assistant plutôt qu'un interrupteur `Secure` décoché. Réserver `SECURE_COOKIES=false` à un bind `127.0.0.1`.

## SEC-04 — Bibliothèques Java en dessous d'un correctif annoncé

**Sévérité :** Moyenne

**Description.** L'arbre Maven `compile` a été résolu (`mvn dependency:list`, Spring Boot 3.5.16) puis interrogé sur l'API OSV. Plusieurs versions du classpath sont antérieures au correctif publié. L'audit n'a pas rejoué les preuves de concept : une partie des avis Tomcat vise des fonctions que Picsou n'active pas (authentification DIGEST, authentification FORM, Rewrite Valve). Ils restent des montées de version à faire, pas des failles confirmées de bout en bout.

**Preuve (versions résolues, plages OSV relues).**

| Composant | Version résolue | Avis confirmé sur cette version | Correctif annoncé |
|-----------|-----------------|----------------------------------|-------------------|
| `tomcat-embed-core` | 10.1.55 | CVE-2026-55956 (autorisation), CVE-2026-65182 (contrôle d'accès), CVE-2026-65905 (DIGEST), CVE-2026-68525 (FORM), CVE-2026-65637 (HTTP/2 et SNI, introduit en 10.1.53), CVE-2026-53404 et CVE-2026-55276 (Rewrite Valve / flot de contrôle) | 10.1.56 à 10.1.59 selon l'avis |
| `org.postgresql:postgresql` | 42.7.11 (présent dans le cache Maven après résolution ; portée runtime, pas dans la liste `compile`) | CVE-2026-54291, rétrogradation silencieuse du *channel binding* | 42.7.12 |
| `jackson-databind` | 2.21.4 | CVE-2026-59889 (`@JsonView`, corrigé en 2.21.5), CVE-2026-91777 (DoS quadratique, corrigé en 2.21.7). Pas d'usage de `@JsonView` dans `backend/src/main/java`. | 2.21.7 |
| `jackson-core` | 2.21.4 | CVE-2026-89425 (DoS, croissance non bornée), plage corrigée en 2.21.7 | 2.21.7 |
| `netty-codec-http` | 4.1.135.Final | CVE-2026-59898, plage `0` → `4.1.136.Final` (validation du handshake WebSocket). OSV associe aussi sept autres avis à cet artefact ; seule cette plage 4.1 a été relue. | 4.1.136.Final au minimum |
| `nimbus-jose-jwt` | 9.47 | CVE-2025-53864, déni de service sur JSON profondément imbriqué, corrigé en 10.0.2 | 10.0.2 |
| `commons-lang3` | 3.17.0 | CVE-2025-48924, récursion non bornée, corrigé en 3.18.0. Déclencheur typique : `ClassUtils` sur une entrée contrôlée, non recherché jusqu'à un appelant ici. | 3.18.0 |
| `log4j-api` | 2.24.3 | CVE-2026-49844 (`MapMessage`). Le backend de log est Logback (`logback-classic` 1.5.34) ; l'API Log4j est un pont. Applicabilité faible. | 2.25.5 |

Les avis Jackson historiques de type « gadget polymorphe » qui exigent le default typing ne s'appliquent pas : aucun `activateDefaultTyping` ni `@JsonTypeInfo` n'est présent dans le code applicatif, et `fail-on-unknown-properties` est faux (`application.yml` lignes 37-41) sans ouvrir le polymorphisme.

**Scénario.** Pour les DoS Jackson et Nimbus : un client envoie un corps JSON ou un JWT pathologique à un endpoint public (`/api/auth/login`, `/api/auth/refresh`, `/oauth2/register`) et dégrade le processus. Pour CVE-2026-54291 : sur une base joignable par un tiers, un attaquant en position de couper TLS fait accepter une authentification sans *channel binding*. Combiné à `sslmode=prefer` (SEC-04 et la ligne citée plus bas), le canal vers une base externe n'est pas garanti chiffré. Pour Tomcat, le scénario précis dépend de l'avis ; ceux qui exigent DIGEST, FORM ou une Rewrite Valve ne correspondent pas à la chaîne JWT de `SecurityConfig`.

**Preuve de configuration liée.** `docker/docker-compose.yml` ligne 36 : `sslmode=prefer`. `charts/picsou/values.yaml` ligne 444 : `jdbcParams: sslmode=prefer`.

**Correctif.** Monter le parent Spring Boot, ou épingler Tomcat, Jackson, Netty et le pilote PostgreSQL au-dessus des versions corrigées, puis relancer OSV. Passer le JDBC des bases non locales à `sslmode=verify-full` avec le certificat de l'autorité. Traiter CVE-2026-55956 et CVE-2026-65182 comme à corriger même sans reproduction locale.

## SEC-05 — Changement de mot de passe sans second facteur

**Sévérité :** Moyenne

**Description.** `POST /api/auth/change-password` vérifie le mot de passe courant, remplace le hash, incrémente `tokenVersion` et révoque les sessions persistantes. Il ne consulte pas `MfaService` et n'exige pas le cookie `reauth_proof`. L'export des données, lui, passe par `ReAuthService.verify` (`MeExportController` lignes 33-35 et 70).

**Preuve.** `backend/src/main/java/com/picsou/controller/AuthController.java` lignes 424-456. Le login, lignes 185 et suivantes, envoie bien vers MFA lorsque `mfaService.isEnabled(user)`.

**Scénario.** Un attaquant dispose déjà d'une session (poste déverrouillé, cookie capturé sur le fil, SEC-03) et du mot de passe (réutilisation, phishing antérieur). Il change le mot de passe sans code TOTP, invalide les autres appareils et conserve la session qu'il vient de se réémettre. Le TOTP reste configuré pour les ouvertures suivantes, mais le titulaire est déconnecté partout ailleurs.

**Correctif.** Exiger le même `reauth_proof` (mot de passe + TOTP si le 2FA est actif) que pour l'export, avant d'accepter le changement.

## SEC-06 — Le reset ne coupe pas les sessions tout de suite

**Sévérité :** Moyenne

**Description.** `FamilyService.resetPasswordToken` pose un jeton d'activation de 32 octets, valable 7 jours, et ne touche ni `tokenVersion` ni les sessions persistantes. L'incrément et `revokeAllForUser` n'ont lieu que dans `ActivationService.complete`, lorsque le lien est consommé.

**Preuve.**

- `backend/src/main/java/com/picsou/service/FamilyService.java` lignes 150-165.
- `backend/src/main/java/com/picsou/service/ActivationService.java` lignes 56-68. Le commentaire dit que le reset doit invalider les sessions ; le code le fait à la consommation du lien, pas à son émission.

**Scénario.** L'administrateur génère un lien de reset pour un membre dont la session est déjà compromise. L'attaquant continue d'appeler l'API avec ses cookies jusqu'à ce que le membre ouvre le lien. La fenêtre peut durer plusieurs jours. Le jeton lui-même est imprévisible (`SecureRandom`, 32 octets) : le sujet n'est pas la forge du lien.

**Correctif.** Dans `resetPasswordToken`, incrémenter `tokenVersion` et appeler `revokeAllForUser` au moment où le lien est émis, comme le fait déjà `AdminRecoveryRunner` (lignes 74-80).

## SEC-07 — Fin de synchronisation bancaire non liée à l'appelant

**Sévérité :** Moyenne

**Description.** `completeConnection` retrouve la réquisition par `oauth_state` global, puis travaille sur le membre **porté par la ligne**, pas sur le membre authentifié. Le commentaire explique que cela répare l'impersonation admin. Conséquence : tout utilisateur authentifié qui présente le `state` et le `code` termine le flux et reçoit la liste des comptes dans la réponse HTTP. Si l'échange répond « déjà autorisé », `resyncLatest` renvoie les soldes du membre cible à l'appelant. Le `state` est un UUID v4, donc non devinable. L'écart est l'absence de lien avec la session qui a démarré le flux.

**Preuve.** `backend/src/main/java/com/picsou/service/SyncService.java` lignes 112-117 et 356-371. La recherche est `RequisitionRepository.findByOauthState` (clé globale, documentée comme exception au filtre membre).

**Scénario.** Le `code` et le `state` figurent dans l'URL de retour du navigateur. Une fuite de cette URL (historique partagé, poste partagé, extension) permet à un autre compte de la même instance de terminer la liaison et de lire la réponse de soldes, même si les lignes sont ensuite enregistrées sous le membre victime.

**Correctif.** Exiger `requisition.member.id == currentMemberId`, avec une exception explicite et testée pour l'impersonation admin. Ne pas renvoyer de soldes à un appelant qui n'est pas ce membre.

## SEC-08 — Formules de tableur dans l'export CSV

**Sévérité :** Moyenne

**Description.** `CsvWriter` applique l'échappement RFC 4180 (virgule, guillemet, saut de ligne) et écrit un BOM UTF-8 pour Excel. Une cellule qui commence par `=`, `+`, `-`, `@` ou une tabulation est écrite telle quelle. Les libellés viennent des banques, des imports et des saisies.

**Preuve.** `backend/src/main/java/com/picsou/export/CsvWriter.java` lignes 12-17 et 53-62. L'export est déclenché par `POST /api/me/export`, qui exige une re-authentification (`MeExportController`).

**Scénario.** Un libellé synchronisé ou importé commence par `=`. Le membre exporte son ZIP et ouvre le CSV dans un tableur qui évalue les formules. L'effet est sur le poste qui ouvre le fichier, pas une exécution sur le serveur.

**Correctif.** Préfixer par une apostrophe, ou tabuler, toute cellule dont le premier caractère est `=`, `+`, `-`, `@`, tabulation ou retour chariot. Couvrir le cas par un test sur `CsvWriter`.

## SEC-09 — SSRF via l'URL de base du fournisseur d'IA

**Sévérité :** Moyenne

**Description.** Un administrateur enregistre un `baseUrl` libre pour OpenAI, OpenRouter, Anthropic ou Ollama. `AiChatModelFactory` le passe au client HTTP. Aucune liste d'hôtes, aucun refus des adresses de lien-local, de loopback ou de métadonnées. L'appel part du processus Picsou lors du test de connexion et lors des catégorisations.

**Preuve.**

- `backend/src/main/java/com/picsou/dto/AdminAiRequest.java` ligne 9 : `baseUrl` est une chaîne libre.
- `backend/src/main/java/com/picsou/config/AiProviderConfig.java` lignes 5-7 : blanc signifie l'URL par défaut du fournisseur, sinon la valeur est utilisée telle quelle.
- `backend/src/main/java/com/picsou/config/AiChatModelFactory.java` lignes 37-38, 44-45 et 55.
- `backend/src/main/java/com/picsou/config/AiConfigProvider.java` lignes 112-118 et 131-138.

Le même soin existe ailleurs et n'est pas repris ici : `SimplefinUrls` limite l'hôte, `SidecarBaseUrl` refuse les URL non locales en HTTP. Ces contrôles ont été lus et tiennent pour ces connecteurs.

**Scénario.** Session administrateur compromise, ou administrateur qui colle une URL interne. Le serveur émet des requêtes vers le réseau du pod (autres services, métadonnées d'un hébergeur, port d'un sidecar). Le modèle de menace « administrateur déjà tout-puissant » limite la sévérité ; l'effet dépasse toutefois les données de Picsou et atteint le réseau.

**Correctif.** N'autoriser que `https` vers des hôtes publics, plus une liste explicite d'hôtes internes (Ollama). Refuser loopback, lien-local, adresses privées et noms qui se résolvent vers celles-ci, sauf opt-in.

## SEC-10 — Jeton de recovery admin écrit dans les logs

**Sévérité :** Moyenne (opt-in ; le défaut est désactivé)

**Description.** `ADMIN_RECOVERY_ENABLED` vaut faux par défaut (`application.yml`, bloc `admin-recovery`). Lorsqu'il est vrai, au démarrage, chaque administrateur est désactivé, son `tokenVersion` est incrémenté, et l'URL `/activate/{token}` est journalisée au niveau warn. Le login HTTP ne renvoie pas cette URL (message générique, `AuthController` lignes 147-152). Le secret est dans les logs, pas dans la réponse HTTP.

**Preuve.** `backend/src/main/java/com/picsou/config/AdminRecoveryRunner.java` lignes 74-110, en particulier la ligne 106 : `log.warn("URL      : {}", url)`.

**Scénario.** L'opérateur active le drapeau pour retrouver un accès, puis laisse un agrégateur de logs (ou un `docker logs` lisible par un autre utilisateur du NAS) conserver la ligne. Quiconque lit ce journal dans l'heure de validité du jeton fixe un nouveau mot de passe administrateur.

**Correctif.** Écrire l'URL uniquement sur la sortie standard du conteneur, avec une mention de ne pas l'envoyer à un collecteur, ou exiger un fichier de mode `0600` sous `/data`. Ne pas passer par SLF4J, qui est souvent branché sur un shipper.

## SEC-11 — Provisionnement administrateur par groupe SSO

**Sévérité :** Moyenne (conditionnel à la configuration de l'IdP)

**Description.** Si le setup est terminé, qu'un groupe admin SSO est configuré, et que le jeton d'identité contient ce groupe, un sujet inconnu est créé comme `UserRole.ADMIN`, activé, sans invitation locale. Le rôle suit ensuite le groupe à chaque connexion (synchronisation documentée).

**Preuve.** `backend/src/main/java/com/picsou/service/sso/SsoAccountService.java` lignes 87-109.

**Scénario.** `SSO_ADMIN_GROUP` est trop large (`users`, un groupe par défaut de l'IdP, une claim que l'IdP laisse au client remplir). La première connexion de ce sujet crée un administrateur Picsou, capable d'inviter, d'exporter et de lire les membres non indépendants. Un IdP qui signe vraiment la claim de groupes limite le scénario à une erreur de configuration, pas à une forge côté Picsou. L'audit n'a pas rejoué un IdP.

**Correctif.** Désactiver le provisionnement automatique par défaut et exiger une invitation locale, même pour le groupe admin. Journaliser et notifier lorsqu'un admin est créé par cette voie. Documenter que la claim de groupes doit être émise par l'IdP et non fournie par le client.

## SEC-12 — Chiffrement au repos : clé colocalisée, AES-128 accepté, pas de rotation

**Sévérité :** Moyenne

**Description.** Les secrets de connecteurs (clés d'exchange, sessions Bourso / CIC / CMES, jetons Wise, etc.) sont chiffrés en AES-GCM avant Postgres. C'est le bon outil, et l'application refuse de démarrer sans clé. Trois limites restent :

1. Docker place la clé dans `/data/.secrets` et la base dans un autre volume du même hôte. Une copie des deux volumes, ou un root sur la machine, déchiffre tout. Le chiffrement protège un dump de base **seul**.
2. `CryptoEncryption` accepte 16, 24 ou 32 octets. La documentation parle d'AES-256. Une clé de 16 octets est de l'AES-128 silencieux.
3. Il n'y a pas d'identifiant de version de clé. Une rotation demande un ré-chiffrement que le code ne porte pas (`docs/features/encryption-at-rest.md`).

Les mots de passe utilisateurs sont des hash bcrypt, ce qui est le bon choix. Les IBAN et les transactions ne sont pas dans le périmètre de ce chiffrement (SEC-22).

**Preuve.** `backend/src/main/java/com/picsou/config/CryptoEncryption.java` lignes 27-50. `docker/Dockerfile` fixe `PICSOU_SECRETS_DIR` (cité par `application.yml` et `SecretBootstrap`). `docs/features/encryption-at-rest.md` lignes 94-99 (rotation absente, clé unique).

**Scénario.** Sauvegarde naïve « volume Postgres + volume `/data` » exfiltrée. L'attaquant lit `crypto_key` et déchiffre les mots de passe Bourso stockés à chaque login.

**Correctif.** Refuser les clés de 16 et 24 octets. Préfixer le ciphertext par un identifiant de clé. Documenter qu'une sauvegarde de `/data` est un secret de même niveau que la base, et proposer un secret injecté par l'orchestrateur plutôt qu'un fichier à côté des données.

## SEC-13 — Helm : l'application n'est pas isolée tant que `appIngressFrom` est vide

**Sévérité :** Moyenne

**Description.** Les NetworkPolicies des sidecars et de PostgreSQL limitent bien l'entrée au pod applicatif. La policy d'entrée de l'application n'est rendue que si `networkPolicy.appIngressFrom` est non vide. La valeur par défaut est `[]`. Avec `networkPolicy.enabled: true`, un pod du namespace peut encore joindre le Service HTTP de Picsou. Le chart le dit dans un commentaire.

**Preuve.** `charts/picsou/values.yaml` lignes 446-454. `charts/picsou/templates/networkpolicy.yaml` lignes 56-79 : le bloc `with .Values.networkPolicy.appIngressFrom` n'émet rien si la liste est vide.

**Scénario.** Autre charge de travail dans le même namespace (sidecar activé par défaut pour chaque connecteur, `values.yaml` autour des entrées `sidecars.*.enabled: true`, ou un pod tiers). Elle appelle l'API Picsou. L'authentification s'applique encore ; l'isolation réseau annoncée par le commentaire « only the app may reach the sidecars and the database » ne se reflète pas dans l'autre sens.

**Correctif.** Lorsque l'ingress du chart est désactivé, une policy par défaut qui ne laisse entrer que les probes et un namespace d'ingress explicite. Échouer le rendu si `networkPolicy.enabled` est vrai et `appIngressFrom` est vide, sauf opt-in `allowClusterIngress: true`.

## SEC-14 — Rafraîchissement de session réutilisable

**Sévérité :** Faible

**Description.** Un login sans « Remember Me » produit un JWT de rafraîchissement stateless. `POST /api/auth/refresh` en accepte un tant que la signature, le type, l'expiration et `tv` sont valides. Il n'y a pas de liste de révocation pour cette variante. La variante persistante, elle, tourne une série et révoque en cas de réutilisation (`PersistentSessionService`, non re-cité ici : le mécanisme a été lu et tient).

**Preuve.** `backend/src/main/java/com/picsou/controller/AuthController.java` lignes 288-322 : un refresh valide est accepté et une nouvelle paire est émise. `SessionIssuer.rotatedRefreshToken` (`backend/src/main/java/com/picsou/service/SessionIssuer.java` lignes 80-81) ne fait que rappeler `generateRefreshToken` ; hors session persistante, le `sid` est `null`. L'ancien JWT reste vérifiable jusqu'à expiration ou jusqu'à un incrément de `tv`. `JwtUtil` lignes 34-38 impose 32 caractères minimum, ce qui écarte une clé HMAC trop courte.

**Scénario.** Copie du cookie `refresh_token` (sauvegarde de profil, SEC-03). L'original et la copie restent valides jusqu'à 7 jours ou jusqu'à un changement de mot de passe. Le cookie est `HttpOnly` : une XSS de page ne le lit pas.

**Correctif.** Émettre systématiquement un identifiant de série, y compris pour les sessions non persistantes, et refuser un rafraîchissement déjà présenté.

## SEC-15 — Renommage sans invalidation des autres sessions

**Sévérité :** Faible

**Description.** `PATCH /api/auth/username` change le nom, réémet les cookies de l'appelant, et n'incrémente pas `tokenVersion`. Les JWT des autres appareils restent valides. L'authentification s'appuie sur `uid` + `tv`, pas sur le nom.

**Preuve.** `backend/src/main/java/com/picsou/controller/AuthController.java` lignes 392-421.

**Scénario.** Session déjà volée : l'attaquant renomme le compte (gêne, confusion avec une invitation) sans forcer les autres navigateurs à se reconnecter.

**Correctif.** Incrémenter `tokenVersion` et réémettre uniquement pour l'appelant, comme pour le mot de passe.

## SEC-16 — Oracle d'expiration du jeton d'activation

**Sévérité :** Faible

**Description.** Un jeton connu mais expiré répond 400 « Activation token has expired ». Un jeton inconnu suit le chemin `UNKNOWN` et une 401 d'identifiants invalides. L'entropie est de 256 bits : l'oracle ne permet pas de chercher un jeton. Il confirme qu'une valeur déjà vue a existé.

**Preuve.** `backend/src/main/java/com/picsou/controller/AuthController.java` lignes 465-483.

**Scénario.** Un ancien lien, présent dans un ticket de support ou un log, est rejoué. La réponse dit qu'il a existé et qu'il est expiré, au lieu de répondre comme pour une chaîne aléatoire.

**Correctif.** Réponse unique pour inconnu et expiré. Le cas expiré peut être journalisé côté serveur.

## SEC-17 — SDK MCP : DNS rebinding

**Sévérité :** Faible

**Description.** OSV signale CVE-2026-35568 sur `io.modelcontextprotocol.sdk:mcp-core` 0.18.3, corrigé en 1.0.0 (plage introduite à `0`). Le serveur MCP de Picsou est embarqué et exige un bearer (clé `psk_` ou JWT OAuth) via `AccessKeyAuthFilter`, limité aux chemins `/mcp`. Un rebinding DNS classique n'envoie pas les cookies d'un autre site. L'audit n'a pas établi un contournement d'authentification à partir de cet avis seul.

**Preuve.** Version résolue dans l'arbre Maven (`spring-ai` 1.1.8 tire `mcp-core` 0.18.3). `backend/src/main/java/com/picsou/config/AccessKeyAuthFilter.java` : `shouldNotFilter` hors `/mcp` (le filtre a été lu ; le garde-fou d'authentification est celui décrit dans `SecurityConfig` lignes 198-204).

**Scénario.** Non démontré au-delà de « la version est dans la plage de l'avis ». À traiter comme une montée de dépendance, pas comme une faille confirmée de vol de données.

**Correctif.** Monter le SDK MCP au-dessus du correctif, puis vérifier que les outils restent bornés au membre de la clé.

## SEC-18 — CSP et CSS de graphique

**Sévérité :** Faible

**Description.** La politique de contenu autorise les styles en ligne. Le composant de graphique écrit un bloc `<style>` via `dangerouslySetInnerHTML`. Les couleurs viennent de la configuration du graphique, pas d'un champ banque saisi par un tiers, et l'identifiant vient de `useId()`. `script-src` reste `'self'` sans `unsafe-inline`. Aucun autre `dangerouslySetInnerHTML` de production n'a été trouvé. Les erreurs SSO passent par une liste de clés, pas par le texte brut de l'URL.

**Preuve.** `backend/src/main/java/com/picsou/config/SecurityConfig.java` lignes 60-62. `frontend/src/components/ui/chart.tsx` lignes 94-112.

**Scénario.** Une couleur de thème contrôlée par un attaquant qui peut modifier le code ou la configuration compilée sortirait du bloc CSS. Ce n'est pas un XSS stocké sur un libellé de transaction. Le `unsafe-inline` élargit surtout l'impact d'une XSS future.

**Correctif.** Générer les variables CSS sans passer par du HTML, ou assainir la couleur (motif `^#[0-9a-fA-F]{3,8}$` ou `oklch(...)` strict).

## SEC-19 — MCP activé par défaut

**Sévérité :** Faible

**Description.** `MCP_ENABLED` vaut vrai (`application.yml` lignes 60-66). `/mcp/**` exige une authentification. La surface existe dès qu'une clé d'accès ou un client OAuth est créé, et le endpoint est présent avant cela (réponse 401). Combiné à SEC-01 et SEC-03, une instance exposée offre un second protocole en plus de l'API cookie.

**Preuve.** `application.yml` lignes 60-66. `SecurityConfig.java` ligne 180 : `.requestMatchers("/mcp/**").authenticated()`.

**Scénario.** Instance jointe depuis le réseau local. Un client devine qu'un MCP est là et tente des clés. Les clés sont stockées par hash (contrôle lu, non re-détaillé). Le risque est la surface, pas un accès anonyme.

**Correctif.** Défaut `MCP_ENABLED=false`, activation dans l'assistant au moment où l'opérateur crée une clé.

## SEC-20 — Debug Fortuneo et chown root

**Sévérité :** Faible

**Description.**

1. `FORTUNEO_DEBUG_ARTIFACTS=true` écrit sous `/tmp/fortuneo-debug/` des captures et le texte de la page bancaire en échec. Le défaut est faux.
2. Le service Compose `data-permissions` tourne `user: "0:0"` le temps d'un `chown -R 1000:1000 /data`. L'image applicative elle-même passe ensuite à l'uid 1000. Les Dockerfiles de sidecars lus sont non-root.

**Preuve.** `services/fortuneo-auth/main.py` lignes 671-672 (désactivé par défaut) et 682-690 : capture d'écran, URL de la page et texte visible du `body`. Le commentaire du code dit exclure codes et identifiants ; l'URL et le texte affiché peuvent quand même porter un libellé de compte. `docker/docker-compose.yml` lignes 65-71.

**Scénario.** Debug laissé actif : un `docker cp` ou une sauvegarde de la couche writable emporte le texte de la page. Le `chown` root est un instant de confiance dans l'image ; il ne laisse pas un processus durable en root.

**Correctif.** Interdire la variable en dehors d'un profil explicite, et écrire les artefacts dans un volume mode `0700` plutôt que dans `/tmp`. Remplacer le conteneur root par un `chown` dans un point d'entrée déjà uid 1000 lorsque le volume le permet.

## SEC-21 — Secrets dans le dépôt et l'historique

**Sévérité :** Info

**Description.** Aucun secret de production n'a été identifié.

Contrôles effectués sur les 1 264 commits (`git rev-list --all`) :

- Noms d'objets : aucun `.env` vivant, `.pem`, `.p12`, `id_rsa` ou `credentials.json`. Seuls des exemples (`.env.example`) et des fichiers de code dont le nom contient « secret ».
- Contenu : aucune clé `AKIA`, aucun `ghp_` / `github_pat_`, aucun `sk_live_` réel, aucun `xox[baprs]-`.
- Les correspondances `BEGIN PRIVATE KEY` sont des marqueurs dans des commentaires, des placeholders d'interface, ou des PEM d'exemple dont le corps fait 11 à 29 caractères (commits `7b5c6816`, `dad9bea1`, `627533a6`, puis commentés). Ce n'est pas une clé PKCS#8 utilisable.
- `sk_live_…` dans `6a25c87b` est une chaîne de test de `CryptoEncryptionTest`.
- `eyJ…` dans `90788ac9` est le JWT factice de `TelemetryScrubberTest`.
- Les fixtures de connecteurs portent des jetons synthétiques du type `FAKE.ACCESS.TOKEN`.

**Ce qui n'a pas été fait.** Pas de scan entropique byte-à-byte de chaque blob (gitleaks / trufflehog absents de l'environnement). Un secret haute entropie sans préfixe connu pourrait avoir échappé.

## SEC-22 — Données financières en clair

**Sévérité :** Info (choix documenté ; à connaître pour les sauvegardes)

**Description.** `Account.iban` est une colonne en clair, utilisée comme clé de rapprochement. Descriptions, contreparties, montants et soldes sont en clair. C'est cohérent avec le besoin de les requêter et de les afficher. Le chiffrement applicatif couvre les identifiants de connecteurs, pas le grand livre.

**Preuve.** `backend/src/main/java/com/picsou/model/Account.java` lignes 87-93. `docs/features/encryption-at-rest.md`, section « What is NOT encrypted ».

**Scénario.** Dump Postgres (SEC-02) ou sauvegarde du volume : l'historique et les IBAN sont lisibles sans la clé.

**Correctif.** Aucun correctif de code n'est proposé ici. Traiter le volume Postgres comme un secret, au même titre que `/data`. Si un chiffrement des IBAN est ajouté plus tard, il doit rester déterministe pour la clé de rapprochement, ou le rapprochement doit changer de clé.

Les journaux lus évitent en général l'IBAN en clair (`LogSanitizer.fingerprint` côté Wise). `EvmWalletAdapter` journalise des adresses publiques de portefeuille : donnée déjà publique sur la chaîne, sensibilité moindre. Le mode trace du connecteur Trade Republic peut, d'après sa documentation, tracer des trames brutes : ne pas l'activer en production. Ce point n'a pas été revalidé en faisant tourner le connecteur.

## SEC-23 — Enregistrement dynamique de clients OAuth

**Sévérité :** Info

**Description.** `POST /oauth2/register` est anonyme, par RFC 7591, avec limite de débit. Les URI de redirection doivent être `https` ou un loopback `http`. Le consentement est requis. L'absence de scope demandé sélectionne les scopes de lecture. Aucun `client_secret` n'est émis (clients publics PKCE).

**Preuve.** `SecurityConfig.java` ligne 175. `DynamicClientRegistrationController.java` lignes 169-215 et 249-254.

**Scénario.** Un tiers enregistre un client dont le nom ressemble à l'application et envoie la victime sur l'URL d'autorisation. Si elle consent, le client obtient les scopes de lecture accordés. C'est le risque habituel d'un serveur d'autorisation avec enregistrement ouvert, pas un contournement du consentement.

**Correctif.** Laisser l'enregistrement ouvert uniquement si un client MCP distant est voulu. Sinon, le désactiver et n'enregistrer que le client iOS déjà configuré.

## SEC-24 — En-têtes, actuator, dépendances de développement

**Sévérité :** Info

**Description.**

- HSTS est désactivé par défaut (`application.yml` ligne 222, `SecurityConfig` lignes 249-254). Le commentaire explique le risque de blocage avec un certificat local. À activer seulement derrière un certificat publiquement reconnu.
- Actuator n'expose que `health` et `info`, `show-details: never`, pas de stack trace en production (`application.yml` lignes 120-122 et 130-148). Le profil `dev` autorise `?trace=true` (`application-dev.yml` ligne 56) et désactive le rate-limit de login (lignes 2-4). Ce profil ne doit pas être celui de Compose (`SPRING_PROFILES_ACTIVE` par défaut `prod`, `docker-compose.yml` ligne 42).
- `npm audit` n'a pas été lancé : le frontend n'a pas de `package-lock.json`, `bun` n'est pas installé ici, et `bun.lock` n'est pas du JSON strict. Les 622 versions du lock ont été envoyées à l'API OSV. Les avis qui touchent le runtime navigateur utile sont limités. `axios@1.21.0` dépend de `follow-redirects@1.16.0` (CVE-2026-111755, CVE-2026-116689, CVE-2026-111756, en-têtes sensibles et redirections). Le bundle navigateur d'axios utilise l'adaptateur XHR ; `follow-redirects` sert au chemin Node. `zod@4.4.3` est avant le correctif 4.6.6 de CVE-2023-54404 (DoS mémoire côté validateur). La validation d'autorité est côté serveur (Jakarta). `undici`, `vitest`, `browserslist`, `minimatch`, `brace-expansion` sont des dépendances d'outils (`jsdom`, `shadcn`, Vitest) et ne partent pas dans l'image nginx de démo ni dans le JAR.
- Les workflows lus (`ci.yml` en lecture seule, `docker.yml` qui ne pousse pas les images sur les pull requests, `pr-size.yml` en `pull_request_target` qui ne checkout que la branche de base, `codeql.yml` en suite `security-extended`) ne montrent pas d'exécution du code de la pull request avec un jeton d'écriture. Aucune signature d'image (cosign) n'est présente dans `docker.yml` : l'intégrité repose sur le registre.

## SEC-25 — Sidecars Python

**Sévérité :** Info

**Description.** `pip-audit`  (service OSV / PyPI) sur `services/base/requirements.txt`, `requirements-chromium.txt` et `requirements-camoufox.txt` : 47 paquets, aucune vulnérabilité connue. Épinglages lus : FastAPI 0.165.0, uvicorn 0.54.0, pydantic 2.14.3, httpx 0.28.1, Playwright 1.64.1, camoufox 0.4.11.

Le middleware partagé refuse de démarrer sans `APP_SIDECAR_API_KEY` et répond 401 hors `GET /health` (`services/base/picsou_sidecar/app.py` lignes 81-82 et 101-110). Compose laisse la variable vide par défaut (`docker-compose.yml` ligne 49) : les sidecars ne démarrent pas, l'application oui. Les ports des sidecars ne sont pas publiés sur l'hôte dans le fichier Compose lu. Leurs URL sont des noms Docker, pas une entrée utilisateur, avec les garde-fous de `SidecarBaseUrl` mentionnés en SEC-09.

L'audit n'a pas relu chaque parseur bancaire ligne à ligne. Un échantillon (La Banque Postale, Natixis) montre des garde-fous d'URL et un refus de journaliser les secrets ; ce n'est pas une preuve pour les quinze connecteurs.

## Contrôles qui tiennent

Ces points ont été lus pour chercher une faille et n'en ont pas montré. Ils évitent de « corriger » un mécanisme déjà en place.

| Sujet | Constat |
|-------|---------|
| Isolation des membres | Les contrôleurs de comptes et d'objectifs passent `currentMemberId()`. L'impersonation admin refuse un membre activé indépendant (`UserContext`). |
| Mots de passe | bcrypt coût 12. Comparaison factice pour égaliser le temps de réponse quand l'utilisateur n'existe pas ou n'a pas de hash (`AuthController` lignes 129-166). |
| JWT | HMAC, refus sous 32 caractères, claim `tv` contrôlé. Pas de confusion d'algorithme évidente (`verify` avec clé symétrique). |
| CSRF | Pas de jeton stocké. Les écritures cross-site qui portent un cookie d'auth sont rejetées. Un en-tête `Authorization` ne dispense pas. Les GET ne doivent pas changer d'état ; le callback bancaire est un POST. |
| CORS | Origines exactes, `*` retiré, échec fermé si la liste est vide. |
| En-têtes | `X-Frame-Options` deny, `nosniff`, Referrer-Policy, Permissions-Policy, `Cache-Control` sur les chemins d'API. CSP avec `script-src 'self'`. |
| Adresse client | `X-Forwarded-For` n'est accepté que depuis `PICSOU_PROXY_IP`. `ClientIp` ne relit pas l'en-tête lui-même. |
| Clés MCP | Hash, préfixe, scopes. Le filtre ne s'applique qu'à `/mcp`. |
| Export | Re-authentification et quota par utilisateur. |
| Open redirect | `SafeRedirect` côté SSO et garde côté SPA. |
| Zip slip | L'import Actual Budget refuse les noms `../`. |
| XXE | Les parseurs XML lus (IBKR Flex, INSEE) désactivent les entités externes. |
| SQL | Requêtes natives à paramètres nommés ou `?`. Pas de concaténation de SQL à partir d'une requête HTTP dans `backend/src/main`. |
| Commande | Pas de `ProcessBuilder` / `Runtime.exec` dans le code de production Java. Pas de `shell=True` dans les sidecars de production échantillonnés. |
| Télémétrie | Désactivée sans DSN. `TelemetryScrubber` retire JWT, IBAN, e-mails, montants. |
| CI | Pas de poussée d'image sur les pull requests. CodeQL `security-extended`. |
| Images | Processus applicatif uid 1000. Pas de secret dans les `ENV` du Dockerfile principal. |

## Limites

- Pas d'exécution de l'application, pas de test d'intrusion, pas de vérification d'une instance déjà déployée (CORS réellement enregistré, mot de passe réellement changé, bind réel).
- Les parseurs des quinze sidecars bancaires n'ont pas été relus un par un.
- `npm audit` et `mvn org.owasp:dependency-check` n'ont pas été exécutés. Substituts : `pip-audit` pour Python, `mvn dependency:list` plus l'API OSV pour le Java `compile` et pour `bun.lock`. Le pilote PostgreSQL a été contrôlé à part (42.7.11).
- Les avis Netty autres que CVE-2026-59898 n'ont pas eu leur plage 4.1 relue individuellement, alors qu'OSV les associe à `netty-codec-http` 4.1.135.Final.
- Pas d'outil dédié de scan de secrets (gitleaks). Le parcours git décrit en SEC-21 couvre les préfixes usuels et les noms de fichiers.
- Le comportement exact de Tomcat sur CVE-2026-55956 et CVE-2026-65182 dans cette configuration (pas de DIGEST, pas de FORM, pas de Rewrite Valve) n'a pas été reproduit.

## Ordre de traitement suggéré

1. SEC-01, SEC-02, SEC-03 : défauts que rencontre un opérateur qui suit Compose sans lire chaque commentaire.
2. SEC-04 : montée Tomcat, JDBC, Jackson, Netty, et `sslmode=verify-full` hors du réseau Docker.
3. SEC-05 et SEC-06 : aligner le mot de passe et le reset sur la révocation déjà écrite pour l'export et pour le recovery admin.
4. SEC-07 à SEC-13 : selon l'exposition (IA, SSO, Helm, exports ouverts dans Excel).

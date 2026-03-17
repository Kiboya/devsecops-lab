[![DevSecOps Pipeline](https://github.com/Kiboya/devsecops-lab/actions/workflows/security.yml/badge.svg)](https://github.com/Kiboya/devsecops-lab/actions/workflows/security.yml)

# TP Noté — Pipeline DevSecOps avec GitHub Actions

## Table des matières

1. [Présentation du projet](#1-présentation-du-projet)
2. [Architecture et structure du dépôt](#2-architecture-et-structure-du-dépôt)
3. [Pipeline DevSecOps](#3-pipeline-devsecops)
4. [Vulnérabilités détectées (état initial)](#4-vulnérabilités-détectées-état-initial)
5. [Corrections appliquées](#5-corrections-appliquées)
6. [Métriques de sécurité](#6-métriques-de-sécurité)
7. [Exercices pratiques réalisés](#7-exercices-pratiques-réalisés)
8. [Leçons apprises](#8-leçons-apprises)
9. [Checklist finale](#9-checklist-finale)

---

## 1. Présentation du projet

Ce dépôt constitue la réalisation du TP noté DevSecOps. L'objectif était d'hériter d'une application Node.js volontairement vulnérable, de mettre en place un pipeline CI/CD sécurisé avec GitHub Actions, de détecter automatiquement les failles via plusieurs outils de sécurité (SAST, SCA, détection de secrets, scan de conteneur, DAST), puis de corriger l'ensemble des vulnérabilités identifiées.

### Outils intégrés dans le pipeline

| Outil | Catégorie | Rôle |
|---|---|---|
| Semgrep | SAST | Analyse statique du code source |
| npm audit | SCA | Audit des dépendances Node.js |
| Gitleaks | Secret Detection | Détection de secrets dans l'historique Git |
| Trivy | Container Scan | Scan des vulnérabilités dans l'image Docker |
| CodeQL | SAST avancé | Analyse sémantique du code (GitHub) |
| OWASP ZAP | DAST | Test dynamique de l'application en cours d'exécution |

---

## 2. Architecture et structure du dépôt

```
devsecops-lab/
├── .github/
│   └── workflows/
│       └── security.yml      # Pipeline DevSecOps complet
├── .env.example              # Variables d'environnement attendues
├── src/
│   ├── server.js             # Application Node.js (sécurisée)
│   ├── package.json          # Dépendances mises à jour
│   └── package-lock.json
├── Dockerfile                # Image Docker sécurisée (node:24-alpine)
├── .gitignore                # Inclut .env, node_modules, etc.
└── README.md                 # Ce fichier
```

---

## 3. Pipeline DevSecOps

Le pipeline est déclenché sur chaque `push` et `pull_request`. Il se compose de 7 jobs organisés avec des dépendances explicites.

### Vue d'ensemble du workflow

```
push / pull_request
        │
        ├─── 🏗️ build ───────────────┬──── 🐳 container-scan (Trivy)
        │                            └──── ⚡ dast (OWASP ZAP)
        ├─── 🔍 sast (Semgrep)
        ├─── 📦 sca (npm audit)
        ├─── 🔐 secrets (Gitleaks)
        ├─── 🔍 codeql
        │
        ├─── 🚦 security-gate (needs: sast, sca, secrets, container-scan, dast, codeql)
        │
        └─── 📊 report
```

### Détail des jobs

#### 🏗️ Build

Construit l'image Docker à partir du `Dockerfile` et la sauvegarde comme artefact pour les jobs suivants (Container Scan, DAST) afin d'éviter de reconstruire plusieurs fois.

```yaml
- name: Build Docker image
  run: docker build -t vuln-app:${{ github.sha }} .
- name: Save image
  run: docker save vuln-app:${{ github.sha }} > image.tar
```

#### 🔍 SAST — Semgrep

Analyse statique du code source avec trois ensembles de règles OWASP :

```yaml
- name: Run Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: >-
      p/security-audit
      p/secrets
      p/owasp-top-ten
```

#### 📦 SCA — npm audit

Vérifie les CVE connues dans les dépendances Node.js et exporte un rapport JSON en artefact.

```yaml
- name: npm audit
  working-directory: ./src
  run: |
    npm audit --json > audit.json
    npm audit
```

#### 🔐 Détection de secrets — Gitleaks

Scanne l'intégralité de l'historique Git (`fetch-depth: 0`) pour détecter tout secret accidentellement commité.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- name: Gitleaks
  uses: gitleaks/gitleaks-action@v2
```

#### 🐳 Container Scan — Trivy

Scanne l'image Docker construite précédemment pour détecter les vulnérabilités CRITICAL dans l'OS de base et les packages système.

```yaml
- name: Trivy scan
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: vuln-app:${{ github.sha }}
    format: 'table'
    exit-code: '1'
    severity: 'CRITICAL'
```

#### 🔍 CodeQL

Analyse sémantique avancée du code JavaScript via l'outil natif de GitHub, avec le pack de requêtes `security-extended`.

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: javascript
    queries: security-extended
- name: Perform Analysis
  uses: github/codeql-action/analyze@v3
```

#### ⚡ DAST — OWASP ZAP

Test dynamique : l'image Docker est lancée, l'application démarre sur le port 3000, puis OWASP ZAP effectue un scan de base.

```yaml
- name: Load and run app
  run: |
    docker load < image.tar
    docker run -d -p 3000:3000 -e JWT_SECRET="${{ secrets.JWT_SECRET }}" --name app vuln-app:${{ github.sha }}
- name: OWASP ZAP Baseline
  uses: zaproxy/action-baseline@v0.14.0
  with:
    target: 'http://localhost:3000'
    allow_issue_writing: false
```

#### 🚦 Security Gate

Bloque le pipeline si l'un des jobs précédents (SAST, SCA, Container Scan, CodeQL) échoue, empêchant tout déploiement en cas de vulnérabilité critique détectée.

#### 📊 Report

Job final qui génère un rapport JSON consolidant les résultats de tous les scans, disponible en artefact GitHub Actions.

---

## 4. Vulnérabilités détectées (état initial)

L'application initiale (`feat: Add vulnerable app + DevSecOps pipeline`) contenait les failles suivantes (découvertes en lisant les rapports de scan de chaque outil).

### 4.1 Secrets hardcodés dans le code source

Le fichier `src/server.js` exposait directement des credentials en clair :

```javascript
// secrets dans le code
const DB_CONNECTION = "mongodb://admin:SuperSecret123!@prod-db.company.com:27017/myapp";
const STRIPE_SECRET_KEY = "sk_live_51Hqp9K2eZvKYlo2C8xO3n4y5z6a7b8c9d0e1f2g3h4i5j";
const SENDGRID_API_KEY = "SG.nExT2-QRDzJcEV39HqCxTg.KnLmOpQrStUvWxYz1234567890aBcDeF";
```

![alt text](images/image-1.png)

Sévérité : CRITICAL — Ces secrets étaient commités dans l'historique Git et donc accessibles publiquement.

### 4.2 Endpoint de debug exposant des données sensibles

```javascript
// fuite d'informations critiques
app.get('/debug', (req, res) => {
  res.json({
    dbConnection: DB_CONNECTION,    // Chaîne de connexion DB avec password
    stripeKey: STRIPE_SECRET_KEY,   // Clé Stripe live
    sendgridKey: SENDGRID_API_KEY,  // Clé SendGrid
    env: process.env                // Variables d'environnement entières
  });
});
```

Sévérité : CRITICAL — Information Disclosure complète, équivalent à un accès root à l'infrastructure.

### 4.3 Authentification faible et token JWT sans expiration

```javascript
// mot de passe admin en clair, JWT sans expiration
if (username === 'admin' && password === 'admin') {
  const token = jwt.sign({ username }, JWT_SECRET);  // Pas d'expiration
  res.json({ token });
}
```
Sévérité : HIGH

### 4.4 Absence de protection HTTP

Aucun middleware de sécurité HTTP (pas de Helmet), pas de rate limiting sur le login, pas de validation des entrées.

Sévérité : HIGH

### 4.5 Image Docker basée sur `node:14`

L'image de base `node:14` est en fin de vie (EOL) et contient de nombreuses vulnérabilités connues dans les packages système.

```dockerfile
FROM node:14
```

Sévérité : CRITICAL

### 4.6 Dépendances obsolètes avec CVE connues

```json
// versions vulnérables
"express": "4.17.1",
"jsonwebtoken": "8.5.1"
```

Les versions `express@4.17.1` et `jsonwebtoken@8.5.1` présentent des CVE documentées (notamment CVE-2022-24999 pour Express et plusieurs CVE pour jsonwebtoken 8.x concernant la vérification de signature).

Sévérité : HIGH à CRITICAL selon les CVE

### 4.7 Résumé des détections initiales

| Outil | Résultat | Principales vulnérabilités détectées |
|---|---|---|
| Semgrep | ❌ FAIL | Secrets hardcodés, manque de validation, OWASP Top 10 |
| npm audit | ❌ FAIL | CVE dans express et jsonwebtoken |
| Gitleaks | ❌ FAIL | secrets détectés dans l'historique Git |
| Trivy | ❌ FAIL | Vulnérabilités CRITICAL dans node:14 |

![alt text](images/image-2.png)
---

## 5. Corrections appliquées

### 5.1 Suppression des secrets — Variables d'environnement

```javascript
// secrets dans des variables d'environnement
require('dotenv').config();
const SECRET = process.env.JWT_SECRET;

if (!SECRET || SECRET.length < 32) {
  console.error('JWT_SECRET must be set and at least 32 characters');
  process.exit(1);
}
```

Les secrets sont désormais stockés dans GitHub Secrets (Settings → Secrets and variables → Actions) et injectés au runtime. Un fichier `.env.example` documente les variables attendues sans exposer les valeurs réelles.

Variables configurées dans GitHub Secrets :
- `JWT_SECRET` — généré avec `openssl rand -base64 32`
- `ADMIN_USER`
- `ADMIN_PASS`

### 5.2 Suppression de l'endpoint `/debug`

L'endpoint `/debug` a été remplacé par un endpoint `/health` ne retournant aucune information sensible. L'endpoint de debug, désormais inoffensif (`{ message: 'Debug mode' }`), est conditionné à `NODE_ENV !== 'production'`.

```javascript
// endpoint de santé sans données sensibles
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// Endpoint debug uniquement hors production
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug', (req, res) => {
    res.json({ message: 'Debug mode' });
  });
}
```

### 5.3 Sécurisation de l'authentification

```javascript
// rate limiting + validation + JWT avec expiration
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

app.post('/api/login',
  loginLimiter,
  [
    body('username').isString().trim().notEmpty(),
    body('password').isString().notEmpty().isLength({ min: 8 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // ...
    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' }); // ✅ Expiration
    res.json({ token });
  }
);
```

### 5.4 Headers de sécurité HTTP avec Helmet

```javascript
app.use(helmet());                          // Headers sécurisés (CSP, HSTS, etc.)
app.use(express.json({ limit: '10kb' }));  // Limitation de la taille des requêtes
```

Helmet configure automatiquement les headers : `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, etc.

### 5.5 Mise à jour des dépendances

```json
// dépendances à jour et sécurisées
{
  "name": "secure-app",
  "version": "2.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.0",
    "express-validator": "^7.0.1",
    "dotenv": "^16.3.1"
  }
}
```

### 5.6 Sécurisation du Dockerfile

```dockerfile
FROM node:24-alpine                          # Image Alpine légère, version LTS récente

RUN apk update && apk upgrade --no-cache    # Mise à jour des packages système

WORKDIR /app
COPY src/package*.json ./
RUN npm ci --only=production && npm cache clean --force   # Dépendances de prod uniquement

COPY src/ ./

# Utilisateur non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app
USER nodejs

EXPOSE 3000

# Healthcheck natif Docker
HEALTHCHECK --interval=30s --timeout=3s \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "server.js"]
```

### 5.7 Configuration de .gitignore

Le fichier `.gitignore` protège contre les commits accidentels de fichiers sensibles :

```
.env
.env.*
node_modules/
src/node_modules/
security-report.json
src/audit.json
```


---

## 6. Métriques de sécurité
Le statut de sécurité dépend du dernier run GitHub Actions (badge en haut du README).
Le rapport JSON est généré à chaque exécution du job `report` et publié en artefact de workflow.


![alt text](images/image-3.png)

## 7. Exercices pratiques réalisés

### Exercice 1 — Injection SQL pédagogique

Une route de démonstration `/training/sqli` a été ajoutée pour illustrer une injection SQL classique, détectable par les outils SAST :

```javascript
// Route pédagogique (uniquement hors production)
if (process.env.NODE_ENV !== 'production') {
  app.get('/training/sqli', (req, res) => {
    const username = req.query.username;
    const query = `SELECT * FROM users WHERE username = '${username}'`; // SQLi
    res.json({
      warning: 'Training endpoint: intentionally vulnerable SQL construction',
      unsafeQuery: query
    });
  });
}
```

Cette route est conditionnée à `NODE_ENV !== 'production'` et est immédiatement détectée par Semgrep (`p/owasp-top-ten` — A03:2021 Injection).

Vecteur d'attaque illustré : `GET /training/sqli?username=' OR '1'='1` montre la requête SQL construite de manière non sûre.

### Exercice 2 — Badge de pipeline dans le README

Le badge de statut du pipeline est intégré en haut de ce README :

```markdown
[![DevSecOps Pipeline](https://github.com/Kiboya/devsecops-lab/actions/workflows/security.yml/badge.svg)](https://github.com/Kiboya/devsecops-lab/actions/workflows/security.yml)
```

### Exercice 3 — Intégration de CodeQL

CodeQL a été configuré dans le pipeline avec le pack `security-extended`, offrant une analyse sémantique plus approfondie que Semgrep seul. 

### Exercice 4 — Security Gate

Un job `security-gate` a été ajouté, dépendant de `[sast, sca, secrets, container-scan, dast, codeql]`. Il bloque le pipeline si l'un des scans échoue, empêchant toute progression vers le déploiement.

---

## 8. Leçons apprises

### 8.1 Intégration de la sécurité dès le commit

Intégrer la sécurité dès le commit (et non en fin de cycle) permet de détecter les failles au coût le plus faible. Dans ce TP, les secrets hardcodés auraient pu être exposés en production si le pipeline n'avait pas bloqué le merge. La règle fondamentale : un secret dans Git est un secret compromis, même si le commit est revert par la suite (l'historique reste accessible).

### 8.2 Complémentarité des outils

Aucun outil seul ne couvre l'ensemble du spectre de sécurité :

- Semgrep détecte les patterns de code dangereux rapidement mais peut produire des faux positifs
- npm audit connaît les CVE publiées mais ne détecte pas les mauvaises pratiques de code
- Gitleaks est indispensable pour l'historique Git mais ne voit pas les vulnérabilités applicatives
- Trivy est le seul à évaluer la sécurité de l'image Docker de base
- CodeQL offre l'analyse sémantique la plus précise mais est plus lent
- OWASP ZAP est le seul à tester l'application en cours d'exécution (runtime behaviors)

La couverture maximale s'obtient en combinant SAST + SCA + Secret Detection + Container Scan + DAST.

### 8.3 La surface d'attaque d'une image Docker

Passer de `node:14` à `node:24-alpine` a éliminé des dizaines de CVE sans aucune modification du code applicatif. Le choix de l'image de base est une décision de sécurité critique souvent sous-estimée. L'utilisation d'un utilisateur non-root limite l'impact d'une compromission : même si un attaquant exécute du code dans le conteneur, il ne dispose pas des privilèges root pour modifier le système.

### 8.4 Gestion des secrets dans un pipeline CI/CD

Le flux recommandé est :
1. Stocker les secrets dans GitHub Secrets (chiffrés au repos)
2. Les injecter comme variables d'environnement dans les jobs qui en ont besoin
3. Ne jamais les loguer (`echo $SECRET` dans les logs est une fuite)
4. Utiliser `.env.example` comme documentation sans valeurs réelles
5. Vérifier que `.env` est bien dans `.gitignore` avant le premier commit

---

## 9. Checklist finale

| Critère | Statut |
|---|---|
| Pipeline s'exécute sans erreur | ✅ |
| Tous les secrets dans GitHub Secrets (pas dans le code) | ✅ |
| Dépendances à jour (pas de CVE critiques) | ✅ |
| Dockerfile sécurisé (utilisateur non-root, image alpine) | ✅ |
| README.md complet avec instructions | ✅ |
| Badge de build dans le README | ✅ |
| `.gitignore` contient `.env` | ✅ |
| Tests de sécurité passent | ✅ |
---
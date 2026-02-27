# TP noté : Pipeline DevSecOps avec GitHub Actions

**Prérequis** : Docker, Git, bases Linux

---

## Objectifs

* Mettre en place un pipeline CI/CD sécurisé
* Détecter automatiquement les vulnérabilités (SAST, SCA, DAST)
* Corriger les failles de sécurité courantes
* Comprendre le DevSecOps en pratique

---

## Scénario

Vous héritez d'une application Node.js **volontairement vulnérable**. Votre mission : créer un pipeline DevSecOps pour détecter et corriger toutes les failles avant le déploiement.

---

## Section 1 : Setup

### 1.1 Créer le projet

```bash
# Créer un nouveau repo sur GitHub
# Puis cloner
git clone [https://github.com/](https://github.com/)<votre-username>/<repo>.git
cd devsecops-lab

# Structure
mkdir -p src .github/workflows

```

### 1.2 Application vulnérable

**src/package.json** :

```json
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1",
    "jsonwebtoken": "8.5.1"
  }
}

```

**src/server.js** :

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();


const DB_CONNECTION = "mongodb://admin:SuperSecret123!@[prod-db.company.com:27017/myapp](https://prod-db.company.com:27017/myapp)";
const STRIPE_SECRET_KEY = "sk_live_51Hqp9K2eZvKYlo2C8xO3n4y5z6a7b8c9d0e1f2g3h4i5j";
const SENDGRID_API_KEY = "SG.nExT2-QRDzJcEV39HqCxTg.KnLmOpQrStUvWxYz1234567890aBcDeF";
app.use(express.json());

app.post('/api/login', (req, res) => {
 const { username, password } = req.body;

 if (username === 'admin' && password === 'admin') {
 const token = jwt.sign({ username }, JWT_SECRET);
 res.json({ token });
 } else {
 res.status(401).json({ error: 'Invalid credentials' });
 }
});

app.get('/debug', (req, res) => {
 res.json({
    dbConnection: DB_CONNECTION,
    stripeKey: STRIPE_SECRET_KEY,
    sendgridKey: SENDGRID_API_KEY,
    env: process.env
  });
});
app.listen(3000, () => console.log('Server running on port 3000'));

```

**Dockerfile** :

```dockerfile
FROM node:14
WORKDIR /app
COPY src/package*.json ./
RUN npm install
COPY src/ ./
EXPOSE 3000
CMD ["node", "server.js"]

```

---

## Section 2 : Pipeline DevSecOps

### 2.1 Workflow GitHub Actions

Créez **.github/workflows/security.yml** :

```yaml
name: DevSecOps Pipeline

on: [push, pull_request]

jobs:
  # ═══════════════════════════════════════
  # 1. BUILD
  # Construit l'image Docker de l'application
  # Permet de valider que le code compile et de préparer l'image pour le scan de vulnérabilités
  # ═══════════════════════════════════════
  build:
    name: 🏗️ Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker image
        run: docker build -t vuln-app:${{ github.sha }} .
      
      - name: Save image
        run: docker save vuln-app:${{ github.sha }} > image.tar
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: docker-image
          path: image.tar

  # ═══════════════════════════════════════
  # 2. SAST - Analyse statique du code (Static Application Security Testing)
  # Détecte les vulnérabilités dans le CODE SOURCE : injection SQL, XSS, failles de sécurité
  # Outil : Semgrep avec règles OWASP Top 10, security-audit, et détection de secrets
  # ═══════════════════════════════════════
  sast:
    name: 🔍 SAST
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten

  # ═══════════════════════════════════════
  # 3. SCA - Analyse des dépendances (Software Composition Analysis)
  # Détecte les vulnérabilités dans les BIBLIOTHÈQUES et packages tiers (npm, etc.)
  # Outil : npm audit pour vérifier les CVE connues dans les dépendances Node.js
  # ═══════════════════════════════════════
  sca:
    name: 📦 SCA
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Install dependencies
        working-directory: ./src
        run: npm install

      - name: npm audit
        working-directory: ./src
        run: |
          npm audit --json > audit.json
          npm audit

      - uses: actions/upload-artifact@v4
        with:
          name: npm-audit
          path: src/audit.json

  # ═══════════════════════════════════════
  # 4. SECRET DETECTION
  # Détecte les SECRETS accidentellement committés : clés API, mots de passe, tokens
  # Outil : Gitleaks qui scanne tout l'historique Git (fetch-depth: 0)
  # ⚠️ Critique : évite les fuites de credentials et violations de sécurité
  # ═══════════════════════════════════════
  secrets:
    name: 🔐 Secrets
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # ═══════════════════════════════════════
  # 5. CONTAINER SCAN
  # Scanne l'IMAGE DOCKER pour détecter les vulnérabilités dans l'OS et les packages système
  # Outil : Trivy qui analyse les CVE dans les couches Docker (image de base, packages installés)
  # Recherche les vulnérabilités CRITICAL uniquement (pragmatisme DevSecOps)
  # ═══════════════════════════════════════
  container-scan:
    name: 🐳 Container Scan
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: docker-image

      - name: Load image
        run: docker load < image.tar

      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: vuln-app:${{ github.sha }}
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL'

  # ═══════════════════════════════════════
  # 6. RAPPORT FINAL
  # Génère un résumé de tous les scans de sécurité
  # Vérifie le statut de chaque job et fait ÉCHOUER le pipeline si des vulnérabilités sont détectées
  # S'exécute toujours (if: always()) même si des jobs précédents ont échoué
  # ═══════════════════════════════════════
  report:
    name: 📊 Report
    runs-on: ubuntu-latest
    needs: [sast, sca, secrets, container-scan]
    if: always()
    steps:
      - name: Generate JSON Report
        run: |
          cat > security-report.json <<EOF
          {
            "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
            "repository": "${{ github.repository }}",
            "commit": "${{ github.sha }}",
            "branch": "${{ github.ref_name }}",
            "workflow_run": "${{ github.run_id }}",
            "results": {
              "sast": {
                "status": "${{ needs.sast.result }}",
                "tool": "Semgrep"
              },
              "sca": {
                "status": "${{ needs.sca.result }}",
                "tool": "npm audit"
              },
              "secrets": {
                "status": "${{ needs.secrets.result }}",
                "tool": "Gitleaks"
              },
              "container_scan": {
                "status": "${{ needs.container-scan.result }}",
                "tool": "Trivy"
              }
            },
            "summary": {
              "total_checks": 4,
              "passed": $(echo '${{ needs.sast.result }} ${{ needs.sca.result }} ${{ needs.secrets.result }} ${{ needs.container-scan.result }}' | grep -o "success" | wc -l),
              "failed": $(echo '${{ needs.sast.result }} ${{ needs.sca.result }} ${{ needs.secrets.result }} ${{ needs.container-scan.result }}' | grep -o "failure" | wc -l),
              "overall_status": "$([[ "${{ needs.sast.result }}" == "failure" ]] || [[ "${{ needs.sca.result }}" == "failure" ]] || [[ "${{ needs.secrets.result }}" == "failure" ]] || [[ "${{ needs.container-scan.result }}" == "failure" ]] && echo "FAILED" || echo "PASSED")"
            }
          }
          EOF

          echo "📄 Security Report Generated:"
          cat security-report.json | jq '.'

      - name: Upload JSON Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json

      - name: Summary
        run: |
          echo "## 🔒 Security Scan Complete" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "### Job Results:" >> $GITHUB_STEP_SUMMARY
          echo "- SAST: ${{ needs.sast.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- SCA: ${{ needs.sca.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- Secrets: ${{ needs.secrets.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- Container Scan: ${{ needs.container-scan.result }}" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "📥 **JSON Report available in artifacts**" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY

          if [[ "${{ needs.sast.result }}" == "failure" ]] || \
             [[ "${{ needs.sca.result }}" == "failure" ]] || \
             [[ "${{ needs.secrets.result }}" == "failure" ]] || \
             [[ "${{ needs.container-scan.result }}" == "failure" ]]; then
            echo "❌ **Security issues detected!**" >> $GITHUB_STEP_SUMMARY
            echo "" >> $GITHUB_STEP_SUMMARY
            echo "⚠️ Please review the failed jobs above" >> $GITHUB_STEP_SUMMARY
            exit 1
          else
            echo "✅ All security checks passed" >> $GITHUB_STEP_SUMMARY
          fi

```

### 2.2 Commit et observer

```bash
git add .
git commit -m "feat: Add vulnerable app + DevSecOps pipeline"
git push origin main

```

➡️ **Rendez-vous dans l'onglet "Actions"** de votre repo GitHub

---

## Section 3 : Analyse des résultats

### 3.1 Vulnérabilités détectées

Après l'exécution du pipeline, que remarquez vous ?

| Outil | Résultat | Vulnérabilités trouvées |
| --- | --- | --- |
| **Semgrep** | ❌ | Secrets hardcodés, manque validation |
| **npm audit** | ❌ | Dépendances obsolètes (CVE) |
| **Gitleaks** | ❌ | Secret détecté dans le code |
| **Trivy** | ❌ | Vulnérabilités dans l'image Docker |

### 3.2 Consulter les rapports

1. **GitHub Security** : Onglet "Security" > "Code scanning"
2. **Artifacts** : Télécharger les rapports JSON
3. **Logs** : Détails dans chaque job

---

## Section 4 : Corrections

### 4.1 Mise à jour des dépendances

**src/package.json** (corrigé) :

```json
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

### 4.2 Code sécurisé

**src/server.js** (corrigé) :

```javascript
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// ✅ Secret depuis variable d'environnement
const SECRET = process.env.JWT_SECRET;

if (!SECRET || SECRET.length < 32) {
  console.error('JWT_SECRET must be set and at least 32 characters');
  process.exit(1);
}

// ✅ Sécurité
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// ✅ Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

// ✅ Validation des entrées
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
    
    const { username, password } = req.body;
    
    // Ici : vérification réelle avec bcrypt + DB
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
      const token = jwt.sign(
        { username },
        SECRET,
        { expiresIn: '1h' }
      );
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  }
);

// ✅ Endpoint de santé (sans infos sensibles)
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// ✅ Pas d'endpoint de debug en production
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug', (req, res) => {
    res.json({ message: 'Debug mode' });
  });
}

app.listen(3000, () => console.log('✅ Secure server running'));

```

### 4.3 Variables d'environnement

**.env.example** :

```bash
JWT_SECRET=generate-a-strong-random-secret-min-32-chars
ADMIN_USER=admin
ADMIN_PASS=strong-password-here
NODE_ENV=production

```

**Ajoutez `.env` au .gitignore** :

```bash
echo ".env" >> .gitignore

```

### 4.4 Dockerfile sécurisé

```dockerfile
# ✅ Image Alpine (plus légère et sécurisée) - Version la plus récente
FROM node:22-alpine

WORKDIR /app

# ✅ Copie des dépendances d'abord (cache)
COPY src/package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY src/ ./

# ✅ Utilisateur non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 3000

# ✅ Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "server.js"]

```

### 4.5 GitHub Secrets

1. Allez dans **Settings** > **Secrets and variables** > **Actions**
2. Ajoutez :
* `JWT_SECRET` : (générez avec `openssl rand -base64 32`)
* `ADMIN_USER` : admin
* `ADMIN_PASS` : (mot de passe fort)



### 4.6 Commit des corrections

```bash
git add .
git commit -m "fix: Apply all security fixes"
git push origin main

```

**Le pipeline devrait maintenant être vert !** ✅

---

## Section 5 : Tests DAST (optionnel)

### 5.1 Ajout du scan OWASP ZAP

Si vous voulez tester l'app en production, ajoutez ce job :

```yaml
  # Après container-scan
  dast:
    name: ⚡ DAST
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/download-artifact@v4
        with:
          name: docker-image
      
      - name: Load and run app
        run: |
          docker load < image.tar
          docker run -d -p 3000:3000 --name app vuln-app:${{ github.sha }}
          sleep 5
      
      - name: OWASP ZAP Baseline
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: 'http://localhost:3000'
          allow_issue_writing: false

```

**Note** : Pour des besoins pédagogiques, **ce test sur localhost suffit** ! Pas besoin de VPS.

---

### **Alternative gratuite : GitHub Pages**

Pour le frontend uniquement (pas l'API) :

```yaml
  deploy:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v4
      - uses: actions/upload-pages-artifact@v3
        with:
          path: './frontend/build'
      - uses: actions/deploy-pages@v4

```

---

## Exercices Pratiques

### Exercice 1 : Ajoutez une nouvelle vulnérabilité

Ajoutez une injection SQL dans le code, puis vérifiez que Semgrep la détecte.

### Exercice 2 : Créez un badge de sécurité

Ajoutez dans votre **[README.md](https://www.google.com/search?q=http://README.html)** :

```markdown
![Security](https://github.com/<user>/<repo>/workflows/DevSecOps%20Pipeline/badge.svg)

```

### Exercice 3 : Configurez CodeQL

Ajoutez CodeQL (l'outil SAST de GitHub) :

```yaml
  codeql:
    name: 🔍 CodeQL
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: javascript
      
      - name: Autobuild
        uses: github/codeql-action/autobuild@v3
      
      - name: Perform Analysis
        uses: github/codeql-action/analyze@v3

```

### Exercice 4 : Politique de sécurité stricte

Ajoutez un job qui **bloque** le merge si vulnérabilités critiques :

```yaml
  security-gate:
    name: 🚦 Security Gate
    runs-on: ubuntu-latest
    needs: [sast, sca, container-scan]
    steps:
      - name: Check results
        run: |
          # Logique pour vérifier les résultats
          # Exit 1 si critique trouvé
          echo "✅ No critical vulnerabilities"

```

---

## Projet Final (à rendre)

### Objectif

Sécurisez une application de votre choix (ou celle fournie) et présentez :

1. **Repo GitHub** avec :
* ✅ Code sécurisé
* ✅ Pipeline DevSecOps fonctionnel
* ✅ README complet


2. **Rapport** :
* Vulnérabilités trouvées (avant)
* Corrections appliquées (après)
* Métriques (nombre de vulns par sévérité)
* Leçons apprises


3. **Présentation** :
* Démo du pipeline
* Explication des outils
* Recommandations



---

## 📚 Ressources

**Documentation** :

* [GitHub Actions](https://docs.github.com/en/actions)
* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [Semgrep Rules](https://semgrep.dev/explore)

**Outils** :

* [Semgrep Playground](https://semgrep.dev/playground)
* [Snyk](https://snyk.io/)
* [GitHub Security Lab](https://securitylab.github.com/)

**Entraînement** :

* [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
* [TryHackMe DevSecOps](https://tryhackme.com/)

---

## ✅ Checklist finale

Avant de rendre votre projet, vérifiez :

* [ ] Pipeline s'exécute sans erreur
* [ ] Tous les secrets sont dans GitHub Secrets (pas dans le code)
* [ ] Dépendances à jour (pas de CVE critiques)
* [ ] Dockerfile sécurisé (utilisateur non-root, image alpine)
* [ ] [README.md](https://www.google.com/search?q=http://README.html) complet avec instructions
* [ ] Badge de build dans le README
* [ ] .gitignore contient .env
* [ ] Tests de sécurité passent (ou justification si échec)

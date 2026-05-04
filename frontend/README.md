# DIRISI 2025 Hackathon – Frontend Streamlit

> **Application web Streamlit pour l'anticipation des pannes réseau par l'IA**
> **Interface simplifiée pour l'aide à la décision et la simulation**

[![Streamlit](https://img.shields.io/badge/Streamlit-1.30-red)](https://streamlit.io/)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![Plotly](https://img.shields.io/badge/Plotly-5.18-blue)](https://plotly.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue)](https://www.docker.com/)
[![Offline-First](https://img.shields.io/badge/Mode-Offline--First-green)](#-mode-offline)

> **Emplacement monorepo** : ce dossier vit sous `ILab-Hackaton_CND-Phase2-Cyberattack_AI_detection/frontend/`. Pour lancer back + front : `cd frontend && make docker-up` (voir README racine du dépôt).

---

## 📋 Vue d'ensemble

Interface web **Streamlit** pour la gestion et la prédiction de pannes réseau.

> ⚠️ **Note**: Le frontend a été migré de React vers Streamlit pour une meilleure compatibilité avec l'environnement Jupyter Lab OVHcloud (pas de Node.js disponible).

**Fonctionnalités principales:**

* 📊 Visualiser la topologie réseau en temps réel
* 🔮 Prédire les risques de panne (IA/ML)
* 🎯 Générer des plans d'action optimisés
* 🧪 Simuler des scénarios de défaillance (*what-if*)
* 📈 Tracer et expliquer les décisions ML (explicabilité)

**Points clés:**

* ✅ **Offline-First** : fonctionne sans backend (fixtures locales)
* ✅ **Simple** : une seule commande pour démarrer
* ✅ **Interactif** : visualisations Plotly intégrées
* ✅ **Production-Ready** : Docker Compose, prêt pour déploiement

---

## 📚 Table des matières

* [🚀 Démarrage rapide](#-démarrage-rapide)
* [✨ Fonctionnalités](#-fonctionnalités)
* [🏗️ Architecture](#️-architecture)
* [🔌 Mode Offline](#-mode-offline)
* [🐳 Docker](#-docker)
* [📂 Structure du projet](#-structure-du-projet)
* [🔧 Configuration](#-configuration)
* [🔄 Migration React → Streamlit](#-migration-react--streamlit)

---

## 🚀 Démarrage Rapide

### Développement local

```bash
# Installer les dépendances
pip install -r requirements.txt

# Lancer Streamlit
streamlit run streamlit_app.py

# Ou avec make
make streamlit
```

### Avec Docker

```bash
# Build et run
make streamlit-docker

# Ou manuellement
docker build -t dirisi-frontend:latest -f Dockerfile.streamlit .
docker run -p 3000:3000 dirisi-frontend:latest
```

### Stack complète (Backend + Frontend)

```bash
cd docker
docker-compose up
```

## 📋 Fonctionnalités

- 📊 **Dashboard**: Vue d'ensemble du réseau et métriques clés
- 🌐 **Topologie**: Visualisation interactive du graphe réseau avec Plotly
- 🔮 **Prédictions**: Prédiction de pannes avec IA
- 📋 **Planification**: Génération de plans d'action optimisés
- 🎮 **Simulation**: Scénarios What-If
- 🔄 **Mode Offline**: Utilise les fixtures quand le backend est indisponible

## 🛠️ Technologies

- **Streamlit** - Framework web Python
- **Plotly** - Visualisations interactives
- **Pandas** - Traitement des données
- **Requests** - Appels API

## 🔧 Configuration

### Variables d'environnement

```bash
# URL du backend (défaut: http://localhost:8080)
export VITE_API_BASE=http://localhost:8080

# Ou
export BACKEND_URL=http://localhost:8080
```

### Sur Jupyter Lab OVHcloud

```bash
# Le backend tourne sur le port 8000 (8080 réservé par Jupyter)
export VITE_API_BASE=http://localhost:8000
streamlit run streamlit_app.py --server.port 3000 --server.address 0.0.0.0 --server.headless true
```

## 📂 Structure

```
├── streamlit_app.py          # Application Streamlit principale
├── requirements.txt          # Dépendances Python
├── Dockerfile.streamlit      # Dockerfile Streamlit
├── src/
│   └── fixtures/            # Données de test (mode offline)
│       ├── topology.json
│       ├── predictions.json
│       ├── plan.json
│       └── simulate.json
└── docker/
    ├── Dockerfile           # Dockerfile React (legacy)
    └── docker-compose.yml   # Stack complète
```

## 🔄 Migration React → Streamlit

### Correspondance des fonctionnalités

| React (ancien)              | Streamlit (nouveau)        |
|-----------------------------|----------------------------|
| React Router                | Sidebar navigation         |
| Zustand stores              | Session state              |
| TypeScript types            | Python types               |
| Vite + Node.js              | Streamlit CLI              |
| TailwindCSS                 | Streamlit native + CSS     |
| Caddy server                | Streamlit server           |

### Routes API utilisées (identiques)

- `GET /health` - Health check
- `GET /v1/topology` - Topologie réseau  
- `POST /v1/predict` - Prédictions
- `POST /v1/plan` - Planification
- `POST /v1/simulate` - Simulation
- `GET /v1/explain` - Explications
- `GET /v1/metrics` - Métriques
- `POST /v1/ingest` - Ingestion de données

## 🧪 Tests

```bash
# Tests unitaires (React legacy)
make test

# Tests E2E (React legacy)
make e2e
```

## 🐳 Docker

### Build

```bash
docker build -t dirisi-frontend:latest -f Dockerfile.streamlit .
```

### Run

```bash
docker run -p 3000:3000 \
  -e VITE_API_BASE=http://backend:8080 \
  dirisi-frontend:latest
```

## 📖 Documentation

- [README_STREAMLIT.md](README_STREAMLIT.md) - Documentation Streamlit détaillée
- [docs/](docs/) - Documentation React (legacy)

## 🤝 Contribution

Voir [CONTRIBUTING.md](../dirisi25-hackathon-backend/CONTRIBUTING.md)

## 📝 License

MIT - Voir [LICENSE](../dirisi25-hackathon-backend/LICENSE)

* 📊 Visualiser la topologie réseau en temps (quasi) réel
* 🔮 Prédire les risques de panne (IA/ML)
* 🎯 Générer des plans d’action optimisés
* 🧪 Simuler des scénarios de défaillance (*what-if*)
* 📈 Tracer et expliquer les décisions ML (explicabilité)

**Points clés**

* ✅ **Offline-First** : fonctionne sans backend (fixtures locales)
* ✅ **Performant** : bundle < **300 KB** gzippé
* ✅ **Sécurisé** : CSP stricte, pas de CDN externe, Caddy durci
* ✅ **Explicable** : features & règles visibles
* ✅ **Production-Ready** : Docker Compose, tests E2E, CI/CD-ready

---

## 📚 Table des matières

* [🚀 Démarrage rapide](#-démarrage-rapide)
* [🎯 Contexte](#-contexte)
* [🏗️ Architecture](#️-architecture)
* [✨ Fonctionnalités](#-fonctionnalités)
* [🐳 Docker](#-docker)
* [🧪 Tests](#-tests)
* [🔌 Mode Offline](#-mode-offline)
* [🔒 Sécurité](#-sécurité)
* [📂 Structure du projet](#-structure-du-projet)
* [🛠️ Développement](#️-développement)
* [📄 Pages](#-pages)
* [❓ Inconnues & Actions](#-inconnues--actions)
* [📄 Licence & 👥 Équipe](#-licence--équipe)

---


## 🚀 Démarrage rapide

### Option 1 – Docker Compose (recommandé)

```bash
# Arborescence requise
DIRISI-Hackathon/
├── dirisi25-hackathon-frontend/   # Ce repo
└── dirisi25-hackathon-backend/    # Backend requis

# Lancer tout
cd dirisi25-hackathon-frontend
make docker
```

Lance :

* Frontend Streamlit : `http://localhost:3000`
* Backend FastAPI : `http://localhost:8080`
* Réseau Docker isolé avec healthchecks

Arrêt propre : **Ctrl+C** ou `docker-compose down`

### Option 2 – Développement local

```bash
# Installation
pip install -r requirements.txt

# Lancer Streamlit (nécessite backend sur 8080)
streamlit run streamlit_app.py

# Ou avec make
make streamlit
```

Le frontend sera accessible sur `http://localhost:8501`

### Option 3 – Streamlit avec Docker seul

```bash
# Build
docker build -t dirisi-frontend:latest -f Dockerfile.streamlit .

# Run
docker run -p 3000:3000 \
  -e VITE_API_BASE=http://backend:8080 \
  dirisi-frontend:latest
```

---

## ✨ Fonctionnalités

### Pages principales

1. **📊 Dashboard**
   - Vue d'ensemble du réseau
   - Métriques clés en temps réel
   - Indicateurs de santé

2. **🌐 Topologie**
   - Graphe interactif du réseau (Plotly)
   - Visualisation des nœuds et liens
   - État en temps réel

3. **🔮 Prédictions**
   - Sélection de cibles (nœuds/liens)
   - Prédiction de risque de panne (ML)
   - Score de risque et ETA
   - Explications des prédictions

4. **📋 Planification**
   - Génération de plans d'action
   - Optimisation multi-objectifs
   - Actions recommandées (rerouting, scaling, etc.)

5. **🎮 Simulation**
   - Scénarios What-If
   - Simulation de pannes
   - Impact sur le réseau

### Mode Offline

✅ L'application fonctionne **sans backend** grâce aux fixtures :
- Active automatiquement si le backend est indisponible
- Données de test dans `src/fixtures/`
- Switch manuel possible via la sidebar

---

## 🏗️ Architecture

### Stack technique

| Technologie | Version | Usage                     |
|-------------|---------|---------------------------|
| Streamlit   | 1.30+   | Framework web             |
| Python      | 3.11    | Langage                   |
| Plotly      | 5.18+   | Visualisations            |
| Pandas      | 2.1+    | Traitement données        |
| Requests    | 2.31+   | Appels API                |
| Docker      | 24+     | Conteneurisation          |

### Architecture applicative

```

┌─────────────────────────────────────────────────────────────┐
│              Frontend Streamlit (Python 3.11)               │
│  Pages    → Dashboard / Topology / Predict / Plan / Simulate│
│  Services → API calls via requests                          │
│  State    → st.session_state (ui, data, mode)               │
│  Mode ONLINE → Backend API (localhost:8080)                 │
│  Mode OFFLINE → fixtures/*.json (seed 42)                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
                    ┌──────────────────┐
                    │  Backend FastAPI │
                    │  (port 8080)     │
                    └──────────────────┘
```

### Flux de données

```
User → Streamlit UI → Session State
                ↓
         Backend Check
                ↓
    ┌───────────┴───────────┐
    ↓                       ↓
ONLINE Mode             OFFLINE Mode
    ↓                       ↓
API Call                Fixtures
    ↓                       ↓
Response → Display
```

---

## 🔌 Mode Offline

L'application détecte automatiquement si le backend est disponible :

- ✅ **Backend disponible** : Mode ONLINE (données en temps réel)
- ❌ **Backend indisponible** : Mode OFFLINE (fixtures locales)

**Fixtures incluses** (`src/fixtures/`) :
- `topology.json` - Structure du réseau
- `predictions.json` - Exemples de prédictions
- `plan.json` - Plans d'action
- `simulate.json` - Résultats de simulation
- `health.json` - État de santé

**Switch manuel** : Bouton dans la sidebar pour forcer le mode

---

## 🐳 Docker

### Fichiers

```
docker/
├── Dockerfile.streamlit   # Image Streamlit
└── docker-compose.yml     # Stack complète
```

### Docker Compose



```bash
# Lancer la stack complète
cd docker
docker-compose up

# En arrière-plan
docker-compose up -d

# Arrêter
docker-compose down

# Rebuild
docker-compose build

# Logs
docker-compose logs -f frontend
```

**Services exposés:**
- Frontend : `http://localhost:3000`
- Backend : `http://localhost:8080`

---

## 📂 Structure du projet

```
dirisi25-hackathon-frontend/
├── streamlit_app.py           # Application principale
├── requirements.txt           # Dépendances Python
├── Dockerfile.streamlit       # Image Docker
├── Makefile                   # Commandes utiles
├── src/
│   └── fixtures/             # Données de test (mode offline)
│       ├── topology.json
│       ├── predictions.json
│       ├── plan.json
│       ├── simulate.json
│       └── health.json
├── docker/
│   ├── Dockerfile            # React legacy (archivé)
│   ├── Caddyfile             # React legacy
│   └── docker-compose.yml    # Stack complète
└── docs/                     # Documentation React legacy
```

---

## 🔧 Configuration

### Variables d'environnement

```bash
# URL du backend
export VITE_API_BASE=http://localhost:8080
# ou
export BACKEND_URL=http://localhost:8080
```

### Configuration Streamlit

Créer `.streamlit/config.toml` :

```toml
[server]
port = 3000
address = "0.0.0.0"
headless = true

[theme]
primaryColor = "#3B82F6"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F3F4F6"
textColor = "#1F2937"
```

### Déploiement Jupyter Lab OVHcloud

```bash
# Le backend utilise le port 8000 (8080 réservé)
export VITE_API_BASE=http://localhost:8000

# Lancer Streamlit
streamlit run streamlit_app.py \
  --server.port 3000 \
  --server.address 0.0.0.0 \
  --server.headless true
```

---

## 🔄 Migration React → Streamlit

### Raisons de la migration

1. **Compatibilité Jupyter Lab** : Pas de Node.js disponible sur l'environnement OVHcloud
2. **Simplicité** : Moins de dépendances, stack Python unifiée
3. **Rapidité de développement** : Moins de code, prototypage rapide
4. **Visualisations** : Plotly intégré nativement

### Correspondance des fonctionnalités

| React (ancien)              | Streamlit (nouveau)        |
|-----------------------------|----------------------------|
| React Router                | Sidebar navigation         |
| Zustand stores              | st.session_state           |
| TypeScript types            | Python type hints          |
| Vite + npm                  | Streamlit CLI + pip        |
| TailwindCSS                 | Streamlit native + CSS     |
| Caddy server                | Streamlit server           |
| Plotly.js                   | Plotly Python              |
| axios/fetch                 | requests                   |

### API Backend (inchangée)

Toutes les routes API restent identiques :

- `GET /health` - Health check
- `GET /v1/topology` - Topologie réseau  
- `POST /v1/predict` - Prédictions
- `POST /v1/plan` - Planification
- `POST /v1/simulate` - Simulation
- `GET /v1/explain` - Explications
- `GET /v1/metrics` - Métriques
- `POST /v1/ingest` - Ingestion de données

### Code Legacy

Le code React original est conservé dans :
- `src/` (composants TypeScript/React)
- `docs/` (documentation React)
- `docker/Dockerfile` (build React/Caddy)

---

## 🤝 Contribution

Voir [CONTRIBUTING.md](../dirisi25-hackathon-backend/CONTRIBUTING.md) dans le backend

---

## 📝 License

MIT - Voir [LICENSE](../dirisi25-hackathon-backend/LICENSE)

---

## 🎯 Contexte

**Hackathon DIRISI 2025** — Thème : **« Anticiper les pannes par l'IA »**

Application **offline-first** démontrable sans internet : visualisation en temps réel, prédiction ML, planification optimisée, simulation what-if, et explicabilité des décisions.

---

## 🔌 Mode Offline

**Détection auto** au boot :

* `GET /health` timeout 2s → si échec : **OFFLINE** ; si succès : **ONLINE**

**Fixtures locales** (`src/fixtures/`):

```
health.json • topology.json • predictions.json • plan.json • simulate.json
```

**UI dégradée** : badge OFFLINE, bouton **Re-essayer**, toutes pages fonctionnelles.

---

## 🔒 Sécurité

### CSP (ex. via Caddy)

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data: https:;
  connect-src 'self' http://localhost:8080 http://127.0.0.1:8080;
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none';
```

**Headers** : `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`,
`Referrer-Policy`, `Permissions-Policy`.
**Principes** : No-CDN, no-analytics, no-cookies, no-eval, HTTPS en prod, timeouts API.

---

## 📂 Structure du projet

```
dirisi25-hackathon-frontend/
├── docker/               # Dockerfile, Caddyfile, compose
├── docs/                 # DOCKER_GUIDE, QUICKSTART, etc.
├── scripts/              # check/start/test docker
├── src/
│   ├── components/       # UI réutilisable
│   ├── routes/           # pages
│   ├── services/         # appels backend, logique métier
│   ├── store/            # Zustand
│   ├── types/            # TS types
│   ├── fixtures/         # données offline
│   └── lib/              # utils (api, layout, format)
├── tests/                # unit + e2e
├── .env.example
├── .eslintrc.cjs
├── .prettierrc
├── playwright.config.ts
├── vite.config.ts
├── vitest.config.ts
├── tailwind.config.js
├── package.json
└── Makefile
```

---

## 🛠️ Développement

### Prérequis

* Node.js 18+, npm 9+
* Docker & Docker Compose (pour la démo complète)

### Setup & scripts

```bash
git clone git@github.com:Rqbln/dirisi25-hackathon-frontend.git
cd dirisi25-hackathon-frontend
npm ci
cp .env.example .env

npm run dev           # serveur dev (HMR)
npm run build         # build prod
npm run preview       # preview du build
npm run lint          # eslint
npm run format        # prettier
npm run type-check    # TS noEmit

# équivalents Make
make dev | make build | make preview | make test | make e2e | make lint | make format
```

**Conventions**

* TypeScript strict (pas de `any`)
* Functional components + hooks
* Tailwind (purge actif)
* Conventional commits (`feat:`, `fix:`, `docs:`, …)

---

## 📄 Pages

* `/` **Dashboard** : 6 cartes métriques, alertes triables
* `/topology` **Carte** : SVG interactif (survol/clic)
* `/predict` **Prédictions** : horizon, cibles, risk bands + explications
* `/plan` **Planification** : objectifs/contraintes → actions + gains
* `/simulate` **Simulation** : scénarios panne (durée/intensité) → impact + plan
* `/about` **À propos** : contexte, statut, liens docs

---

## ❓ Inconnues & Actions

**Inconnues**

1. **Design tokens Défense** : palettes/couleurs officielles ?
2. **Critères UX** : interopérabilité, a11y, perf ?
3. **Sécurité poste** : navigateur imposé (Firefox ESR ?), poste isolé ?
4. **Données réelles** : volumétrie/latences (pagination/virtualisation) ?
5. **Déploiement** : intranet Défense / proxys / ports autorisés ?

**Plan A (actuel)** : UI minimaliste + fixtures + backend local, offline-first
**Plan B (si autorisé)** : polling 5–10s / WebSocket notifications / export PDF / thème Défense / virtualisation >1000 entités

**Objectifs perf** : bundle < 300 KB, FP < 1s, TTI < 2s, Lighthouse > 90

---

## 📄 Licence & 👥 Équipe

**Licence** : MIT — voir `LICENSE`
**Équipe** : Projet Hackathon DIRISI 2025 — *Anticiper les pannes par l’IA*

> **Note déploiement**
>
> * Front & back dans le même dossier parent (compose)
> * `make docker` lance automatiquement les deux services
> * En prod : HTTPS dans le Caddyfile + variables d’environnement sécurisées

---
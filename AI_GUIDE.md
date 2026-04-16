# Guide IA pour ShareMyBleedings

> Ce fichier est concu pour qu'un RSSI ou un ingenieur securite puisse copier-coller ce contexte dans Claude, ChatGPT, OpenCode ou tout autre assistant IA pour comprendre, modifier et ameliorer le projet rapidement.

---

## Qu'est-ce que ShareMyBleedings ?

Outil d'audit SMB en lecture seule pour equipes blue/purple team.

**Ce qu'il fait en 4 etapes :**
1. **Decouverte** — Scan TCP/445 pour trouver les machines SMB sur le reseau
2. **Enumeration** — Connexion SMB via impacket, liste des partages
3. **Analyse ACL** — Lecture des permissions, scoring du risque (CRITICAL/HIGH/MEDIUM/INFO)
4. **Rapport** — Dashboard HTML interactif autonome (un seul fichier, zero dependance externe)

**Optionnel :** Scan de contenu sensible (mots de passe, cles, IBAN...) via manspider.

---

## Stack technique

| Composant | Technologie |
|-----------|------------|
| Langage | Python 3.11+ |
| CLI | Typer (sous-commandes) |
| Affichage console | Rich (progress bars, tables, couleurs) |
| Connexion SMB | impacket (SMBConnection, ACL, SID) |
| Decouverte reseau | asyncio + socket natif (nmap optionnel) |
| Template HTML | Jinja2 pour le rapport, HTML/CSS/JS inline pour le dashboard |
| Config | TOML optionnel + .env + CLI flags |
| Tests | pytest avec mocks (pas de reseau reel) |

---

## Architecture des fichiers

```
ShareMyBleedings/
├── smb_bleedings/                  # Code source principal
│   ├── __init__.py                 # Version (7 lignes)
│   ├── main.py                     # CLI Typer — point d'entree (587 lignes)
│   ├── config.py                   # PipelineConfig dataclass, chargement .env/TOML (202 lignes)
│   ├── models.py                   # Dataclasses : Host, Share, AclEntry, Finding... (81 lignes)
│   ├── pipeline.py                 # Orchestrateur des 4 etapes (374 lignes)
│   │
│   ├── agents/                     # Les 4+1 agents du pipeline
│   │   ├── discovery.py            # Etape 1 : scan reseau TCP/445 (196 lignes)
│   │   ├── enumerator.py           # Etape 2 : liste des partages SMB (381 lignes)
│   │   ├── acl_analyzer.py         # Etape 3 : lecture ACL + scoring (584 lignes)
│   │   ├── content_scanner.py      # Optionnel : scan fichiers sensibles (428 lignes)
│   │   └── reporter.py             # Etape 4 : generation JSON/CSV/XLSX (708 lignes)
│   │
│   └── utils/
│       ├── cidr.py                 # Parsing plages CIDR (84 lignes)
│       ├── risk.py                 # RISK_MATRIX + score_acl() (288 lignes)
│       ├── sid_resolver.py         # Resolution SID→nom via LDAP (286 lignes)
│       └── templates/
│           ├── dashboard.html      # Dashboard HTML autonome complet (5425 lignes)
│           └── report.html.j2      # Template Jinja2 rapport exportable
│
├── tests/                          # Tests pytest (mocks, pas de reseau)
│   ├── test_discovery.py           # Tests decouverte (121 lignes)
│   ├── test_acl_analyzer.py        # Tests analyse ACL (78 lignes)
│   ├── test_risk.py                # Tests scoring risque (188 lignes)
│   ├── test_reporter.py            # Tests generation rapport (244 lignes)
│   ├── test_config.py              # Tests configuration (250 lignes)
│   ├── test_content_scanner.py     # Tests scan contenu (160 lignes)
│   ├── test_pipeline.py            # Tests pipeline complet (132 lignes)
│   └── test_main_utils.py          # Tests utilitaires CLI (77 lignes)
│
├── examples/                       # Donnees de demo
│   ├── corporate_audit.json        # Jeu 1 : audit siege social (FR, 10 findings)
│   ├── multi_site_audit.json       # Jeu 2 : audit multi-sites (EN, 11 findings)
│   └── demo_dashboard.html         # Dashboard pre-genere
│
├── pyproject.toml                  # Config projet, dependances, entry point
├── config.example.toml             # Exemple de config TOML
├── .env.example                    # Exemple de variables d'environnement
├── Dockerfile + docker-compose.yml # Conteneurisation
├── README.md                       # Documentation utilisateur
├── LICENSE                         # MIT
└── CLAUDE.md                       # Instructions pour Claude Code
```

---

## Comment installer et tester

```bash
# Cloner et installer
git clone <repo-url>
cd ShareMyBleedings
pip install -e ".[dev,nmap]"

# Lancer les tests (141 tests, pas de reseau requis)
pytest

# Generer le dashboard de demo
bleedings dashboard -o demo.html --no-browser

# Scan reel (necessite un reseau avec du SMB)
bleedings scan --ranges 192.168.1.0/24 -o rapport.json
bleedings dashboard -o dashboard.html
```

---

## Commandes CLI disponibles

| Commande | Description |
|----------|-------------|
| `bleedings scan --ranges <CIDR>` | Scan complet : decouverte → enumeration → ACL → JSON |
| `bleedings scan --ranges <CIDR> -u DOMAIN\\user -p pass` | Scan avec credentials AD |
| `bleedings demo` | Genere un JSON de demo (pas de reseau) |
| `bleedings dashboard -o dash.html` | Genere le dashboard HTML statique |

---

## Logique de scoring de risque (fichier cle : `utils/risk.py`)

La matrice `RISK_MATRIX` est le coeur du scoring :

| Condition | Niveau | Score |
|-----------|--------|-------|
| Everyone + Full/Change | CRITICAL | 95 |
| Domain Users + Full/Change | CRITICAL | 85-90 |
| Authenticated Users + Full/Change | CRITICAL | 85 |
| BUILTIN\Users + Full/Change | HIGH | 75 |
| Everyone + Read | HIGH | 65 |
| Domain Users + Read | MEDIUM | 40 |
| Authenticated Users + Read | MEDIUM | 35 |
| Partage AD legitime (NETLOGON, SYSVOL) | INFO | 10 |

Les raisons sont bilingues (FR/EN) via des dicts `{"en": ..., "fr": ...}`.

---

## Format JSON de sortie

Structure du fichier JSON genere par `bleedings scan` ou `bleedings demo` :

```json
{
  "meta": {
    "tool": "ShareMyBleedings",
    "version": "1.0.0",
    "title": "...",
    "generated_at": "2026-04-15T09:32:17+00:00",
    "duration_seconds": 124.7,
    "ranges": ["192.168.1.0/24"],
    "total_ips_scanned": 256,
    "hosts_discovered": 8,
    "lang": "fr"
  },
  "summary": {
    "critical": 3, "high": 3, "medium": 2, "info": 2,
    "total_findings": 10, "hosts_with_findings": 7
  },
  "findings": [
    {
      "risk_level": "CRITICAL|HIGH|MEDIUM|INFO",
      "risk_score": 0-100,
      "host": { "ip": "...", "hostname": "...", "smb_version": "...", "signing_required": true/false },
      "share": { "name": "...", "unc_path": "...", "description": "...", "share_type": "disk", "anonymous_access": false },
      "acl": [{ "account": "...", "access_right": "Full|Change|Read", "ace_type": "Allow|Deny" }],
      "all_acl": [/* toutes les ACE, y compris legitimes */],
      "reasons": ["Explication humaine du risque"],
      "impacts": ["Impact metier concret"],
      "recommendations": ["Action corrective avec commande"],
      "content_matches": [
        { "file_path": "...", "file_size": 1234, "matched_keywords": ["password", "iban"], "sha256": "..." }
      ]
    }
  ]
}
```

---

## Le Dashboard HTML (`utils/templates/dashboard.html`)

C'est le fichier le plus gros (5425 lignes). Un seul fichier HTML autonome contenant :

- **CSS complet** inline (dark/light themes via CSS variables)
- **JavaScript complet** inline (Chart.js, filtres, tri, recherche, export)
- **Pas de dependance externe** — fonctionne offline

### Fonctionnalites du dashboard :
- Import de fichiers JSON via drag & drop ou file picker
- Graphiques interactifs (repartition risques, timeline, heatmap)
- Filtrage par niveau de risque, recherche, tri par colonne
- Vue par machine (accordion) et vue par finding
- Contenu sensible : tableau avec checkboxes, actions masquer/supprimer
- Export de rapport HTML autonome depuis le dashboard
- Le rapport exporte supporte : dark/light theme, raccourcis clavier, impression, deep links, tooltips ACL

### Architecture JS du dashboard :
- `LOCALES` objet avec cles FR/EN, accesseur `L(key)`
- `CH` namespace pour Chart.js (colors, config, render)
- `renderFindingDetail(f, fi)` — rendu partage utilise par dashboard ET rapport exporte
- `exportReport()` — genere le HTML du rapport comme template literal
- CSS variables : `--rk-bg`, `--rk-text`, `--rk-border`, etc. (rapport), `--surface`, `--text`, `--border` (dashboard)

---

## Modeles de donnees (`models.py`)

```python
@dataclass
class Host:
    ip: str
    hostname: str | None = None
    port: int = 445
    os_hint: str | None = None
    reachable: bool = True

@dataclass
class Share:
    host: Host
    name: str
    unc_path: str
    description: str = ""
    share_type: str = "disk"
    is_system: bool = False

@dataclass
class AclEntry:
    account: str
    access_right: str   # "Full", "Change", "Read"
    ace_type: str       # "Allow", "Deny"

@dataclass
class Finding:
    share: Share
    acl_entries: list[AclEntry]
    risk_level: str     # "CRITICAL", "HIGH", "MEDIUM", "INFO"
    risk_score: int     # 0-100
    reasons: list[str]
```

---

## Convention de code

- **Type hints** sur toutes les fonctions
- **Dataclasses** pour tous les modeles (pas de dicts nus)
- **Pas de `print()`** — utiliser Rich Console ou logging
- **Erreurs reseau** : catchees et loguees, jamais fatales
- **Tests** : pytest avec mocks impacket, `asyncio_mode = "auto"`
- **Bilingue** : raisons et impacts en FR et EN via flag `--fr`
- Variables et commentaires parfois en francais

---

## Idees d'amelioration possibles

### Securite et fonctionnel
- [ ] Ajouter le support LDAP pour resolution automatique des groupes AD
- [ ] Detecter SMB signing desactive (deja dans les donnees, pas encore affiche clairement)
- [ ] Ajouter un score global de posture SMB du reseau (note /100)
- [ ] Exporter en PDF (via weasyprint ou puppeteer)
- [ ] Comparaison entre 2 scans (diff avant/apres remediation)
- [ ] Integration SIEM (export syslog/CEF)

### UX Dashboard
- [ ] Mode comparaison : charger 2 JSON et voir les differences
- [ ] Filtres avances (par subnet, par type de partage, par host)
- [ ] Timeline de remediation avec suivi des tickets
- [ ] Notifications email automatiques pour findings CRITICAL

### Code qualite
- [ ] Augmenter la couverture de tests (actuellement ~141 tests)
- [ ] Ajouter des tests E2E pour le dashboard (Playwright)
- [ ] Reduire la taille du dashboard.html (5400+ lignes → split en modules?)
- [ ] Ajouter mypy strict sur tout le projet

---

## Comment demander a l'IA de modifier le projet

### Exemples de prompts efficaces :

**Pour modifier le scoring :**
> "Dans le fichier smb_bleedings/utils/risk.py, ajoute une regle dans RISK_MATRIX pour detecter les comptes de service (SVC-*) avec des permissions Full et scorer ca en HIGH avec un score de 70."

**Pour modifier le dashboard :**
> "Dans smb_bleedings/utils/templates/dashboard.html, ajoute un bouton 'Exporter CSV' dans la section des findings qui genere un CSV avec les colonnes : host, share, risk_level, risk_score, reasons."

**Pour ajouter une commande CLI :**
> "Dans smb_bleedings/main.py, ajoute une commande 'compare' qui prend 2 fichiers JSON en entree et affiche les differences de findings entre les 2 scans."

**Pour corriger un bug :**
> "Lance pytest et corrige les tests qui echouent. Montre-moi le diff de chaque correction."

**Pour comprendre le code :**
> "Explique-moi le flux complet depuis la commande 'bleedings scan --ranges 192.168.1.0/24' jusqu'a la generation du JSON. Quels fichiers sont impliques et dans quel ordre ?"

---

## Commandes utiles pour l'IA

```bash
# Installer en mode dev
pip install -e ".[dev,nmap]"

# Lancer tous les tests
pytest

# Lancer un test specifique
pytest tests/test_risk.py -v

# Generer une demo
bleedings demo

# Generer le dashboard
bleedings dashboard -o test.html --no-browser

# Verifier les types (si mypy installe)
mypy smb_bleedings/

# Formater le code (si ruff installe)
ruff format smb_bleedings/
ruff check smb_bleedings/ --fix
```

---

## Points d'attention

1. **Le dashboard.html est un monolithe** — 5400+ lignes de HTML/CSS/JS inline. Toute modification doit etre testee visuellement en ouvrant le fichier dans un navigateur.

2. **Le rapport exporte est genere par JavaScript** — La fonction `exportReport()` dans le dashboard cree le HTML du rapport comme un template literal JS. Les modifications du rapport doivent etre faites dans cette fonction.

3. **Les 2 jeux de donnees de demo** sont dans `examples/` — `corporate_audit.json` (FR, 10 findings) et `multi_site_audit.json` (EN, 11 findings). Ils couvrent CRITICAL, HIGH, MEDIUM et INFO.

4. **Impacket n'est jamais appele dans les tests** — Tout est mocke. Les tests n'ont besoin d'aucun reseau.

5. **La config suit une priorite** : CLI flags > .env > TOML > defaults dans PipelineConfig.

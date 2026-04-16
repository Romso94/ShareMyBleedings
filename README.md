# ShareMyBleedings 🩸

> *"Because your network bleeds more than you think."*

**Read-only** SMB share audit toolkit for blue & purple teams.  
Discovers SMB hosts, enumerates shares, analyzes ACLs, scans file contents for secrets, and produces an interactive HTML dashboard.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Pipeline

```
CIDR ranges ──► Discovery ──► Enumeration ──► ACL Analysis ──► Report
                 TCP/445       SMB shares      Risk scoring     HTML/JSON/CSV
                 + nmap        + permissions    + recommendations
                                                     │
                                              Content Scanning
                                              (manspider, optional)
```

## Features

- **Network discovery** — async TCP/445 sweep + optional nmap fallback
- **Share enumeration** — anonymous, guest, or AD-authenticated
- **ACL analysis** — risk scoring with bilingual EN/FR explanations
- **Content scanning** — [manspider](https://github.com/blacklanternsecurity/MANSPIDER) integration (passwords, keys, PII)
- **Interactive dashboard** — single-file HTML, offline, filterable, CSV/PDF export
- **Checkpoint/resume** — long scans survive interruptions
- **Bilingual** — `--fr` for French output

---

## Installation

### Native (Linux / WSL)

```bash
git clone https://github.com/Romso94/ShareMyBleedings.git
cd ShareMyBleedings
./install.sh
```

Installs system deps, manspider, and `bleedings` CLI via pipx.  
Requires **Python >= 3.11** and apt-get (Debian/Ubuntu/WSL).

### Docker

```bash
git clone https://github.com/Romso94/ShareMyBleedings.git
cd ShareMyBleedings
docker compose build
docker compose run --rm bleedings scan 192.168.1.0/24 -o /out/report.json
```

Reports in `./out/`, manspider loot in `./loot/`.

### Manual (pip)

```bash
pip install -e ".[nmap]"
```

---

## Usage

```bash
# Sanity check — generates demo data, no network needed
bleedings demo

# Full scan with AD credentials
bleedings scan 192.168.1.0/24 -u DOMAIN\\user -p '***' -o report.json

# Scan + content search for secrets
bleedings scan 10.0.0.0/24 -u user -p '***' \
    --scan-content -k password -k api_key -k 'BEGIN.*PRIVATE KEY' \
    --loot-dir ./loot -o report.json

# French output
bleedings scan 192.168.1.0/24 -o report.json --fr

# From a file of CIDR ranges
bleedings scan -f ranges.txt -o report.json

# Generate standalone dashboard (import JSON in browser)
bleedings dashboard -o dashboard.html
```

### Step-by-step

Each pipeline stage can run independently:

```bash
bleedings discover  192.168.1.0/24     --out hosts.json
bleedings enumerate --hosts hosts.json  --out shares.json
bleedings analyze   --shares shares.json --out findings.json
bleedings report    --findings findings.json --out report.html
```

---

## Configuration

Copy `.env.example` to `.env`:

```env
SMB_USERNAME=DOMAIN\user
SMB_PASSWORD=secret
SMB_DOMAIN=DOMAIN
SMB_DC=dc01.domain.local
SMB_RANGES=192.168.1.0/24,10.0.0.0/24
```

Optional TOML config — see [`config.example.toml`](config.example.toml).

Priority: **CLI flags > .env > config.toml > defaults**.

---

## Safety

ShareMyBleedings is **strictly read-only** on target shares:

| Stage | Operation |
|-------|-----------|
| Discovery | TCP connect on port 445 |
| Enumeration | `NetShareEnum` (list only) |
| Permission test | `openFile()` with WRITE/DELETE bits — handle closed immediately, writes nothing |
| ACL analysis | `READ_CONTROL` + `queryInfo(SECURITY)` |
| Content scan | manspider in read-only mode (downloads matching files only) |

> **Note:** Permission probes may trigger Windows Event ID **4663** if file auditing (SACL) is enabled. Coordinate with your SOC before scanning monitored networks.

---

## Risk scoring

| Condition | Level | Score |
|-----------|-------|-------|
| Everyone + Full/Change | CRITICAL | 95 |
| Domain Users + Full/Change | CRITICAL | 90 |
| Authenticated Users + Full/Change | CRITICAL | 85 |
| BUILTIN\Users + Full/Change | HIGH | 75 |
| Everyone + Read | HIGH | 65 |
| Domain Users + Read | MEDIUM | 40 |
| Authenticated Users + Read | MEDIUM | 35 |

AD-legitimate shares (NETLOGON, SYSVOL) with standard read access are auto-downgraded to INFO.  
System shares (ADMIN$, IPC$, C$) are excluded by default.

---

## Output formats

| Format | Description |
|--------|-------------|
| **JSON** | Full structured data — use with the dashboard or your own tooling |
| **HTML dashboard** | Single-file, offline, dark/light theme, search, CSV export |
| **CSV** | One row per finding, UTF-8 BOM + `;` separator (Excel-friendly) |
| **XLSX** | Multi-sheet workbook (requires `pip install ".[xlsx]"`) |

---

## Project structure

```
smb_bleedings/
├── agents/
│   ├── discovery.py        # Stage 1: network scan
│   ├── enumerator.py       # Stage 2: share listing
│   ├── acl_analyzer.py     # Stage 3: ACL + risk scoring
│   ├── content_scanner.py  # Optional: manspider wrapper
│   └── reporter.py         # Stage 4: output generation
├── utils/
│   ├── risk.py             # Risk matrix + scoring logic
│   ├── sid_resolver.py     # SID → name via LDAP
│   ├── cidr.py             # CIDR parsing
│   └── templates/          # Jinja2 + dashboard HTML
├── models.py               # Dataclasses (Host, Share, Finding...)
├── config.py               # Config loading (TOML + .env)
├── pipeline.py             # Orchestrator
└── main.py                 # Typer CLI
```

---

## Demo data

The `examples/` folder contains sample datasets to test the dashboard without a real network:

| File | Description |
|------|-------------|
| `corporate_audit.json` | Initial audit — HQ network, 10 findings (FR) |
| `corporate_audit_Q3.json` | Same network 3 months later — post-remediation |
| `multi_site_audit.json` | Multi-site audit — Paris/Lyon/Remote, 11 findings (EN) |
| `multi_site_audit_Q3.json` | Same multi-site network — post-remediation |
| `demo_dashboard.html` | Pre-generated dashboard |

Import multiple JSON files into the dashboard to compare scan evolution over time.

---

## AI-assisted development

See **[AI_GUIDE.md](AI_GUIDE.md)** — a comprehensive guide designed for CISOs and security engineers who want to use Claude, ChatGPT, or other AI assistants to understand, modify, and improve this project. Contains full architecture docs, prompt examples, and improvement ideas.

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Run tests: `pytest`
4. Open a PR

---

## License

MIT — see [LICENSE](LICENSE).

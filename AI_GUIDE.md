# AI Guide — ShareMyBleedings

> Copy-paste this file into Claude, ChatGPT, OpenCode, or any AI assistant to understand, modify, and extend the project quickly.

---

## What is ShareMyBleedings?

Read-only SMB share audit tool for blue/purple teams. Scans a network, enumerates SMB shares, analyzes ACL permissions, scores risk, and produces an interactive HTML dashboard — all in a single standalone file.

**Pipeline in 4 stages:**

1. **Discovery** — Async TCP/445 sweep (optional nmap) → list of SMB hosts
2. **Enumeration** — impacket SMBConnection → list of shares per host
3. **ACL Analysis** — Read ACLs via `READ_CONTROL`, score risk with `RISK_MATRIX`
4. **Reporting** — JSON/CSV/XLSX output + standalone HTML dashboard

**Optional:** Sensitive content scanning (passwords, keys, IBAN...) via manspider wrapper.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| CLI | Typer (subcommands) |
| Console | Rich (progress bars, tables, colors) |
| SMB | impacket (SMBConnection, ACL, SID resolution) |
| Network discovery | asyncio + native socket (nmap optional) |
| HTML dashboard | Self-contained HTML/CSS/JS (Chart.js inline, zero external deps) |
| HTML report export | Generated client-side from dashboard via `exportReport()` |
| Config | TOML optional + .env + CLI flags (priority: CLI > .env > TOML > defaults) |
| Tests | pytest with mocked impacket, no real network needed |

---

## Project Structure

```
ShareMyBleedings/
├── smb_bleedings/                      # Main source code
│   ├── __init__.py                     # Version via importlib.metadata
│   ├── main.py                         # Typer CLI entry point (587 lines)
│   ├── config.py                       # PipelineConfig dataclass, .env/TOML loader (202 lines)
│   ├── models.py                       # Dataclasses: Host, Share, AclEntry, Finding... (81 lines)
│   ├── pipeline.py                     # 4-stage pipeline orchestrator with Rich progress (374 lines)
│   │
│   ├── agents/                         # Pipeline stages
│   │   ├── discovery.py                # Stage 1: TCP/445 network scan (196 lines)
│   │   ├── enumerator.py               # Stage 2: SMB share listing (381 lines)
│   │   ├── acl_analyzer.py             # Stage 3: ACL reading + risk scoring (584 lines)
│   │   ├── content_scanner.py          # Optional: sensitive file scanning (428 lines)
│   │   └── reporter.py                 # Stage 4: JSON/CSV/XLSX generation (708 lines)
│   │
│   └── utils/
│       ├── cidr.py                     # CIDR range parsing & expansion (84 lines)
│       ├── risk.py                     # RISK_MATRIX + score_acl() — scoring engine (288 lines)
│       ├── sid_resolver.py             # SID→name via LDAP, cache + well-known SIDs (286 lines)
│       └── templates/
│           ├── dashboard.html          # Self-contained HTML dashboard (5466 lines)
│           └── report.html.j2          # Jinja2 template for exported report (841 lines)
│
├── tests/                              # pytest tests (mocked, no network)
│   ├── test_discovery.py               # Discovery agent tests (121 lines)
│   ├── test_acl_analyzer.py            # ACL analysis tests (78 lines)
│   ├── test_risk.py                    # Risk scoring tests (188 lines)
│   ├── test_reporter.py                # Reporter tests (244 lines)
│   ├── test_config.py                  # Config loading tests (250 lines)
│   ├── test_content_scanner.py         # Content scanner tests (160 lines)
│   ├── test_pipeline.py                # Full pipeline tests (132 lines)
│   └── test_main_utils.py             # CLI utility tests (77 lines)
│
├── examples/                           # Demo datasets
│   ├── corporate_audit.json            # Dataset 1: corporate HQ audit (FR, 10 findings)
│   ├── corporate_audit_Q3.json         # Dataset 2: corporate Q3 follow-up (FR)
│   ├── multi_site_audit.json           # Dataset 3: multi-site audit (EN, 11 findings)
│   ├── multi_site_audit_Q3.json        # Dataset 4: multi-site Q3 follow-up (EN)
│   └── demo_dashboard.html             # Pre-generated dashboard with demo data
│
├── pyproject.toml                      # Project config, dependencies, entry point
├── config.example.toml                 # Sample TOML config
├── .env.example                        # Sample environment variables
├── Dockerfile + docker-compose.yml     # Containerization
├── install.sh                          # Quick install script
├── README.md                           # User documentation
├── LICENSE                             # MIT
└── AI_GUIDE.md                         # This file
```

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Romso94/ShareMyBleedings.git
cd ShareMyBleedings
pip install -e ".[dev,nmap]"

# Run tests (no network required)
pytest

# Generate demo dashboard
bleedings demo                              # → demo JSON
bleedings dashboard -o demo.html            # → interactive HTML dashboard

# Real scan (requires network with SMB hosts)
bleedings scan --ranges 192.168.1.0/24 -o report.json
bleedings dashboard -o dashboard.html       # load JSON in browser
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `bleedings scan --ranges <CIDR>` | Full scan: discovery → enumeration → ACL → JSON |
| `bleedings scan --ranges <CIDR> -u DOMAIN\\user -p pass` | Scan with AD credentials |
| `bleedings scan --ranges-file targets.txt` | Scan from file (one CIDR per line) |
| `bleedings demo` | Generate demo JSON (no network) |
| `bleedings dashboard -o dash.html` | Generate standalone HTML dashboard |
| `bleedings dashboard -o dash.html --no-browser` | Generate without opening browser |

### Bilingual support

Add `--fr` for French output, default is English. Risk reasons, impacts, and recommendations are all bilingual.

---

## Risk Scoring Engine (`utils/risk.py`)

The `RISK_MATRIX` dict is the single source of truth for all scoring rules.

`score_acl()` returns: `(level, score, reasons, dangerous_entries, recommendations, impacts)`

| Condition | Level | Score |
|-----------|-------|-------|
| Everyone + Full/Change | CRITICAL | 95 |
| Domain Users + Full/Change | CRITICAL | 85-90 |
| Authenticated Users + Full/Change | CRITICAL | 85 |
| BUILTIN\Users + Full/Change | HIGH | 75 |
| Everyone + Read | HIGH | 65 |
| Domain Users + Read | MEDIUM | 40 |
| Authenticated Users + Read | MEDIUM | 35 |
| AD-legitimate share (NETLOGON, SYSVOL) + Auth Users Read | INFO | 10 |

Reasons are bilingual dicts: `{"en": "...", "fr": "..."}`.
System shares (ADMIN$, IPC$, C$, PRINT$, NETLOGON, SYSVOL) excluded by default but logged.

---

## JSON Output Format

```json
{
  "meta": {
    "tool": "ShareMyBleedings",
    "version": "0.1.0",
    "title": "SMB Audit — Corporate Network",
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
      "risk_level": "CRITICAL",
      "risk_score": 95,
      "host": {
        "ip": "192.168.1.10",
        "hostname": "SRV-FILES",
        "smb_version": "3.1.1",
        "signing_required": false
      },
      "share": {
        "name": "Public",
        "unc_path": "\\\\192.168.1.10\\Public",
        "description": "Shared folder",
        "share_type": "disk",
        "anonymous_access": false
      },
      "acl": [
        { "account": "Everyone", "access_right": "Full", "ace_type": "Allow" }
      ],
      "all_acl": [],
      "reasons": ["Everyone has Full Control — anyone can read, write, delete"],
      "impacts": ["Data exfiltration risk", "Ransomware propagation vector"],
      "recommendations": ["Remove Everyone, grant access to specific security groups"],
      "content_matches": [
        {
          "file_path": "\\\\SRV-FILES\\Public\\passwords.xlsx",
          "file_size": 15234,
          "matched_keywords": ["password", "credential"],
          "sha256": "a1b2c3..."
        }
      ]
    }
  ]
}
```

---

## HTML Dashboard (`utils/templates/dashboard.html`)

Self-contained HTML file (5466 lines, CSS + JS inline, zero external dependencies):

### Features
- **JSON import** via drag & drop or file picker
- **Interactive charts** — risk distribution (doughnut), severity bar chart, host heatmap
- **Filtering** — by risk level, keyword search, column sorting
- **Two views** — findings table + per-host accordion
- **Content matches** — table with checkboxes for sensitive file findings
- **Report export** — generates a standalone HTML report from loaded data
- **Themes** — dark/light mode toggle
- **Keyboard shortcuts** — navigation, theme toggle, search focus
- **Print-ready** — CSS print styles included
- **Fully offline** — works without internet

### JS Architecture
- `LOCALES` object with FR/EN keys, accessor `L(key)`
- `CH` namespace for Chart.js (colors, config, render functions)
- `renderFindingDetail(f, fi)` — shared renderer used by dashboard AND exported report
- `exportReport()` — generates the report HTML as a JS template literal
- CSS variables: `--rk-bg`, `--rk-text`, `--rk-border` (report), `--surface`, `--text`, `--border` (dashboard)

---

## Data Models (`models.py`)

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
    share_type: str = "disk"       # disk, printer, ipc, special
    is_system: bool = False        # ADMIN$, IPC$, C$ → excluded by default

@dataclass
class AclEntry:
    account: str
    access_right: str              # "Full", "Change", "Read"
    ace_type: str                  # "Allow", "Deny"

@dataclass
class Finding:
    share: Share
    acl_entries: list[AclEntry]
    risk_level: str                # "CRITICAL", "HIGH", "MEDIUM", "INFO"
    risk_score: int                # 0-100
    reasons: list[str]
```

---

## Code Conventions

- **Type hints** on all functions, no untyped signatures
- **Dataclasses** for all models (no bare dicts)
- **No `print()`** — use `rich.console.Console` or `logging` with Rich handler
- **Network errors** always caught and logged, never fatal (scan continues)
- **Tests** use pytest with mocked impacket, `asyncio_mode = "auto"` in pyproject.toml
- **Bilingual** — risk reasons and impacts in FR/EN via `--fr` flag
- Variables and comments sometimes in French

---

## Configuration

### Priority order: CLI flags > .env > TOML > defaults

### TOML example (`config.example.toml`)

```toml
[scan]
threads = 30
timeout = 3.0
exclude_system_shares = true

[credentials]
username = ""
password = ""
domain = ""

[risk]
dangerous_groups = [
  "Everyone", "Tout le monde",
  "Domain Users", "Authenticated Users",
  "BUILTIN\\Users", "NT AUTHORITY\\Authenticated Users"
]

[output]
default_format = "html"
open_browser = true
```

---

## Useful AI Prompts

### Modify risk scoring
> "In `smb_bleedings/utils/risk.py`, add a RISK_MATRIX entry to detect service accounts (SVC-*) with Full permissions and score them HIGH at 70."

### Modify the dashboard
> "In `smb_bleedings/utils/templates/dashboard.html`, add a CSV export button in the findings section with columns: host, share, risk_level, risk_score, reasons."

### Add a CLI command
> "In `smb_bleedings/main.py`, add a `compare` command that takes 2 JSON files and displays the differences between the two scans."

### Fix bugs
> "Run `pytest` and fix any failing tests. Show me the diff for each fix."

### Understand the flow
> "Explain the complete flow from `bleedings scan --ranges 192.168.1.0/24` to JSON generation. Which files are involved and in what order?"

### Modify the exported report
> "The `exportReport()` function in `dashboard.html` generates the report HTML. Add a summary table at the top of the exported report showing total findings per risk level."

---

## Key Files to Know

| File | Role | Why it matters |
|------|------|----------------|
| `utils/risk.py` | Scoring engine | All risk rules live in `RISK_MATRIX` — change scoring here |
| `utils/templates/dashboard.html` | Dashboard UI | Monolith (5466 lines), test visually in browser after changes |
| `main.py` | CLI entry point | All Typer commands, argument parsing, output handling |
| `pipeline.py` | Orchestrator | Chains the 4 stages with Rich progress display |
| `models.py` | Data models | Small (81 lines) but every agent depends on these dataclasses |
| `config.py` | Config loader | Priority chain: CLI > .env > TOML > defaults |

---

## Development Tips

1. **Dashboard is a monolith** — 5466 lines of inline HTML/CSS/JS. Always test visually in a browser after any change.

2. **Exported report is JS-generated** — `exportReport()` in dashboard.html builds the report as a template literal. Modifications to the report format go there.

3. **Demo datasets** in `examples/` — 4 JSON files covering FR and EN, CRITICAL to INFO, plus a pre-generated dashboard. Use them to test dashboard changes.

4. **impacket is never called in tests** — everything is mocked. Tests need zero network access.

5. **Config priority** — CLI flags > .env > TOML > PipelineConfig defaults. If a setting seems ignored, check the override chain.

6. **Bilingual output** — `--fr` flag switches to French. Risk reasons are stored as `{"en": ..., "fr": ...}` dicts in `RISK_MATRIX`.

---

## Future Ideas

### Security & Features
- [ ] LDAP integration for automatic AD group resolution
- [ ] SMB signing detection display (data exists, not surfaced yet)
- [ ] Global SMB posture score for the network (/100)
- [ ] PDF export (via weasyprint or puppeteer)
- [ ] Scan comparison (diff before/after remediation)
- [ ] SIEM integration (syslog/CEF export)

### Dashboard UX
- [ ] Comparison mode: load 2 JSONs and visualize differences
- [ ] Advanced filters (by subnet, share type, host)
- [ ] Remediation timeline with ticket tracking
- [ ] Auto-notifications for CRITICAL findings

### Code Quality
- [ ] E2E tests for the dashboard (Playwright)
- [ ] mypy strict mode across the project
- [ ] Split dashboard.html into modular components

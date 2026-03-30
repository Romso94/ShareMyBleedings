# ShareMyBleedings 🩸

> *"Because your network bleeds more than you think."*

SMB share audit toolkit for blue & purple teams. Discovers SMB hosts on your network, enumerates shares, analyzes ACLs, optionally scans file contents for secrets — and produces an interactive HTML report.

**100% read-only.** Never creates, modifies, or deletes anything on the target shares. Safe to run in production.

---

## Features

- 🔍 **Network discovery** — TCP/445 sweep across CIDR ranges (with optional nmap)
- 📂 **Share enumeration** — anonymous, guest, or authenticated
- 🔐 **ACL analysis** — flags dangerous ACEs (Everyone / Domain Users / Authenticated Users with Write/Full)
- 🩸 **Content scanning** — optional integration with [manspider](https://github.com/blacklanternsecurity/MANSPIDER) to find sensitive files (passwords, keys, PII…) — **download only on match**
- 📊 **Interactive HTML report** — single-file, offline, sortable, searchable, exportable to CSV/PDF
- 🌐 **Standalone dashboard** — import any scan JSON in your browser, no install needed
- 🇫🇷🇬🇧 Bilingual output (`--fr` / default English)

---

## Installation

### Option 1 — Native (Linux / WSL, recommended)

```bash
git clone https://github.com/Romso94/ShareMyBleedings.git ShareMyBleedings
cd ShareMyBleedings
./install.sh
```

The installer takes care of:
- system deps (`nmap`, `libmagic1`, `antiword`, `poppler-utils`, `unrtf`, `tesseract-ocr`, `libreoffice-core`)
- `manspider` via `pipx`
- `bleedings` itself via `pipx` (isolated, in your `$PATH`)

Requires Python ≥ 3.11 and `apt-get` (Debian/Ubuntu/WSL).

### Option 2 — Docker (zero-install)

```bash
git clone https://github.com/Romso94/ShareMyBleedings.git ShareMyBleedings
cd ShareMyBleedings
docker compose build
docker compose run --rm bleedings scan 192.168.1.0/24 -o /out/report.html --no-browser
```

Reports land in `./out/`, manspider matches in `./loot/`.

---

## Quick start

```bash
# Demo report (no network) — sanity check
bleedings demo

# Full scan
bleedings scan 192.168.1.0/24 -u DOMAIN\\user -p '***' \
    --output report.html --fr

# Scan + content search for sensitive files
bleedings scan 10.0.0.0/24 -u user -p '***' \
    --scan-content -k password -k api_key -k 'BEGIN.*PRIVATE KEY' \
    --loot-dir ./loot --output report.html

# From a file of CIDR ranges
bleedings scan --ranges-file ranges.txt -o report.html

# Standalone dashboard (import JSON in browser later)
bleedings dashboard -o dashboard.html
```

### Step-by-step pipeline

```bash
bleedings discover  192.168.1.0/24 --out hosts.json
bleedings enumerate --hosts hosts.json --out shares.json
bleedings analyze   --shares shares.json --out findings.json
bleedings report    --findings findings.json --out report.html
```

---

## Configuration

### `.env` (credentials)

```env
SMB_USERNAME=DOMAIN\user
SMB_PASSWORD=secret
SMB_DOMAIN=DOMAIN
SMB_DC=dc01.domain.local
SMB_RANGES=192.168.1.0/24,10.0.0.0/24
```

### `config.toml` (optional)

```toml
[scan]
threads = 30
timeout = 3.0
exclude_system_shares = true

[credentials]
username = ""
password = ""
domain = ""
dc = ""

[content_scan]
enabled = false
keywords = ["password", "api[_-]?key", "BEGIN.*PRIVATE KEY"]
extensions = ["txt", "conf", "ini", "env", "yml", "json", "xlsx", "docx"]
loot_dir = "./loot"
max_filesize = "10M"
keep_loot = true

[output]
default_format = "html"
open_browser = true
```

---

## Safety guarantees

ShareMyBleedings is **strictly read-only** on target SMB shares:

| Component       | What it does on the share                                              |
|-----------------|------------------------------------------------------------------------|
| Discovery       | TCP connect on port 445                                                |
| Enumeration     | `NetShareEnum` (lists shares only)                                     |
| Permission test | `openFile()` with WRITE/DELETE access bits → handle closed immediately. **Triggers an ACL check server-side, but writes nothing.** |
| ACL analysis    | `READ_CONTROL` + `queryInfo(SECURITY)`                                 |
| Content scan    | `manspider` spider (read-only by design, downloads only files matching your keywords) |

> ⚠️ Permission probes may generate Windows Event ID **4663** if file auditing (SACL) is enabled. This is a *detection* signal, not a modification. Coordinate with your blue team before scanning monitored networks.

---

## Reports

- **HTML** — single-file, offline, dark/light theme, search, CSV export, print-friendly PDF
- **JSON** — full structured data (use with the dashboard, or your own tooling)
- **CSV** — one row per dangerous ACE, UTF-8 BOM + `;` separator (Excel-friendly)

The standalone dashboard (`bleedings dashboard`) lets anyone load a JSON scan in a browser — no Python, no install.

---

## Tech stack

Python 3.11+ · Typer · Rich · impacket · python-nmap · Jinja2 · ldap3 · manspider

---

## License

MIT — see [LICENSE](LICENSE).

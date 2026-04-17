"""CLI ShareMyBleedings — Point d'entrée Typer."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.prompt import Prompt

from smb_bleedings.config import PipelineConfig, load_config, load_env

# Module-level quiet flag — when True, suppresses all Rich output
_quiet = False
from smb_bleedings.models import (
    AclEntry,
    ContentMatch,
    Finding,
    Host,
    Share,
)
from smb_bleedings.pipeline import run_pipeline

app = typer.Typer(
    name="bleedings",
    help="ShareMyBleedings — Permissive SMB share audit toolkit",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

BANNER = r"""[bold red]
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █                                                               █
   █  ░██████╗███╗░░░███╗██████╗░██╗░░░░░███████╗███████╗██████╗░ █
   █  ██╔════╝████╗░████║██╔══██╗██║░░░░░██╔════╝██╔════╝██╔══██╗ █
   █  ╚█████╗░██╔████╔██║██████╦╝██║░░░░░█████╗░░█████╗░░██║░░██║ █
   █  ░╚═══██╗██║╚██╔╝██║██╔══██╗██║░░░░░██╔══╝░░██╔══╝░░██║░░██║ █
   █  ██████╔╝██║░╚═╝░██║██████╦╝███████╗███████╗███████╗██████╔╝ █
   █  ╚═════╝░╚═╝░░░░░╚═╝╚═════╝░╚══════╝╚══════╝╚══════╝╚═════╝░ █
   █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█
              ╷         ╷                       ╷
              │         ·                       │
              ·    [dark_red]▓▓▒▒░░[/dark_red]                      ·
                   [dark_red]▓▒░[/dark_red]             [dark_red]▓▒░[/dark_red]
                   [dark_red]░[/dark_red]               [dark_red]▒░[/dark_red]
                                  [dark_red]░[/dark_red]
[/bold red][dim]        "Because your network bleeds more than you think."[/dim]
"""


def _setup_logging(verbose: bool) -> None:
    """Configure le logging avec Rich handler."""
    from rich.logging import RichHandler

    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
        force=True,
    )


def _is_junk_line(line: str) -> bool:
    """Return True if the line is obviously not an IP/CIDR (headers, notes, N/A, etc.)."""
    low = line.lower().strip()
    # Common headers and labels
    if low in ("ip", "ip address", "ip addr", "address", "host", "hostname"):
        return True
    # Lines starting with "N/A", "n/a", "NA", etc.
    if low.startswith(("n/a", "na ", "none", "null", "-")):
        return True
    # Lines with no digits at all can't be IPs
    if not any(c.isdigit() for c in low):
        return True
    return False


def _validate_ranges(ranges: list[str]) -> list[str]:
    """Valide les plages CIDR. Skip silencieusement les entrées non-IP."""
    import ipaddress

    valid: list[str] = []
    skipped: list[str] = []
    for r in ranges:
        r = r.strip()
        if not r:
            continue
        try:
            ipaddress.ip_network(r, strict=False)
            valid.append(r)
            continue
        except ValueError:
            pass
        try:
            ipaddress.ip_address(r)
            valid.append(r)
            continue
        except ValueError:
            pass
        # Try range format "x.x.x.x-y"
        if "-" in r and "." in r:
            valid.append(r)
            continue
        # Not a valid IP/CIDR — skip with warning
        skipped.append(r)

    if skipped:
        console.print(f"[yellow]  {len(skipped)} non-IP entry(ies) skipped: {', '.join(repr(s) for s in skipped[:5])}{'...' if len(skipped) > 5 else ''}")

    total = 0
    for r in valid:
        try:
            total += ipaddress.ip_network(r, strict=False).num_addresses
        except ValueError:
            total += 1

    if total > 65536:
        console.print(f"[yellow]  {total:,} IPs to scan — this may take a while...")

    return valid


@app.command()
def scan(
    ranges: Annotated[list[str] | None, typer.Argument(help="Plages CIDR ou IPs")] = None,
    ranges_file: Annotated[str | None, typer.Option("--ranges-file", "-f", help="Fichier de plages")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="Nom d'utilisateur")] = "",
    password: Annotated[str | None, typer.Option("--password", "-p", help="Mot de passe")] = None,
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domaine AD")] = "",
    dc: Annotated[str, typer.Option("--dc", help="Domain Controller pour resolution LDAP des SIDs")] = "",
    threads: Annotated[int, typer.Option(help="Threads pour le scan")] = 50,
    timeout: Annotated[float, typer.Option(help="Timeout TCP en secondes")] = 3.0,
    output: Annotated[str | None, typer.Option("--output", "-o", help="Fichier de sortie")] = None,
    fmt: Annotated[str, typer.Option("--format", help="Format: json|csv|xlsx|all (HTML supprimé — utilisez 'bleedings dashboard')")] = "json",
    include_read: Annotated[bool, typer.Option("--include-read", help="Inclure les lectures")] = False,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Ne pas ouvrir le navigateur")] = False,
    checkpoint: Annotated[str | None, typer.Option("--checkpoint", help="Répertoire checkpoints")] = None,
    resume: Annotated[str | None, typer.Option("--resume", help="Reprendre depuis un répertoire de checkpoints")] = None,
    config_file: Annotated[str | None, typer.Option("--config", help="Fichier config TOML")] = None,
    env_file: Annotated[str | None, typer.Option("--env", help="Fichier .env (defaut: .env)")] = None,
    title: Annotated[str, typer.Option("--title", "-t", help="Report title")] = "",
    fr: Annotated[bool, typer.Option("--fr", help="French output (default: English)")] = False,
    scan_content: Annotated[bool, typer.Option("--scan-content", help="Enable content scanning via manspider")] = False,
    keywords: Annotated[list[str] | None, typer.Option("--keyword", "-k", help="Keyword/regex for content scan (repeatable)")] = None,
    keywords_file: Annotated[str | None, typer.Option("--keywords-file", help="File with one keyword/regex per line")] = None,
    loot_dir: Annotated[str, typer.Option("--loot-dir", help="Directory to store matched files")] = "./loot",
    no_loot: Annotated[bool, typer.Option("--no-loot", help="Don't keep matched files locally (manspider -n)")] = False,
    content_threads: Annotated[int, typer.Option("--content-threads", help="Nb de manspider parallèles (1 par share)")] = 100,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose mode")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress Rich output (CI/CD mode). Only writes output file.")] = False,
) -> None:
    """[bold]Full scan[/bold]: discovery -> shares -> ACL -> report"""
    if quiet:
        console.quiet = True
        # Also silence pipeline + reporter + acl_analyzer consoles
        from smb_bleedings import pipeline as _pl
        from smb_bleedings.agents import reporter as _rp
        from smb_bleedings.agents import acl_analyzer as _acl
        _pl.console.quiet = True
        _rp.console.quiet = True
        _acl.console.quiet = True
    else:
        console.print(BANNER)
    _setup_logging(verbose)

    # Charger config : .env (fallback) -> TOML -> options CLI (prioritaires)
    env_cfg = load_env(env_file)
    cfg = load_config(config_file) if config_file else env_cfg

    all_ranges = list(ranges or [])
    if ranges_file:
        raw = Path(ranges_file).read_text(encoding="utf-8")
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Skip lines that are obviously not IPs (headers, notes, etc.)
            if _is_junk_line(line):
                continue
            # Support comma / semicolon / space separated values on a single line
            for sep in (",", ";"):
                if sep in line:
                    line = line.replace(sep, " ")
            all_ranges.extend(part.strip() for part in line.split() if part.strip())
    all_ranges = [r.strip() for r in all_ranges if r.strip() and not r.strip().startswith("#")]

    # Fallback sur les ranges du .env si rien en CLI
    if not all_ranges and env_cfg.ranges:
        all_ranges = env_cfg.ranges

    if not all_ranges and not resume:
        console.print("[red]  No IP range provided. Use RANGES, --ranges-file, SMB_RANGES in .env, or --resume")
        raise typer.Exit(1)

    if all_ranges:
        all_ranges = _validate_ranges(all_ranges)
    cfg.ranges = all_ranges
    if username:
        # Parse DOMAIN\user format from CLI
        if "\\" in username:
            parts = username.split("\\", 1)
            if not domain:
                domain = parts[0]
            username = parts[1]
        cfg.username = username
    if password is not None:
        cfg.password = password
    if domain:
        cfg.domain = domain

    # Prompt password si username fourni mais pas de password
    if cfg.username and not cfg.password:
        cfg.password = Prompt.ask(f"Mot de passe pour {cfg.username}", password=True)

    cfg.threads_discovery = threads
    cfg.timeout = timeout
    if output:
        cfg.output_path = output
    if fmt in ("html", "all"):
        console.print("[yellow]  HTML format removed from scan — use [bold]bleedings dashboard[/] on the generated JSON. Falling back to 'json'.")
        fmt = "json"
    cfg.output_format = fmt
    cfg.include_read_only = include_read
    if no_browser:
        cfg.open_browser = False
    cfg.checkpoint_dir = checkpoint
    cfg.resume_dir = resume
    # If resuming, also use resume dir as checkpoint dir for new saves
    if resume and not checkpoint:
        cfg.checkpoint_dir = resume
    cfg.verbose = verbose
    cfg.quiet = quiet
    if quiet:
        cfg.open_browser = False
    if title:
        cfg.title = title
    if dc:
        cfg.dc = dc
    cfg.lang = "fr" if fr else "en"

    # Content scan options
    if scan_content:
        cfg.scan_content = True
    kw_list: list[str] = list(keywords or [])
    if keywords_file:
        kw_list += [
            ln.strip() for ln in Path(keywords_file).read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    cfg.content_loot_dir = loot_dir
    cfg.content_threads = content_threads
    if no_loot:
        cfg.content_keep_loot = False

    if cfg.scan_content:
        from smb_bleedings.agents.content_scanner import build_keywords, DEFAULT_KEYWORDS
        cfg.content_keywords = build_keywords(kw_list, include_defaults=True)
        console.print(
            f"[cyan]  Content scan: {len(cfg.content_keywords)} keyword(s) "
            f"(user={len(kw_list)}, defaults={len(DEFAULT_KEYWORDS)}, après dédup)[/]"
        )
    elif kw_list:
        cfg.content_keywords = kw_list

    asyncio.run(run_pipeline(cfg))


@app.command()
def demo() -> None:
    """Simulation animée d'un scan SMB (aucun fichier généré)"""
    import random
    import time

    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table

    console.print(BANNER)
    time.sleep(0.5)

    # ── Demo data ──────────────────────────────────────────────────
    hosts = [
        Host(ip="192.168.1.10", hostname="SRV-FILE01.domain.local"),
        Host(ip="192.168.1.25", hostname=None),
        Host(ip="192.168.1.30", hostname="NAS-BACKUP"),
        Host(ip="10.0.0.5", hostname="SRV-APPLI01"),
        Host(ip="10.0.0.12", hostname="DC01.domain.local"),
    ]

    shares_data = [
        (hosts[0], "Commun", "Partage commun bureaux"),
        (hosts[0], "Projets", "Projets en cours"),
        (hosts[0], "RH-Confidentiel", "Documents RH"),
        (hosts[1], "Public", ""),
        (hosts[2], "Backup", "Sauvegardes"),
        (hosts[2], "Archives", "Archives 2023"),
        (hosts[3], "Apps", "Applications"),
        (hosts[3], "Logs", "Logs applicatifs"),
        (hosts[4], "Scripts", "Scripts de déploiement"),
        (hosts[4], "NETLOGON", "Logon scripts"),
    ]

    shares = [
        Share(host=h, name=n, path=f"\\\\{h.hostname or h.ip}\\{n}", description=d)
        for h, n, d in shares_data
    ]

    findings_data = [
        {
            "share": shares[0],
            "acl_entries": [
                AclEntry("Tout le monde", "Full", "Allow"),
                AclEntry("BUILTIN\\Administrators", "Full", "Allow"),
                AclEntry("DOMAIN\\GRP-Compta", "Read", "Allow"),
                AclEntry("SYSTEM", "Full", "Allow"),
            ],
            "dangerous_entries": [AclEntry("Tout le monde", "Full", "Allow")],
            "risk_level": "CRITICAL", "risk_score": 95,
            "reasons": ["[Commun] 'Everyone' → Full control granted to ALL users (anonymous included)"],
            "impacts": ["[Commun] Anyone can read, modify or delete every file on this share, even without an account"],
            "recommendations": ["Immediately remove 'Everyone' full control on 'Commun'. Command: icacls \"\\\\SRV-FILE01\\Commun\" /remove \"Everyone\""],
            "content_matches": [
                ContentMatch(file_path="Comptabilite/config_backup.xml", file_size=4820, matched_keywords=["password", "connectionstring"], sha256="a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"),
                ContentMatch(file_path="IT/deploy_notes.txt", file_size=1250, matched_keywords=["api_key", "token"], sha256="b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890ab"),
                ContentMatch(file_path="RH/salaires_2025.xlsx", file_size=89400, matched_keywords=["iban", "salaire"], sha256="c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890abcd"),
            ],
        },
        {
            "share": shares[1],
            "acl_entries": [
                AclEntry("Domain Users", "Change", "Allow"),
                AclEntry("BUILTIN\\Administrators", "Full", "Allow"),
                AclEntry("DOMAIN\\Adm-ERP", "Full", "Allow"),
                AclEntry("S-1-5-21-1234567890-9876543210-1122334455-1001", "Read", "Allow"),
            ],
            "dangerous_entries": [AclEntry("Domain Users", "Change", "Allow")],
            "risk_level": "CRITICAL", "risk_score": 85,
            "reasons": ["[Projets] 'Domain Users' → Change access granted to all domain users"],
            "impacts": ["[Projets] Any employee can modify files — a single compromised account is enough to alter data"],
            "recommendations": ["Create a dedicated AD security group (e.g. GS_Projets_RW) and replace 'Domain Users' on 'Projets'."],
            "content_matches": [
                ContentMatch(file_path="Infrastructure/credentials.ini", file_size=520, matched_keywords=["password", "motdepasse"], sha256="d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890abcde1"),
                ContentMatch(file_path="DevOps/docker-compose.prod.yml", file_size=3200, matched_keywords=["password", "postgres://"], sha256="e5f67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"),
            ],
        },
        {
            "share": shares[4],
            "acl_entries": [
                AclEntry("BUILTIN\\Users", "Change", "Allow"),
                AclEntry("BUILTIN\\Administrators", "Full", "Allow"),
                AclEntry("SYSTEM", "Full", "Allow"),
            ],
            "dangerous_entries": [AclEntry("BUILTIN\\Users", "Change", "Allow")],
            "risk_level": "HIGH", "risk_score": 70,
            "reasons": ["[Backup] 'BUILTIN\\Users' → Change access granted to local Users group"],
            "impacts": ["[Backup] Local users can modify files on this share"],
            "recommendations": ["Remove 'BUILTIN\\Users' on 'Backup' and restrict to business groups."],
        },
        {
            "share": shares[3],
            "acl_entries": [
                AclEntry("Everyone", "Read", "Allow"),
                AclEntry("BUILTIN\\Administrators", "Full", "Allow"),
            ],
            "dangerous_entries": [AclEntry("Everyone", "Read", "Allow")],
            "risk_level": "HIGH", "risk_score": 65,
            "reasons": ["[Public] 'Everyone' → Read access granted to anyone (anonymous included)"],
            "impacts": ["[Public] Data accessible without authentication — potential information leak"],
            "recommendations": ["Replace 'Everyone' with a restricted AD group for legitimate users on 'Public'."],
            "content_matches": [
                ContentMatch(file_path="Docs/vpn_access.pdf", file_size=156000, matched_keywords=["BEGIN PRIVATE KEY", "password"], sha256="f67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234"),
            ],
        },
        {
            "share": shares[8],
            "acl_entries": [
                AclEntry("Domain Users", "Read", "Allow"),
                AclEntry("BUILTIN\\Administrators", "Full", "Allow"),
                AclEntry("DOMAIN\\GRP-Deploy", "Change", "Allow"),
            ],
            "dangerous_entries": [AclEntry("Domain Users", "Read", "Allow")],
            "risk_level": "MEDIUM", "risk_score": 40,
            "reasons": ["[Scripts] 'Domain Users' → Read access granted to all domain users"],
            "impacts": ["[Scripts] All employees can view these files — verify this is intentional"],
            "recommendations": ["Verify that 'Domain Users' read access on 'Scripts' is business-justified."],
        },
        {
            "share": shares[7],
            "acl_entries": [
                AclEntry("Authenticated Users", "Read", "Allow"),
                AclEntry("BUILTIN\\Administrators", "Full", "Allow"),
                AclEntry("DOMAIN\\SVC-AppLog", "Change", "Allow"),
            ],
            "dangerous_entries": [AclEntry("Authenticated Users", "Read", "Allow")],
            "risk_level": "MEDIUM", "risk_score": 35,
            "reasons": ["[Logs] 'Authenticated Users' → Read access granted to any authenticated user"],
            "impacts": ["[Logs] Any account can read this data — broad exposure but may be legitimate"],
            "recommendations": ["Evaluate whether 'Authenticated Users' read access on 'Logs' is needed."],
        },
    ]

    # ── Fake IPs to scan (background noise) ───────────────────────
    fake_ips = [f"192.168.1.{i}" for i in range(1, 255)] + [f"10.0.0.{i}" for i in range(1, 255)]
    random.shuffle(fake_ips)

    risk_colors = {"CRITICAL": "bold red", "HIGH": "yellow", "MEDIUM": "cyan", "INFO": "dim"}

    # ═══════════════════════════════════════════════════════════════
    # STAGE 1 — Discovery : TCP/445 sweep
    # ═══════════════════════════════════════════════════════════════
    console.print("\n  [bold cyan]▶ Stage 1/4[/] — [bold]Network Discovery[/] (TCP/445 sweep)")
    console.print(f"  [dim]Scanning 192.168.1.0/24, 10.0.0.0/24 — 512 IPs[/dim]\n")
    time.sleep(0.3)

    host_ips = {h.ip for h in hosts}
    discovered: list[Host] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("  Probing ports", total=len(fake_ips))
        for ip in fake_ips:
            time.sleep(random.uniform(0.002, 0.015))
            progress.advance(task)
            if ip in host_ips:
                host = next(h for h in hosts if h.ip == ip)
                discovered.append(host)
                hostname_str = f" ({host.hostname})" if host.hostname else ""
                progress.console.print(f"    [green]✓[/] [bold]{ip}[/]{hostname_str} — port 445 [green]open[/]")

    console.print(f"\n  [bold green]{len(discovered)}[/] SMB hosts discovered\n")
    time.sleep(0.6)

    # ═══════════════════════════════════════════════════════════════
    # STAGE 2 — Share Enumeration
    # ═══════════════════════════════════════════════════════════════
    console.print("  [bold cyan]▶ Stage 2/4[/] — [bold]Share Enumeration[/] (SMB connect)")
    console.print("  [dim]Connecting as guest / anonymous session[/dim]\n")
    time.sleep(0.3)

    shares_by_host: dict[str, list[Share]] = {}
    for s in shares:
        shares_by_host.setdefault(s.host.ip, []).append(s)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("  Enumerating shares", total=len(hosts))
        for host in hosts:
            time.sleep(random.uniform(0.4, 1.0))
            host_shares = shares_by_host.get(host.ip, [])
            hostname_str = host.hostname or host.ip
            progress.console.print(f"    [bold]{hostname_str}[/] — [green]{len(host_shares)}[/] shares found")
            for s in host_shares:
                sys_tag = " [dim](system)[/]" if s.name in ("NETLOGON", "SYSVOL", "ADMIN$", "IPC$", "C$") else ""
                progress.console.print(f"      [dim]├─[/] {s.name}{sys_tag}")
                time.sleep(random.uniform(0.05, 0.15))
            progress.advance(task)

    console.print(f"\n  [bold green]{len(shares)}[/] shares enumerated across {len(hosts)} hosts\n")
    time.sleep(0.6)

    # ═══════════════════════════════════════════════════════════════
    # STAGE 3 — ACL Analysis + Risk Scoring
    # ═══════════════════════════════════════════════════════════════
    console.print("  [bold cyan]▶ Stage 3/4[/] — [bold]ACL Analysis & Risk Scoring[/]")
    console.print("  [dim]Reading security descriptors (READ_CONTROL)[/dim]\n")
    time.sleep(0.3)

    findings: list[Finding] = []
    findings_by_share = {id(fd["share"]): fd for fd in findings_data}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("  Analyzing ACLs", total=len(shares))
        for s in shares:
            time.sleep(random.uniform(0.3, 0.8))
            progress.advance(task)

            fd = findings_by_share.get(id(s))
            if fd is not None:
                f = Finding(**fd)
                findings.append(f)
                color = risk_colors.get(f.risk_level, "dim")
                progress.console.print(
                    f"    [{color}]■ {f.risk_level:<8}[/{color}] "
                    f"[bold]{s.name}[/] on {s.host.hostname or s.host.ip} "
                    f"[dim](score {f.risk_score})[/]"
                )
                for de in f.dangerous_entries:
                    progress.console.print(
                        f"               [dim]└─[/] [{color}]{de.account} → {de.access_right}[/{color}]"
                    )
            else:
                progress.console.print(
                    f"    [dim]■ OK       {s.name}[/] on {s.host.hostname or s.host.ip}"
                )

    console.print(f"\n  [bold green]{len(findings)}[/] findings — ", end="")
    crit = sum(1 for f in findings if f.risk_level == "CRITICAL")
    high = sum(1 for f in findings if f.risk_level == "HIGH")
    med = sum(1 for f in findings if f.risk_level == "MEDIUM")
    console.print(f"[bold red]{crit} CRITICAL[/] · [yellow]{high} HIGH[/] · [cyan]{med} MEDIUM[/]\n")
    time.sleep(0.6)

    # ═══════════════════════════════════════════════════════════════
    # STAGE 4 — Report Generation
    # ═══════════════════════════════════════════════════════════════
    console.print("  [bold cyan]▶ Stage 4/4[/] — [bold]Report Generation[/]")
    time.sleep(0.3)

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Hosts scanned", f"[bold]{len(hosts)}[/]")
    table.add_row("Shares found", f"[bold]{len(shares)}[/]")
    table.add_row("Findings", f"[bold]{len(findings)}[/]")
    table.add_row("Critical", f"[bold red]{crit}[/]")
    table.add_row("High", f"[yellow]{high}[/]")
    table.add_row("Medium", f"[cyan]{med}[/]")

    console.print()
    console.print(Panel(table, title="[bold]Scan Summary[/]", border_style="green", width=45))

    # Point to example JSON for dashboard usage
    example_file = "examples/corporate_audit.json"
    time.sleep(0.3)
    console.print(f"\n  [bold green]✓[/] Demo complete — no file generated")
    console.print(f"  [dim]Try with a real dataset:[/dim] [bold]bleedings dashboard -i {example_file}[/bold]\n")


@app.command()
def discover(
    ranges: Annotated[list[str], typer.Argument(help="Plages CIDR")],
    out: Annotated[str, typer.Option("--out", "-o", help="Fichier de sortie JSON")] = "hosts.json",
    threads: Annotated[int, typer.Option(help="Threads")] = 50,
    timeout: Annotated[float, typer.Option(help="Timeout TCP")] = 3.0,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """[bold]Découverte réseau[/bold] : identifie les hôtes SMB"""
    from smb_bleedings.agents.discovery import discover as do_discover

    _setup_logging(verbose)
    console.print(BANNER)
    hosts = asyncio.run(do_discover(ranges, threads, timeout, verbose))
    data = [{"ip": h.ip, "hostname": h.hostname, "port": h.port} for h in hosts]
    Path(out).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"\n  [bold green]{len(hosts)}[/] hosts saved to {out}")


@app.command()
def enumerate(
    hosts_file: Annotated[str, typer.Option("--hosts", help="Fichier hosts.json")],
    out: Annotated[str, typer.Option("--out", "-o")] = "shares.json",
    username: Annotated[str, typer.Option("-u")] = "",
    password: Annotated[str | None, typer.Option("-p")] = None,
    domain: Annotated[str, typer.Option("-d")] = "",
    threads: Annotated[int, typer.Option()] = 10,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """[bold]Énumération[/bold] : liste les partages SMB par hôte"""
    from smb_bleedings.agents.enumerator import enumerate_all

    _setup_logging(verbose)
    console.print(BANNER)
    # Prompt password interactively if username is set but password is not
    if username and password is None:
        password = Prompt.ask(f"Password for {username}", password=True)
    raw = json.loads(Path(hosts_file).read_text(encoding="utf-8"))
    hosts = [Host(**h) for h in raw]
    shares, _ = enumerate_all(hosts, threads, username, password or "", domain)
    data = [
        {"host_ip": s.host.ip, "name": s.name, "path": s.path,
         "description": s.description, "share_type": s.share_type, "is_system": s.is_system}
        for s in shares
    ]
    Path(out).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"\n  [bold green]{len(shares)}[/] shares saved to {out}")


@app.command()
def analyze(
    shares_file: Annotated[str, typer.Option("--shares", help="Fichier shares.json")],
    out: Annotated[str, typer.Option("--out", "-o")] = "findings.json",
    username: Annotated[str, typer.Option("-u")] = "",
    password: Annotated[str | None, typer.Option("-p")] = None,
    domain: Annotated[str, typer.Option("-d")] = "",
    dc: Annotated[str, typer.Option("--dc", help="Domain Controller pour resolution LDAP des SIDs")] = "",
    threads: Annotated[int, typer.Option()] = 10,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """[bold]Analyse ACL[/bold] : scoring de risque par partage"""
    from smb_bleedings.agents.acl_analyzer import analyze_all

    _setup_logging(verbose)
    console.print(BANNER)
    # Prompt password interactively if username is set but password is not
    if username and password is None:
        password = Prompt.ask(f"Password for {username}", password=True)
    raw = json.loads(Path(shares_file).read_text(encoding="utf-8"))
    shares = [
        Share(host=Host(ip=s["host_ip"]), name=s["name"], path=s["path"],
              description=s.get("description", ""), share_type=s.get("share_type", "disk"),
              is_system=s.get("is_system", False))
        for s in raw
    ]
    findings = analyze_all(shares, threads, username, password or "", domain, dc=dc)
    data = [
        {"share_path": f.share.path, "risk_level": f.risk_level, "risk_score": f.risk_score,
         "reasons": f.reasons, "recommendations": f.recommendations,
         "dangerous_acl": [{"account": e.account, "right": e.access_right} for e in f.dangerous_entries]}
        for f in findings
    ]
    Path(out).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"\n  [bold green]{len(findings)}[/] findings saved to {out}")


@app.command()
def report(
    findings_file: Annotated[str, typer.Option("--findings", help="Fichier findings.json")],
    out: Annotated[str, typer.Option("--out", "-o")] = "rapport.html",
    fmt: Annotated[str, typer.Option("--format")] = "html",
    no_browser: Annotated[bool, typer.Option("--no-browser")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """[bold]Rapport[/bold] : génère HTML/JSON/CSV depuis les findings"""
    from smb_bleedings.agents.reporter import build_summary, generate_report

    _setup_logging(verbose)
    console.print(BANNER)
    raw = json.loads(Path(findings_file).read_text(encoding="utf-8"))
    findings = [
        Finding(
            share=Share(host=Host(ip="unknown"), name=f.get("share_path", ""), path=f.get("share_path", "")),
            risk_level=f["risk_level"],
            risk_score=f["risk_score"],
            reasons=f.get("reasons", []),
            recommendations=f.get("recommendations", []),
            dangerous_entries=[AclEntry(a["account"], a["right"]) for a in f.get("dangerous_acl", [])],
        )
        for f in raw
    ]
    summary = build_summary(findings, [], 0, 0, len(findings), datetime.now(tz=timezone.utc))
    generate_report(findings, summary, out, fmt, open_browser=not no_browser)


@app.command()
def dashboard(
    output: Annotated[str, typer.Option("--output", "-o", help="Fichier de sortie")] = "bleedings_dashboard.html",
    no_browser: Annotated[bool, typer.Option("--no-browser")] = False,
) -> None:
    """Genere le [bold]dashboard statique[/bold] permanent (import JSON via navigateur)"""
    import shutil

    console.print(BANNER)
    src = Path(__file__).resolve().parent / "utils" / "templates" / "dashboard.html"
    dst = Path(output)
    shutil.copy2(src, dst)
    console.print(f"  [green]Dashboard generated:[/] {dst}")
    console.print(f"  [dim]Open it in a browser and import your .json scan files.[/]")

    if not no_browser:
        from smb_bleedings.agents.reporter import _open_report
        _open_report(str(dst))


if __name__ == "__main__":
    app()

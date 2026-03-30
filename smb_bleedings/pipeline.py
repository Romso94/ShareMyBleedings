"""Orchestrateur du pipeline ShareMyBleedings."""

from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from rich.console import Console

from smb_bleedings.agents.acl_analyzer import analyze_all
from smb_bleedings.agents.discovery import discover
from smb_bleedings.agents.enumerator import enumerate_all
from smb_bleedings.agents.reporter import build_summary, generate_report
from smb_bleedings.config import PipelineConfig
from smb_bleedings.models import Finding

log = logging.getLogger(__name__)
console = Console()

# Step labels for the pipeline
_STEP_ICONS = {
    "discovery": "[bold red]01[/]",
    "enum_acl": "[bold red]02[/]",
    "content": "[bold red]03[/]",
    "report": "[bold red]04[/]",
}


@contextmanager
def timed_step(name: str) -> Generator[None, None, None]:
    """Context manager qui mesure et affiche le temps d'une étape."""
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        console.print(f"  [dim]{name} completed in {elapsed:.1f}s[/]")


def _step_header(step: str, title: str, subtitle: str = "") -> None:
    """Affiche un header d'étape du pipeline."""
    icon = _STEP_ICONS.get(step, "[bold red]--[/]")
    console.print()
    console.rule(f"{icon} [bold]{title}[/]", style="red")
    if subtitle:
        console.print(f"  [dim]{subtitle}[/]")


def _asdict_recursive(obj: Any) -> Any:
    """Sérialise un objet (dataclass ou list) en dict JSON-compatible."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _asdict_recursive(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_asdict_recursive(item) for item in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def _checkpoint_save(config: PipelineConfig, stage: str, data: Any) -> None:
    """Sauvegarde un checkpoint intermédiaire en JSON."""
    if not config.checkpoint_dir:
        return
    path = Path(config.checkpoint_dir) / f"bleedings_checkpoint_{stage}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_asdict_recursive(data), f, default=str, ensure_ascii=False)
    log.debug("Checkpoint saved: %s", path)


def _checkpoint_load(config: PipelineConfig, stage: str) -> list[dict] | None:
    """Charge un checkpoint existant. Retourne None si absent."""
    search_dir = config.resume_dir or config.checkpoint_dir
    if not search_dir:
        return None
    path = Path(search_dir) / f"bleedings_checkpoint_{stage}.json"
    if path.exists():
        console.print(f"  [dim]  Reprise depuis checkpoint : {path.name}")
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return None


def _dicts_to_hosts(data: list[dict]) -> list:
    """Reconstruit des Host depuis des dicts checkpoint."""
    from smb_bleedings.models import Host
    return [
        Host(
            ip=d["ip"],
            hostname=d.get("hostname"),
            port=d.get("port", 445),
            reachable=d.get("reachable", True),
            smb_version=d.get("smb_version"),
            signing_required=d.get("signing_required"),
        )
        for d in data
    ]


def _dicts_to_shares(data: list[dict], hosts_by_ip: dict) -> list:
    """Reconstruit des Share depuis des dicts checkpoint."""
    from smb_bleedings.models import Share
    result = []
    for d in data:
        host_d = d.get("host", {})
        ip = host_d.get("ip", "")
        host = hosts_by_ip.get(ip)
        if not host:
            from smb_bleedings.models import Host
            host = Host(ip=ip, hostname=host_d.get("hostname"),
                        smb_version=host_d.get("smb_version"),
                        signing_required=host_d.get("signing_required"))
        result.append(Share(
            host=host, name=d.get("name", ""), path=d.get("path", ""),
            description=d.get("description", ""),
            share_type=d.get("share_type", "disk"),
            is_system=d.get("is_system", False),
            anonymous_readable=d.get("anonymous_readable", False),
            auth_method=d.get("auth_method", "none"),
            tested_permissions=d.get("tested_permissions", []),
        ))
    return result


def _dicts_to_findings(data: list[dict], hosts_by_ip: dict) -> list[Finding]:
    """Reconstruit des Finding depuis des dicts checkpoint."""
    from smb_bleedings.models import AclEntry, ContentMatch, Host, Share
    results = []
    for d in data:
        share_d = d.get("share", {})
        host_d = share_d.get("host", {})
        ip = host_d.get("ip", "")
        host = hosts_by_ip.get(ip)
        if not host:
            host = Host(ip=ip, hostname=host_d.get("hostname"),
                        smb_version=host_d.get("smb_version"),
                        signing_required=host_d.get("signing_required"))
        share = Share(
            host=host, name=share_d.get("name", ""), path=share_d.get("path", ""),
            description=share_d.get("description", ""),
            share_type=share_d.get("share_type", "disk"),
            is_system=share_d.get("is_system", False),
            anonymous_readable=share_d.get("anonymous_readable", False),
            tested_permissions=share_d.get("tested_permissions", []),
        )
        acl = [AclEntry(**e) for e in d.get("acl_entries", [])]
        dangerous = [AclEntry(**e) for e in d.get("dangerous_entries", [])]
        cms = [
            ContentMatch(
                file_path=m.get("file_path", ""),
                file_size=m.get("file_size", 0),
                matched_keywords=m.get("matched_keywords", []),
                local_loot_path=m.get("local_loot_path"),
                sha256=m.get("sha256"),
            )
            for m in d.get("content_matches", [])
        ]
        ts = d.get("timestamp")
        results.append(Finding(
            share=share, acl_entries=acl, dangerous_entries=dangerous,
            risk_level=d.get("risk_level", "INFO"),
            risk_score=d.get("risk_score", 0),
            reasons=d.get("reasons", []),
            impacts=d.get("impacts", []),
            recommendations=d.get("recommendations", []),
            anonymous_access=d.get("anonymous_access", False),
            content_matches=cms,
            timestamp=datetime.fromisoformat(ts) if ts else datetime.now(tz=timezone.utc),
        ))
    return results


def _auto_filename(ranges: list[str], fmt: str, title: str = "") -> str:
    """Génère un nom de fichier automatique basé sur le titre ou les ranges."""
    if title:
        # Slugify le titre : minuscules, espaces → underscores, pas de caractères spéciaux
        import re
        slug = re.sub(r"[^\w\s-]", "", title.strip()).replace(" ", "_").lower()
    else:
        slug = ranges[0].replace("/", "-") if len(ranges) == 1 else "multi"
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M")
    return f"bleedings_{slug}_{ts}.{fmt}"


async def run_pipeline(config: PipelineConfig) -> list[Finding]:
    """Exécute le pipeline complet Discovery → Enum → ACL → Report."""
    from smb_bleedings.utils.cidr import expand_ranges

    started_at = datetime.now(tz=timezone.utc)
    total_ips = len(expand_ranges(config.ranges))
    findings: list[Finding] = []
    hosts = []
    shares = []

    try:
        # ── Resume from checkpoint? ──
        _resumed = False
        if config.resume_dir:
            # Try most advanced checkpoint first
            for ckpt_stage in ("findings_with_content", "findings"):
                ckpt_data = _checkpoint_load(config, ckpt_stage)
                if ckpt_data is not None:
                    hosts_data = _checkpoint_load(config, "hosts") or []
                    shares_data = _checkpoint_load(config, "shares") or []
                    hosts_by_ip = {h.ip: h for h in _dicts_to_hosts(hosts_data)} if hosts_data else {}
                    hosts = list(hosts_by_ip.values())
                    shares = _dicts_to_shares(shares_data, hosts_by_ip) if shares_data else []
                    findings = _dicts_to_findings(ckpt_data, hosts_by_ip)
                    console.print(f"  [green]Resumed from checkpoint '{ckpt_stage}'[/]: "
                                  f"{len(hosts)} host(s), {len(shares)} share(s), {len(findings)} finding(s)")
                    _resumed = True
                    break
            if not _resumed:
                # Try hosts-only checkpoint → skip discovery
                hosts_data = _checkpoint_load(config, "hosts")
                if hosts_data is not None:
                    hosts = _dicts_to_hosts(hosts_data)
                    console.print(f"  [green]Resumed hosts from checkpoint[/]: {len(hosts)} host(s)")
                    _resumed = True

        # -- Étape 1 : Discovery --
        if not hosts:
            _step_header("discovery", "Découverte réseau", f"{total_ips} IPs à scanner")
            with timed_step("Découverte"):
                hosts = await discover(
                    ranges=config.ranges,
                    threads=config.threads_discovery,
                    timeout=config.timeout,
                    verbose=config.verbose,
                )
            _checkpoint_save(config, "hosts", hosts)

        if not hosts:
            console.print("[yellow]  No SMB hosts found. Check ranges and connectivity.")
            return []

        # -- Étape 2+3 : Énumération + Analyse ACL (connexion unique par hôte) --
        if not findings and not _resumed:
            _step_header("enum_acl", "Énumération + Analyse ACL", f"{len(hosts)} hôtes à traiter")
            with timed_step("Énumération + ACL"):
                shares, findings = enumerate_all(
                    hosts=hosts,
                    threads=config.threads_enum,
                    username=config.username,
                    password=config.password,
                    domain=config.domain,
                    exclude_system=config.exclude_system_shares,
                    timeout=config.timeout,
                    analyze_acl=True,
                    dangerous_groups=config.dangerous_groups,
                    include_read_only=config.include_read_only,
                    dc=config.dc,
                    lang=config.lang,
                )
            _checkpoint_save(config, "shares", shares)
            _checkpoint_save(config, "findings", findings)
        elif _resumed and not findings:
            # Resumed hosts but no findings checkpoint → run enum+ACL
            _step_header("enum_acl", "Énumération + Analyse ACL", f"{len(hosts)} hôtes à traiter")
            with timed_step("Énumération + ACL"):
                shares, findings = enumerate_all(
                    hosts=hosts,
                    threads=config.threads_enum,
                    username=config.username,
                    password=config.password,
                    domain=config.domain,
                    exclude_system=config.exclude_system_shares,
                    timeout=config.timeout,
                    analyze_acl=True,
                    dangerous_groups=config.dangerous_groups,
                    include_read_only=config.include_read_only,
                    dc=config.dc,
                    lang=config.lang,
                )
            _checkpoint_save(config, "shares", shares)
            _checkpoint_save(config, "findings", findings)

        if not shares and not findings:
            console.print("[yellow]  No accessible shares found.")
            return []

        # -- Étape 3 : Content scan (optionnel, manspider) --
        if config.scan_content and config.content_keywords and findings:
            from pathlib import Path as _P
            from smb_bleedings.agents.content_scanner import scan_findings
            # Sous-dossier loot par scan : <base>/<title> (fallback timestamp)
            if config.title and config.title.strip():
                _scan_tag = config.title.strip().replace(" ", "_").replace("/", "_").replace("\\", "_")
            else:
                _scan_tag = "scan_" + started_at.strftime("%Y%m%d_%H%M%S")
            _scoped_loot = str(_P(config.content_loot_dir) / _scan_tag)
            _P(_scoped_loot).mkdir(parents=True, exist_ok=True)
            config.content_loot_dir = _scoped_loot
            _step_header(
                "content",
                "Content scan (manspider)",
                f"{len(config.content_keywords)} keyword(s), loot={_scoped_loot}",
            )
            with timed_step("Content scan"):
                from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
                progress = Progress(
                    TextColumn("[bold cyan]manspider[/]"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TextColumn("• {task.fields[label]}"),
                    TextColumn("• [green]{task.fields[hits]} hits[/]"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=False,
                )
                with progress:
                    task_id = progress.add_task("scan", total=1, label="…", hits=0)
                    def _cb(done: int, total: int, label: str, hits: int) -> None:
                        progress.update(task_id, completed=done, total=total or 1, label=label, hits=hits)
                    total_matches = scan_findings(
                        findings,
                        keywords=config.content_keywords,
                        extensions=config.content_extensions or None,
                        loot_dir=config.content_loot_dir,
                        max_filesize=config.content_max_filesize,
                        keep_loot=config.content_keep_loot,
                        username=config.username,
                        password=config.password,
                        domain=config.domain,
                        progress_cb=_cb,
                        parallel=config.content_threads,
                    )
            console.print(f"  [cyan]{total_matches} sensitive file(s) detected[/]")
            # Boost risk scores for findings with content matches
            from smb_bleedings.utils.risk import boost_score_for_content
            boosted = 0
            for f in findings:
                old_score = f.risk_score
                boost_score_for_content(f, lang=config.lang)
                if f.risk_score != old_score:
                    boosted += 1
            if boosted:
                console.print(f"  [yellow]{boosted} finding(s) score adjusted for sensitive content[/]")
                findings.sort(key=lambda f: f.risk_score, reverse=True)
            _checkpoint_save(config, "findings_with_content", findings)

        # -- Étape 4 : Rapport --
        _step_header("report", "Génération du rapport")

    except KeyboardInterrupt:
        console.print("\n[yellow]  Scan interrupted — generating partial report...")

    finally:
        if findings or shares:
            summary = build_summary(
                findings=findings,
                ranges=config.ranges,
                total_ips=total_ips,
                hosts_discovered=len(hosts),
                shares_total=len(shares),
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc),
                title=config.title,
                lang=config.lang,
            )
            output = config.output_path or _auto_filename(
                config.ranges, config.output_format, config.title
            )
            generate_report(
                findings, summary, output, config.output_format, config.open_browser
            )

    return findings

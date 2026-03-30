"""Modèles de données ShareMyBleedings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Host:
    ip: str
    hostname: str | None = None
    port: int = 445
    reachable: bool = True
    smb_version: str | None = None       # "SMBv1", "SMB2.0.2", "SMB2.1", "SMB3.0", "SMB3.0.2", "SMB3.1.1"
    signing_required: bool | None = None  # True/False/None (unknown)


@dataclass
class Share:
    host: Host
    name: str
    path: str
    description: str = ""
    share_type: str = "disk"
    is_system: bool = False
    anonymous_readable: bool = False
    auth_method: str = "none"
    tested_permissions: list[str] = field(default_factory=list)


@dataclass
class AclEntry:
    account: str
    access_right: str  # "Full", "Change", "Read"
    ace_type: str = "Allow"  # "Allow", "Deny"


@dataclass
class ContentMatch:
    """Un fichier sensible détecté sur un partage par le content scanner (manspider)."""
    file_path: str               # chemin relatif dans le share
    file_size: int = 0
    matched_keywords: list[str] = field(default_factory=list)
    local_loot_path: str | None = None  # chemin local si le fichier a été conservé
    sha256: str | None = None


@dataclass
class Finding:
    share: Share
    acl_entries: list[AclEntry] = field(default_factory=list)
    dangerous_entries: list[AclEntry] = field(default_factory=list)
    risk_level: str = "INFO"
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    impacts: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    anonymous_access: bool = False
    content_matches: list[ContentMatch] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


@dataclass
class ScanSummary:
    title: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    finished_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    duration_seconds: float = 0.0
    ranges_scanned: list[str] = field(default_factory=list)
    total_ips: int = 0
    hosts_discovered: int = 0
    hosts_with_findings: int = 0
    shares_total: int = 0
    shares_analyzed: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_info: int = 0
    findings_ok: int = 0
    lang: str = "en"

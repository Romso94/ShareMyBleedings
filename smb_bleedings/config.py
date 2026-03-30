"""Chargement de la configuration TOML / .env et valeurs par défaut."""

from __future__ import annotations

import logging
import os
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger(__name__)


DANGEROUS_GROUPS_DEFAULT: list[str] = [
    "Everyone",
    "Tout le monde",
    "Authenticated Users",
    "Utilisateurs authentifiés",
    "NT AUTHORITY\\Authenticated Users",
    "Domain Users",
    "Utilisateurs du domaine",
    "BUILTIN\\Users",
    "Utilisateurs",
]


@dataclass
class PipelineConfig:
    ranges: list[str] = field(default_factory=list)
    username: str = ""
    password: str = ""
    domain: str = ""
    threads_discovery: int = 50
    threads_enum: int = 10
    threads_acl: int = 10
    timeout: float = 3.0
    exclude_system_shares: bool = True
    include_read_only: bool = False
    output_path: str | None = None
    output_format: str = "json"
    open_browser: bool = True
    checkpoint_dir: str | None = None
    resume_dir: str | None = None
    dangerous_groups: list[str] = field(default_factory=lambda: list(DANGEROUS_GROUPS_DEFAULT))
    verbose: bool = False
    quiet: bool = False
    title: str = ""
    dc: str = ""  # Domain Controller pour résolution LDAP des SIDs
    lang: str = "en"  # "en" (default) or "fr"
    # Content scanning (manspider wrapper) — optionnel
    scan_content: bool = False
    content_keywords: list[str] = field(default_factory=list)
    content_extensions: list[str] = field(default_factory=list)
    content_loot_dir: str = "./loot"
    content_max_filesize: str = "10M"
    content_keep_loot: bool = True
    content_threads: int = 5


def _load_dotenv(env_path: str | Path | None = None) -> None:
    """Charge un fichier .env dans os.environ (sans dépendance externe)."""
    path = Path(env_path) if env_path else Path(".env")
    if not path.is_file():
        return
    _warn_if_world_readable(path)

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)


def load_env(env_path: str | Path | None = None) -> PipelineConfig:
    """Charge la config depuis le fichier .env et les variables d'environnement."""
    _load_dotenv(env_path)
    cfg = PipelineConfig()

    cfg.username = os.environ.get("SMB_USERNAME", cfg.username)
    cfg.password = os.environ.get("SMB_PASSWORD", cfg.password)
    cfg.domain = os.environ.get("SMB_DOMAIN", cfg.domain)

    # Parse DOMAIN\user format — extract domain from username if present
    if "\\" in cfg.username:
        parts = cfg.username.split("\\", 1)
        if not cfg.domain:
            cfg.domain = parts[0]
        cfg.username = parts[1]

    ranges_str = os.environ.get("SMB_RANGES", "")
    if ranges_str:
        cfg.ranges = [r.strip() for r in ranges_str.split(",") if r.strip()]

    if threads := os.environ.get("SMB_THREADS"):
        cfg.threads_discovery = int(threads)

    if timeout := os.environ.get("SMB_TIMEOUT"):
        cfg.timeout = float(timeout)

    cfg.title = os.environ.get("SMB_TITLE", cfg.title)
    cfg.dc = os.environ.get("SMB_DC", cfg.dc)
    cfg.output_format = os.environ.get("SMB_OUTPUT_FORMAT", cfg.output_format)

    open_browser = os.environ.get("SMB_OPEN_BROWSER", "").lower()
    if open_browser in ("false", "0", "no"):
        cfg.open_browser = False

    # Exclude system shares
    exclude_sys = os.environ.get("SMB_EXCLUDE_SYSTEM", "").lower()
    if exclude_sys in ("false", "0", "no"):
        cfg.exclude_system_shares = False

    # Language
    lang = os.environ.get("SMB_LANG", "").lower()
    if lang in ("fr", "en"):
        cfg.lang = lang

    # Content scan options
    scan_content = os.environ.get("SMB_SCAN_CONTENT", "").lower()
    if scan_content in ("true", "1", "yes"):
        cfg.scan_content = True

    if kw := os.environ.get("SMB_CONTENT_KEYWORDS"):
        cfg.content_keywords = [k.strip() for k in kw.split(",") if k.strip()]

    if loot_dir := os.environ.get("SMB_CONTENT_LOOT_DIR"):
        cfg.content_loot_dir = loot_dir

    if max_fs := os.environ.get("SMB_CONTENT_MAX_FILESIZE"):
        cfg.content_max_filesize = max_fs

    keep_loot = os.environ.get("SMB_CONTENT_KEEP_LOOT", "").lower()
    if keep_loot in ("false", "0", "no"):
        cfg.content_keep_loot = False

    return cfg


def _warn_if_world_readable(path: Path) -> None:
    """Warn if a credential file is readable by group or others."""
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            _log.warning(
                "Config file %s is readable by group/others (mode %s). "
                "Consider: chmod 600 %s",
                path, oct(mode), path,
            )
    except OSError:
        pass


def load_config(path: str | Path) -> PipelineConfig:
    """Charge un fichier TOML et retourne un PipelineConfig."""
    config_path = Path(path)
    _warn_if_world_readable(config_path)
    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    cfg = PipelineConfig()

    scan = data.get("scan", {})
    cfg.threads_discovery = scan.get("threads", cfg.threads_discovery)
    cfg.timeout = scan.get("timeout", cfg.timeout)
    cfg.exclude_system_shares = scan.get("exclude_system_shares", cfg.exclude_system_shares)
    cfg.include_read_only = scan.get("include_read_only", cfg.include_read_only)

    creds = data.get("credentials", {})
    cfg.username = creds.get("username", cfg.username)
    cfg.password = creds.get("password", cfg.password)
    cfg.domain = creds.get("domain", cfg.domain)

    # Parse DOMAIN\user format
    if "\\" in cfg.username:
        parts = cfg.username.split("\\", 1)
        if not cfg.domain:
            cfg.domain = parts[0]
        cfg.username = parts[1]

    cfg.dc = creds.get("dc", cfg.dc)

    risk = data.get("risk", {})
    if "dangerous_groups" in risk:
        cfg.dangerous_groups = risk["dangerous_groups"]

    content = data.get("content_scan", {})
    cfg.scan_content = content.get("enabled", cfg.scan_content)
    cfg.content_keywords = content.get("keywords", cfg.content_keywords)
    cfg.content_extensions = content.get("extensions", cfg.content_extensions)
    cfg.content_loot_dir = content.get("loot_dir", cfg.content_loot_dir)
    cfg.content_max_filesize = content.get("max_filesize", cfg.content_max_filesize)
    cfg.content_keep_loot = content.get("keep_loot", cfg.content_keep_loot)

    output = data.get("output", {})
    cfg.output_format = output.get("default_format", cfg.output_format)
    cfg.open_browser = output.get("open_browser", cfg.open_browser)

    return cfg

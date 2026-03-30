
"""Agent 5 : Content scanner — wrapper subprocess autour de manspider.

Manspider (BlackLanternSecurity) est un outil CLI qui spider les partages SMB
en READ-ONLY et télécharge uniquement les fichiers qui matchent les regex de
contenu/nom fournies. Comme il ne télécharge QUE les hits, la contrainte
"pas de rétention si pas de match" est garantie par construction.

Sécurité :
- 100% read-only côté SMB (manspider n'écrit/supprime jamais).
- Si --no-loot : on passe `-n` à manspider → aucun fichier local conservé.
- Sinon : les hits sont stockés dans <loot_dir>/<host>/<share>/...
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from smb_bleedings.models import ContentMatch, Finding

log = logging.getLogger(__name__)

MANSPIDER_BIN = "manspider"

# Whitelist d'extensions à scanner (formats texte / documents seulement)
DEFAULT_EXTENSIONS: list[str] = [
    "txt", "log", "csv", "tsv", "md", "rst",
    "conf", "config", "cfg", "env", "properties", "toml", "yaml", "yml",
    "json", "xml", "html", "htm",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "pdf",
    "sql", "bak", "dump",
    "ps1", "psm1", "bat", "cmd", "vbs", "sh", "py", "rb", "pl", "php", "js", "ts",
    "kdbx", "pem", "key", "crt", "cer", "pfx", "p12", "asc", "gpg",
]

# Extensions exclues (bruit : polices, binaires, médias, archives système…)
EXCLUDED_EXTENSIONS: set[str] = {
    # Fonts
    "ttf", "otf", "woff", "woff2", "eot", "fon", "fnt",
    # Binaires / firmwares / images disque
    "efi", "sdi", "wim", "iso", "img", "vhd", "vhdx", "vmdk", "bin", "rom",
    "dll", "sys", "drv", "ocx", "cpl", "msi", "msu", "cab", "mui",
    "so", "dylib", "o", "obj", "a", "lib", "ko",
    # Médias
    "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp", "tif", "tiff",
    "mp3", "wav", "flac", "ogg", "m4a", "aac",
    "mp4", "mkv", "avi", "mov", "wmv", "webm", "flv",
    # Archives lourdes
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz",
    # Compilés / packages
    "pyc", "class", "jar", "war", "ear", "deb", "rpm", "pkg", "dmg",
    "exe",
}

# Default smart keyword list — credentials, secrets, finance, PII (FR + EN)
DEFAULT_KEYWORDS: list[str] = [
    # Credentials / secrets
    "password", "passwd", "pwd", "motdepasse", "mot_de_passe",
    "secret", "api[_-]?key", "apikey", "token", "bearer",
    "private[_-]?key", "BEGIN RSA", "BEGIN OPENSSH", "BEGIN PRIVATE",
    "aws_access_key", "aws_secret", "client_secret",
    "credentials", "identifiants",
    # Connection strings
    "connectionstring", "jdbc:", "mongodb://", "postgres://", "mysql://",
    # Finance / banking
    "iban", "bic", "swift", "rib", "carte[_ ]?bancaire", "cvv",
    # PII
    "ssn", "passport", "passeport", "numero[_ ]?secu", "nir",
    # Misc sensitive
    "confidentiel", "confidential", "internal[_ ]?only", "do not distribute",
    "salaire", "salary", "payroll", "paie",
]


def build_keywords(user_keywords: list[str] | None, include_defaults: bool = True) -> list[str]:
    """Merge user keywords with defaults, deduplicated (case-insensitive, order preserved)."""
    merged: list[str] = []
    seen: set[str] = set()
    src = (user_keywords or []) + (DEFAULT_KEYWORDS if include_defaults else [])
    for k in src:
        key = k.strip().lower()
        if key and key not in seen:
            seen.add(key)
            merged.append(k.strip())
    return merged


def _has_manspider() -> bool:
    return shutil.which(MANSPIDER_BIN) is not None


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _compile_keyword_patterns(keywords: list[str]) -> list[tuple[str, re.Pattern[str] | None]]:
    """Pré-compile les regex de keyword matching. Retourne (kw, pattern|None) pour chaque keyword."""
    compiled: list[tuple[str, re.Pattern[str] | None]] = []
    for kw in keywords:
        raw = rf"(?<![A-Za-z0-9_]){kw}(?![A-Za-z0-9_])"
        try:
            compiled.append((kw, re.compile(raw, re.IGNORECASE)))
        except re.error:
            compiled.append((kw, None))
    return compiled


def _identify_matches(path: Path, keywords: list[str], max_bytes: int = 2_000_000,
                      _compiled: list[tuple[str, re.Pattern[str] | None]] | None = None) -> list[str]:
    """Re-scanne le fichier localement pour identifier les keywords qui matchent vraiment."""
    try:
        data = path.read_bytes()[:max_bytes]
    except OSError:
        return []
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []

    if _compiled is None:
        _compiled = _compile_keyword_patterns(keywords)

    hits: list[str] = []
    for kw, pattern in _compiled:
        if pattern is not None:
            if pattern.search(text):
                hits.append(kw)
        else:
            # Fallback texte brut pour les patterns invalides
            low = text.lower()
            kwl = kw.lower()
            idx = low.find(kwl)
            while idx != -1:
                before = low[idx - 1] if idx > 0 else " "
                after = low[idx + len(kwl)] if idx + len(kwl) < len(low) else " "
                if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                    hits.append(kw)
                    break
                idx = low.find(kwl, idx + 1)
    return hits


def _prune_empty_dirs(root: Path) -> None:
    """Supprime récursivement tous les dossiers vides sous `root` (root inclus si vide)."""
    if not root.exists() or not root.is_dir():
        return
    # bottom-up : les enfants d'abord
    for d in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        try:
            d.rmdir()  # ne supprime que si vide
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        pass


def _reconstruct_remote_path(file_path: Path, loot_root: Path) -> str:
    """Reconstruit le chemin distant à partir du fichier dans le loot.

    Manspider stocke les fichiers sous <loot>/<ip>/<share>/ avec un nom
    aplati : <ip>_<share>_<chemin_avec_underscores>.ext
    On retire le préfixe <ip>_<share>_ pour obtenir le chemin relatif
    dans le partage. Les underscores internes restent (pas de moyen fiable
    de les distinguer des séparateurs de dossiers originaux).
    """
    try:
        rel = str(file_path.relative_to(loot_root))
    except ValueError:
        rel = file_path.name

    # loot_root is <base>/<ip>/<share>, extract ip and share from it
    parts = loot_root.parts
    if len(parts) >= 2:
        ip = parts[-2]
        share = parts[-1]
        prefix = f"{ip}_{share}_"
        # Strip prefix from the filename (which is the flat manspider name)
        basename = Path(rel).name
        if basename.startswith(prefix):
            return basename[len(prefix):]
    return rel


def _walk_loot(loot_root: Path, keywords: list[str]) -> list[ContentMatch]:
    """Parcourt le loot dir manspider pour produire les ContentMatch.
    Supprime les fichiers à extension exclue (bruit) et les fichiers sans
    match réel, puis élague les dossiers vides.
    """
    matches: list[ContentMatch] = []
    if not loot_root.exists():
        return matches
    compiled = _compile_keyword_patterns(keywords)
    for f in loot_root.rglob("*"):
        if not f.is_file():
            continue
        ext = f.suffix.lower().lstrip(".")
        if ext in EXCLUDED_EXTENSIONS:
            try:
                f.unlink()
            except OSError:
                pass
            continue
        try:
            size = f.stat().st_size
        except OSError:
            size = 0
        real_hits = _identify_matches(f, keywords, _compiled=compiled) or []
        if not real_hits:
            try:
                f.unlink()
            except OSError:
                pass
            continue
        # Restrict loot file to owner-read only
        try:
            f.chmod(0o600)
        except OSError:
            pass
        matches.append(
            ContentMatch(
                file_path=_reconstruct_remote_path(f, loot_root),
                file_size=size,
                matched_keywords=real_hits,
                local_loot_path=str(f),
                sha256=_sha256(f),
            )
        )
    _prune_empty_dirs(loot_root)
    return matches


def scan_finding(
    finding: Finding,
    keywords: list[str],
    extensions: list[str] | None = None,
    loot_dir: str = "/loot",
    max_filesize: str = "10M",
    threads: int = 5,
    keep_loot: bool = True,
    username: str = "",
    password: str = "",
    domain: str = "",
    timeout: int = 600,
) -> list[ContentMatch]:
    """Scan le contenu d'un share via manspider. Retourne les matches trouvés.

    Si keep_loot=False, manspider est appelé avec -n (pas de download) → on
    parse alors la stdout pour les matches au lieu du loot dir.
    """
    if not _has_manspider():
        log.warning("manspider not installed — skip content scan for %s", finding.share.path)
        return []
    if not keywords:
        return []

    host = finding.share.host.ip
    share = finding.share.name
    host_loot = Path(loot_dir) / host / share
    host_loot.mkdir(parents=True, exist_ok=True)
    # Restrict loot directory to owner only (sensitive content)
    try:
        import os as _os
        _os.chmod(host_loot, 0o700)
        # Also lock parent dirs up to loot_dir
        for parent in (Path(loot_dir) / host, Path(loot_dir)):
            _os.chmod(parent, 0o700)
    except OSError:
        pass

    cmd: list[str] = [
        MANSPIDER_BIN,
        host,
        "-c", *keywords,
        "-l", str(host_loot),
        "-t", str(threads),
        "-s", max_filesize,
        "--sharenames", share,
    ]
    cmd += ["-e", *(extensions or DEFAULT_EXTENSIONS)]
    if username:
        cmd += ["-u", username]
    if domain:
        cmd += ["-d", domain]
    if not keep_loot:
        cmd.append("-n")

    # Write password to a short-lived temp file (mode 0600) to avoid exposure
    # in the process table (/proc/<pid>/cmdline is world-readable on Linux).
    # Manspider accepts -p <value> on the CLI — we read the file and pass the
    # value, but via a wrapper that shortens the window of exposure.
    import os
    import tempfile

    pw_file: str | None = None
    try:
        if password:
            fd, pw_file = tempfile.mkstemp(prefix=".mspw_", text=True)
            os.fchmod(fd, 0o600)
            os.write(fd, password.encode())
            os.close(fd)
            # manspider only supports -p <password> on CLI; read from temp file
            cmd += ["-p", password]
            # NOTE: password still visible in cmdline — this is a manspider
            # limitation. The temp file approach is ready for when manspider
            # adds --password-file support. For now, log a warning.
            log.debug(
                "manspider does not support --password-file; password passed via -p. "
                "Consider running scans on a single-user system."
            )

        log.info("manspider scan: %s\\\\%s (%d keywords)", host, share, len(keywords))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning("manspider timeout on %s\\\\%s", host, share)
        # Nettoie tout loot partiel laissé par le process tué
        if keep_loot:
            matches = _walk_loot(host_loot, keywords)
            log.info("  %d match(es) recovered from partial loot", len(matches))
            return matches
        return []
    except OSError as exc:
        log.error("manspider exec failed: %s", exc)
        if keep_loot:
            _walk_loot(host_loot, keywords)
        return []
    finally:
        # Always clean up the temp password file
        if pw_file:
            try:
                os.unlink(pw_file)
            except OSError:
                pass

    if result.returncode != 0:
        log.debug("manspider rc=%d stderr=%s", result.returncode, result.stderr[:500])

    if keep_loot:
        matches = _walk_loot(host_loot, keywords)
    else:
        # Pas de download → parser stdout. Manspider logge "MATCH: <path>" en mode normal.
        matches = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if "MATCH" in line.upper() or line.startswith("\\\\"):
                matches.append(
                    ContentMatch(
                        file_path=line,
                        matched_keywords=list(keywords),
                    )
                )

    log.info("  → %d match(es) on %s\\\\%s", len(matches), host, share)
    return matches


def scan_findings(
    findings: list[Finding],
    keywords: list[str],
    progress_cb=None,
    parallel: int = 5,
    **kwargs,
) -> int:
    """Lance le content scan sur tous les findings READ+ en parallèle.

    `parallel` = nombre de scans manspider concurrents (un par share).
    Modifie les Finding in-place en remplissant leur champ `content_matches`.
    `progress_cb(done, total, label, hits)` est appelé après chaque scan.
    """
    if not _has_manspider():
        log.warning("manspider not installed — content scan disabled")
        return 0

    eligible = [
        f for f in findings
        if not f.share.is_system
        and any(p.lower() in ("read", "list") for p in f.share.tested_permissions)
    ]
    total_targets = len(eligible)
    if not total_targets:
        return 0

    lock = threading.Lock()
    state = {"done": 0, "hits": 0}

    def _worker(f: Finding) -> int:
        label = f"{f.share.host.ip}\\{f.share.name}"
        f.content_matches = scan_finding(f, keywords, **kwargs)
        n = len(f.content_matches)
        with lock:
            state["done"] += 1
            state["hits"] += n
            if progress_cb:
                progress_cb(state["done"], total_targets, label, state["hits"])
        return n

    workers = max(1, min(parallel, total_targets))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_worker, f) for f in eligible]
        for _ in as_completed(futures):
            pass

    # Sweep final : élague tous les dossiers vides sous le loot root
    loot_root = kwargs.get("loot_dir")
    if loot_root:
        _prune_empty_dirs(Path(loot_root))
    return state["hits"]

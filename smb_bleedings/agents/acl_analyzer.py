"""Agent 3 : Analyse des ACL SMB et scoring de risque."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

from smb_bleedings.config import DANGEROUS_GROUPS_DEFAULT
from smb_bleedings.models import AclEntry, Finding, Share
from smb_bleedings.utils.risk import score_acl
from smb_bleedings.utils.sid_resolver import WELL_KNOWN_SIDS, SidResolver, create_resolver

log = logging.getLogger(__name__)
console = Console()

FULL_MASK = 0x001F01FF
CHANGE_MASK = 0x001301BF
READ_MASK = 0x001200A9


def _mask_to_right(mask: int) -> str:
    """Convertit un masque d'accès Windows en label lisible."""
    if mask & FULL_MASK == FULL_MASK:
        return "Full"
    if mask & CHANGE_MASK == CHANGE_MASK:
        return "Change"
    if mask & READ_MASK == READ_MASK:
        return "Read"
    return f"Custom (0x{mask:08X})"


def _sid_to_name(sid: object, resolver: SidResolver | None = None) -> str:
    """Convertit un SID en nom lisible via la table des SIDs connus ou LDAP."""
    sid_str = str(sid).strip()
    # D'abord les SIDs bien connus (pas besoin de réseau)
    if sid_str in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid_str]
    # Si on a un resolver LDAP, tenter la résolution
    if resolver is not None:
        return resolver.resolve(sid_str)
    return sid_str


def _parse_sd_bytes(sd_bytes: bytes, resolver: SidResolver | None = None) -> list[AclEntry]:
    """Parse des bytes de Security Descriptor en ACL entries."""
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

    entries: list[AclEntry] = []
    try:
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)
    except Exception as exc:
        log.warning("Failed to parse Security Descriptor (%d bytes): %s", len(sd_bytes), exc)
        return entries

    if sd["Dacl"]:
        for ace in sd["Dacl"].aces:
            try:
                sid_str = ace["Ace"]["Sid"].formatCanonical()
                entries.append(
                    AclEntry(
                        account=_sid_to_name(sid_str, resolver),
                        access_right=_mask_to_right(ace["Ace"]["Mask"]["Mask"]),
                        ace_type="Allow" if ace["AceType"] == 0 else "Deny",
                    )
                )
            except Exception as exc:
                log.warning("Failed to parse ACE in DACL: %s", exc)
    # Si pas de DACL mais un Owner, le noter
    if not entries and sd["OwnerSid"]:
        owner = _sid_to_name(sd["OwnerSid"].formatCanonical(), resolver)
        entries.append(
            AclEntry(account=owner, access_right="Full", ace_type="Owner")
        )
    return entries


def _get_share_acl_smb2(conn: "SMBConnection", share_name: str, resolver: SidResolver | None = None) -> list[AclEntry]:
    """Lit les ACL NTFS du root d'un partage via SMB2 CREATE + QUERY_INFO.

    Utilise creationOption=FILE_DIRECTORY_FILE pour ouvrir le root
    comme un répertoire, puis _SMBConnection.queryInfo pour lire
    le Security Descriptor (DACL + Owner).
    C'est exactement ce que fait Windows clic droit → Sécurité.
    """
    from impacket.smb3structs import (
        FILE_DIRECTORY_FILE,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        FILE_SHARE_WRITE,
        SMB2_0_INFO_SECURITY,
    )

    FILE_LIST_DIRECTORY = 0x0001
    READ_CONTROL = 0x00020000
    DACL_SECURITY_INFORMATION = 0x04
    OWNER_SECURITY_INFORMATION = 0x01

    try:
        tid = conn.connectTree(share_name)
    except Exception as exc:
        log.debug("connectTree failed for %s: %s", share_name, exc)
        return []

    try:
        fid = conn.openFile(
            tid, "",
            desiredAccess=FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
            shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE,
            creationOption=FILE_DIRECTORY_FILE,
        )
    except Exception as exc:
        log.debug("openFile (directory) failed for %s: %s", share_name, exc)
        try:
            conn.disconnectTree(tid)
        except Exception:
            pass
        return []

    try:
        smb3 = conn._SMBConnection
        sd_bytes = smb3.queryInfo(
            tid, fid,
            infoType=SMB2_0_INFO_SECURITY,
            fileInfoClass=0,
            additionalInformation=DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
        )
    except Exception as exc:
        log.debug("queryInfo (security) failed for %s: %s", share_name, exc)
        sd_bytes = None
    finally:
        try:
            conn.closeFile(tid, fid)
        except Exception:
            pass
        try:
            conn.disconnectTree(tid)
        except Exception:
            pass

    if sd_bytes and isinstance(sd_bytes, bytes):
        return _parse_sd_bytes(sd_bytes, resolver)
    return []


def _get_share_acl_srvsvc(conn: "SMBConnection", share_name: str, resolver: SidResolver | None = None) -> list[AclEntry]:
    """Lit les ACL d'un partage via srvsvc (NetShareGetInfo niveau 502).

    Fallback RPC : récupère les permissions de partage (pas NTFS).
    """
    try:
        from impacket.dcerpc.v5 import srvs, transport

        rpctransport = transport.SMBTransport(
            conn.getRemoteHost(),
            filename=r"\srvsvc",
            smb_connection=conn,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        resp = srvs.hNetrShareGetInfo(dce, share_name, 502)
        sd_bytes = b"".join(resp["InfoStruct"]["ShareInfo502"]["shi502_SecurityDescriptor"])
        dce.disconnect()

        if sd_bytes:
            return _parse_sd_bytes(sd_bytes, resolver)

    except Exception as exc:
        log.debug("srvsvc ACL read failed for %s: %s", share_name, exc)
    return []


def _dedup_acl(entries: list[AclEntry]) -> list[AclEntry]:
    """Supprime les doublons et les ACE Custom (bruit NTFS)."""
    seen: set[tuple[str, str, str]] = set()
    result: list[AclEntry] = []
    for e in entries:
        if e.access_right.startswith("Custom"):
            continue
        key = (e.account, e.access_right, e.ace_type)
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result


def _get_share_acl(conn: "SMBConnection", share_name: str, resolver: SidResolver | None = None) -> list[AclEntry]:
    """Lit les ACL d'un partage. Essaie 2 méthodes :

    1. SMB2 QUERY_INFO sur le root (ACL NTFS = clic droit → Sécurité)
    2. srvsvc NetShareGetInfo 502 (permissions de partage)
    """
    entries = _get_share_acl_smb2(conn, share_name, resolver)
    if entries:
        return _dedup_acl(entries)

    entries = _get_share_acl_srvsvc(conn, share_name, resolver)
    if entries:
        return _dedup_acl(entries)

    log.debug("All ACL read methods failed for %s", share_name)
    return []


def _analyze_acl_entries(
    conn: "SMBConnection",
    share: Share,
    dangerous_groups: list[str] | None = None,
    include_read_only: bool = False,
    resolver: SidResolver | None = None,
    lang: str = "en",
) -> Finding | None:
    """Analyse les ACL d'un partage en réutilisant une connexion existante."""
    if dangerous_groups is None:
        dangerous_groups = list(DANGEROUS_GROUPS_DEFAULT)

    try:
        acl_entries = _get_share_acl(conn, share.name, resolver)
    except Exception as exc:
        log.debug("ACL analysis failed for %s: %s", share.path, exc)
        acl_entries = []

    if not acl_entries:
        if share.anonymous_readable:
            if lang == "fr":
                reasons = [f"[{share.name}] Partage accessible en anonyme sans ACL lisibles"]
                impacts = [f"[{share.name}] N'importe qui sur le réseau peut accéder à ces données sans aucun compte"]
                recs = [f"Désactiver l'accès anonyme sur '{share.name}' (RestrictAnonymous=2). Commande : Set-SmbShare -Name \"{share.name}\" -EncryptData $true -Force"]
            else:
                reasons = [f"[{share.name}] Share accessible anonymously with no readable ACL"]
                impacts = [f"[{share.name}] Anyone on the network can access this data without any account"]
                recs = [f"Disable anonymous access on '{share.name}' (RestrictAnonymous=2). Command: Set-SmbShare -Name \"{share.name}\" -EncryptData $true -Force"]
            _enrich_smb_warnings(share.host, reasons, recs, impacts, 70, lang)
            return Finding(
                share=share,
                acl_entries=[],
                dangerous_entries=[],
                risk_level="HIGH",
                risk_score=70,
                reasons=reasons,
                impacts=impacts,
                recommendations=recs,
                anonymous_access=True,
                timestamp=datetime.now(tz=timezone.utc),
            )
        return None

    level, score, reasons, dangerous, recs, impacts = score_acl(acl_entries, dangerous_groups, share.name, lang)

    # Enrich with SMB protocol warnings
    _enrich_smb_warnings(share.host, reasons, recs, impacts, score, lang)

    # Anonymous readable share with no dangerous ACL still deserves a finding
    if score == 0 and share.anonymous_readable:
        score = 55
        level = "HIGH"
        if lang == "fr":
            reasons.append(f"[{share.name}] Partage accessible en anonyme malgré des ACL non dangereuses")
            impacts.append(f"[{share.name}] L'accès anonyme contourne les restrictions ACL — fuite de données possible")
            recs.append(f"Désactiver l'accès anonyme sur '{share.name}' (RestrictAnonymous=2).")
        else:
            reasons.append(f"[{share.name}] Share accessible anonymously despite non-dangerous ACLs")
            impacts.append(f"[{share.name}] Anonymous access bypasses ACL restrictions — potential data leak")
            recs.append(f"Disable anonymous access on '{share.name}' (RestrictAnonymous=2).")

    if score == 0:
        return None

    if not include_read_only and level == "INFO":
        return None

    return Finding(
        share=share,
        acl_entries=acl_entries,
        dangerous_entries=dangerous,
        risk_level=level,
        risk_score=score,
        reasons=reasons,
        impacts=impacts,
        recommendations=recs,
        anonymous_access=share.anonymous_readable,
        timestamp=datetime.now(tz=timezone.utc),
    )


def _enrich_smb_warnings(
    host: "Host", reasons: list[str], recs: list[str], impacts: list[str], score: int, lang: str = "en"
) -> None:
    """Ajoute des avertissements SMBv1 / signing disabled aux raisons."""
    if host.smb_version and "SMBv1" in host.smb_version:
        if lang == "fr":
            reasons.append("SMBv1 activé — vulnérable à EternalBlue, WannaCry et attaques relay")
            impacts.append("Un attaquant peut prendre le contrôle de la machine à distance (exploit connu)")
            recs.append("Désactiver SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).")
        else:
            reasons.append("SMBv1 enabled — vulnerable to EternalBlue, WannaCry and relay attacks")
            impacts.append("An attacker can take remote control of the machine (known exploit)")
            recs.append("Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).")
    if host.signing_required is False:
        if lang == "fr":
            reasons.append("Signing SMB non requis — vulnérable aux attaques NTLM relay")
            impacts.append("Un attaquant sur le réseau peut usurper l'identité d'un utilisateur légitime")
            recs.append("Activer le signing obligatoire (RequireSecuritySignature=1 via GPO).")
        else:
            reasons.append("SMB signing not required — vulnerable to NTLM relay attacks")
            impacts.append("A network attacker can impersonate a legitimate user")
            recs.append("Enforce mandatory signing (RequireSecuritySignature=1 via GPO).")


def _generate_host_findings(host: "Host", lang: str = "en") -> list[Finding]:
    """Génère des findings standalone pour SMBv1 et signing disabled au niveau host.

    Appelé quand aucun finding de share n'a capturé ces avertissements pour ce host.
    """
    from smb_bleedings.models import Host as _Host  # avoid circular at module level

    findings: list[Finding] = []
    # Dummy share to attach the host-level finding
    dummy_share = Share(
        host=host, name="(host-level)", path=f"\\\\{host.ip}",
        description="Host-level protocol finding", share_type="host",
    )

    if host.smb_version and "SMBv1" in host.smb_version:
        reasons: list[str] = []
        impacts: list[str] = []
        recs: list[str] = []
        if lang == "fr":
            reasons.append(f"[{host.ip}] SMBv1 activé — vulnérable à EternalBlue, WannaCry et attaques relay")
            impacts.append(f"[{host.ip}] Un attaquant peut prendre le contrôle de la machine à distance (exploit connu)")
            recs.append("Désactiver SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).")
        else:
            reasons.append(f"[{host.ip}] SMBv1 enabled — vulnerable to EternalBlue, WannaCry and relay attacks")
            impacts.append(f"[{host.ip}] An attacker can take remote control of the machine (known exploit)")
            recs.append("Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).")
        findings.append(Finding(
            share=dummy_share, risk_level="HIGH", risk_score=80,
            reasons=reasons, impacts=impacts, recommendations=recs,
            timestamp=datetime.now(tz=timezone.utc),
        ))

    if host.signing_required is False:
        reasons = []
        impacts = []
        recs = []
        if lang == "fr":
            reasons.append(f"[{host.ip}] Signing SMB non requis — vulnérable aux attaques NTLM relay")
            impacts.append(f"[{host.ip}] Un attaquant sur le réseau peut usurper l'identité d'un utilisateur légitime")
            recs.append("Activer le signing obligatoire (RequireSecuritySignature=1 via GPO).")
        else:
            reasons.append(f"[{host.ip}] SMB signing not required — vulnerable to NTLM relay attacks")
            impacts.append(f"[{host.ip}] A network attacker can impersonate a legitimate user")
            recs.append("Enforce mandatory signing (RequireSecuritySignature=1 via GPO).")
        findings.append(Finding(
            share=dummy_share, risk_level="MEDIUM", risk_score=60,
            reasons=reasons, impacts=impacts, recommendations=recs,
            timestamp=datetime.now(tz=timezone.utc),
        ))

    return findings


def analyze_share(
    share: Share,
    username: str = "",
    password: str = "",
    domain: str = "",
    timeout: float = 10.0,
    dangerous_groups: list[str] | None = None,
    include_read_only: bool = False,
    resolver: SidResolver | None = None,
    lang: str = "en",
) -> Finding | None:
    """Analyse les ACL d'un partage (ouvre sa propre connexion). Fallback si pas de pooling."""
    from impacket.smbconnection import SMBConnection, SessionError

    if dangerous_groups is None:
        dangerous_groups = list(DANGEROUS_GROUPS_DEFAULT)

    # Safety net: parse DOMAIN\user format
    if "\\" in username:
        parts = username.split("\\", 1)
        if not domain:
            domain = parts[0]
        username = parts[1]

    try:
        conn = SMBConnection(share.host.ip, share.host.ip, timeout=timeout)
        if username:
            conn.login(username, password, domain)
        else:
            conn.login("", "", "")
    except Exception as exc:
        log.debug("Cannot connect to %s for ACL: %s", share.host.ip, exc)
        return None

    try:
        return _analyze_acl_entries(conn, share, dangerous_groups, include_read_only, resolver, lang)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _analyze_host_shares(
    host_ip: str,
    host_shares: list[Share],
    username: str,
    password: str,
    domain: str,
    timeout: float,
    dangerous_groups: list[str],
    include_read_only: bool,
    resolver: SidResolver | None,
    lang: str,
) -> list[Finding | None]:
    """Analyse all shares on a single host using ONE SMB connection (pooled)."""
    from impacket.smbconnection import SMBConnection, SessionError

    # Parse DOMAIN\user format
    u, p, d = username, password, domain
    if "\\" in u:
        parts = u.split("\\", 1)
        if not d:
            d = parts[0]
        u = parts[1]

    try:
        conn = SMBConnection(host_ip, host_ip, timeout=timeout)
        if u:
            conn.login(u, p, d)
        else:
            conn.login("", "", "")
    except Exception as exc:
        log.debug("Cannot connect to %s for ACL: %s", host_ip, exc)
        return [None] * len(host_shares)

    try:
        results: list[Finding | None] = []
        for share in host_shares:
            try:
                finding = _analyze_acl_entries(
                    conn, share, dangerous_groups, include_read_only, resolver, lang
                )
                results.append(finding)
            except Exception as exc:
                log.debug("ACL analysis failed for %s: %s", share.path, exc)
                results.append(None)
        return results
    finally:
        try:
            conn.close()
        except Exception:
            pass


def analyze_all(
    shares: list[Share],
    threads: int = 10,
    username: str = "",
    password: str = "",
    domain: str = "",
    dangerous_groups: list[str] | None = None,
    include_read_only: bool = False,
    timeout: float = 10.0,
    dc: str = "",
    lang: str = "en",
) -> list[Finding]:
    """Analyse les ACL de tous les partages en parallèle (pooled par host)."""
    if not shares:
        return []

    if dangerous_groups is None:
        dangerous_groups = list(DANGEROUS_GROUPS_DEFAULT)

    # Initialiser le resolver LDAP si un DC est fourni
    resolver = create_resolver(dc, username, password, domain) if dc else None
    if resolver:
        console.print(f"  [dim]LDAP[/]      [green]connected[/] via {dc}")
    elif dc:
        console.print(f"  [dim]LDAP[/]      [yellow]indisponible[/] ({dc})")

    # Group shares by host IP for connection pooling
    shares_by_host: dict[str, list[Share]] = {}
    for share in shares:
        shares_by_host.setdefault(share.host.ip, []).append(share)

    console.print(f"  [dim]Shares[/]  {len(shares)} to analyze across {len(shares_by_host)} host(s)\n")
    findings: list[Finding] = []

    level_styles = {
        "CRITICAL": "[bold red]CRIT[/]",
        "HIGH": "[yellow]HIGH[/]",
        "MEDIUM": "[blue]MED [/]",
        "INFO": "[dim]INFO[/]",
    }

    # Collect results during progress, print after
    acl_results: list[tuple[str, int]] = []  # (formatted_line, sort_key)

    with (
        ThreadPoolExecutor(max_workers=threads) as executor,
        Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as progress,
    ):
        task = progress.add_task("[cyan]Analyse des ACL...", total=len(shares))

        # Submit one task per HOST (not per share) — reuses connection
        futures = {
            executor.submit(
                _analyze_host_shares,
                host_ip,
                host_shares,
                username,
                password,
                domain,
                timeout,
                dangerous_groups,
                include_read_only,
                resolver,
                lang,
            ): (host_ip, host_shares)
            for host_ip, host_shares in shares_by_host.items()
        }

        for future in as_completed(futures):
            host_ip, host_shares = futures[future]
            try:
                host_findings = future.result()
                for share, finding in zip(host_shares, host_findings):
                    if finding:
                        findings.append(finding)
                        tag = level_styles.get(finding.risk_level, "[dim]INFO[/]")
                        acl_results.append((
                            f"    {tag}  {share.path:<35} score {finding.risk_score}",
                            -finding.risk_score,
                        ))
                    else:
                        acl_results.append((
                            f"    [green] OK [/]  {share.path:<35} [dim]aucun risque[/]",
                            1,
                        ))
                    progress.advance(task)
            except Exception as exc:
                log.debug("Analysis failed for host %s: %s", host_ip, exc)
                for _ in host_shares:
                    progress.advance(task)

    # Print results sorted: highest risk first, then OK
    for line, _ in sorted(acl_results, key=lambda x: x[1]):
        console.print(line)

    # Fermer la connexion LDAP
    if resolver:
        resolver.close()

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.risk_level] = counts.get(f.risk_level, 0) + 1
    level_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "INFO": "dim"}
    parts = [f"[{level_colors.get(k, 'white')}]{v} {k}[/]" for k, v in sorted(counts.items())]
    console.print(f"\n  [bold]{len(findings)}[/] findings  {' [dim]|[/] '.join(parts)}" if parts else f"\n  [green]Aucun finding[/]")

    return sorted(findings, key=lambda f: f.risk_score, reverse=True)

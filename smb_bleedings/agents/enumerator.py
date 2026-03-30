"""Agent 2 : Énumération des partages SMB par hôte."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

from smb_bleedings.models import Host, Share

log = logging.getLogger(__name__)
console = Console()

SYSTEM_SHARES = {"ADMIN$", "IPC$", "C$", "D$", "E$", "F$", "PRINT$", "FAX$"}

# Dialect → human-readable SMB version
_DIALECT_MAP: dict[int | str, str] = {
    "NT LM 0.12": "SMBv1",
    0x0202: "SMB2.0.2",
    0x0210: "SMB2.1",
    0x0300: "SMB3.0",
    0x0302: "SMB3.0.2",
    0x0311: "SMB3.1.1",
}


def _detect_smb_info(conn: "SMBConnection", host: Host) -> None:
    """Détecte la version SMB et le signing depuis une connexion active."""
    try:
        dialect = conn.getDialect()
        host.smb_version = _DIALECT_MAP.get(dialect, f"Unknown(0x{dialect:04X})" if isinstance(dialect, int) else str(dialect))
    except Exception:
        pass

    try:
        host.signing_required = conn.isSigningRequired()
    except Exception:
        pass

    log.debug(
        "%s: %s, signing=%s",
        host.ip,
        host.smb_version or "?",
        host.signing_required,
    )


def _connect(
    host: Host,
    username: str,
    password: str,
    domain: str,
    timeout: float,
) -> "SMBConnection | None":
    """Tente la connexion SMB avec fallback anonyme/guest."""
    import socket

    from impacket.smbconnection import SMBConnection, SessionError

    # Pre-flight: fast TCP check to avoid slow impacket timeout on dead hosts
    try:
        sock = socket.create_connection((host.ip, 445), timeout=min(timeout, 2.0))
        sock.close()
    except (OSError, TimeoutError):
        log.debug("%s: port 445 unreachable (pre-flight)", host.ip)
        return None

    # Safety net: parse DOMAIN\user if caller didn't split it
    if "\\" in username:
        parts = username.split("\\", 1)
        if not domain:
            domain = parts[0]
        username = parts[1]

    attempts: list[tuple[str, str, str]] = []
    if username:
        attempts.append((username, password, domain))
    attempts += [("", "", ""), ("guest", "", "")]

    for user, pwd, dom in attempts:
        try:
            conn = SMBConnection(host.ip, host.ip, timeout=timeout)
            conn.login(user, pwd, dom)
            log.debug("%s: logged in as %r", host.ip, user or "(anonymous)")
            _detect_smb_info(conn, host)
            return conn
        except SessionError as exc:
            log.debug("%s login failed (%r): %s", host.ip, user, exc)
        except Exception as exc:
            log.warning("%s connection error: %s", host.ip, exc)

    return None


def _list_shares(
    conn: "SMBConnection",
    host: Host,
    exclude_system: bool,
) -> list[Share]:
    """Liste les partages d'une connexion SMB."""
    shares: list[Share] = []
    type_map = {0: "disk", 1: "printer", 2: "device", 3: "ipc"}

    try:
        raw_shares = conn.listShares()
    except Exception as exc:
        log.warning("%s: listShares failed: %s", host.ip, exc)
        return shares

    for share_info in raw_shares:
        raw_name = share_info["shi1_netname"]
        name = raw_name.rstrip("\x00") if isinstance(raw_name, str) else str(raw_name)
        share_type_raw = share_info["shi1_type"]
        try:
            remark = share_info["shi1_remark"]
        except (KeyError, Exception):
            remark = ""
        description = remark.rstrip("\x00") if isinstance(remark, str) and remark else ""

        share_type = type_map.get(share_type_raw & 0x3, "unknown")
        is_system = name.upper() in SYSTEM_SHARES or name.endswith("$")

        if exclude_system and is_system:
            log.debug("Skipping system share: \\\\%s\\%s", host.ip, name)
            continue

        shares.append(
            Share(
                host=host,
                name=name,
                path=f"\\\\{host.ip}\\{name}",
                description=description,
                share_type=share_type,
                is_system=is_system,
            )
        )

    return shares


def _test_permissions(conn: "SMBConnection", share_name: str) -> list[str]:
    """Teste les permissions effectives en lecture seule, sans aucune écriture.

    Retourne une liste parmi "LIST", "READ", "EXECUTE", "WRITE", "DELETE".
    WRITE/DELETE sont déduits via openFile avec FILE_WRITE_DATA / DELETE en
    desiredAccess (probe non destructif : ouvre le handle sur la racine du
    partage, ne crée et ne supprime jamais aucun fichier ou dossier).
    Ne lève jamais d'exception.
    """
    from impacket.smbconnection import SessionError

    permissions: list[str] = []

    # LIST + READ
    try:
        conn.listPath(share_name, "*")
        permissions.append("LIST")
        permissions.append("READ")
    except (SessionError, Exception):
        pass

    # WRITE / DELETE / EXECUTE via low-level open (aucune création de fichier)
    try:
        from impacket.smb3structs import (
            FILE_READ_ATTRIBUTES,
            FILE_EXECUTE,
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            DELETE,
            FILE_SHARE_READ,
        )
        tid = conn.connectTree(share_name)
        probes = [
            ("EXECUTE", FILE_READ_ATTRIBUTES | FILE_EXECUTE),
            ("WRITE",   FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | FILE_APPEND_DATA),
            ("DELETE",  FILE_READ_ATTRIBUTES | DELETE),
        ]
        for label, access in probes:
            try:
                fid = conn.openFile(tid, "\\", desiredAccess=access, shareMode=FILE_SHARE_READ)
                conn.closeFile(tid, fid)
                permissions.append(label)
            except (SessionError, Exception):
                pass
        try:
            conn.disconnectTree(tid)
        except (SessionError, Exception):
            pass
    except (ImportError, Exception):
        pass

    return permissions


def _check_anonymous_access(conn: "SMBConnection", share_name: str) -> bool:
    """Teste si un partage est lisible sans auth."""
    from impacket.smbconnection import SessionError

    try:
        conn.listPath(share_name, "*")
        return True
    except (SessionError, Exception):
        return False


def enumerate_host(
    host: Host,
    username: str = "",
    password: str = "",
    domain: str = "",
    exclude_system: bool = True,
    timeout: float = 10.0,
    analyze_acl: bool = False,
    dangerous_groups: list[str] | None = None,
    include_read_only: bool = False,
    sid_resolver: "SidResolver | None" = None,
    lang: str = "en",
) -> tuple[list[Share], list["Finding"]]:
    """Liste les partages SMB d'un hôte et optionnellement analyse les ACL.

    Retourne (shares, findings). Ne lève jamais d'exception.
    Quand analyze_acl=True, réutilise la même connexion pour enum + ACL.
    """
    from smb_bleedings.models import Finding

    conn = _connect(host, username, password, domain, timeout)
    if conn is None:
        log.warning("%s: all connection attempts failed (anonymous + guest)", host.ip)
        return [], []

    auth_method = "credentials" if username else "anonymous"
    try:
        shares = _list_shares(conn, host, exclude_system)
    except Exception as exc:
        log.warning("%s: enumeration failed: %s", host.ip, exc)
        try:
            conn.close()
        except Exception:
            pass
        return [], []

    for share in shares:
        share.auth_method = auth_method
        try:
            share.anonymous_readable = _check_anonymous_access(conn, share.name)
        except Exception:
            pass
        try:
            share.tested_permissions = _test_permissions(conn, share.name)
        except Exception:
            pass

    findings: list[Finding] = []
    if analyze_acl:
        from smb_bleedings.agents.acl_analyzer import _analyze_acl_entries

        for share in shares:
            finding = _analyze_acl_entries(
                conn, share, dangerous_groups, include_read_only, sid_resolver, lang
            )
            if finding:
                findings.append(finding)

    try:
        conn.close()
    except Exception:
        pass

    return shares, findings


def enumerate_all(
    hosts: list[Host],
    threads: int = 10,
    username: str = "",
    password: str = "",
    domain: str = "",
    exclude_system: bool = True,
    timeout: float = 10.0,
    analyze_acl: bool = False,
    dangerous_groups: list[str] | None = None,
    include_read_only: bool = False,
    dc: str = "",
    lang: str = "en",
) -> tuple[list[Share], list["Finding"]]:
    """Lance enumerate_host en parallèle sur tous les hôtes.

    Quand analyze_acl=True, fusionne enum + ACL sur la même connexion.
    Retourne (shares, findings).
    """
    if not hosts:
        return [], []

    # Initialiser le resolver LDAP si un DC est fourni
    from smb_bleedings.utils.sid_resolver import SidResolver, create_resolver

    resolver = create_resolver(dc, username, password, domain) if dc else None
    if resolver:
        console.print(f"  [dim]LDAP[/]   [green]connected[/] via {dc}")
    elif dc:
        console.print(f"  [dim]LDAP[/]   [yellow]indisponible[/] ({dc})")

    console.print(f"  [dim]Hosts[/]  {len(hosts)}  [dim]|[/]  {threads} threads\n")
    all_shares: list[Share] = []
    all_findings: list["Finding"] = []
    errors = 0
    # Collect results during progress, print after
    host_results: list[tuple[str, bool]] = []  # (formatted_line, is_success)

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
        task = progress.add_task(
            "[cyan]Énumération des partages...", total=len(hosts)
        )

        futures = {
            executor.submit(
                enumerate_host, host, username, password, domain, exclude_system, timeout,
                analyze_acl, dangerous_groups, include_read_only, resolver, lang,
            ): host
            for host in hosts
        }

        for future in as_completed(futures):
            host = futures[future]
            try:
                shares, host_findings = future.result()
                if shares:
                    label = host.hostname or host.ip
                    ver = host.smb_version or "?"
                    sign = "[red]no-sign[/]" if host.signing_required is False else "[green]signed[/]" if host.signing_required else "[dim]?[/]"
                    host_results.append((
                        f"    [green]+[/] {label:<20} [bold]{len(shares)}[/] partages  [dim]|[/] {ver} [dim]|[/] {sign}",
                        True,
                    ))
                    all_shares.extend(shares)
                    all_findings.extend(host_findings)
                else:
                    errors += 1
                    label = host.hostname or host.ip
                    host_results.append((
                        f"    [red]x[/] {label:<20} [red]connexion échouée[/]",
                        False,
                    ))
            except Exception as exc:
                errors += 1
                log.debug("%s: %s", host.ip, exc)
            progress.advance(task)

    # Print results: successes first, then failures
    for line, _ in sorted(host_results, key=lambda x: (not x[1], x[0])):
        console.print(line)

    # Fermer la connexion LDAP
    if resolver:
        resolver.close()

    err_str = f"  [dim]|[/]  [red]{errors} erreurs[/]" if errors else ""
    console.print(
        f"\n  [bold green]{len(all_shares)}[/] partages trouvés sur "
        f"{len(hosts)} hôtes{err_str}"
    )
    return all_shares, all_findings

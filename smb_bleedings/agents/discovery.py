"""Agent 1 : Découverte réseau — scan des hôtes SMB (port 445)."""

from __future__ import annotations

import asyncio
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

from smb_bleedings.models import Host
from smb_bleedings.utils.cidr import expand_ranges

log = logging.getLogger(__name__)
console = Console()


def _check_port(ip: str, port: int, timeout: float) -> bool:
    """Test TCP connect sur ip:port avec retry + backoff. Retourne True si ouvert."""
    import time

    for attempt in range(2):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (OSError, TimeoutError):
            if attempt == 0:
                time.sleep(0.05)  # Small backoff before retry
                continue
            return False
    return False


def _resolve_hostname(ip: str) -> str | None:
    """PTR DNS lookup. Retourne None si échec."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _scan_with_nmap(ranges: list[str], timeout: float) -> list[str] | None:
    """Tente un scan nmap. Retourne None si nmap indisponible."""
    try:
        import nmap  # type: ignore[import-untyped]
    except ImportError:
        return None

    try:
        nm = nmap.PortScanner()
        nm.scan(
            hosts=" ".join(ranges),
            ports="445",
            arguments=f"-T4 --open --host-timeout {int(timeout)}s",
        )
        return [
            host
            for host in nm.all_hosts()
            if nm[host].get("tcp", {}).get(445, {}).get("state") == "open"
        ]
    except Exception as exc:
        log.warning("nmap scan failed, falling back to socket: %s", exc)
        return None


async def discover(
    ranges: list[str],
    threads: int = 30,
    timeout: float = 3.0,
    verbose: bool = False,
    resolve_hostnames: bool = True,
) -> list[Host]:
    """Scanne les plages CIDR et retourne les hôtes avec le port 445 ouvert.

    Args:
        resolve_hostnames: If False, skip PTR DNS lookups (much faster on large ranges).
    """
    all_ips = expand_ranges(ranges)
    total_ips = len(all_ips)

    if total_ips == 0:
        console.print("[yellow]No IPs to scan.")
        return []

    if total_ips > 65536:
        console.print(
            f"[yellow]  {total_ips:,} IPs à scanner — ça peut prendre un moment..."
        )

    # Truncate ranges display if too many
    if len(ranges) <= 5:
        ranges_str = ", ".join(ranges)
    else:
        ranges_str = f"{', '.join(ranges[:4])} [dim]... +{len(ranges) - 4} autres[/]"

    console.print(
        f"  [dim]Plages[/]  {ranges_str}\n"
        f"  [dim]Cibles[/]  {total_ips} IPs  [dim]|[/]  {threads} threads  [dim]|[/]  timeout {timeout}s\n"
    )

    # Event loop (nécessaire pour run_in_executor dans les deux branches)
    loop = asyncio.get_running_loop()

    # Auto-disable hostname resolution for large ranges (saves 30s+ per dead IP)
    if total_ips > 1024 and resolve_hostnames:
        log.info("Large range (%d IPs) — disabling hostname resolution for speed", total_ips)
        resolve_hostnames = False

    # Essayer nmap d'abord (only for small-medium ranges; nmap is slow on large ones)
    nmap_results = None
    if total_ips <= 4096:
        nmap_results = _scan_with_nmap(ranges, timeout)
    else:
        log.info("Large range (%d IPs) — skipping nmap, using async socket scan", total_ips)
    if nmap_results is not None:
        log.info("nmap scan returned %d hosts", len(nmap_results))
        open_ips = set(nmap_results)
    else:
        # Fallback: scan socket parallèle
        open_ips: set[str] = set()

        async def _scan_ip(ip: str, executor: ThreadPoolExecutor) -> tuple[str, bool]:
            try:
                result = await loop.run_in_executor(executor, _check_port, ip, 445, timeout)
                return ip, result
            except Exception as exc:
                log.debug("Error scanning %s: %s", ip, exc)
                return ip, False

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
                f"[cyan]Découverte sur {total_ips} IPs...", total=total_ips
            )

            # Process in batches to update progress
            batch_size = threads * 4
            for i in range(0, len(all_ips), batch_size):
                batch = all_ips[i : i + batch_size]
                results = await asyncio.gather(
                    *[_scan_ip(ip, executor) for ip in batch]
                )
                for ip, is_open in results:
                    if is_open:
                        open_ips.add(ip)
                    progress.advance(task)

    # Résoudre les hostnames en parallèle (skip si désactivé)
    hosts: list[Host] = []

    if resolve_hostnames and open_ips:
        async def _resolve(ip: str, executor: ThreadPoolExecutor) -> tuple[str, str | None]:
            try:
                hostname = await loop.run_in_executor(executor, _resolve_hostname, ip)
                return ip, hostname
            except Exception:
                return ip, None

        with ThreadPoolExecutor(max_workers=min(threads, len(open_ips))) as executor:
            results = await asyncio.gather(
                *[_resolve(ip, executor) for ip in sorted(open_ips)]
            )
            for ip, hostname in results:
                hosts.append(Host(ip=ip, hostname=hostname, port=445, reachable=True))
    else:
        for ip in sorted(open_ips):
            hosts.append(Host(ip=ip, hostname=None, port=445, reachable=True))

    hosts.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))

    console.print(f"\n  [bold green]{len(hosts)}[/] SMB hosts discovered out of {total_ips} IPs scanned")
    if hosts:
        console.print()
        for h in hosts:
            label = h.hostname or "[dim]hostname non résolu[/]"
            console.print(f"    [green]{h.ip:<16}[/] {label}")

    return hosts

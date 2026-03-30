"""Parsing et expansion des plages CIDR."""

from __future__ import annotations

import ipaddress
import re

MAX_IPS = 131_072  # /15 — plafond de sécurité contre les expansions accidentelles


def expand_cidr(cidr: str) -> list[str]:
    """Expanse une notation CIDR, IP simple ou range en liste d'IPs.

    Formats supportés :
        - "192.168.1.0/24"       → 256 IPs
        - "10.0.0.5"             → ["10.0.0.5"]
        - "10.0.0.1-10"          → ["10.0.0.1", ..., "10.0.0.10"]
        - "10.0.0.1-10.0.0.10"   → range complète
    """
    cidr = cidr.strip()

    # Range format: "10.0.0.1-10" or "10.0.0.1-10.0.0.10"
    range_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+(?:\.\d+\.\d+\.\d+)?)$", cidr)
    if range_match:
        start_str = range_match.group(1)
        end_part = range_match.group(2)
        if "." in end_part:
            # Full IP range
            start = int(ipaddress.IPv4Address(start_str))
            end = int(ipaddress.IPv4Address(end_part))
        else:
            # Short range: last octet only
            base = start_str.rsplit(".", 1)[0]
            start = int(ipaddress.IPv4Address(start_str))
            end = int(ipaddress.IPv4Address(f"{base}.{end_part}"))

        if end < start:
            raise ValueError(f"Range invalide : {cidr} (fin < début)")
        count = end - start + 1
        if count > MAX_IPS:
            raise ValueError(
                f"Range trop large : {cidr} ({count:,} IPs, max {MAX_IPS:,})"
            )
        return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]

    # CIDR or single IP
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Plage CIDR invalide : {cidr!r}") from exc

    if network.prefixlen == 32:
        return [str(network.network_address)]

    if network.num_addresses > MAX_IPS:
        raise ValueError(
            f"CIDR trop large : {cidr} ({network.num_addresses:,} IPs, max {MAX_IPS:,})"
        )
    return [str(ip) for ip in network]


def expand_ranges(ranges: list[str]) -> list[str]:
    """Expanse une liste de plages CIDR en liste d'IPs uniques.

    Les entrées invalides sont silencieusement ignorées (loguées en debug).
    """
    import logging

    log = logging.getLogger(__name__)
    seen: set[str] = set()
    result: list[str] = []
    for r in ranges:
        try:
            for ip in expand_cidr(r):
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
        except ValueError as exc:
            log.warning("Skipped invalid entry %r: %s", r, exc)
    if len(result) > MAX_IPS:
        raise ValueError(
            f"Total trop large : {len(result):,} IPs combinées (max {MAX_IPS:,})"
        )
    return result

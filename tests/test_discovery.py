"""Tests pour smb_bleedings.agents.discovery et utils.cidr."""

import asyncio
from unittest.mock import patch

import pytest

from smb_bleedings.agents.discovery import discover
from smb_bleedings.models import Host
from smb_bleedings.utils.cidr import expand_cidr, expand_ranges


# ── Tests CIDR ──────────────────────────────────────────────

def test_expand_cidr_24() -> None:
    result = expand_cidr("192.168.1.0/24")
    assert len(result) == 256
    assert result[0] == "192.168.1.0"
    assert result[255] == "192.168.1.255"


def test_expand_cidr_32() -> None:
    result = expand_cidr("10.0.0.5/32")
    assert result == ["10.0.0.5"]


def test_expand_single_ip() -> None:
    result = expand_cidr("10.0.0.1")
    assert result == ["10.0.0.1"]


def test_expand_short_range() -> None:
    result = expand_cidr("10.0.0.1-10")
    assert len(result) == 10
    assert result[0] == "10.0.0.1"
    assert result[-1] == "10.0.0.10"


def test_expand_full_range() -> None:
    result = expand_cidr("10.0.0.1-10.0.0.5")
    assert len(result) == 5


def test_expand_invalid_raises() -> None:
    with pytest.raises(ValueError, match="invalide"):
        expand_cidr("not_an_ip")


def test_expand_ranges_deduplicates() -> None:
    result = expand_ranges(["10.0.0.1", "10.0.0.1", "10.0.0.2"])
    assert result == ["10.0.0.1", "10.0.0.2"]


def test_expand_cidr_16() -> None:
    result = expand_cidr("172.16.0.0/16")
    assert len(result) == 65536


# ── Tests Discovery ─────────────────────────────────────────

def test_check_port_closed() -> None:
    from smb_bleedings.agents.discovery import _check_port

    # 192.0.2.1 is TEST-NET, should be unreachable
    assert _check_port("192.0.2.1", 445, 0.5) is False


def test_resolve_hostname_invalid() -> None:
    from smb_bleedings.agents.discovery import _resolve_hostname

    # Unresolvable IP
    result = _resolve_hostname("192.0.2.1")
    # Should return None or a string, never raise
    assert result is None or isinstance(result, str)


@patch("smb_bleedings.agents.discovery._check_port")
def test_discover_returns_only_reachable(mock_check: "MagicMock") -> None:
    reachable = {"192.168.1.1", "192.168.1.10", "192.168.1.100"}

    def side_effect(ip: str, port: int, timeout: float) -> bool:
        return ip in reachable

    mock_check.side_effect = side_effect

    with patch("smb_bleedings.agents.discovery._resolve_hostname", return_value=None):
        with patch("smb_bleedings.agents.discovery._scan_with_nmap", return_value=None):
            result = asyncio.run(discover(["192.168.1.0/24"], threads=10, timeout=0.1))

    assert len(result) == 3
    assert all(h.reachable for h in result)
    ips = {h.ip for h in result}
    assert ips == reachable


# ── Edge cases (6.3) ──

def test_expand_empty_ranges():
    assert expand_ranges([]) == []


def test_expand_ranges_invalid_skipped():
    result = expand_ranges(["10.0.0.1", "not-valid", "10.0.0.2"])
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result
    assert len(result) == 2


def test_discover_empty_ranges():
    result = asyncio.run(discover([], threads=1, timeout=0.1))
    assert result == []


def test_nmap_returns_ips():
    """When nmap succeeds, its IPs are used directly."""
    with patch("smb_bleedings.agents.discovery._scan_with_nmap", return_value=["10.0.0.1", "10.0.0.5"]):
        with patch("smb_bleedings.agents.discovery._resolve_hostname", return_value=None):
            result = asyncio.run(discover(["10.0.0.0/24"], threads=1, timeout=0.1))
    assert len(result) == 2
    ips = {h.ip for h in result}
    assert ips == {"10.0.0.1", "10.0.0.5"}

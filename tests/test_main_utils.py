"""Tests pour les fonctions utilitaires de smb_bleedings.main."""

import pytest

from smb_bleedings.main import _is_junk_line, _validate_ranges


# ── _is_junk_line ──

def test_junk_headers():
    for h in ("ip", "IP", "ip address", "IP Address", "host", "hostname", "address"):
        assert _is_junk_line(h) is True, f"Should be junk: {h!r}"


def test_junk_na_values():
    for v in ("n/a", "N/A", "NA ", "none", "null", "-"):
        assert _is_junk_line(v) is True, f"Should be junk: {v!r}"


def test_junk_no_digits():
    assert _is_junk_line("some random text") is True
    assert _is_junk_line("   ") is True
    assert _is_junk_line("abc") is True


def test_valid_ip_not_junk():
    assert _is_junk_line("192.168.1.1") is False
    assert _is_junk_line("10.0.0.0/24") is False
    assert _is_junk_line("10.0.0.1-10") is False


def test_empty_string_is_junk():
    assert _is_junk_line("") is True


def test_whitespace_around_valid_ip():
    assert _is_junk_line("  192.168.1.1  ") is False


# ── _validate_ranges ──

def test_validate_single_ip():
    result = _validate_ranges(["10.0.0.1"])
    assert result == ["10.0.0.1"]


def test_validate_cidr():
    result = _validate_ranges(["192.168.1.0/24"])
    assert result == ["192.168.1.0/24"]


def test_validate_range_format():
    result = _validate_ranges(["10.0.0.1-10"])
    assert result == ["10.0.0.1-10"]


def test_validate_skips_invalid():
    result = _validate_ranges(["192.168.1.0/24", "not-an-ip", "hello", "10.0.0.1"])
    assert "192.168.1.0/24" in result
    assert "10.0.0.1" in result
    assert "not-an-ip" not in result
    assert "hello" not in result


def test_validate_skips_empty():
    result = _validate_ranges(["", "  ", "10.0.0.1"])
    assert result == ["10.0.0.1"]


def test_validate_strips_whitespace():
    result = _validate_ranges(["  10.0.0.1  "])
    assert result == ["10.0.0.1"]


def test_validate_empty_list():
    result = _validate_ranges([])
    assert result == []

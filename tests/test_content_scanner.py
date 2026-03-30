"""Tests pour smb_bleedings.agents.content_scanner — keywords et matching."""

import pytest
from pathlib import Path

from smb_bleedings.agents.content_scanner import (
    build_keywords,
    _identify_matches,
    _compile_keyword_patterns,
    DEFAULT_KEYWORDS,
)


# ── build_keywords ──

def test_build_keywords_defaults_only():
    kws = build_keywords(None, include_defaults=True)
    assert len(kws) > 0
    assert "password" in kws


def test_build_keywords_user_only():
    kws = build_keywords(["custom1", "custom2"], include_defaults=False)
    assert kws == ["custom1", "custom2"]


def test_build_keywords_merge_dedup():
    kws = build_keywords(["password", "custom"], include_defaults=True)
    count = sum(1 for k in kws if k.lower() == "password")
    assert count == 1, "password should appear only once"


def test_build_keywords_case_insensitive_dedup():
    kws = build_keywords(["PASSWORD", "password"], include_defaults=False)
    assert len(kws) == 1


def test_build_keywords_preserves_original_case():
    kws = build_keywords(["MySecret"], include_defaults=False)
    assert kws == ["MySecret"]


def test_build_keywords_strips_whitespace():
    kws = build_keywords(["  spaced  "], include_defaults=False)
    assert kws == ["spaced"]


def test_build_keywords_empty_strings_filtered():
    kws = build_keywords(["", "  ", "valid"], include_defaults=False)
    assert kws == ["valid"]


def test_build_keywords_none_user():
    kws = build_keywords(None, include_defaults=False)
    assert kws == []


def test_build_keywords_user_takes_priority():
    """User keywords appear before defaults."""
    kws = build_keywords(["my_first"], include_defaults=True)
    assert kws[0] == "my_first"


# ── _compile_keyword_patterns ──

def test_compile_valid_regex():
    compiled = _compile_keyword_patterns(["password", "api[_-]?key"])
    assert len(compiled) == 2
    assert all(p is not None for _, p in compiled)


def test_compile_invalid_regex_returns_none():
    compiled = _compile_keyword_patterns(["valid", "[invalid"])
    assert compiled[0][1] is not None  # valid
    assert compiled[1][1] is None  # invalid regex


# ── _identify_matches ──

def test_identify_basic_match(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("The password is secret123")
    hits = _identify_matches(f, ["password"])
    assert "password" in hits


def test_identify_no_match(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("Nothing sensitive here")
    hits = _identify_matches(f, ["password"])
    assert hits == []


def test_identify_word_boundary(tmp_path):
    """'rib' should not match inside 'attribution'."""
    f = tmp_path / "test.txt"
    f.write_text("This is an attribution note")
    hits = _identify_matches(f, ["rib"])
    assert hits == []


def test_identify_word_boundary_standalone(tmp_path):
    """'rib' should match when standalone."""
    f = tmp_path / "test.txt"
    f.write_text("Le rib du client est confidentiel")
    hits = _identify_matches(f, ["rib"])
    assert "rib" in hits


def test_identify_case_insensitive(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("PASSWORD=admin123")
    hits = _identify_matches(f, ["password"])
    assert "password" in hits


def test_identify_multiple_keywords(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("password=secret\niban=FR76123456")
    hits = _identify_matches(f, ["password", "iban", "ssn"])
    assert "password" in hits
    assert "iban" in hits
    assert "ssn" not in hits


def test_identify_regex_keyword(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("aws_access_key=AKIAIOSFODNN7EXAMPLE")
    hits = _identify_matches(f, ["aws_access_key"])
    assert "aws_access_key" in hits


def test_identify_nonexistent_file(tmp_path):
    f = tmp_path / "does_not_exist.txt"
    hits = _identify_matches(f, ["password"])
    assert hits == []


def test_identify_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("")
    hits = _identify_matches(f, ["password"])
    assert hits == []


def test_identify_with_precompiled(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("secret token here")
    compiled = _compile_keyword_patterns(["secret", "token"])
    hits = _identify_matches(f, ["secret", "token"], _compiled=compiled)
    assert "secret" in hits
    assert "token" in hits


def test_identify_binary_content(tmp_path):
    """Binary content should not crash, just return no matches."""
    f = tmp_path / "binary.bin"
    f.write_bytes(b"\x00\xff\xfe\x80" * 100)
    hits = _identify_matches(f, ["password"])
    assert hits == []

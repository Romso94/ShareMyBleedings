"""Tests pour smb_bleedings.pipeline — fonctions utilitaires."""

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from smb_bleedings.config import PipelineConfig
from smb_bleedings.models import Host, Share, Finding, AclEntry
from smb_bleedings.pipeline import _asdict_recursive, _checkpoint_save, _checkpoint_load, _auto_filename


# ── _asdict_recursive ──

def test_asdict_recursive_dataclass():
    host = Host(ip="10.0.0.1", hostname="srv01")
    result = _asdict_recursive(host)
    assert isinstance(result, dict)
    assert result["ip"] == "10.0.0.1"
    assert result["hostname"] == "srv01"


def test_asdict_recursive_list():
    hosts = [Host(ip="10.0.0.1"), Host(ip="10.0.0.2")]
    result = _asdict_recursive(hosts)
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["ip"] == "10.0.0.1"


def test_asdict_recursive_datetime():
    dt = datetime(2026, 1, 15, 12, 30, 0, tzinfo=timezone.utc)
    result = _asdict_recursive(dt)
    assert result == "2026-01-15T12:30:00+00:00"


def test_asdict_recursive_primitive():
    assert _asdict_recursive(42) == 42
    assert _asdict_recursive("hello") == "hello"
    assert _asdict_recursive(None) is None


def test_asdict_recursive_nested():
    host = Host(ip="10.0.0.1")
    share = Share(host=host, name="Data", path="\\\\10.0.0.1\\Data")
    result = _asdict_recursive(share)
    assert result["host"]["ip"] == "10.0.0.1"
    assert result["name"] == "Data"


# ── _checkpoint_save / _checkpoint_load ──

def test_checkpoint_save_creates_file(tmp_path):
    cfg = PipelineConfig(checkpoint_dir=str(tmp_path))
    data = [Host(ip="10.0.0.1", hostname="srv01")]
    _checkpoint_save(cfg, "hosts", data)
    path = tmp_path / "bleedings_checkpoint_hosts.json"
    assert path.exists()
    loaded = json.loads(path.read_text("utf-8"))
    assert isinstance(loaded, list)
    assert loaded[0]["ip"] == "10.0.0.1"


def test_checkpoint_save_no_dir():
    """No checkpoint_dir = no-op, no error."""
    cfg = PipelineConfig(checkpoint_dir=None)
    _checkpoint_save(cfg, "hosts", [])  # should not raise


def test_checkpoint_save_creates_parent_dirs(tmp_path):
    nested = tmp_path / "deep" / "nested"
    cfg = PipelineConfig(checkpoint_dir=str(nested))
    _checkpoint_save(cfg, "test", {"key": "value"})
    assert (nested / "bleedings_checkpoint_test.json").exists()


def test_checkpoint_load_existing(tmp_path):
    cfg = PipelineConfig(checkpoint_dir=str(tmp_path))
    data = [{"ip": "10.0.0.1"}]
    (tmp_path / "bleedings_checkpoint_hosts.json").write_text(
        json.dumps(data), encoding="utf-8"
    )
    result = _checkpoint_load(cfg, "hosts")
    assert result == data


def test_checkpoint_load_missing(tmp_path):
    cfg = PipelineConfig(checkpoint_dir=str(tmp_path))
    result = _checkpoint_load(cfg, "nonexistent")
    assert result is None


def test_checkpoint_load_no_dir():
    cfg = PipelineConfig(checkpoint_dir=None)
    result = _checkpoint_load(cfg, "hosts")
    assert result is None


# ── _auto_filename ──

@patch("smb_bleedings.pipeline.datetime")
def test_auto_filename_with_title(mock_dt):
    mock_dt.now.return_value = datetime(2026, 4, 13, 14, 30, tzinfo=timezone.utc)
    mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
    result = _auto_filename(["10.0.0.0/24"], "json", title="Audit Q1 2026")
    assert result.startswith("bleedings_audit_q1_2026_")
    assert result.endswith(".json")


@patch("smb_bleedings.pipeline.datetime")
def test_auto_filename_single_range(mock_dt):
    mock_dt.now.return_value = datetime(2026, 4, 13, 14, 30, tzinfo=timezone.utc)
    mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
    result = _auto_filename(["192.168.1.0/24"], "csv")
    assert "192.168.1.0-24" in result
    assert result.endswith(".csv")


@patch("smb_bleedings.pipeline.datetime")
def test_auto_filename_multi_ranges(mock_dt):
    mock_dt.now.return_value = datetime(2026, 4, 13, 14, 30, tzinfo=timezone.utc)
    mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
    result = _auto_filename(["10.0.0.0/24", "192.168.1.0/24"], "json")
    assert "multi" in result


def test_auto_filename_title_special_chars():
    result = _auto_filename(["10.0.0.0/24"], "json", title="Audit (Mars) / 2026!")
    assert "(" not in result
    assert "/" not in result
    assert "!" not in result

"""Tests pour smb_bleedings.config — parsing .env, TOML, DOMAIN\\user."""

import os
import textwrap
from unittest.mock import patch

import pytest

from smb_bleedings.config import PipelineConfig, load_env, load_config, _load_dotenv


# ── _load_dotenv ──

def test_load_dotenv_parses_key_value(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("MY_VAR=hello\n")
    with patch.dict(os.environ, {}, clear=True):
        _load_dotenv(str(env_file))
        assert os.environ["MY_VAR"] == "hello"


def test_load_dotenv_strips_quotes(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text('MY_VAR="quoted value"\n')
    with patch.dict(os.environ, {}, clear=True):
        _load_dotenv(str(env_file))
        assert os.environ["MY_VAR"] == "quoted value"


def test_load_dotenv_skips_comments_and_blanks(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\n\nVALID=yes\n")
    with patch.dict(os.environ, {}, clear=True):
        _load_dotenv(str(env_file))
        assert os.environ.get("VALID") == "yes"
        assert "# comment" not in os.environ


def test_load_dotenv_does_not_overwrite_existing(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("MY_VAR=from_file\n")
    with patch.dict(os.environ, {"MY_VAR": "existing"}, clear=True):
        _load_dotenv(str(env_file))
        assert os.environ["MY_VAR"] == "existing"


def test_load_dotenv_missing_file_no_error():
    _load_dotenv("/nonexistent/.env")


# ── load_env ──

def test_load_env_basic_credentials(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_USERNAME=admin\nSMB_PASSWORD=secret\nSMB_DOMAIN=corp.local\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.username == "admin"
    assert cfg.password == "secret"
    assert cfg.domain == "corp.local"


def test_load_env_domain_backslash_parsing(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_USERNAME=CORP\\admin\nSMB_PASSWORD=pass\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.username == "admin"
    assert cfg.domain == "CORP"


def test_load_env_domain_backslash_no_override(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_USERNAME=CORP\\admin\nSMB_PASSWORD=pass\nSMB_DOMAIN=explicit.local\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.domain == "explicit.local"
    assert cfg.username == "admin"


def test_load_env_ranges_comma_separated(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_RANGES=10.0.0.0/24,192.168.1.0/24\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.ranges == ["10.0.0.0/24", "192.168.1.0/24"]


def test_load_env_threads_and_timeout(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_THREADS=50\nSMB_TIMEOUT=5.5\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.threads_discovery == 50
    assert cfg.timeout == 5.5


def test_load_env_open_browser_false(tmp_path):
    env_file = tmp_path / ".env"
    for val in ("false", "0", "no"):
        env_file.write_text(f"SMB_OPEN_BROWSER={val}\n")
        with patch.dict(os.environ, {}, clear=True):
            cfg = load_env(str(env_file))
        assert cfg.open_browser is False, f"Failed for value: {val}"


# ── load_config (TOML) ──

def test_load_config_basic(tmp_path):
    toml_file = tmp_path / "config.toml"
    toml_file.write_text(textwrap.dedent("""\
        [scan]
        threads = 40
        timeout = 2.0
        exclude_system_shares = false

        [credentials]
        username = "user1"
        password = "pass1"
        domain = "test.local"
    """))
    cfg = load_config(str(toml_file))
    assert cfg.threads_discovery == 40
    assert cfg.timeout == 2.0
    assert cfg.exclude_system_shares is False
    assert cfg.username == "user1"
    assert cfg.domain == "test.local"


def test_load_config_domain_backslash(tmp_path):
    toml_file = tmp_path / "config.toml"
    toml_file.write_text(textwrap.dedent("""\
        [credentials]
        username = "CORP\\\\admin"
        password = "pass"
    """))
    cfg = load_config(str(toml_file))
    assert cfg.username == "admin"
    assert cfg.domain == "CORP"


def test_load_config_dangerous_groups(tmp_path):
    toml_file = tmp_path / "config.toml"
    toml_file.write_text(textwrap.dedent("""\
        [risk]
        dangerous_groups = ["Everyone", "Custom Group"]
    """))
    cfg = load_config(str(toml_file))
    assert cfg.dangerous_groups == ["Everyone", "Custom Group"]


def test_load_config_content_scan(tmp_path):
    toml_file = tmp_path / "config.toml"
    toml_file.write_text(textwrap.dedent("""\
        [content_scan]
        enabled = true
        keywords = ["password", "secret"]
        loot_dir = "/tmp/loot"
    """))
    cfg = load_config(str(toml_file))
    assert cfg.scan_content is True
    assert cfg.content_keywords == ["password", "secret"]
    assert cfg.content_loot_dir == "/tmp/loot"


# ── load_env — new variables (suggestions2 1.3) ──

def test_load_env_exclude_system_false(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_EXCLUDE_SYSTEM=false\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.exclude_system_shares is False


def test_load_env_exclude_system_default(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.exclude_system_shares is True


def test_load_env_lang_fr(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_LANG=fr\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.lang == "fr"


def test_load_env_lang_invalid_ignored(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_LANG=de\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.lang == "en"  # default unchanged


def test_load_env_scan_content_true(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_SCAN_CONTENT=true\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.scan_content is True


def test_load_env_content_keywords(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_CONTENT_KEYWORDS=password,secret,iban\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.content_keywords == ["password", "secret", "iban"]


def test_load_env_content_loot_dir(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_CONTENT_LOOT_DIR=/tmp/my_loot\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.content_loot_dir == "/tmp/my_loot"


def test_load_env_content_max_filesize(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_CONTENT_MAX_FILESIZE=50M\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.content_max_filesize == "50M"


def test_load_env_content_keep_loot_false(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMB_CONTENT_KEEP_LOOT=false\n")
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_env(str(env_file))
    assert cfg.content_keep_loot is False


# ── PipelineConfig defaults ──

def test_pipeline_config_defaults():
    cfg = PipelineConfig()
    assert cfg.threads_discovery == 50
    assert cfg.timeout == 3.0
    assert cfg.exclude_system_shares is True
    assert cfg.lang == "en"
    assert cfg.output_format == "json"
    assert cfg.content_threads == 5
    assert len(cfg.dangerous_groups) > 0

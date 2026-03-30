"""Tests pour smb_bleedings.agents.acl_analyzer."""

from smb_bleedings.agents.acl_analyzer import (
    WELL_KNOWN_SIDS,
    _mask_to_right,
    _sid_to_name,
)


def test_mask_to_right_full() -> None:
    assert _mask_to_right(0x001F01FF) == "Full"


def test_mask_to_right_change() -> None:
    assert _mask_to_right(0x001301BF) == "Change"


def test_mask_to_right_read() -> None:
    assert _mask_to_right(0x001200A9) == "Read"


def test_mask_to_right_custom() -> None:
    result = _mask_to_right(0x00000001)
    assert result.startswith("Custom")
    assert "0x00000001" in result


def test_mask_full_includes_change() -> None:
    # Full mask has all bits of Change, so Full wins
    assert _mask_to_right(0x001F01FF) == "Full"


def test_sid_everyone() -> None:
    assert _sid_to_name("S-1-1-0") == "Everyone"


def test_sid_authenticated_users() -> None:
    assert _sid_to_name("S-1-5-11") == "Authenticated Users"


def test_sid_builtin_users() -> None:
    assert _sid_to_name("S-1-5-32-545") == "BUILTIN\\Users"


def test_sid_builtin_admins() -> None:
    assert _sid_to_name("S-1-5-32-544") == "BUILTIN\\Administrators"


def test_sid_unknown_returns_raw() -> None:
    assert _sid_to_name("S-1-5-21-1234") == "S-1-5-21-1234"


def test_sid_system() -> None:
    assert _sid_to_name("S-1-5-18") == "SYSTEM"


def test_all_well_known_sids_mapped() -> None:
    for sid, name in WELL_KNOWN_SIDS.items():
        assert _sid_to_name(sid) == name


# ── Edge cases (6.3) ──

def test_mask_zero() -> None:
    result = _mask_to_right(0x00000000)
    assert result.startswith("Custom")


def test_mask_all_bits() -> None:
    result = _mask_to_right(0xFFFFFFFF)
    assert result == "Full"


def test_mask_read_plus_extra_bits() -> None:
    """Read mask with extra bits should still be at least Read."""
    result = _mask_to_right(0x001200A9 | 0x00000002)
    # Extra bits don't change the hierarchy: check it's Read or higher
    assert result in ("Read", "Change", "Full")

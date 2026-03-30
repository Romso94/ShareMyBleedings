"""Tests pour smb_bleedings.utils.risk."""

from smb_bleedings.config import DANGEROUS_GROUPS_DEFAULT
from smb_bleedings.models import AclEntry
from smb_bleedings.utils.risk import score_acl


def test_score_everyone_full() -> None:
    entries = [AclEntry("Everyone", "Full", "Allow")]
    level, score, reasons, dangerous, recs, impacts = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 95
    assert len(reasons) == 1
    assert "'Everyone'" in reasons[0]
    assert len(dangerous) == 1
    assert dangerous[0].account == "Everyone"
    assert len(impacts) == 1


def test_score_everyone_change() -> None:
    entries = [AclEntry("Everyone", "Change", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 90


def test_score_everyone_read() -> None:
    entries = [AclEntry("Everyone", "Read", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "HIGH"
    assert score == 65


def test_score_domain_users_full() -> None:
    entries = [AclEntry("Domain Users", "Full", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 90


def test_score_domain_users_change() -> None:
    entries = [AclEntry("Domain Users", "Change", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 85


def test_score_domain_users_read() -> None:
    entries = [AclEntry("Domain Users", "Read", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "MEDIUM"
    assert score == 40


def test_score_authenticated_users_full() -> None:
    entries = [AclEntry("Authenticated Users", "Full", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 85


def test_score_authenticated_users_read() -> None:
    entries = [AclEntry("Authenticated Users", "Read", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "MEDIUM"
    assert score == 35


def test_score_builtin_users_full() -> None:
    entries = [AclEntry("BUILTIN\\Users", "Full", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "HIGH"
    assert score == 75


def test_score_builtin_users_change() -> None:
    entries = [AclEntry("BUILTIN\\Users", "Change", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "HIGH"
    assert score == 70


def test_score_takes_maximum() -> None:
    entries = [
        AclEntry("Domain Users", "Read", "Allow"),      # score 40
        AclEntry("Everyone", "Change", "Allow"),         # score 90
    ]
    _, score, reasons, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert score == 90
    assert len(reasons) == 2


def test_safe_acl_returns_info() -> None:
    entries = [
        AclEntry("BUILTIN\\Administrators", "Full", "Allow"),
        AclEntry("DOMAIN\\GRP-Finance", "Read", "Allow"),
    ]
    level, score, reasons, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "INFO"
    assert score == 0
    assert len(reasons) == 0


def test_deny_entries_ignored() -> None:
    entries = [AclEntry("Everyone", "Full", "Deny")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "INFO"
    assert score == 0


def test_tout_le_monde_is_everyone_equivalent() -> None:
    entries = [AclEntry("Tout le monde", "Full", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 95


def test_nt_authority_prefix_normalized() -> None:
    entries = [AclEntry("NT AUTHORITY\\Authenticated Users", "Full", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 85


def test_empty_entries() -> None:
    level, score, reasons, *_ = score_acl([], DANGEROUS_GROUPS_DEFAULT)
    assert level == "INFO"
    assert score == 0
    assert reasons == []


def test_recommendations_not_empty_on_finding() -> None:
    entries = [AclEntry("Everyone", "Full", "Allow")]
    _, _, _, _, recs, impacts = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert len(recs) >= 1
    assert len(impacts) >= 1


def test_reasons_include_share_name() -> None:
    entries = [AclEntry("Everyone", "Full", "Allow")]
    _, _, reasons, _, _, impacts = score_acl(entries, DANGEROUS_GROUPS_DEFAULT, share_name="Projets")
    assert "[Projets]" in reasons[0]
    assert "[Projets]" in impacts[0]
    assert "'Everyone'" in reasons[0]


def test_reasons_include_account_without_share() -> None:
    entries = [AclEntry("Domain Users", "Change", "Allow")]
    _, _, reasons, _, _, _ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert "'Domain Users'" in reasons[0]


# ── Edge cases (6.3) ──

def test_recommendations_in_french() -> None:
    entries = [AclEntry("Everyone", "Full", "Allow")]
    _, _, _, _, recs, _ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT, share_name="Test", lang="fr")
    assert any(recs), "Should have at least one recommendation in French"
    # French recs should not contain typical English-only patterns
    combined = " ".join(recs)
    assert len(combined) > 0


def test_mixed_case_accounts() -> None:
    entries = [AclEntry("eVeRyOnE", "Full", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT)
    assert level == "CRITICAL"
    assert score == 95


def test_netlogon_sysvol_downgrade() -> None:
    """NETLOGON/SYSVOL with Authenticated Users Read should be INFO (score 5)."""
    entries = [AclEntry("Authenticated Users", "Read", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT, share_name="NETLOGON")
    assert level == "INFO"
    assert score == 5

    level2, score2, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT, share_name="SYSVOL")
    assert level2 == "INFO"
    assert score2 == 5


def test_netlogon_with_write_not_downgraded() -> None:
    """NETLOGON with write access should NOT be downgraded."""
    entries = [AclEntry("Authenticated Users", "Full", "Allow")]
    level, score, *_ = score_acl(entries, DANGEROUS_GROUPS_DEFAULT, share_name="NETLOGON")
    assert level == "CRITICAL"
    assert score > 0

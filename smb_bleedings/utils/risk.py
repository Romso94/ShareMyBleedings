"""Risk scoring logic for SMB ACLs (bilingual EN/FR)."""

from __future__ import annotations

from smb_bleedings.config import DANGEROUS_GROUPS_DEFAULT
from smb_bleedings.models import AclEntry


# (group_pattern, access_right, level, score, reason_tech_dict, reason_impact_dict)
# Each text field is a dict {"en": "...", "fr": "..."}.
RISK_MATRIX: list[tuple[str, str, str, int, dict[str, str], dict[str, str]]] = [
    ("Everyone", "Full", "CRITICAL", 95,
     {"en": "Full control granted to EVERYONE (anonymous users included)",
      "fr": "Contrôle total accordé à TOUS les utilisateurs (anonymes inclus)"},
     {"en": "Anyone can read, modify or delete every file on this share, even without an account",
      "fr": "N'importe qui peut lire, modifier ou supprimer tous les fichiers de ce partage, même sans compte"}),
    ("Tout le monde", "Full", "CRITICAL", 95,
     {"en": "Full control granted to EVERYONE (anonymous users included)",
      "fr": "Contrôle total accordé à TOUS les utilisateurs (anonymes inclus)"},
     {"en": "Anyone can read, modify or delete every file on this share, even without an account",
      "fr": "N'importe qui peut lire, modifier ou supprimer tous les fichiers de ce partage, même sans compte"}),
    ("Everyone", "Change", "CRITICAL", 90,
     {"en": "Modify access granted to anyone on the network",
      "fr": "Modification possible par n'importe qui sur le réseau"},
     {"en": "Anyone can drop or alter malicious files on this share",
      "fr": "N'importe qui peut modifier ou déposer des fichiers malveillants sur ce partage"}),
    ("Tout le monde", "Change", "CRITICAL", 90,
     {"en": "Modify access granted to anyone on the network",
      "fr": "Modification possible par n'importe qui sur le réseau"},
     {"en": "Anyone can drop or alter malicious files on this share",
      "fr": "N'importe qui peut modifier ou déposer des fichiers malveillants sur ce partage"}),
    ("Domain Users", "Full", "CRITICAL", 90,
     {"en": "Full control granted to all domain users",
      "fr": "Contrôle total accordé à tous les utilisateurs du domaine"},
     {"en": "Any domain employee can delete or encrypt the share data (ransomware risk)",
      "fr": "Tout employé du domaine peut supprimer ou chiffrer les données de ce partage (risque ransomware)"}),
    ("Domain Users", "Change", "CRITICAL", 85,
     {"en": "Modify access granted to all domain users",
      "fr": "Modification possible par tous les utilisateurs du domaine"},
     {"en": "Any employee can alter files — a single compromised account is enough to tamper with data",
      "fr": "Tout employé peut modifier les fichiers — un compte compromis suffit pour altérer les données"}),
    ("Authenticated Users", "Full", "CRITICAL", 85,
     {"en": "Full control granted to any authenticated user",
      "fr": "Contrôle total pour tout utilisateur authentifié"},
     {"en": "Anyone with an account can delete the entire share content",
      "fr": "Toute personne avec un compte peut supprimer l'intégralité des données du partage"}),
    ("Authenticated Users", "Change", "CRITICAL", 80,
     {"en": "Modify access granted to any authenticated user",
      "fr": "Modification pour tout utilisateur authentifié"},
     {"en": "Any authenticated account can alter files — extremely large attack surface",
      "fr": "Tout compte authentifié peut modifier les fichiers — surface d'attaque très large"}),
    ("BUILTIN\\Users", "Full", "HIGH", 75,
     {"en": "Full control granted to local Users group",
      "fr": "Contrôle total pour le groupe local Users"},
     {"en": "Local users on the machine have full access — risky if the host is compromised",
      "fr": "Les utilisateurs locaux de la machine ont un accès complet — risque si la machine est compromise"}),
    ("BUILTIN\\Users", "Change", "HIGH", 70,
     {"en": "Modify access granted to local Users group",
      "fr": "Modification pour le groupe local Users"},
     {"en": "Local users can alter files on the share",
      "fr": "Les utilisateurs locaux peuvent modifier les fichiers du partage"}),
    ("Everyone", "Read", "HIGH", 65,
     {"en": "Read access granted to anyone (anonymous users included)",
      "fr": "Lecture possible par n'importe qui (anonymes inclus)"},
     {"en": "Data accessible without authentication — potential information leak",
      "fr": "Données accessibles sans authentification — fuite d'information potentielle"}),
    ("Tout le monde", "Read", "HIGH", 65,
     {"en": "Read access granted to anyone (anonymous users included)",
      "fr": "Lecture possible par n'importe qui (anonymes inclus)"},
     {"en": "Data accessible without authentication — potential information leak",
      "fr": "Données accessibles sans authentification — fuite d'information potentielle"}),
    ("Domain Users", "Read", "MEDIUM", 40,
     {"en": "Read access granted to all domain users",
      "fr": "Lecture pour tous les utilisateurs du domaine"},
     {"en": "Every employee can browse these files — verify whether this is intentional",
      "fr": "Tous les employés peuvent consulter ces fichiers — vérifier si c'est intentionnel"}),
    ("Authenticated Users", "Read", "MEDIUM", 35,
     {"en": "Read access granted to any authenticated user",
      "fr": "Lecture pour tout utilisateur authentifié"},
     {"en": "Any account can read this data — broad exposure but may be legitimate",
      "fr": "Tout compte peut lire ces données — exposition large mais peut être légitime"}),
    ("BUILTIN\\Users", "Read", "LOW", 20,
     {"en": "Read access granted to local Users group",
      "fr": "Lecture pour le groupe local Users"},
     {"en": "Local users can read files on this share — verify whether this is intended",
      "fr": "Les utilisateurs locaux peuvent lire les fichiers de ce partage — vérifier si c'est voulu"}),
]


def _normalize_account(account: str) -> str:
    return account.strip().upper().replace("NT AUTHORITY\\", "")


def _match_group(account: str, pattern: str) -> bool:
    norm = _normalize_account(account)
    pnorm = _normalize_account(pattern)
    return norm == pnorm or norm.endswith("\\" + pnorm)


def _get_recommendation(account: str, access_right: str, share_name: str = "", lang: str = "en") -> str:
    """Context-aware recommendation based on the dangerous account and right."""
    norm = _normalize_account(account)
    right_lower = access_right.lower()

    if lang == "fr":
        share_ctx = f" sur '{share_name}'" if share_name else ""
        for key in ("EVERYONE", "TOUT LE MONDE"):
            if norm == key:
                if right_lower == "full":
                    return f"Retirer immédiatement '{account}' en contrôle total{share_ctx}. Commande : icacls \"chemin\" /remove Everyone. Créer un groupe AD dédié avec les droits nécessaires."
                if right_lower == "change":
                    return f"Retirer '{account}' en modification{share_ctx}. Si un accès public est requis, le limiter à la lecture seule via un groupe AD."
                return f"Remplacer '{account}' par un groupe AD restreint aux utilisateurs légitimes{share_ctx}."
        for key in ("DOMAIN USERS", "UTILISATEURS DU DOMAINE"):
            if norm == key or norm.endswith("\\" + key):
                if right_lower in ("full", "change"):
                    return f"Créer un groupe de sécurité AD dédié (ex: GS_{share_name or 'NomPartage'}_RW) et remplacer '{account}'{share_ctx}. Commande : Remove-SmbShareAccess -Name \"{share_name}\" -AccountName \"{account}\" -Force"
                return f"Vérifier si l'accès en lecture par '{account}'{share_ctx} est justifié métier. Si non, restreindre à un groupe dédié."
        if "AUTHENTICATED USERS" in norm:
            if right_lower in ("full", "change"):
                return f"Remplacer '{account}' par un groupe AD restreint{share_ctx}. Tout compte compromis du domaine a actuellement un accès en écriture."
            return f"Évaluer si '{account}' en lecture{share_ctx} est nécessaire. Envisager un groupe AD ciblé."
        if "BUILTIN\\USERS" in norm or norm == "USERS":
            if right_lower in ("full", "change"):
                return f"Retirer '{account}'{share_ctx} et restreindre aux groupes métier. Les utilisateurs locaux ne devraient pas avoir d'accès en écriture sur les partages réseau."
            return f"Auditer l'accès de '{account}'{share_ctx}. Préférer un groupe AD aux groupes locaux."
        return f"Auditer les droits de '{account}' ({access_right}){share_ctx} et appliquer le principe du moindre privilège."

    # English (default)
    share_ctx = f" on '{share_name}'" if share_name else ""
    for key in ("EVERYONE", "TOUT LE MONDE"):
        if norm == key:
            if right_lower == "full":
                return f"Immediately remove '{account}' full control{share_ctx}. Command: icacls \"path\" /remove Everyone. Create a dedicated AD group with the required rights."
            if right_lower == "change":
                return f"Remove '{account}' modify access{share_ctx}. If public access is required, restrict it to read-only via an AD group."
            return f"Replace '{account}' with an AD group restricted to legitimate users{share_ctx}."
    for key in ("DOMAIN USERS", "UTILISATEURS DU DOMAINE"):
        if norm == key or norm.endswith("\\" + key):
            if right_lower in ("full", "change"):
                return f"Create a dedicated AD security group (e.g. GS_{share_name or 'ShareName'}_RW) and replace '{account}'{share_ctx}. Command: Remove-SmbShareAccess -Name \"{share_name}\" -AccountName \"{account}\" -Force"
            return f"Verify whether read access by '{account}'{share_ctx} is business-justified. If not, restrict to a dedicated group."
    if "AUTHENTICATED USERS" in norm:
        if right_lower in ("full", "change"):
            return f"Replace '{account}' with a restricted AD group{share_ctx}. Any compromised domain account currently has write access."
        return f"Evaluate whether '{account}' read access{share_ctx} is needed. Consider a targeted AD group."
    if "BUILTIN\\USERS" in norm or norm == "USERS":
        if right_lower in ("full", "change"):
            return f"Remove '{account}'{share_ctx} and restrict to business groups. Local users should not have write access to network shares."
        return f"Audit '{account}' access{share_ctx}. Prefer AD groups over local groups."
    return f"Audit '{account}' rights ({access_right}){share_ctx} and apply the principle of least privilege."


#: Shares whose "Authenticated Users : Read" ACE is the legitimate Microsoft
#: baseline (GPO replication / logon scripts). Never scored above INFO unless
#: Everyone or a write right is granted (still detected by the matrix).
AD_LEGITIMATE_READ_SHARES = {"NETLOGON", "SYSVOL"}


def score_acl(
    acl_entries: list[AclEntry],
    dangerous_groups: list[str] | None = None,
    share_name: str = "",
    lang: str = "en",
) -> tuple[str, int, list[str], list[AclEntry], list[str], list[str]]:
    """Compute risk score for an ACL list.

    Returns:
        (risk_level, risk_score, reasons, dangerous_entries, recommendations, impacts)
    """
    if dangerous_groups is None:
        dangerous_groups = DANGEROUS_GROUPS_DEFAULT

    is_ad_legit = share_name.upper() in AD_LEGITIMATE_READ_SHARES

    best_level = "INFO"
    best_score = 0
    reasons: list[str] = []
    dangerous_entries: list[AclEntry] = []
    recommendations: list[str] = []
    seen_reasons: set[str] = set()
    seen_rec_keys: set[tuple[str, str]] = set()  # (normalized_account, right) for dedup
    impacts: list[str] = []

    for entry in acl_entries:
        if entry.ace_type.upper() == "DENY":
            continue

        for pattern, right, level, score, reason_tech_d, reason_impact_d in RISK_MATRIX:
            if not _match_group(entry.account, pattern):
                continue
            if entry.access_right.upper() != right.upper():
                continue

            reason_tech = reason_tech_d.get(lang, reason_tech_d["en"])
            reason_impact = reason_impact_d.get(lang, reason_impact_d["en"])

            eff_level, eff_score = level, score
            if is_ad_legit and right.upper() == "READ" and "AUTHENTICATED USERS" in _normalize_account(entry.account):
                eff_level, eff_score = "INFO", 5

            if eff_score > best_score:
                best_score = eff_score
                best_level = eff_level

            if reason_tech not in seen_reasons:
                seen_reasons.add(reason_tech)
                ctx_reason = f"'{entry.account}' → {reason_tech}"
                ctx_impact = reason_impact
                if share_name:
                    ctx_reason = f"[{share_name}] {ctx_reason}"
                    ctx_impact = f"[{share_name}] {ctx_impact}"
                reasons.append(ctx_reason)
                impacts.append(ctx_impact)
                dangerous_entries.append(entry)
                rec_key = (_normalize_account(entry.account), entry.access_right.upper())
                if rec_key not in seen_rec_keys:
                    seen_rec_keys.add(rec_key)
                    rec = _get_recommendation(entry.account, entry.access_right, share_name, lang)
                    recommendations.append(rec)

    return best_level, best_score, reasons, dangerous_entries, recommendations, impacts


# Keywords whose presence in a file strongly suggests real secrets (not just the word "password")
_HIGH_CONFIDENCE_KEYWORDS: set[str] = {
    "BEGIN RSA", "BEGIN OPENSSH", "BEGIN PRIVATE",
    "aws_access_key", "aws_secret", "client_secret",
    "jdbc:", "mongodb://", "postgres://", "mysql://",
    "connectionstring", "private_key", "private-key",
}

_LEVEL_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_LEVEL_BY_RANK = {v: k for k, v in _LEVEL_ORDER.items()}


def boost_score_for_content(finding: "Finding", lang: str = "en") -> None:
    """Adjust a finding's risk score based on content_matches (in-place).

    Conservative boost: high-confidence keywords (key material, connection
    strings) get +15, others (password, token…) get +10.  Score capped at 100.
    Level promoted at most one step to avoid false-positive escalation.
    """
    if not finding.content_matches:
        return

    all_keywords: set[str] = set()
    for cm in finding.content_matches:
        all_keywords.update(kw.lower() for kw in cm.matched_keywords)

    has_high_confidence = any(
        hk.lower() in kw for kw in all_keywords for hk in _HIGH_CONFIDENCE_KEYWORDS
    )

    boost = 15 if has_high_confidence else 10
    n_files = len(finding.content_matches)

    finding.risk_score = min(100, finding.risk_score + boost)

    # Promote level at most one step
    current_rank = _LEVEL_ORDER.get(finding.risk_level, 0)
    max_rank = min(current_rank + 1, 4)
    if finding.risk_score >= 90 and max_rank >= _LEVEL_ORDER["CRITICAL"]:
        finding.risk_level = "CRITICAL"
    elif finding.risk_score >= 65 and max_rank >= _LEVEL_ORDER["HIGH"]:
        finding.risk_level = _LEVEL_BY_RANK.get(max(current_rank, _LEVEL_ORDER["HIGH"]), finding.risk_level)
    elif finding.risk_score >= 35 and max_rank >= _LEVEL_ORDER["MEDIUM"]:
        finding.risk_level = _LEVEL_BY_RANK.get(max(current_rank, _LEVEL_ORDER["MEDIUM"]), finding.risk_level)

    sample_kw = ", ".join(sorted(all_keywords)[:5])
    if lang == "fr":
        finding.reasons.append(
            f"[{finding.share.name}] {n_files} fichier(s) sensible(s) détecté(s) "
            f"(mots-clés : {sample_kw}) — score ajusté +{boost}"
        )
        finding.impacts.append(
            f"[{finding.share.name}] Des fichiers contenant des secrets potentiels "
            f"sont exposés sur ce partage"
        )
    else:
        finding.reasons.append(
            f"[{finding.share.name}] {n_files} sensitive file(s) detected "
            f"(keywords: {sample_kw}) — score adjusted +{boost}"
        )
        finding.impacts.append(
            f"[{finding.share.name}] Files containing potential secrets "
            f"are exposed on this share"
        )

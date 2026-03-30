"""Résolution des SIDs Active Directory en noms lisibles via LDAP."""

from __future__ import annotations

import logging
import re
from threading import Lock

log = logging.getLogger(__name__)

# Regex de validation d'un SID (empêche l'injection LDAP)
_SID_RE = re.compile(r"^S-\d+-\d+(?:-\d+)*$")

# SIDs bien connus (pas besoin de LDAP pour ceux-là)
WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-0-0":      "Nobody",
    "S-1-1-0":      "Everyone",
    "S-1-2-0":      "LOCAL",
    "S-1-3-0":      "CREATOR OWNER",
    "S-1-3-1":      "CREATOR GROUP",
    "S-1-5-1":      "DIALUP",
    "S-1-5-2":      "NETWORK",
    "S-1-5-4":      "INTERACTIVE",
    "S-1-5-6":      "SERVICE",
    "S-1-5-7":      "ANONYMOUS LOGON",
    "S-1-5-9":      "Enterprise Domain Controllers",
    "S-1-5-10":     "SELF",
    "S-1-5-11":     "Authenticated Users",
    "S-1-5-12":     "RESTRICTED",
    "S-1-5-13":     "Terminal Server Users",
    "S-1-5-14":     "Remote Interactive Logon",
    "S-1-5-15":     "This Organization",
    "S-1-5-17":     "IUSR",
    "S-1-5-18":     "SYSTEM",
    "S-1-5-19":     "LOCAL SERVICE",
    "S-1-5-20":     "NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

# RIDs bien connus pour les domaines (S-1-5-21-xxx-xxx-xxx-<RID>)
WELL_KNOWN_RIDS: dict[int, str] = {
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    553: "RAS and IAS Servers",
}


def _is_domain_sid(sid_str: str) -> bool:
    """Vérifie si un SID est un SID de domaine (S-1-5-21-...)."""
    return bool(re.match(r"S-1-5-21-\d+-\d+-\d+-\d+", sid_str))


class SidResolver:
    """Résout les SIDs en noms lisibles via LDAP avec cache."""

    def __init__(
        self,
        dc: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        use_ssl: bool = False,
        use_gc: bool = True,
    ) -> None:
        self._dc = dc
        self._username = username
        self._password = password
        self._domain = domain
        self._use_ssl = use_ssl
        self._use_gc = use_gc
        self._cache: dict[str, str] = dict(WELL_KNOWN_SIDS)
        self._lock = Lock()
        self._connection: object | None = None
        self._base_dn: str = ""
        self._is_gc: bool = False

    def _connect(self) -> None:
        """Établit la connexion LDAP au DC (Global Catalog 3268 si dispo)."""
        if self._connection is not None:
            return

        from impacket.ldap.ldap import LDAPConnection, LDAPSessionError

        # Tenter d'abord le Global Catalog (gc:// port 3268) qui couvre toute la forêt
        gc_url = f"gc://{self._dc}"
        ldap_url = f"{'ldaps' if self._use_ssl else 'ldap'}://{self._dc}"

        urls = [gc_url, ldap_url] if self._use_gc else [ldap_url]
        last_exc: Exception | None = None

        for url in urls:
            try:
                conn = LDAPConnection(url, baseDN="")

                if self._username:
                    conn.login(self._username, self._password, self._domain)
                else:
                    conn.login("", "")

                self._connection = conn

                # Déterminer le baseDN
                if self._domain:
                    self._base_dn = ",".join(
                        f"DC={part}" for part in self._domain.split(".")
                    )
                else:
                    self._base_dn = self._read_default_naming_context()

                if not self._base_dn:
                    raise RuntimeError(
                        f"Cannot determine baseDN for {self._dc} — "
                        "provide domain= or fix RootDSE access"
                    )

                self._is_gc = url.startswith("gc://")
                log.info("LDAP connection established to %s (%s, baseDN=%s)", self._dc, url, self._base_dn)
                return

            except (OSError, RuntimeError) as exc:
                last_exc = exc
                log.warning("LDAP connection failed via %s: %s", url, exc)
                continue
            except Exception as exc:
                last_exc = exc
                log.warning("Unexpected error connecting via %s: %s", url, exc)
                continue

        # Aucune URL n'a fonctionné
        log.warning("LDAP connection failed to %s: %s", self._dc, last_exc)
        self._connection = None
        raise last_exc  # type: ignore[misc]

    def _read_default_naming_context(self) -> str:
        """Lit le defaultNamingContext depuis le RootDSE."""
        try:
            resp = self._connection.search(
                searchBase="",
                searchFilter="(objectClass=*)",
                attributes=["defaultNamingContext"],
                sizeLimit=1,
            )
            for item in resp:
                if hasattr(item, "getComponentByName"):
                    attrs = item.getComponentByName("attributes")
                    if attrs:
                        for attr in attrs:
                            if str(attr.getComponentByName("type")) == "defaultNamingContext":
                                vals = attr.getComponentByName("vals")
                                if vals:
                                    return str(vals.getComponentByPosition(0))
        except Exception as exc:
            log.warning("RootDSE lookup failed: %s", exc)
        return ""

    def _ldap_lookup(self, sid_str: str) -> str | None:
        """Recherche un SID dans l'AD via LDAP et retourne le nom.

        Thread-safe : sérialise l'accès à la connexion LDAP partagée.
        """
        if self._connection is None:
            return None

        # Valider le format SID pour empêcher l'injection LDAP
        if not _SID_RE.match(sid_str):
            log.debug("Invalid SID format, skipped: %s", sid_str)
            return None

        try:
            search_filter = f"(objectSid={sid_str})"
            search_base = "" if self._is_gc else self._base_dn

            # Sérialiser l'accès — impacket LDAPConnection n'est pas thread-safe
            with self._lock:
                resp = self._connection.search(
                    searchBase=search_base,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                )

            for item in resp:
                if not hasattr(item, "getComponentByName"):
                    continue

                attrs = item.getComponentByName("attributes")
                if not attrs:
                    continue

                for attr in attrs:
                    if str(attr.getComponentByName("type")) == "sAMAccountName":
                        vals = attr.getComponentByName("vals")
                        if vals:
                            sam_name = str(vals.getComponentByPosition(0))
                            prefix = self._domain.upper() if self._domain else ""
                            return f"{prefix}\\{sam_name}" if prefix else sam_name

        except Exception as exc:
            log.warning("LDAP lookup failed for SID %s: %s", sid_str, exc)

        return None

    def resolve(self, sid_str: str) -> str:
        """Résout un SID en nom lisible. Retourne le SID brut si non résolu."""
        sid_str = sid_str.strip()

        # Déjà en cache ?
        with self._lock:
            if sid_str in self._cache:
                return self._cache[sid_str]

        # Pas un SID ? Retourner tel quel
        if not sid_str.startswith("S-"):
            return sid_str

        # SID de domaine avec RID bien connu ?
        if _is_domain_sid(sid_str):
            rid = int(sid_str.rsplit("-", 1)[-1])
            if rid in WELL_KNOWN_RIDS:
                name = WELL_KNOWN_RIDS[rid]
                if self._domain:
                    name = f"{self._domain.upper()}\\{name}"
                with self._lock:
                    self._cache[sid_str] = name
                return name

        # Tenter le LDAP
        name = self._ldap_lookup(sid_str)
        if name:
            with self._lock:
                self._cache[sid_str] = name
            return name

        # Non résolu — retourner le SID brut
        return sid_str

    def resolve_bulk(self, sids: list[str]) -> dict[str, str]:
        """Résout une liste de SIDs en une passe."""
        return {sid: self.resolve(sid) for sid in sids}

    def close(self) -> None:
        """Ferme la connexion LDAP."""
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None


def create_resolver(
    dc: str,
    username: str = "",
    password: str = "",
    domain: str = "",
) -> SidResolver | None:
    """Crée un SidResolver connecté, ou None si pas de DC ou échec."""
    if not dc:
        return None

    try:
        resolver = SidResolver(dc, username, password, domain)
        resolver._connect()
        return resolver
    except Exception as exc:
        log.warning("SID resolver disabled (LDAP connection failed): %s", exc)
        return None

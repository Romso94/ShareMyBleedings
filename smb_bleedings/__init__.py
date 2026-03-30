"""ShareMyBleedings — Audit des partages SMB permissifs."""

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("sharemybleedings")
except Exception:
    __version__ = "0.0.0-dev"

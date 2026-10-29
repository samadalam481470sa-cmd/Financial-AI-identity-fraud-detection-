"""Tenant-scoped pseudonymous identifiers for fraud evidence.

Production/staging secret is external to source control. Rotating this key
requires a carefully planned re-keying migration for historical references.
"""
import hashlib
import hmac
import os


def reference_key():
    key = os.getenv("AEGIS_REFERENCE_HMAC_KEY", "")
    if not key:
        if os.getenv("AEGIS_MODE", "development") != "development":
            raise RuntimeError("AEGIS_REFERENCE_HMAC_KEY required outside development")
        return b"LOCAL-DEVELOPMENT-ONLY-NEVER-USE-OUTSIDE-SYNTHETIC-SANDBOX"
    if len(key.encode("utf-8")) < 32:
        raise RuntimeError("AEGIS_REFERENCE_HMAC_KEY must have at least 32 bytes")
    return key.encode("utf-8")


def ref(tenant, identifier):
    if not isinstance(tenant, str) or not isinstance(identifier, str):
        raise TypeError("Reference inputs must be strings")
    key = reference_key()
    data = (str(len(tenant)) + ":" + tenant + ":" + identifier).encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()[:32]

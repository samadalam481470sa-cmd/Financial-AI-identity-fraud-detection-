"""Strict staging OAuth/OIDC JWT validation; development API keys are never permitted in staging.

Only RS256 access tokens issued by the configured issuer, for the expected API
audience, with tenant and role claims are accepted. No user-provided JWKS URL.
"""
import json
import os
import hmac
from functools import lru_cache

import jwt
from fastapi import Header, HTTPException
from jwt import PyJWKClient

ALLOWED_ROLES = {"admin", "analyst", "service"}

@lru_cache(maxsize=1)
def jwks_client():
    url = os.environ["AEGIS_OIDC_JWKS_URL"]
    if not url.startswith("https://"):
        raise RuntimeError("OIDC JWKS URL must use HTTPS")
    return PyJWKClient(url, cache_jwk_set=True, lifespan=300)

def validate_mode():
    mode = os.getenv("AEGIS_MODE", "development")
    if mode not in ("development", "staging", "production"):
        raise RuntimeError("Invalid AEGIS_MODE")
    if mode == "staging":
        required = ("AEGIS_OIDC_ISSUER", "AEGIS_OIDC_AUDIENCE", "AEGIS_OIDC_JWKS_URL", "AEGIS_REFERENCE_HMAC_KEY")
        if any(not os.getenv(key) for key in required):
            raise RuntimeError("OIDC issuer, audience and JWKS are mandatory for staging")
        if not os.environ["AEGIS_OIDC_ISSUER"].startswith("https://"):
            raise RuntimeError("OIDC issuer must use HTTPS")
        if not os.environ["AEGIS_OIDC_JWKS_URL"].startswith("https://"):
            raise RuntimeError("OIDC JWKS must use HTTPS")
        if len(os.getenv("AEGIS_REFERENCE_HMAC_KEY", "").encode("utf-8")) < 32:
            raise RuntimeError("AEGIS_REFERENCE_HMAC_KEY must contain at least 32 bytes")
        if os.getenv("AEGIS_API_KEYS"):
            raise RuntimeError("Demo API keys are forbidden in staging")
    if mode == "production":
        raise RuntimeError("Production blocked: credential proofing, recovery, RLS, trusted telemetry and independent audit incomplete")

def _claims_principal(token):
    try:
        key = jwks_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=os.environ["AEGIS_OIDC_AUDIENCE"],
            issuer=os.environ["AEGIS_OIDC_ISSUER"], options={"require": ["exp", "iat", "iss", "aud", "sub"]}
        )
    except (jwt.PyJWTError, ValueError, KeyError, RuntimeError):
        raise HTTPException(401, "Invalid access token")
    tenant = claims.get("aegis_tenant")
    role = claims.get("aegis_role")
    if not isinstance(tenant, str) or not tenant or len(tenant) > 128 or role not in ALLOWED_ROLES:
        raise HTTPException(403, "Missing required authorized tenant/role claims")
    return {"tenant": tenant, "role": role, "subject": claims["sub"]}

def principal(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
    mode = os.getenv("AEGIS_MODE", "development")
    if mode == "staging":
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer access token required")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(401, "Bearer access token required")
        return _claims_principal(token)
    if mode != "development":
        raise HTTPException(503, "Production is not enabled")
    if not x_api_key:
        raise HTTPException(401, "API key required for development")
    try:
        keys = json.loads(os.getenv("AEGIS_API_KEYS", "{}"))
    except (ValueError, TypeError):
        keys = {}
    if not isinstance(keys, dict):
        keys = {}
    for expected, attrs in keys.items():
        if isinstance(expected, str) and hmac.compare_digest(expected, x_api_key) and isinstance(attrs, dict):
            if isinstance(attrs.get("tenant"), str) and attrs.get("tenant") and attrs.get("role") in ALLOWED_ROLES:
                return {"tenant": attrs["tenant"], "role": attrs["role"], "subject": "local-development"}
    raise HTTPException(401, "Invalid API key")

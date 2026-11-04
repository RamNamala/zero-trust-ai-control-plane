"""Bearer-token authentication for the MCP gateway.

The production path is an HS256 JWT with a required ``exp`` (a token that never expires defeats
zero trust) and a configurable leeway for clock skew. The algorithm list is pinned to ``HS256``
so ``alg: none`` and algorithm-confusion tokens are rejected by PyJWT itself.

Static and unsigned base64-JSON tokens let anyone who can type
``{"role":"admin"}`` become admin, so they exist only behind ``allow_insecure_dev_tokens`` (off by
default, warned at startup). ``AuthError.reason`` is a fixed category for audit logs; callers
always get the same generic ``Unauthenticated`` response, so failures can't be used as an oracle.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from dataclasses import dataclass
from typing import Literal, cast

import jwt

from control_plane.common.settings import Settings

Role = Literal["admin", "viewer"]
TokenKind = Literal["jwt", "dev_static", "dev_unsigned"]
ROLES: frozenset[str] = frozenset({"admin", "viewer"})

# RFC 6750 token68 after a case-insensitive scheme and exactly one space.
_BEARER = re.compile(r"[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9\-._~+/]+=*)")

_DEV_STATIC_TOKENS: tuple[tuple[bytes, Role], ...] = (
    (b"admin-secret-token", "admin"),
    (b"viewer-secret-token", "viewer"),
)


@dataclass(frozen=True, slots=True)
class Principal:
    role: Role
    subject: str
    token_kind: TokenKind


class AuthError(Exception):
    """``reason`` is one of: missing, malformed, expired, not_yet_valid, invalid, bad_role,
    dev_tokens_disabled, duplicate_header. Safe for logs; never echoed to the caller."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def parse_bearer(header: str | None) -> str:
    if header is None or header == "":
        raise AuthError("missing")
    match = _BEARER.fullmatch(header)
    if match is None:
        raise AuthError("malformed")
    return match.group(1)


def _checked_role(value: object) -> Role:
    if not isinstance(value, str) or value not in ROLES:
        raise AuthError("bad_role")
    return cast(Role, value)


def _decode_jwt(token: str, settings: Settings) -> Principal:
    try:
        claims = jwt.decode(
            token,
            settings.jwt_hs256_secret,
            algorithms=["HS256"],
            leeway=settings.jwt_leeway_seconds,
            audience=settings.jwt_audience,
            options={"require": ["exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise AuthError("not_yet_valid") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("invalid") from exc
    role = _checked_role(claims.get("role"))
    sub = claims.get("sub")
    subject = sub if isinstance(sub, str) else "unknown"
    return Principal(role=role, subject=subject, token_kind="jwt")  # noqa: S106 - a kind, not a secret


def _decode_dev_token(token: str) -> Principal:
    raw = token.encode("ascii")
    matched: Role | None = None
    # Compare against every static token so timing doesn't reveal which (if any) matched.
    for candidate, role in _DEV_STATIC_TOKENS:
        if hmac.compare_digest(raw, candidate):
            matched = role
    if matched is not None:
        return Principal(role=matched, subject=f"dev-static-{matched}", token_kind="dev_static")  # noqa: S106

    try:
        padded = raw + b"=" * (-len(raw) % 4)
        payload = json.loads(base64.b64decode(padded, altchars=b"-_", validate=True))
    except (binascii.Error, ValueError) as exc:
        raise AuthError("invalid") from exc
    if not isinstance(payload, dict):
        raise AuthError("invalid")
    role = _checked_role(payload.get("role"))
    return Principal(role=role, subject=f"dev-unsigned-{role}", token_kind="dev_unsigned")  # noqa: S106


def authenticate(header: str | None, settings: Settings) -> Principal:
    token = parse_bearer(header)
    if token.count(".") == 2:
        return _decode_jwt(token, settings)
    if not settings.allow_insecure_dev_tokens:
        raise AuthError("dev_tokens_disabled")
    return _decode_dev_token(token)

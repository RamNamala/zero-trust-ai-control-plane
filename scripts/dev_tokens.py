"""Print HS256 JWTs for the admin and viewer roles, for curl demos against the MCP gateway.

Uses the same secret the gateway reads (``CP_JWT_HS256_SECRET``), so the tokens validate without
turning on ``CP_ALLOW_INSECURE_DEV_TOKENS``. Tokens expire after ``--ttl`` seconds (default 3600):
the gateway requires ``exp``.

    uv run python scripts/dev_tokens.py            # both roles, KEY=VALUE lines
    uv run python scripts/dev_tokens.py --role viewer
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import jwt

from control_plane.common.settings import DEFAULT_JWT_SECRET


def mint(role: str, secret: str, ttl: int, now: int | None = None) -> str:
    issued = int(time.time()) if now is None else now
    claims = {"sub": f"dev-{role}", "role": role, "iat": issued, "exp": issued + ttl}
    return jwt.encode(claims, secret, algorithm="HS256")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--role", choices=["admin", "viewer"], help="print a single bare token")
    parser.add_argument("--ttl", type=int, default=3600, help="seconds until exp")
    args = parser.parse_args()

    secret = os.environ.get("CP_JWT_HS256_SECRET", DEFAULT_JWT_SECRET)
    if secret == DEFAULT_JWT_SECRET:
        print("warning: using the default dev secret; set CP_JWT_HS256_SECRET", file=sys.stderr)

    if args.role:
        print(mint(args.role, secret, args.ttl))
        return
    for role in ("admin", "viewer"):
        print(f"{role.upper()}_TOKEN={mint(role, secret, args.ttl)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Create .env from .env.example, filling in the values that must be random.

Kept as a script rather than a Makefile recipe because Make hands each recipe line to a
separate shell, which quietly mangles heredocs.
"""

import pathlib
import re
import secrets
import sys

GENERATED = (
    "KEYCLOAK_ADMIN_PASSWORD",
    "POSTGRES_PASSWORD",
    "GATEWAY_CLIENT_SECRET",
    "PORTAL_ADMIN_SECRET",
)

root = pathlib.Path(__file__).resolve().parent.parent
env = root / ".env"
example = root / ".env.example"

if env.exists():
    sys.exit(f"{env} already exists — refusing to overwrite.")

text = example.read_text()
for key in GENERATED:
    text = re.sub(rf"^{key}=\s*$", f"{key}={secrets.token_urlsafe(24)}", text, flags=re.M)
env.write_text(text)
env.chmod(0o600)

gateway = re.search(r"^GATEWAY_CLIENT_SECRET=(.*)$", text, flags=re.M).group(1)

print(f"Wrote {env}\n")
print("Still to fill in by hand:")
print("  GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, from your GitHub OAuth App.\n")
print("Copy this into the data plane's .env as GATEWAY_CLIENT_SECRET:")
print(f"  {gateway}")

#!/usr/bin/env python3
"""Create .env from .env.example, filling in the values that must be random.

GATEWAY_CLIENT_SECRET is deliberately NOT generated here: it belongs to the control
plane, which is the only place it can be set. Copy it across.
"""

import pathlib
import re
import secrets
import sys

GENERATED = ("SESSION_SECRET", "LOCAL_API_KEY_ACME", "LOCAL_API_KEY_DASHBOARD")

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

print(f"Wrote {env}\n")
print("Still to fill in: GATEWAY_CLIENT_SECRET — copy it from the control plane's .env.\n")
print("Your operator-issued API keys, for the /local/ route:")
for key in ("LOCAL_API_KEY_ACME", "LOCAL_API_KEY_DASHBOARD"):
    print(f"  {key}={re.search(rf'^{key}=(.*)$', text, flags=re.M).group(1)}")

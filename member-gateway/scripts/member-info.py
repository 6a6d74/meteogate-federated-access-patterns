#!/usr/bin/env python3
"""Collect what the federation's operator needs to admit this gateway.

Run it where the gateway will run. It asks a few questions, checks that this machine
can reach the federation's identity provider, and writes member-registration.json.
Send that file to the federation operator. It holds no secrets.

What the operator does with it:

  * Adds the GitHub accounts listed under `people` to the control plane's allow-list,
    so each can sign in and get a federation credential. The list is matched on the
    numeric GitHub ID, which this script looks up, so a renamed account does not carry
    access to whoever takes the old name.
  * Records the gateway, its contact and its routes, so the federation knows who is
    relying on its tokens — for example before rotating signing keys.

The gateway itself needs nothing from the control plane but its public discovery and
key documents: tokens are checked locally against the published keys, and no request
ever goes to the centre.

Usage:  member-info.py [--federation-env federation.env] [--gateway config/gateway.yaml]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

Fetch = Callable[[str], Any]


def fetch_json(url: str) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "member-gateway-info"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip().strip('"').strip("'")
    return env


# ══════════════════════════════════════════════════════════════════════════════════
# Checks
# ══════════════════════════════════════════════════════════════════════════════════

def check_federation(base: str, realm: str, fetch: Fetch = fetch_json) -> dict[str, Any]:
    """Can this machine read the documents the gateway depends on?"""
    issuer = f"{base.rstrip('/')}/realms/{realm}"
    result: dict[str, Any] = {"issuer": issuer, "discovery": False, "jwks": False,
                              "signing_keys": 0, "problems": []}
    try:
        discovery = fetch(f"{issuer}/.well-known/openid-configuration")
        result["discovery"] = True
    except (urllib.error.URLError, OSError, ValueError) as exc:
        result["problems"].append(f"discovery document unreachable: {exc}")
        return result
    if discovery.get("issuer") != issuer:
        result["problems"].append(
            f"discovery names issuer {discovery.get('issuer')!r}, expected {issuer!r}: "
            "tokens would be refused. Check CONTROL_BASE_URL and KC_REALM.")
    try:
        keys = fetch(discovery["jwks_uri"]).get("keys", [])
        result["jwks"] = True
        result["signing_keys"] = sum(1 for k in keys
                                     if k.get("use", "sig") == "sig" and k.get("alg") == "RS256")
        if not result["signing_keys"]:
            result["problems"].append("the key document has no RS256 signing key")
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        result["problems"].append(f"key document unreachable: {exc}")
    return result


def github_user(login: str, fetch: Fetch = fetch_json) -> dict[str, Any]:
    """GitHub's numeric ID for a login: the allow-list matches on it."""
    try:
        user = fetch(f"https://api.github.com/users/{login}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise LookupError(f"GitHub has no user {login!r}") from exc
        return {"login": login, "id": None, "note": f"lookup failed ({exc.code}); "
                                                    "the operator will look it up"}
    except (urllib.error.URLError, OSError) as exc:
        return {"login": login, "id": None, "note": f"lookup failed ({exc}); "
                                                    "the operator will look it up"}
    return {"login": user["login"], "id": user["id"],
            **({"name": user["name"]} if user.get("name") else {})}


def gateway_routes(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The service and routes from config/gateway.yaml, if the helper has run."""
    if not path.is_file():
        return {}, []
    try:
        import yaml
    except ImportError:
        return {}, []
    spec = yaml.safe_load(path.read_text()) or {}
    routes = [{"path": r["path"], "door": "open" if r.get("auth") == "none" else r.get("auth"),
               "quota_per_minute": r.get("rate_limiting", {}).get("requests_per_minute")}
              for r in spec.get("routes", [])]
    return spec, routes


# ══════════════════════════════════════════════════════════════════════════════════
# Questions
# ══════════════════════════════════════════════════════════════════════════════════

def ask(prompt: str, default: str = "", check: Callable[[str], str | None] | None = None,
        optional: bool = False) -> str:
    shown = f" [{default}]" if default else (" (Enter to skip)" if optional else "")
    while True:
        answer = input(f"{prompt}{shown}: ").strip() or default
        if not answer:
            if optional:
                return ""
            print("  (an answer is needed)")
            continue
        problem = check(answer) if check else None
        if problem:
            print(f"  {problem}")
            continue
        return answer


def interview(spec: dict[str, Any], fetch: Fetch = fetch_json) -> dict[str, Any]:
    service = spec.get("service", {})
    print("\n── Who runs this gateway ──────────────────────────────────────────────")
    organisation = ask("Organisation")
    operator = ask("Your name")
    github = ask("Your GitHub login", check=lambda a: None if LOGIN.match(a) else "not a GitHub login")
    contact = ask("Contact email for the federation operator", service.get("contact", ""),
                  lambda a: None if EMAIL.match(a) else "an email address, please")

    print("\n── The service ────────────────────────────────────────────────────────")
    name = ask("Service name", service.get("name", ""))
    description = ask("One line on what it serves", optional=True)
    host = spec.get("listen", {}).get("host", "")
    url = ask("The gateway's public URL", f"https://{host}" if host else "",
              lambda a: None if a.startswith("https://") else "an https:// URL")
    docs = ask("Public documentation URL", service.get("docs", ""), optional=True)

    print("\n── Who needs a federation credential ──────────────────────────────────")
    print("GitHub accounts to add to the federation's allow-list: you, and anyone\n"
          "else who will call federated routes. Enter one login per line, blank to end.")
    people: list[dict[str, Any]] = []
    logins = [github]
    while True:
        login = input("  GitHub login: ").strip().lstrip("@")
        if not login:
            break
        if not LOGIN.match(login):
            print("  not a GitHub login")
            continue
        logins.append(login)
    for login in dict.fromkeys(l.lower() for l in logins):
        try:
            person = github_user(login, fetch)
        except LookupError as exc:
            print(f"  {exc} — left out")
            continue
        shown = f"@{person['login']}" + (f" ({person['id']})" if person["id"] else "")
        print(f"  {shown}{' — ' + person['note'] if person.get('note') else ''}")
        people.append(person)

    return {
        "organisation": organisation,
        "operator": {"name": operator, "github": github, "email": contact},
        "service": {"name": name, "gateway_url": url,
                    **({"description": description} if description else {}),
                    **({"docs": docs} if docs else {})},
        "people": people,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--federation-env", type=Path, default=Path("federation.env"))
    parser.add_argument("--gateway", type=Path, default=Path("config/gateway.yaml"))
    parser.add_argument("-o", "--output", type=Path, default=Path("member-registration.json"))
    args = parser.parse_args()

    env = load_env(args.federation_env)
    base, realm = env.get("CONTROL_BASE_URL", ""), env.get("KC_REALM", "")
    if not base or not realm:
        print(f"error: {args.federation_env} needs CONTROL_BASE_URL and KC_REALM. The "
              "federation operator sends you this file.", file=sys.stderr)
        return 1

    spec, routes = gateway_routes(args.gateway)
    try:
        record = interview(spec)
    except (EOFError, KeyboardInterrupt):
        print("\nStopped; nothing written.", file=sys.stderr)
        return 1

    print("\n── Checking this machine can reach the federation ────────────────────")
    federation = check_federation(base, realm)
    for problem in federation["problems"]:
        print(f"  ✗ {problem}")
    if not federation["problems"]:
        print(f"  ✓ {federation['issuer']}: discovery and "
              f"{federation['signing_keys']} signing key(s) readable")

    record = {
        "kind": "federation-member-registration",
        "version": 1,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **record,
        "routes": routes or "not yet chosen — run scripts/routes-helper.py",
        "federation_check": federation,
    }
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(f"\nWrote {args.output}. Send it to the federation operator; it holds no secrets.")
    if federation["problems"]:
        print("Fix the reachability problems above first: until they are fixed, the "
              "gateway will refuse every federated request.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

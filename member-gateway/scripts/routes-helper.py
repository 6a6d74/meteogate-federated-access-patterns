#!/usr/bin/env python3
"""Choose the routes a member gateway protects, and the quotas on each.

Asks about the service, then about each *target* — a path on the service — and which
front doors it should have:

  federated  a bearer token from the federation    /api/obs        (per user)
  apikey     a key this operator issues             /local/api/obs  (per key)
  open       no credential                          /open/api/obs   (per address)

One global decision switches every open route off. Switched off, they stay in
config/targets.yaml, so switching them back on loses nothing, but they are left out of
config/gateway.yaml — and so out of APISIX's configuration — entirely.

Writes:
  config/targets.yaml   your answers; edit and rerun with --render, or rerun to change
  config/gateway.yaml   the gateway's operator YAML, generated from targets.yaml
  gateway.env           one random key per API-key consumer, kept across reruns

Usage:
  routes-helper.py              ask, starting from config/targets.yaml if it exists
  routes-helper.py --render     regenerate gateway.yaml from targets.yaml, no questions
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml, or run this inside the gateway "
             "image (see the README).")

DOORS = ("federated", "apikey", "open")
DEFAULT_PREFIX = {"federated": "", "apikey": "/local", "open": "/open"}
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class Invalid(Exception):
    pass


# ══════════════════════════════════════════════════════════════════════════════════
# targets.yaml → gateway.yaml
# ══════════════════════════════════════════════════════════════════════════════════

def key_var(consumer: str) -> str:
    return "LOCAL_API_KEY_" + re.sub(r"[^A-Z0-9]", "_", consumer.upper())


def validate(targets: dict[str, Any]) -> None:
    for field in ("service", "listen", "targets"):
        if field not in targets:
            raise Invalid(f"targets.yaml has no `{field}`")
    if not targets["service"].get("upstream", "").startswith(("http://", "https://")):
        raise Invalid("service.upstream must be an http:// or https:// URL")
    if not targets["listen"].get("host"):
        raise Invalid("listen.host is empty")
    if targets.get("open_routes") not in ("enabled", "disabled"):
        raise Invalid("open_routes must be `enabled` or `disabled`")

    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    for consumer in targets.get("api_keys", []):
        if not NAME.match(consumer.get("name", "")):
            raise Invalid(f"API key name {consumer.get('name')!r}: use a-z, 0-9 and -")
    for target in targets["targets"]:
        name = target.get("name", "")
        if not NAME.match(name):
            raise Invalid(f"target name {name!r}: use a-z, 0-9 and -")
        if not target.get("path", "").startswith("/") or "*" in target["path"]:
            raise Invalid(f"{name}: path must start with / and have no *; "
                          "set `subtree: true` to include what is under it")
        doors = [d for d in DOORS if target.get(d)]
        if not doors:
            raise Invalid(f"{name}: has no federated, apikey or open route")
        for door in doors:
            route = target[door]
            path = route.get("path", "")
            if not path.startswith("/") or "*" in path:
                raise Invalid(f"{name}.{door}.path {path!r}: start with /, no *")
            if path in seen_paths:
                raise Invalid(f"{name}.{door}: {path} is already used by another route")
            seen_paths.add(path)
            if int(route.get("quota", 0)) < 0:
                raise Invalid(f"{name}.{door}.quota: 0 means unlimited; no negatives")
        if name in seen_names:
            raise Invalid(f"target {name} appears twice")
        seen_names.add(name)


def routes_for(target: dict[str, Any], door: str) -> list[dict[str, Any]]:
    """One target behind one door: the path, and its subtree if asked for."""
    route = target[door]
    front, back = route["path"].rstrip("/") or "/", target["path"].rstrip("/") or "/"
    name = target["name"] if door == "federated" else f"{target['name']}-{'key' if door == 'apikey' else 'open'}"
    auth = "none" if door == "open" else door
    quota = int(route.get("quota", 0))
    methods = target.get("methods", ["GET"])

    exact: dict[str, Any] = {"name": name, "path": front, "methods": methods, "auth": auth}
    if front != back:
        exact["upstream_path"] = back
    out = [exact]

    if target.get("subtree"):
        sub: dict[str, Any] = {"name": f"{name}-sub", "path": f"{front.rstrip('/')}/*",
                               "methods": methods, "auth": auth}
        if front != back:
            sub["upstream_path"] = f"{back.rstrip('/')}/$1"
        out.append(sub)

    for r in out:
        r["rate_limiting"] = {"requests_per_minute": quota}
        if quota and len(out) > 1:
            # The path and everything under it are one allowance, not two.
            r["rate_limiting"]["group"] = name
    return out


def render(targets: dict[str, Any]) -> dict[str, Any]:
    """The operator YAML for data-plane/scripts/gen-apisix-config.py."""
    validate(targets)
    service = targets["service"]
    listen = targets["listen"]

    spec: dict[str, Any] = {
        "service": {
            "name": service["name"],
            "upstream": service["upstream"],
            "pass_host": "node" if service.get("own_host_header") else "pass",
        },
        "listen": {"host": listen["host"]},
        # Public facts about the federation's identity provider, from federation.env.
        # The gateway fetches the signing keys once and checks every token locally.
        "auth": {
            "provider": "keycloak",
            "discovery": "${CONTROL_BASE_URL}/realms/${KC_REALM}/.well-known/openid-configuration",
            "issuer": "${CONTROL_BASE_URL}/realms/${KC_REALM}",
            "jwks_url": "${CONTROL_BASE_URL}/realms/${KC_REALM}/protocol/openid-connect/certs",
            "audience": "${FEDERATION_AUDIENCE}",
            "portal": "${CONTROL_PORTAL_URL}",
            "help": "${FEDERATION_HELP_URL}",
            "cli": {"client_id": "${FEDERATION_CLI_CLIENT}",
                    "account_name": "${FEDERATION_ACCOUNT_NAME}"},
            "token_url": "${CONTROL_BASE_URL}/realms/${KC_REALM}/protocol/openid-connect/token",
        },
        "rate_limiting": {"requests_per_minute": int(targets.get("default_quota", 60))},
    }
    if service.get("docs"):
        spec["service"]["docs"] = service["docs"]
    if service.get("contact"):
        spec["service"]["contact"] = service["contact"]
    if listen.get("tls"):
        spec["listen"]["tls"] = {"cert": "/certs/server.crt", "key": "/certs/server.key"}
        spec["listen"]["redirect_http_to_https"] = True

    if targets.get("api_keys"):
        spec["local_keys"] = {"header": "apikey", "consumers": []}
        for consumer in targets["api_keys"]:
            entry: dict[str, Any] = {"name": consumer["name"],
                                     "key": "${" + key_var(consumer["name"]) + "}"}
            if consumer.get("quota"):
                entry["quota"] = {"requests_per_minute": int(consumer["quota"])}
            spec["local_keys"]["consumers"].append(entry)

    doors = ["federated", "apikey"]
    if targets["open_routes"] == "enabled":
        doors.append("open")
    spec["routes"] = [r for target in targets["targets"] for door in doors
                      if target.get(door) for r in routes_for(target, door)]
    if not spec["routes"]:
        raise Invalid("no routes left: every target is open-only and open routes are disabled")
    return spec


GATEWAY_HEADER = """\
# ═══════════════════════════════════════════════════════════════════════════════
# Member gateway — operator configuration. GENERATED by scripts/routes-helper.py
# from config/targets.yaml: change that (or rerun the helper), not this.
#
# The container turns this into APISIX's own configuration each time it starts.
# ${{VARS}} come from federation.env and gateway.env; no secret is written here.
#
# Open routes: {open}.
# ═══════════════════════════════════════════════════════════════════════════════
"""


def write_gateway(targets: dict[str, Any], config_dir: Path) -> dict[str, Any]:
    spec = render(targets)
    body = yaml.safe_dump(spec, sort_keys=False, width=100, default_flow_style=False)
    (config_dir / "gateway.yaml").write_text(
        GATEWAY_HEADER.format(open=targets["open_routes"]) + "\n" + body)
    return spec


def sync_keys(targets: dict[str, Any], env_file: Path) -> list[str]:
    """Give each consumer a key in gateway.env, keeping any it already has."""
    lines = env_file.read_text().splitlines() if env_file.is_file() else []
    have = {line.split("=", 1)[0] for line in lines if "=" in line and not line.startswith("#")}
    added = []
    for consumer in targets.get("api_keys", []):
        var = key_var(consumer["name"])
        if var not in have:
            lines.append(f"{var}={secrets.token_urlsafe(32)}")
            added.append(var)
    if added or not env_file.is_file():
        if not lines or not lines[0].startswith("#"):
            lines.insert(0, "# The gateway's own secrets. Keep out of version control.")
        env_file.write_text("\n".join(lines) + "\n")
        env_file.chmod(0o600)
    return added


def summary(spec: dict[str, Any], targets: dict[str, Any]) -> str:
    rows = [f"  {'ROUTE':<28} {'DOOR':<10} {'QUOTA/min':>9}  PATH → SERVICE"]
    for r in spec["routes"]:
        quota = r["rate_limiting"]["requests_per_minute"] or "none"
        door = "open" if r["auth"] == "none" else r["auth"]
        rows.append(f"  {r['name']:<28} {door:<10} {str(quota):>9}  "
                    f"{r['path']} → {r.get('upstream_path', r['path'])}")
    held = [t["name"] for t in targets["targets"] if t.get("open")]
    if targets["open_routes"] == "disabled" and held:
        rows.append(f"\n  Open routes are disabled; kept in targets.yaml but not served: "
                    f"{', '.join(n + '-open' for n in held)}")
    return "\n".join(rows)


# ══════════════════════════════════════════════════════════════════════════════════
# Questions
# ══════════════════════════════════════════════════════════════════════════════════

def ask(prompt: str, default: Any = None, check=None) -> str:
    shown = f" [{default}]" if default not in (None, "") else ""
    while True:
        answer = input(f"{prompt}{shown}: ").strip()
        if not answer and default is not None:
            answer = str(default)
        if not answer:
            print("  (an answer is needed)")
            continue
        if check:
            problem = check(answer)
            if problem:
                print(f"  {problem}")
                continue
        return answer


def ask_optional(prompt: str, default: str = "") -> str:
    shown = f" [{default}]" if default else " (Enter to skip, - to clear)"
    answer = input(f"{prompt}{shown}: ").strip()
    if answer == "-":
        return ""
    return answer or default


def yes(prompt: str, default: bool) -> bool:
    while True:
        answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes", "n", "no"):
            return answer.startswith("y")


def number(prompt: str, default: int) -> int:
    return int(ask(prompt, default, lambda a: None if a.isdigit() else "a whole number, please"))


def path_check(answer: str) -> str | None:
    if not answer.startswith("/"):
        return "a path starts with /"
    if "*" in answer:
        return "no wildcards — you'll be asked about what is under it next"
    return None


def interview(old: dict[str, Any]) -> dict[str, Any]:
    service = old.get("service", {})
    listen = old.get("listen", {})
    print("\n── The service you are protecting ─────────────────────────────────────")
    name = ask("Service name, as users see it on error pages", service.get("name"))
    upstream = ask("Where the gateway reaches it (URL, from inside the container;\n"
                   "  a service on this machine is http://host.docker.internal:PORT)",
                   service.get("upstream"),
                   lambda a: None if a.startswith(("http://", "https://")) else "http:// or https://")
    own_host = yes("Send the service its own hostname? (yes if it sits behind a web server\n"
                   "  or has its own TLS; no if it's on the same network)",
                   service.get("own_host_header", upstream.startswith("https://")))
    docs = ask_optional("Public documentation URL", service.get("docs", ""))
    contact = ask_optional("Operator contact — shown publicly on refusal pages",
                           service.get("contact", ""))

    print("\n── The gateway ────────────────────────────────────────────────────────")
    host = ask("Public hostname of this gateway (no https://)", listen.get("host"),
               lambda a: "just the hostname" if "/" in a or ":" in a else None)
    tls = yes("Does the gateway terminate TLS itself? (no if a load balancer or CDN in\n"
              "  front does; yes needs certs/server.crt and certs/server.key)",
              listen.get("tls", False))

    print("\n── Open routes ────────────────────────────────────────────────────────")
    print("Open routes need no credential. You can still define them per target; this\n"
          "switch decides whether any of them are served.")
    open_on = yes("Serve open routes?", old.get("open_routes", "disabled") == "enabled")
    default_quota = number("Default quota, requests per minute (0 = unlimited)",
                           old.get("default_quota", 60))

    print("\n── Your own API keys ──────────────────────────────────────────────────")
    print("Keys you issue yourself, for partners or internal systems. Each gets a\n"
          "random key in gateway.env. A key's own quota, if you set one, replaces the\n"
          "route's on every API-key route.")
    keys = []
    for consumer in old.get("api_keys", []):
        if yes(f"Keep key `{consumer['name']}`?", True):
            keys.append(consumer)
    while yes("Add an API key?", not keys):
        kname = ask("  Key name (a-z, 0-9, -)", None,
                    lambda a: None if NAME.match(a) else "a-z, 0-9 and - only")
        quota = number("  Its own quota per minute (0 = use each route's)", 0)
        keys.append({"name": kname, **({"quota": quota} if quota else {})})

    print("\n── Targets ────────────────────────────────────────────────────────────")
    print("A target is a path on your service. Each can have a federated, an API-key\n"
          "and an open route in front of it, each with its own quota.")
    targets = []
    for target in old.get("targets", []):
        if yes(f"Keep target `{target['name']}` ({target['path']})?", True):
            if yes("  Change it?", False):
                target = ask_target(target, default_quota)
            targets.append(target)
    while yes("Add a target?", not targets):
        targets.append(ask_target({}, default_quota))

    return {
        "service": {"name": name, "upstream": upstream, "own_host_header": own_host,
                    **({"docs": docs} if docs else {}),
                    **({"contact": contact} if contact else {})},
        "listen": {"host": host, "tls": tls},
        "open_routes": "enabled" if open_on else "disabled",
        "default_quota": default_quota,
        "api_keys": keys,
        "targets": targets,
    }


def ask_target(old: dict[str, Any], default_quota: int) -> dict[str, Any]:
    name = ask("  Target name (a-z, 0-9, -)", old.get("name"),
               lambda a: None if NAME.match(a) else "a-z, 0-9 and - only")
    path = ask("  Path on the service, e.g. /api/obs", old.get("path"), path_check).rstrip("/") or "/"
    subtree = yes(f"  Include everything under {path.rstrip('/')}/ too?", old.get("subtree", True))
    methods = ask("  HTTP methods", " ".join(old.get("methods", ["GET"]))).upper().split()
    target: dict[str, Any] = {"name": name, "path": path, "subtree": subtree, "methods": methods}
    for door in DOORS:
        had = old.get(door)
        label = {"federated": "a federated route (federation token)",
                 "apikey": "an API-key route (your keys)",
                 "open": "an open route (no credential)"}[door]
        if not yes(f"  Give it {label}?", bool(had) if old else door == "federated"):
            continue
        suggested = (had or {}).get("path") or (DEFAULT_PREFIX[door] + path if path != "/" else DEFAULT_PREFIX[door] or "/")
        front = ask(f"    {door} path", suggested, path_check).rstrip("/") or "/"
        quota = number(f"    {door} quota per minute (0 = unlimited)",
                       (had or {}).get("quota", default_quota))
        target[door] = {"path": front, "quota": quota}
    return target


# ══════════════════════════════════════════════════════════════════════════════════

TARGETS_HEADER = """\
# Your answers to scripts/routes-helper.py. Edit, then run it with --render (or rerun
# it to be asked again). config/gateway.yaml is generated from this file.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config-dir", type=Path, default=Path("config"))
    parser.add_argument("--env-file", type=Path, default=Path("gateway.env"))
    parser.add_argument("--render", action="store_true",
                        help="regenerate gateway.yaml from targets.yaml without asking")
    args = parser.parse_args()

    args.config_dir.mkdir(parents=True, exist_ok=True)
    targets_file = args.config_dir / "targets.yaml"
    old = yaml.safe_load(targets_file.read_text()) if targets_file.is_file() else {}

    if args.render:
        if not old:
            print(f"error: {targets_file} not found; run without --render first", file=sys.stderr)
            return 1
        targets = old
    else:
        try:
            targets = interview(old or {})
        except (EOFError, KeyboardInterrupt):
            print("\nStopped; nothing written.", file=sys.stderr)
            return 1

    try:
        spec = write_gateway(targets, args.config_dir)
    except Invalid as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not args.render:
        targets_file.write_text(TARGETS_HEADER + "\n" + yaml.safe_dump(targets, sort_keys=False))
    added = sync_keys(targets, args.env_file)

    print("\n" + summary(spec, targets) + "\n")
    print(f"Wrote {args.config_dir / 'gateway.yaml'}"
          + ("" if args.render else f" and {targets_file}"))
    if added:
        print(f"Added {', '.join(added)} to {args.env_file}. Hand each key to its holder "
              "privately; it is sent in the `apikey` header.")
    if any(t.get("apikey") for t in targets["targets"]) and not targets.get("api_keys"):
        print("Note: there are API-key routes but no keys, so they refuse everyone.")
    print("Restart the gateway to apply: docker compose up -d --force-recreate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

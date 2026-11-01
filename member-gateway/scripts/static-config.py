#!/usr/bin/env python3
"""APISIX's static configuration for this gateway: the image's copy, plus the proxy setting.

  static-config.py GATEWAY_YAML BASE_CONFIG OUT

Behind a reverse proxy or load balancer, every request arrives from the proxy's address,
so the open routes' per-address quota is one quota for everyone, and the access log shows
the proxy. With `listen.trusted_proxies` in gateway.yaml, nginx takes the client's address
from the header those proxies set, and only from them:

  listen:
    trusted_proxies: [10.0.0.0/8]            # addresses or networks
    client_address_header: X-Forwarded-For   # or X-Real-IP; X-Forwarded-For if unset

List only a proxy that overwrites or strips that header on the requests it passes on.
Otherwise a client can send its own and choose the address its quota is counted against.

Without `trusted_proxies`, BASE_CONFIG is copied unchanged. It is written afresh on every
start, so removing the setting takes effect on the next restart.
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from typing import Any

import yaml

HEADERS = ("X-Forwarded-For", "X-Real-IP")


def proxy_settings(listen: dict[str, Any]) -> dict[str, Any]:
    """nginx's real_ip settings for `listen`, or {} when there is no trusted proxy."""
    proxies = listen.get("trusted_proxies") or []
    if not isinstance(proxies, list):
        raise ValueError("listen.trusted_proxies: a list of addresses or networks")
    for proxy in proxies:
        try:
            ipaddress.ip_network(str(proxy), strict=False)
        except ValueError:
            raise ValueError(f"listen.trusted_proxies: {proxy!r} is not an address or network") from None
    header = listen.get("client_address_header", "X-Forwarded-For")
    if header not in HEADERS:
        raise ValueError(f"listen.client_address_header: {' or '.join(HEADERS)}, not {header!r}")
    if not proxies:
        return {}
    return {
        "real_ip_header": header,
        # Keep APISIX's own defaults: its internal requests come from these.
        "real_ip_from": ["127.0.0.1", "unix:", *map(str, proxies)],
        # X-Forwarded-For may hold a chain. Walk back from the right, past every trusted
        # proxy, to the first address that isn't one: the client as the outermost
        # trusted proxy saw it.
        "real_ip_recursive": "on" if header == "X-Forwarded-For" else "off",
    }


def render(gateway: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    settings = proxy_settings(gateway.get("listen", {}))
    if settings:
        base.setdefault("nginx_config", {}).setdefault("http", {}).update(settings)
    return base


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    gateway_path, base_path, out_path = map(Path, argv[1:])
    base_text = base_path.read_text()
    gateway = yaml.safe_load(gateway_path.read_text()) or {}
    try:
        settings = proxy_settings(gateway.get("listen", {}))
    except ValueError as exc:
        print(f"error: {gateway_path}: {exc}", file=sys.stderr)
        return 1
    if not settings:
        out_path.write_text(base_text)  # unchanged, comments and all
        return 0
    out_path.write_text(
        "# Generated at start from the image's config.yaml and gateway.yaml's\n"
        "# listen.trusted_proxies (scripts/static-config.py). Don't edit.\n"
        + yaml.safe_dump(render(gateway, yaml.safe_load(base_text)), sort_keys=False))
    print(f"Client addresses from {settings['real_ip_header']}, trusted from: "
          + ", ".join(settings["real_ip_from"][2:]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

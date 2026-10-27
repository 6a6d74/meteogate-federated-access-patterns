#!/usr/bin/env python3
"""Generate APISIX's native configuration from the operator-facing YAML.

This is the "simplified YAML configuration layer" the architecture document proposes
distributing to sovereign data service operators. The operator writes a short file
describing their service, their credential requirements and their routes; this turns it
into APISIX's own vocabulary — upstreams, consumers, TLS material, plugin chains, route
priorities, and the OIDC callback plumbing.

Design rules, in order of importance:

  1. The operator never sees an APISIX concept they did not ask for. Anything APISIX
     needs but the operator should not have to think about — the OIDC callback route,
     the subject-extraction function, plugin priorities — is synthesised here.
  2. Nothing secret is written to the operator's YAML. ${VARS} are resolved from the
     environment at generation time.
  3. The output is a build artefact. It is regenerated, never hand-edited, and the
     generated file says so.

Usage:  gen-apisix-config.py [config.yaml ...] -o apisix/conf/apisix.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml (or run `make config` which "
             "falls back to a container)")


# ══════════════════════════════════════════════════════════════════════════════════
# Variable expansion
# ══════════════════════════════════════════════════════════════════════════════════

VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class MissingVariable(Exception):
    pass


def expand(value: Any, env: dict[str, str], where: str = "") -> Any:
    """Recursively substitute ${NAME} from the environment."""
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in env or env[name] == "":
                raise MissingVariable(
                    f"{where}: ${{{name}}} is unset or empty. Add it to .env."
                )
            return env[name]
        return VAR.sub(replace, value)
    if isinstance(value, dict):
        return {k: expand(v, env, f"{where}.{k}" if where else k) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v, env, f"{where}[{i}]") for i, v in enumerate(value)]
    return value


def load_env(path: Path) -> dict[str, str]:
    """Read a .env file, letting the real environment win so CI can override."""
    env: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip().strip('"').strip("'")
    env.update(os.environ)
    return env


# ══════════════════════════════════════════════════════════════════════════════════
# Route path handling
# ══════════════════════════════════════════════════════════════════════════════════

def route_priority(path: str) -> int:
    """More specific paths must be tried first.

    APISIX resolves ambiguity between routes with `priority` (higher wins). Length of
    the fixed portion is a good proxy for specificity; an exact path beats a wildcard
    of the same length, so `/api/birds` is not shadowed by `/api/birds/*`.
    """
    fixed = path.rstrip("*")
    return len(fixed) * 10 + (5 if "*" not in path else 0)


def path_to_regex(path: str) -> str:
    """`/local/api/birds/*` → `^/local/api/birds/(.*)$`, for proxy-rewrite."""
    if path.endswith("*"):
        return "^" + re.escape(path[:-1]).replace(r"\-", "-") + "(.*)$"
    return "^" + re.escape(path).replace(r"\-", "-") + "$"


# ══════════════════════════════════════════════════════════════════════════════════
# Plugin builders
# ══════════════════════════════════════════════════════════════════════════════════

# Runs in the rewrite phase, before openid-connect validates anything, and pins the
# JWT subject into a header of its own.
#
# Two things make this safe despite reading an unverified token:
#
#   * it ALWAYS overwrites the header, so a client cannot supply its own value and
#     charge its requests to somebody else's quota;
#   * openid-connect (priority 2599) rejects an invalid token before limit-count
#     (priority 1002) ever reads the header, so by the time the value is used, the
#     token it came from has been verified against the federation's JWKS.
#
# The alternative — keying the quota on X-Userinfo, which openid-connect sets — does
# not work: that blob contains `iat` and `exp`, so it changes with every token and a
# user would get a fresh allowance each time they refreshed.
SUBJECT_EXTRACTOR = r"""
return function(conf, ctx)
    local core = require("apisix.core")
    local subject = "anonymous"
    local auth = core.request.header(ctx, "Authorization")
    if auth then
        local token = string.match(auth, "^[Bb]earer%s+(.+)$")
        if token then
            local segment = string.match(token, "^[^.]+%.([^.]+)%.")
            if segment then
                segment = string.gsub(segment, "-", "+")
                segment = string.gsub(segment, "_", "/")
                local padding = #segment % 4
                if padding > 0 then
                    segment = segment .. string.rep("=", 4 - padding)
                end
                local raw = ngx.decode_base64(segment)
                if raw then
                    local claims = core.json.decode(raw)
                    if claims and claims.sub then
                        subject = claims.sub
                        if claims.preferred_username then
                            core.request.set_header(ctx, "X-Fed-Username",
                                                    claims.preferred_username)
                        end
                    end
                end
            end
        end
    end
    core.request.set_header(ctx, "X-Fed-Subject", subject)
end
""".strip()


def limit_count(per_minute: int, key: str, key_type: str = "var") -> dict[str, Any]:
    return {
        "count": per_minute,
        "time_window": 60,
        "key": key,
        "key_type": key_type,
        "rejected_code": 429,
        # Without this, a rejected request falls through to nginx's stock 429 page —
        # which is HTML, and therefore exactly the wrong answer for the scripted client
        # that is most likely to hit a quota. With it, limit-count emits JSON, and
        # friendly-errors swaps in the readable page only when the client asked for one.
        "rejected_msg": (
            f"Quota exceeded: {per_minute} requests per 60 seconds. "
            "X-RateLimit-Reset gives the seconds remaining in the current window."
        ),
        # The quota headers are what the friendly-errors page reads to tell the user
        # how long to wait, so they must be on the rejection as well as the success.
        "show_limit_quota_header": True,
        # A gateway that fails open on a counter error is not enforcing a quota.
        "allow_degradation": False,
        "policy": "local",
    }


def openid_bearer(auth: dict[str, Any]) -> dict[str, Any]:
    """Bearer-token validation against the federation's JWKS. No call to the centre."""
    return {
        # client_id is doing double duty. The plugin schema requires it, and it is also
        # what claim_validator.audience.match_with_client_id compares the `aud` claim
        # against — there is no separate "expected audience" field. Setting it to the
        # federation audience is therefore how you say "only tokens minted for the
        # federation open this door". No secret is used on this path: verification is
        # local, against the cached JWKS.
        "client_id": auth["audience"],
        "client_secret": "unused-on-the-bearer-path",
        "discovery": auth["discovery"],
        "bearer_only": True,
        "use_jwks": True,
        "realm": auth.get("realm", "federation"),
        "ssl_verify": True,
        "token_signing_alg_values_expected": "RS256",
        "claim_validator": {
            "issuer": {"valid_issuers": [auth["issuer"]]},
            "audience": {"claim": "aud", "required": True, "match_with_client_id": True},
        },
        # Hand the verified claims to the backend, so a service that wants to do its own
        # per-user logic can, without re-parsing the token.
        "set_userinfo_header": True,
        "set_id_token_header": False,
        "set_access_token_header": False,
    }


def openid_session(auth: dict[str, Any], host: str, session_secret: str) -> dict[str, Any]:
    """Authorization code + PKCE with a session cookie, for browser navigation.

    A browser cannot put an Authorization header on an address-bar request. This is the
    mechanism that makes a protected URL simply work when pasted into Chrome, and the
    reason a `?token=` query-parameter fallback is not needed.
    """
    session = auth["session"]
    return {
        "client_id": session["client_id"],
        "client_secret": session["client_secret"],
        "discovery": auth["discovery"],
        "bearer_only": False,
        "use_pkce": True,
        "scope": session.get("scope", "openid profile email"),
        "realm": auth.get("realm", "federation"),
        "ssl_verify": True,
        "unauth_action": "auth",
        "session": {
            "secret": session_secret,
            "cookie": {"lifetime": session.get("cookie_lifetime", 3600)},
        },
        # Explicit rather than the plugin's default of appending `.apisix/redirect` to
        # whatever URI was requested: a fixed callback path can have a route of its own,
        # which is what makes the flow work under a path prefix that gets rewritten.
        "redirect_uri": f"https://{host}/session/callback",
        "logout_path": "/session/logout",
        "post_logout_redirect_uri": f"https://{host}/birds/",
        "set_access_token_header": True,
        "access_token_in_authorization_header": True,
        "set_userinfo_header": True,
        "set_id_token_header": False,
    }


def friendly_errors(spec: dict[str, Any], service: dict[str, Any],
                    auth: dict[str, Any], mode: str) -> dict[str, Any]:
    cli = auth.get("cli", {})
    return {
        "mode": mode if mode in ("federated", "apikey", "open") else "federated",
        "service_name": service["name"],
        "portal_url": auth.get("portal", ""),
        "docs_url": service.get("docs", ""),
        "token_url": auth.get("token_url", ""),
        "contact": service.get("contact", ""),
        # The refusal page has to print a setup command that works for someone with
        # nothing installed, so it needs the issuer and the public client id — not just
        # a usage example that assumes they are already configured.
        "issuer": auth.get("issuer", ""),
        "cli_client": cli.get("client_id", "federation-cli"),
        "account_name": cli.get("account_name", "meteogate"),
        # Where the refusal pages' "how to get a credential" links go. Unset, they point
        # at this gateway's own /help/, which only the testbed's data plane serves.
        "help_url": auth.get("help", ""),
    }


# ══════════════════════════════════════════════════════════════════════════════════
# Assembly
# ══════════════════════════════════════════════════════════════════════════════════

def build(spec: dict[str, Any], base: Path, session_secret: str) -> dict[str, Any]:
    service = spec["service"]
    listen = spec["listen"]
    auth = spec.get("auth", {})
    default_rate = spec.get("rate_limiting", {}).get("requests_per_minute", 60)

    # ── Upstreams. One per distinct backend URL named anywhere in the file. ────────
    upstreams: dict[str, str] = {}

    def upstream_id(url: str) -> str:
        if url not in upstreams:
            upstreams[url] = f"upstream-{len(upstreams) + 1}"
        return upstreams[url]

    upstream_id(service["upstream"])       # claim id 1 for the service's own backend

    # ── TLS. Inlined, because APISIX in standalone mode holds certificates in the
    #    same document as the routes. This is why the generated file is git-ignored.
    #
    #    Optional: an operator whose gateway sits behind a load balancer or CDN that
    #    terminates TLS leaves `listen.tls` out, and APISIX serves plain HTTP to that
    #    proxy alone. Redirecting to HTTPS is then the proxy's job — APISIX only ever
    #    sees HTTP, so its own redirect would send every request round in a loop. ─
    tls = listen.get("tls")
    ssls = []
    if tls:
        cert_path = (base / tls["cert"]).resolve()
        key_path = (base / tls["key"]).resolve()
        for path in (cert_path, key_path):
            if not path.is_file():
                sys.exit(f"TLS material missing: {path}\nRun `make certs` first.")
        ssls.append({
            "id": "default",
            "cert": cert_path.read_text(),
            "key": key_path.read_text(),
            "snis": [listen["host"], *listen.get("aliases", [])],
        })
    elif listen.get("redirect_http_to_https"):
        sys.exit("listen.redirect_http_to_https needs listen.tls. Without TLS here, "
                 "whatever terminates it in front of the gateway must redirect instead; "
                 "APISIX would only ever see HTTP and redirect every request forever.")

    # ── Consumers, for the operator's own API keys. ───────────────────────────────
    consumers = []
    key_header = spec.get("local_keys", {}).get("header", "apikey")
    for consumer in spec.get("local_keys", {}).get("consumers", []):
        plugins: dict[str, Any] = {"key-auth": {"key": consumer["key"]}}
        quota = consumer.get("quota", {}).get("requests_per_minute")
        if quota:
            # Consumer-level plugin config overrides the route's, so each partner can
            # carry their own allowance without a route per partner.
            plugins["limit-count"] = limit_count(quota, "consumer_name")
        consumers.append({"username": consumer["name"], "plugins": plugins})

    # ── Routes. ───────────────────────────────────────────────────────────────────
    routes = []
    uses_session = False

    for entry in spec["routes"]:
        mode = entry.get("auth", "none")
        path = entry["path"]
        plugins: dict[str, Any] = {}

        if mode == "federated":
            plugins["serverless-pre-function"] = {
                "phase": "rewrite",
                "functions": [SUBJECT_EXTRACTOR],
            }
            plugins["openid-connect"] = openid_bearer(auth)
            quota_key, quota_key_type = "http_x_fed_subject", "var"

        elif mode == "session":
            uses_session = True
            plugins["openid-connect"] = openid_session(auth, listen["host"], session_secret)
            # The session cookie is the identity here; the access token the plugin
            # injects downstream carries the subject, but the quota key has to be
            # something available at limit-count time, and the cookie is it.
            quota_key, quota_key_type = "cookie_session", "var"

        elif mode == "apikey":
            plugins["key-auth"] = {"header": key_header, "query": key_header}
            quota_key, quota_key_type = "consumer_name", "var"

        else:
            quota_key, quota_key_type = "remote_addr", "var"

        rate = entry.get("rate_limiting", {}).get("requests_per_minute", default_rate)
        if rate:
            plugins["limit-count"] = limit_count(rate, quota_key, quota_key_type)
            # Routes naming the same group share one counter: `/x` and `/x/*` are then
            # one allowance, not two. APISIX insists their quotas match.
            group = entry.get("rate_limiting", {}).get("group")
            if group:
                plugins["limit-count"]["group"] = group

        if entry.get("redirect"):
            plugins["redirect"] = {"uri": entry["redirect"], "ret_code": 302}

        upstream_path = entry.get("upstream_path")
        if upstream_path:
            if "$1" in upstream_path:
                plugins["proxy-rewrite"] = {
                    "regex_uri": [path_to_regex(path), upstream_path]
                }
            else:
                plugins["proxy-rewrite"] = {"uri": upstream_path}

        plugins["friendly-errors"] = friendly_errors(
            spec, service, auth, "apikey" if mode == "apikey" else
            ("open" if mode == "none" else "federated"))

        routes.append({
            "id": entry["name"],
            "name": entry["name"],
            "desc": f"{mode} · {path}",
            "uri": path,
            "methods": entry.get("methods", ["GET"]),
            "priority": entry.get("priority", route_priority(path)),
            "upstream_id": upstream_id(entry.get("upstream", service["upstream"])),
            "plugins": plugins,
        })

    # ── The OIDC callback route, synthesised.
    #
    #    The operator asked for `auth: session` on some routes; they did not ask for a
    #    callback endpoint, a logout path, or a route whose only job is to complete an
    #    authorization code exchange. Hiding this is most of the value of the layer.
    if uses_session:
        routes.append({
            "id": "session-callback",
            "name": "session-callback",
            "desc": "synthesised · OIDC redirect and logout endpoints for session routes",
            "uris": ["/session/callback", "/session/logout"],
            "methods": ["GET", "POST"],
            "priority": 10_000,
            "upstream_id": upstream_id(service["upstream"]),
            "plugins": {
                "openid-connect": openid_session(auth, listen["host"], session_secret),
            },
        })

    document: dict[str, Any] = {
        "upstreams": [
            {
                "id": uid,
                "type": "roundrobin",
                "scheme": url.split("://", 1)[0],
                "nodes": {url.split("://", 1)[1]: 1},
                # A backend that has fallen over should surface as a 502 the gateway
                # can explain, not as a request that hangs until the client gives up.
                "timeout": {"connect": 3, "send": 30, "read": 30},
                # `node` sends the backend its own hostname, which a backend behind a
                # virtual host or a TLS endpoint of its own needs. The default, `pass`,
                # forwards the gateway's, which suits a backend on the same network.
                "pass_host": service.get("pass_host", "pass"),
            }
            for url, uid in upstreams.items()
        ],
    }
    if ssls:
        document["ssls"] = ssls
    document["routes"] = routes

    if consumers:
        document["consumers"] = consumers

    if listen.get("redirect_http_to_https"):
        document["global_rules"] = [{
            "id": "http-to-https",
            "plugins": {"redirect": {"http_to_https": True}},
        }]

    return document


HEADER = """\
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  GENERATED FILE — DO NOT EDIT                                                ║
# ║                                                                              ║
# ║  Produced by scripts/gen-apisix-config.py from:                              ║
# ║{sources}
# ║                                                                              ║
# ║  Edit those, then run `make config`. Anything changed here is lost on the     ║
# ║  next generation, and APISIX reloads this file within a second of it          ║
# ║  changing — so a hand edit will appear to work, briefly.                     ║
# ║                                                                              ║
# ║  Contains private key material. Git-ignored deliberately.                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sources", nargs="+", type=Path,
                        help="operator configuration file(s)")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--print-routes", action="store_true",
                        help="summarise the generated routes on stderr")
    args = parser.parse_args()

    env = load_env(args.env)
    base = args.sources[0].parent.parent      # data-plane root, from gateway-config/x.yaml

    session_secret = env.get("SESSION_SECRET", "")
    if len(session_secret) < 16:
        return _fail("SESSION_SECRET must be at least 16 characters. Run `make secrets`.")

    merged: dict[str, Any] = {"routes": []}
    for source in args.sources:
        try:
            raw = yaml.safe_load(source.read_text())
            spec = expand(raw, env, source.name)
        except MissingVariable as exc:
            return _fail(str(exc))
        except yaml.YAMLError as exc:
            return _fail(f"{source}: {exc}")
        routes = spec.pop("routes", [])
        merged = {**merged, **spec, "routes": merged["routes"] + routes}

    document = build(merged, base, session_secret)

    sources = "\n".join(
        f"# ║    {str(s):<72}║" for s in args.sources
    )
    body = yaml.safe_dump(document, sort_keys=False, width=100, default_flow_style=False)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    # APISIX's standalone loader stops at #END; without it the file is ignored.
    args.output.write_text(HEADER.format(sources=sources) + "\n" + body + "#END\n")

    if args.print_routes:
        print(f"\n  {'ROUTE':<24} {'AUTH':<10} {'QUOTA/min':>9}  PATH", file=sys.stderr)
        for route in document["routes"]:
            plugins = route["plugins"]
            mode = ("federated" if plugins.get("openid-connect", {}).get("bearer_only")
                    else "session" if "openid-connect" in plugins
                    else "apikey" if "key-auth" in plugins
                    else "open")
            quota = plugins.get("limit-count", {}).get("count", "—")
            uri = route.get("uri") or ", ".join(route.get("uris", []))
            print(f"  {route['name']:<24} {mode:<10} {str(quota):>9}  {uri}", file=sys.stderr)
        print(file=sys.stderr)

    print(f"Wrote {args.output} "
          f"({len(document['routes'])} routes, "
          f"{len(document['upstreams'])} upstreams, "
          f"{len(document.get('consumers', []))} local consumers)", file=sys.stderr)
    return 0


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

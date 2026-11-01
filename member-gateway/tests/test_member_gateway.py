"""The member gateway's helpers, and what the shared generator makes of their output.

  python3 -m pytest member-gateway/tests        (needs pytest and PyYAML)

The end-to-end test, against the built image, is tests/e2e.py.
"""

from __future__ import annotations

import builtins
import copy
import importlib.util
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest
import yaml

PACKAGE = Path(__file__).resolve().parents[1]
REPO = PACKAGE.parent
GENERATOR = REPO / "data-plane" / "scripts" / "gen-apisix-config.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


routes = load(PACKAGE / "scripts" / "routes-helper.py", "routes_helper")
info = load(PACKAGE / "scripts" / "member-info.py", "member_info")
static = load(PACKAGE / "scripts" / "static-config.py", "static_config")

FEDERATION_ENV = {
    "CONTROL_BASE_URL": "https://identity.example.org", "KC_REALM": "federation",
    "CONTROL_PORTAL_URL": "https://identity.example.org/",
    "FEDERATION_CLI_CLIENT": "federation-cli", "FEDERATION_ACCOUNT_NAME": "meteogate",
    "FEDERATION_HELP_URL": "https://help.example.org/", "SESSION_SECRET": "x" * 32,
}

TARGETS = {
    "service": {"name": "Obs", "audience": "obs", "upstream": "https://obs.internal.example.org",
                "own_host_header": True, "contact": "ops@example.org"},
    "listen": {"host": "gw.example.org", "tls": False},
    "open_routes": "disabled",
    "default_quota": 60,
    "api_keys": [{"name": "partner-a", "quota": 10}, {"name": "internal"}],
    "targets": [
        {"name": "obs", "path": "/api/obs", "subtree": True, "methods": ["GET"],
         "federated": {"path": "/api/obs", "quota": 30},
         "apikey": {"path": "/local/api/obs", "quota": 60},
         "open": {"path": "/open/api/obs", "quota": 5}},
        {"name": "stations", "path": "/api/stations", "subtree": False, "methods": ["GET"],
         "open": {"path": "/open/api/stations", "quota": 0}},
    ],
}


def targets(**changes):
    out = copy.deepcopy(TARGETS)
    out.update(changes)
    return out


def generate(spec: dict, tmp_path: Path, monkeypatch) -> dict:
    """Run the data plane's generator on the helper's output, as the container does."""
    for key, value in FEDERATION_ENV.items():
        monkeypatch.setenv(key, value)
    for consumer in spec.get("local_keys", {}).get("consumers", []):
        monkeypatch.setenv(consumer["key"][2:-1], "k-" + consumer["name"])
    config = tmp_path / "config"
    config.mkdir(exist_ok=True)
    (config / "gateway.yaml").write_text(yaml.safe_dump(spec))
    out = tmp_path / "apisix.yaml"
    result = subprocess.run([sys.executable, str(GENERATOR), str(config / "gateway.yaml"),
                             "-o", str(out), "--env", "/dev/null"],
                            capture_output=True, text=True, env=None)
    assert result.returncode == 0, result.stderr
    return yaml.safe_load(out.read_text().replace("#END", ""))


# ── Open routes: the global switch ─────────────────────────────────────────────────

def test_disabled_open_routes_are_absent_from_the_yaml_and_from_apisix(tmp_path, monkeypatch):
    spec = routes.render(targets())
    assert all(r["auth"] != "none" for r in spec["routes"])
    assert "/open/" not in yaml.safe_dump(spec)
    document = generate(spec, tmp_path, monkeypatch)
    assert not [r for r in document["routes"] if "/open/" in r["uri"]]
    # The open-only target has no route at all; the other keeps its two doors.
    assert {r["name"] for r in document["routes"]} == {"obs", "obs-sub", "obs-key", "obs-key-sub"}


def test_enabled_open_routes_are_served(tmp_path, monkeypatch):
    document = generate(routes.render(targets(open_routes="enabled")), tmp_path, monkeypatch)
    by_name = {r["name"]: r for r in document["routes"]}
    assert by_name["stations-open"]["uri"] == "/open/api/stations"
    assert "limit-count" not in by_name["stations-open"]["plugins"]      # quota 0: unlimited
    assert by_name["obs-open-sub"]["plugins"]["proxy-rewrite"]["regex_uri"] == [
        "^/open/api/obs/(.*)$", "/api/obs/$1"]
    assert "openid-connect" not in by_name["obs-open"]["plugins"]
    assert by_name["obs-open"]["plugins"]["friendly-errors"]["mode"] == "open"


def test_disabled_open_routes_are_kept_in_targets_so_nothing_is_lost(tmp_path):
    config, env = tmp_path / "config", tmp_path / "gateway.env"
    config.mkdir()
    (config / "targets.yaml").write_text(yaml.safe_dump(targets()))
    old = sys.argv
    sys.argv = ["routes-helper.py", "--render", "--config-dir", str(config), "--env-file", str(env)]
    try:
        assert routes.main() == 0
    finally:
        sys.argv = old
    assert yaml.safe_load((config / "targets.yaml").read_text())["targets"][1]["open"]
    gateway = (config / "gateway.yaml").read_text()
    assert "Open routes: disabled." in gateway and "/open/" not in gateway


def test_nothing_left_when_every_target_is_open_only_and_open_is_off():
    with pytest.raises(routes.Invalid, match="no routes left"):
        routes.render(targets(targets=[TARGETS["targets"][1]]))


# ── Routes, quotas and keys ────────────────────────────────────────────────────────

def test_federated_routes_check_tokens_against_the_federation(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    oidc = {r["name"]: r for r in document["routes"]}["obs"]["plugins"]["openid-connect"]
    assert oidc["bearer_only"] and oidc["use_jwks"]
    # Only tokens naming this service: the per-service audience, and its scope advertised.
    assert oidc["client_id"] == "obs"
    friendly = {r["name"]: r for r in document["routes"]}["obs"]["plugins"]["friendly-errors"]
    assert friendly["token_scope"] == "service:obs"
    assert oidc["discovery"] == "https://identity.example.org/realms/federation/.well-known/openid-configuration"
    assert oidc["claim_validator"]["issuer"]["valid_issuers"] == ["https://identity.example.org/realms/federation"]


def test_a_path_and_its_subtree_share_one_quota(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    by_name = {r["name"]: r for r in document["routes"]}
    assert by_name["obs"]["uri"] == "/api/obs" and by_name["obs-sub"]["uri"] == "/api/obs/*"
    exact, sub = by_name["obs"]["plugins"]["limit-count"], by_name["obs-sub"]["plugins"]["limit-count"]
    assert exact == sub and exact["group"] == "obs" and exact["count"] == 30
    assert exact["key"] == "http_x_fed_subject"


def test_api_key_routes_rewrite_to_the_service_path_and_carry_per_key_quotas(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    by_name = {r["name"]: r for r in document["routes"]}
    assert by_name["obs-key"]["plugins"]["proxy-rewrite"]["uri"] == "/api/obs"
    assert by_name["obs-key"]["plugins"]["key-auth"]["header"] == "apikey"
    consumers = {c["username"]: c["plugins"] for c in document["consumers"]}
    assert consumers["partner-a"]["limit-count"]["count"] == 10
    assert "limit-count" not in consumers["internal"]
    assert consumers["partner-a"]["key-auth"]["key"] == "k-partner-a"


def test_the_key_and_the_token_stop_at_the_gateway(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    by_name = {r["name"]: r for r in document["routes"]}
    key_auth = by_name["obs-key"]["plugins"]["key-auth"]
    assert key_auth["hide_credentials"] is True and key_auth["query"] == "apikey"
    removed = by_name["obs"]["plugins"]["proxy-rewrite"]["headers"]["remove"]
    assert "Authorization" in removed


def test_forward_token_keeps_the_bearer_token(tmp_path, monkeypatch):
    t = targets()
    t["service"]["forward_token"] = True
    document = generate(routes.render(t), tmp_path, monkeypatch)
    by_name = {r["name"]: r for r in document["routes"]}
    assert "Authorization" not in by_name["obs"]["plugins"]["proxy-rewrite"]["headers"]["remove"]


def test_a_client_cannot_supply_identity_headers(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    for route in document["routes"]:
        removed = set(route["plugins"]["proxy-rewrite"]["headers"]["remove"])
        if route["name"].endswith(("-key", "-key-sub")):
            assert "X-Fed-Subject" in removed and "X-Userinfo" in removed
            assert "X-Consumer-Username" not in removed
        elif route["plugins"].get("openid-connect"):
            assert "X-Consumer-Username" in removed
            assert "X-Fed-Subject" not in removed and "X-Userinfo" not in removed
        else:
            assert {"X-Fed-Subject", "X-Userinfo", "X-Consumer-Username"} <= removed


def test_every_route_pins_the_credential_kind_for_the_log(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    for route in document["routes"]:
        functions = route["plugins"]["serverless-pre-function"]["functions"]
        assert "ngx.var.cred_kind" in functions[0], route["name"]


def test_backend_hostname_and_help_link(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    assert document["upstreams"][0]["pass_host"] == "node"
    assert document["upstreams"][0]["scheme"] == "https"
    friendly = document["routes"][0]["plugins"]["friendly-errors"]
    assert friendly["help_url"] == "https://help.example.org/"
    assert friendly["contact"] == "ops@example.org"
    off = generate(routes.render(targets(service={**TARGETS["service"], "own_host_header": False})),
                   tmp_path, monkeypatch)
    assert off["upstreams"][0]["pass_host"] == "pass"


# ── Behind a proxy: the client's address (#12) ───────────────────────────────────────

BEHIND = {"host": "gw.example.org", "tls": False, "trusted_proxies": ["10.0.0.0/8", "192.0.2.1"]}


def test_no_proxy_leaves_the_static_config_byte_for_byte(tmp_path):
    gateway = tmp_path / "gateway.yaml"
    gateway.write_text(yaml.safe_dump(routes.render(targets())))
    out = tmp_path / "config.yaml"
    base = PACKAGE / "apisix" / "config.yaml"
    assert static.main(["x", str(gateway), str(base), str(out)]) == 0
    assert out.read_text() == base.read_text()


def test_trusted_proxies_become_nginx_real_ip_settings(tmp_path, monkeypatch):
    spec = routes.render(targets(listen=BEHIND))
    assert spec["listen"]["trusted_proxies"] == ["10.0.0.0/8", "192.0.2.1"]
    assert spec["listen"]["client_address_header"] == "X-Forwarded-For"
    generate(spec, tmp_path, monkeypatch)  # the route generator doesn't mind the new keys
    gateway = tmp_path / "config" / "gateway.yaml"
    out = tmp_path / "config.yaml"
    assert static.main(["x", str(gateway), str(PACKAGE / "apisix" / "config.yaml"), str(out)]) == 0
    http = yaml.safe_load(out.read_text())["nginx_config"]["http"]
    assert http["real_ip_header"] == "X-Forwarded-For" and http["real_ip_recursive"] == "on"
    assert http["real_ip_from"] == ["127.0.0.1", "unix:", "10.0.0.0/8", "192.0.2.1"]
    # Everything else is the image's config: the log format, the credential maps.
    assert "$log_uri" in http["access_log_format"]
    assert "cred_kind" in yaml.safe_load(out.read_text())["nginx_config"]["http_configuration_snippet"]


def test_x_real_ip_needs_no_recursion():
    settings = static.proxy_settings({**BEHIND, "client_address_header": "X-Real-IP"})
    assert settings["real_ip_header"] == "X-Real-IP" and settings["real_ip_recursive"] == "off"


@pytest.mark.parametrize("listen, message", [
    ({**BEHIND, "trusted_proxies": ["not-a-network"]}, "not an address or network"),
    ({**BEHIND, "trusted_proxies": "10.0.0.0/8"}, "a list"),
    ({**BEHIND, "client_address_header": "Forwarded"}, "X-Forwarded-For or X-Real-IP"),
])
def test_proxy_settings_are_checked(listen, message):
    with pytest.raises(routes.Invalid, match=message):
        routes.render(targets(listen=listen))


def test_rerunning_the_questions_keeps_settings_not_asked_about(monkeypatch, capsys):
    old = targets(listen=BEHIND, service={**TARGETS["service"], "forward_token": True})
    monkeypatch.setattr(builtins, "input", lambda prompt="": "")  # accept every default
    new = routes.interview(old)
    assert new["service"]["forward_token"] is True
    assert new["listen"]["trusted_proxies"] == ["10.0.0.0/8", "192.0.2.1"]


# ── Links: the public host and prefix (#9) ─────────────────────────────────────────

@pytest.mark.parametrize("front, back, prefix", [
    ("/api/obs", "/api/obs", ""), ("/local/api/obs", "/api/obs", "/local"),
    ("/open", "/", "/open"), ("/elsewhere", "/api/obs", ""),
])
def test_the_prefix_is_what_the_door_adds(front, back, prefix):
    assert routes.forwarded_prefix(front, back) == prefix


def test_prefixed_doors_tell_the_service_their_prefix(tmp_path, monkeypatch):
    t = targets(open_routes="enabled")
    document = generate(routes.render(t), tmp_path, monkeypatch)
    by_name = {r["name"]: r["plugins"]["proxy-rewrite"]["headers"] for r in document["routes"]}
    assert by_name["obs-key"]["set"]["X-Forwarded-Prefix"] == "/local"
    assert by_name["obs-open-sub"]["set"]["X-Forwarded-Prefix"] == "/open"
    assert "X-Forwarded-Prefix" not in by_name["obs"]["set"]
    assert "X-Forwarded-Prefix" in by_name["obs"]["remove"]   # a client's own is dropped
    for headers in by_name.values():
        assert headers["set"]["X-Forwarded-Host"] == "$host"


def test_a_trailing_slash_reaches_the_same_place(tmp_path, monkeypatch):
    t = targets(open_routes="enabled")
    t["targets"].append({"name": "home", "path": "/", "subtree": False, "methods": ["GET"],
                         "open": {"path": "/open", "quota": 5}})
    spec = routes.render(t)
    by_name = {r["name"]: r for r in spec["routes"]}
    assert by_name["home-open-slash"]["path"] == "/open/"
    assert by_name["home-open-slash"]["upstream_path"] == "/"
    assert by_name["stations-open-slash"]["upstream_path"] == "/api/stations/"
    # One allowance for /open and /open/.
    assert by_name["home-open-slash"]["rate_limiting"]["group"] == by_name["home-open"]["rate_limiting"]["group"]
    assert "obs-slash" not in by_name     # a subtree's /* covers it
    generate(spec, tmp_path, monkeypatch)


# ── Browser apps on other sites (#10) ──────────────────────────────────────────────

def test_cors_on_every_door_by_default(tmp_path, monkeypatch):
    document = generate(routes.render(targets(open_routes="enabled")), tmp_path, monkeypatch)
    for route in document["routes"]:
        cors = route["plugins"]["cors"]
        assert cors["allow_origins"] == "*" and cors["allow_credential"] is False
        assert "Authorization" in cors["allow_headers"] and "apikey" in cors["allow_headers"]
        assert "WWW-Authenticate" in cors["expose_headers"] and "Retry-After" in cors["expose_headers"]
        assert "OPTIONS" in route["methods"]


def test_cors_origins_can_be_named_or_switched_off(tmp_path, monkeypatch):
    named = targets(service={**TARGETS["service"], "cors_origins": ["https://maps.example.org"]})
    document = generate(routes.render(named), tmp_path, monkeypatch)
    assert document["routes"][0]["plugins"]["cors"]["allow_origins"] == "https://maps.example.org"
    off = generate(routes.render(targets(service={**TARGETS["service"], "cors_origins": []})),
                   tmp_path, monkeypatch)
    assert all("cors" not in r["plugins"] and "OPTIONS" not in r["methods"] for r in off["routes"])


@pytest.mark.parametrize("origins", [["maps.example.org"], ["https://a.example/x"], ["*", "https://a.example"], "*"])
def test_cors_origins_are_checked(origins):
    with pytest.raises(routes.Invalid, match="cors_origins"):
        routes.render(targets(service={**TARGETS["service"], "cors_origins": origins}))


# ── Upstream timeout (#11) ───────────────────────────────────────────────────────────

def test_upstream_timeout_defaults(tmp_path, monkeypatch):
    document = generate(routes.render(targets()), tmp_path, monkeypatch)
    assert document["upstreams"][0]["timeout"] == {"connect": 3, "send": 30, "read": 30}


def test_service_timeout_overrides_only_what_it_names(tmp_path, monkeypatch):
    service = {**TARGETS["service"], "timeout": {"read": 45}}
    document = generate(routes.render(targets(service=service)), tmp_path, monkeypatch)
    assert document["upstreams"][0]["timeout"] == {"connect": 3, "send": 30, "read": 45}


@pytest.mark.parametrize("timeout", [{"read": 0}, {"read": 601}, {"read": "45"}, {"total": 5}, 45])
def test_service_timeout_is_checked(timeout):
    with pytest.raises(routes.Invalid, match="service.timeout"):
        routes.render(targets(service={**TARGETS["service"], "timeout": timeout}))


def test_the_generator_checks_the_timeout_too(tmp_path, monkeypatch):
    spec = routes.render(targets())
    spec["service"]["timeout"] = {"read": -1}
    for key, value in FEDERATION_ENV.items():
        monkeypatch.setenv(key, value)
    for consumer in spec.get("local_keys", {}).get("consumers", []):
        monkeypatch.setenv(consumer["key"][2:-1], "k")
    (tmp_path / "gateway.yaml").write_text(yaml.safe_dump(spec))
    result = subprocess.run([sys.executable, str(GENERATOR), str(tmp_path / "gateway.yaml"),
                             "-o", str(tmp_path / "out.yaml"), "--env", "/dev/null"],
                            capture_output=True, text=True)
    assert result.returncode != 0 and "service.timeout.read" in result.stderr


def test_rerunning_the_questions_keeps_connect_and_send(monkeypatch):
    service = {**TARGETS["service"], "timeout": {"connect": 5, "read": 45}}
    monkeypatch.setattr(builtins, "input", lambda prompt="": "")
    assert routes.interview(targets(service=service))["service"]["timeout"] == {"connect": 5, "read": 45}


def test_tls_at_the_gateway(tmp_path, monkeypatch):
    spec = routes.render(targets(listen={"host": "gw.example.org", "tls": True}))
    assert spec["listen"]["tls"] == {"cert": "/certs/server.crt", "key": "/certs/server.key"}
    assert spec["listen"]["redirect_http_to_https"] is True


def test_no_secret_or_federation_address_is_written_to_gateway_yaml():
    text = yaml.safe_dump(routes.render(targets()))
    assert "${LOCAL_API_KEY_PARTNER_A}" in text and "${CONTROL_BASE_URL}" in text
    assert "identity.example.org" not in text


@pytest.mark.parametrize("change, message", [
    ({"open_routes": "maybe"}, "open_routes"),
    ({"service": {**TARGETS["service"], "audience": "Federation Services"}}, "service.audience"),
    ({"service": {**TARGETS["service"], "audience": ""}}, "service.audience"),
    ({"targets": [{**TARGETS["targets"][0], "path": "/api/obs/*"}]}, "no \\*"),
    ({"targets": [{**TARGETS["targets"][0], "name": "Obs!"}]}, "target name"),
    ({"targets": [{"name": "x", "path": "/x"}]}, "has no federated"),
    ({"targets": [TARGETS["targets"][0], {**TARGETS["targets"][0], "name": "again"}]}, "already used"),
    ({"service": {"name": "x", "audience": "x", "upstream": "obs:8000"}}, "upstream"),
])
def test_validation(change, message):
    with pytest.raises(routes.Invalid, match=message):
        routes.render(targets(**change))


def test_keys_are_generated_once_and_kept(tmp_path):
    env = tmp_path / "gateway.env"
    assert routes.sync_keys(TARGETS, env) == ["LOCAL_API_KEY_PARTNER_A", "LOCAL_API_KEY_INTERNAL"]
    first = env.read_text()
    assert routes.sync_keys(TARGETS, env) == []
    assert env.read_text() == first
    assert oct(env.stat().st_mode & 0o777) == "0o600"


def test_the_questions_end_to_end(tmp_path, monkeypatch, capsys):
    answers = iter([
        "Obs", "http://host.docker.internal:8080", "obs", "n", "45", "", "", "ops@example.org",  # service
        "gw.example.org", "n", "y", "10.0.0.0/8", "",                            # gateway, behind a proxy
        "n", "60",                                                               # open off, quota
        "y", "partner-a", "0", "n",                                              # one key
        "y", "obs", "/api/obs", "y", "GET",                                           # target
        "y", "", "30",                                                           #   federated
        "y", "", "",                                                             #   apikey
        "y", "", "5",                                                            #   open
        "n",                                                                     # no more
    ])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(answers))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["routes-helper.py"])
    assert routes.main() == 0
    saved = yaml.safe_load((tmp_path / "config" / "targets.yaml").read_text())
    assert saved["targets"][0]["open"] == {"path": "/open/api/obs", "quota": 5}
    assert saved["targets"][0]["apikey"] == {"path": "/local/api/obs", "quota": 60}
    gateway = yaml.safe_load((tmp_path / "config" / "gateway.yaml").read_text())
    assert gateway["service"]["timeout"] == {"read": 45}
    assert gateway["listen"]["trusted_proxies"] == ["10.0.0.0/8"]
    assert gateway["listen"]["client_address_header"] == "X-Forwarded-For"
    assert [r["path"] for r in gateway["routes"]] == ["/api/obs", "/api/obs/*",
                                                     "/local/api/obs", "/local/api/obs/*"]
    out = capsys.readouterr().out
    assert "kept in targets.yaml but not served: obs-open" in out
    key = (tmp_path / "gateway.env").read_text().split("LOCAL_API_KEY_PARTNER_A=")[1].strip()
    assert key not in out          # keys go to the file, never the terminal


# ── The static configuration ───────────────────────────────────────────────────────

def test_static_config_matches_the_data_plane_apart_from_status():
    member = yaml.safe_load((PACKAGE / "apisix" / "config.yaml").read_text())
    data = yaml.safe_load((REPO / "data-plane" / "apisix" / "config.yaml").read_text())
    assert member["apisix"].pop("status") == {"ip": "0.0.0.0", "port": 7085}
    assert member == data


# ── member-info.py ─────────────────────────────────────────────────────────────────

ISSUER = "https://identity.example.org/realms/federation"


def fake_fetch(documents):
    def fetch(url):
        if url not in documents:
            raise urllib.error.URLError("unreachable")
        return documents[url]
    return fetch


def test_federation_check_passes_with_the_right_issuer_and_a_signing_key():
    fetch = fake_fetch({
        f"{ISSUER}/.well-known/openid-configuration": {"issuer": ISSUER, "jwks_uri": "https://k/certs"},
        "https://k/certs": {"keys": [{"alg": "RS256", "use": "sig"}, {"alg": "RSA-OAEP", "use": "enc"}]},
    })
    result = info.check_federation("https://identity.example.org/", "federation", fetch)
    assert result["problems"] == [] and result["signing_keys"] == 1


def test_federation_check_names_the_problem():
    unreachable = info.check_federation("https://identity.example.org", "federation", fake_fetch({}))
    assert "discovery document unreachable" in unreachable["problems"][0]
    wrong = info.check_federation("https://identity.example.org", "federation", fake_fetch({
        f"{ISSUER}/.well-known/openid-configuration": {"issuer": "https://other/realms/x", "jwks_uri": "https://k"},
        "https://k": {"keys": []},
    }))
    assert "tokens would be refused" in wrong["problems"][0]
    assert "no RS256 signing key" in wrong["problems"][1]


def test_github_ids_are_looked_up_and_unknown_logins_refused():
    def fetch(url):
        if url.endswith("/octocat"):
            return {"login": "octocat", "id": 583231, "name": "The Octocat"}
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
    assert info.github_user("octocat", fetch) == {"login": "octocat", "id": 583231, "name": "The Octocat"}
    with pytest.raises(LookupError):
        info.github_user("no-such-user-xyz", fetch)


def test_registration_file(tmp_path, monkeypatch):
    (tmp_path / "federation.env").write_text(
        "CONTROL_BASE_URL=https://identity.example.org\nKC_REALM=federation\n")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "gateway.yaml").write_text(yaml.safe_dump(routes.render(targets())))
    answers = iter(["Example Met Service", "Ada Operator", "octocat", "", "Observations", "", "", "", "",
                    "hubot", "nobody-here", ""])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(answers))
    users = {"octocat": {"login": "octocat", "id": 583231}, "hubot": {"login": "hubot", "id": 480938}}

    def fetch(url):
        login = url.rsplit("/", 1)[1]
        if login in users:
            return users[login]
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(info, "fetch_json", fetch)
    monkeypatch.setattr(info, "check_federation", lambda base, realm: {
        "issuer": f"{base}/realms/{realm}", "discovery": True, "jwks": True,
        "signing_keys": 1, "problems": []})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["member-info.py"])
    # interview() takes its fetch as a default argument, bound at definition time.
    monkeypatch.setattr(info, "interview", lambda spec, f=fetch, _i=info.interview: _i(spec, f))
    assert info.main() == 0

    record = json.loads((tmp_path / "member-registration.json").read_text())
    assert record["operator"] == {"name": "Ada Operator", "github": "octocat", "email": "ops@example.org"}
    assert record["service"]["gateway_url"] == "https://gw.example.org"
    assert record["service"]["name"] == "Observations"
    assert record["service"]["audience"] == "obs"          # from gateway.yaml, confirmed
    assert [p["id"] for p in record["people"]] == [583231, 480938]
    assert {"path": "/api/obs", "door": "federated", "quota_per_minute": 30} in record["routes"]
    assert "LOCAL_API_KEY" not in json.dumps(record)

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

FEDERATION_ENV = {
    "CONTROL_BASE_URL": "https://identity.example.org", "KC_REALM": "federation",
    "CONTROL_PORTAL_URL": "https://identity.example.org/", "FEDERATION_AUDIENCE": "federation-services",
    "FEDERATION_CLI_CLIENT": "federation-cli", "FEDERATION_ACCOUNT_NAME": "meteogate",
    "FEDERATION_HELP_URL": "https://help.example.org/", "SESSION_SECRET": "x" * 32,
}

TARGETS = {
    "service": {"name": "Obs", "upstream": "https://obs.internal.example.org",
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
    assert oidc["client_id"] == "federation-services"
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
    assert by_name["obs-key"]["plugins"]["proxy-rewrite"] == {"uri": "/api/obs"}
    assert by_name["obs-key"]["plugins"]["key-auth"]["header"] == "apikey"
    consumers = {c["username"]: c["plugins"] for c in document["consumers"]}
    assert consumers["partner-a"]["limit-count"]["count"] == 10
    assert "limit-count" not in consumers["internal"]
    assert consumers["partner-a"]["key-auth"]["key"] == "k-partner-a"


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
    ({"targets": [{**TARGETS["targets"][0], "path": "/api/obs/*"}]}, "no \\*"),
    ({"targets": [{**TARGETS["targets"][0], "name": "Obs!"}]}, "target name"),
    ({"targets": [{"name": "x", "path": "/x"}]}, "has no federated"),
    ({"targets": [TARGETS["targets"][0], {**TARGETS["targets"][0], "name": "again"}]}, "already used"),
    ({"service": {"name": "x", "upstream": "obs:8000"}}, "upstream"),
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
        "Obs", "http://host.docker.internal:8080", "n", "", "ops@example.org",   # service
        "gw.example.org", "n",                                                   # gateway
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
    answers = iter(["Example Met Service", "Ada Operator", "octocat", "", "Observations", "", "", "",
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
    assert [p["id"] for p in record["people"]] == [583231, 480938]
    assert {"path": "/api/obs", "door": "federated", "quota_per_minute": 30} in record["routes"]
    assert "LOCAL_API_KEY" not in json.dumps(record)

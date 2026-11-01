#!/usr/bin/env python3
"""End-to-end: the sign-in door, against a real Keycloak (#13).

A local Keycloak with a test user and a member-obs client, the gateway image with a
session door on web.gw.example.org, and the stand-in service. A scripted browser
(session_browser.py, in a container on the same network) signs in, browses, and signs
out. Checks the things a bearer-door test can't:

  * the session asks for service:obs, and the service sees the user, not the token;
  * a client's own X-Access-Token, X-Fed-Subject or Authorization changes nothing;
  * one quota per person, however many times they sign in;
  * the session survives a gateway restart (the session secret is in gateway.env);
  * the access token renews when it expires;
  * logout, with a session and without, never stops on "id_token_hint" (#3);
  * a session whose token doesn't name the service is refused.

Run from the repository root, after building the image (takes about four minutes):

  docker build -f member-gateway/Dockerfile -t member-gateway:test .
  python3 member-gateway/tests/e2e_session.py [--image member-gateway:test]

Needs docker and PyYAML on the host, and pulls quay.io/keycloak/keycloak:26.4.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("e2e", HERE / "e2e.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)

KEYCLOAK = "quay.io/keycloak/keycloak:26.4"
PYTHON = "python:3.12.11-slim-bullseye"
SECRET = "member-obs-secret-for-the-e2e-test-0123456789"
TOKEN_LIFETIME = 90   # seconds; short, so renewal can be seen

REALM = {
    "realm": "federation", "enabled": True, "accessTokenLifespan": TOKEN_LIFETIME,
    # So the test can see the gateway refresh the token, not just keep using an old one.
    "eventsEnabled": True, "enabledEventTypes": ["LOGIN", "CODE_TO_TOKEN", "REFRESH_TOKEN", "LOGOUT"],
    "users": [{"username": "tester", "enabled": True, "email": "tester@example.org",
               "emailVerified": True, "firstName": "Test", "lastName": "User",
               "credentials": [{"type": "password", "value": "tester-pass", "temporary": False}]}],
}

SCOPE = {
    "name": "service:obs", "protocol": "openid-connect",
    "attributes": {"include.in.token.scope": "true"},
    "protocolMappers": [{"name": "audience", "protocol": "openid-connect",
                         "protocolMapper": "oidc-audience-mapper",
                         "config": {"included.custom.audience": "obs", "access.token.claim": "true"}}],
}

CLIENT = {   # what control-plane/keycloak/bootstrap.sh makes from a `web` block
    "clientId": "member-obs", "enabled": True, "publicClient": False, "secret": SECRET,
    "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
    "redirectUris": ["https://web.gw.example.org/session/callback"],
    "attributes": {"pkce.code.challenge.method": "S256",
                   "post.logout.redirect.uris": "https://web.gw.example.org/"},
}

TARGETS = {
    "service": {"name": "Test Observations", "audience": "obs", "upstream": "http://svc:8000",
                "own_host_header": True},
    "listen": {"host": "gw.example.org", "tls": False},
    "session": {"host": "web.gw.example.org"},
    "open_routes": "disabled",
    "default_quota": 60,
    "api_keys": [],
    "targets": [{"name": "obs", "path": "/api/obs", "subtree": True, "methods": ["GET"],
                 "federated": {"path": "/api/obs", "quota": 60},
                 "session": {"quota": 3}}],
}


class SessionRun(e2e.Run):
    def kc(self, *args: str, stdin: str | None = None) -> str:
        cmd = ["docker", "exec", *(["-i"] if stdin else []), f"{self.net}-kc",
               "/opt/keycloak/bin/kcadm.sh", *args]
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=True).stdout

    def keycloak(self) -> None:
        realm = self.work / "realm.json"
        realm.write_text(json.dumps(REALM))
        self.container("kc", "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
                       "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin-e2e",
                       "-v", f"{realm}:/opt/keycloak/data/import/realm.json:ro",
                       KEYCLOAK, "start-dev", "--import-realm")
        for _ in range(90):
            try:
                self.kc("config", "credentials", "--server", "http://localhost:8080",
                        "--realm", "master", "--user", "admin", "--password", "admin-e2e")
                self.kc("get", "realms/federation")
                break
            except subprocess.CalledProcessError:
                time.sleep(2)
        else:
            sys.exit("Keycloak never came up:\n" + e2e.docker("logs", f"{self.net}-kc", check=False)[-2000:])
        self.kc("create", "client-scopes", "-r", "federation", "-f", "-", stdin=json.dumps(SCOPE))
        self.kc("create", "clients", "-r", "federation", "-f", "-", stdin=json.dumps(CLIENT))
        self.client_uuid = self.id_of("clients", "clientId", "member-obs")
        self.scope_uuid = self.id_of("client-scopes", "name", "service:obs")
        self.kc("update", f"clients/{self.client_uuid}/default-client-scopes/{self.scope_uuid}",
                "-r", "federation")

    def id_of(self, kind: str, field: str, value: str) -> str:
        for item in json.loads(self.kc("get", kind, "-r", "federation")):
            if item.get(field) == value:
                return item["id"]
        sys.exit(f"no {kind} with {field}={value}")

    def browser(self, phase: str) -> dict:
        out = subprocess.run(["docker", "run", "--rm", "--network", self.net,
                              "-v", f"{self.work}:/w", PYTHON,
                              "python3", "/w/session_browser.py", "/w/state.json", phase],
                             capture_output=True, text=True)
        try:
            return json.loads(out.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            return {"error": out.stdout[-500:] + out.stderr[-500:]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="member-gateway:test")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="mgw-session-") as tmp:
        work = Path(tmp)
        shutil.copy(HERE / "session_browser.py", work / "session_browser.py")
        (work / "svc.py").write_text(e2e.SERVICE)
        (work / "federation.env").write_text("\n".join([
            "CONTROL_BASE_URL=http://kc:8080", "KC_REALM=federation",
            "CONTROL_PORTAL_URL=https://portal.example.org/",
            "FEDERATION_CLI_CLIENT=federation-cli", "FEDERATION_ACCOUNT_NAME=meteogate",
            "FEDERATION_HELP_URL=https://help.example.org/cli", ""]))
        config, env = e2e.render(work, "door", TARGETS)
        text = env.read_text()
        assert "SESSION_SECRET=" in text and "SESSION_CLIENT_ID=\n" in text, text
        env.write_text(text.replace("SESSION_CLIENT_ID=\n", "SESSION_CLIENT_ID=member-obs\n")
                           .replace("SESSION_CLIENT_SECRET=\n", f"SESSION_CLIENT_SECRET={SECRET}\n"))

        run = SessionRun(args.image, work)
        check = run.check
        try:
            e2e.docker("network", "create", run.net)
            print("Starting Keycloak (about a minute)...")
            run.keycloak()
            run.container("svc", "-v", f"{work / 'svc.py'}:/svc.py:ro", PYTHON, "python3", "/svc.py")
            run.gateway(config, env)
            # The browser reaches the gateway as "gateway"; Run.gateway names it so.

            print("\nSigning in:")
            seen = run.browser("signin")
            check("an unsigned browser is sent to the identity provider", seen.get("to_idp"), seen)
            check("…asking for this service's scope", "service:obs" in seen.get("asked_scope", "").split(), seen)
            check("…and comes back through the callback", seen.get("back_to") == "https://web.gw.example.org/api/obs", seen)
            got = run.browser("get:/api/obs")
            headers = (got.get("echo") or {}).get("headers", {})
            check("signed in: the service answers", got.get("status") == 200, got)
            check("…knows the user (X-Fed-Username)", headers.get("x-fed-username") == "tester", headers)
            check("…by subject (X-Fed-Subject)", len(headers.get("x-fed-subject", "")) > 8, headers)
            check("…gets the verified claims (X-Userinfo)", bool(headers.get("x-userinfo")), headers)
            check("…but not the token", "x-access-token" not in headers and "authorization" not in headers, headers)
            subject = headers.get("x-fed-subject")

            got = run.browser("forged")
            headers = (got.get("echo") or {}).get("headers", {})
            check("forged X-Access-Token, X-Fed-Subject, Authorization change nothing",
                  got.get("status") == 200 and headers.get("x-fed-subject") == subject
                  and "mallory" not in json.dumps(headers), got)
            got = run.browser("get:/api/obs/7")
            check("the subtree, third request", got.get("status") == 200, got)
            got = run.browser("get:/api/obs")
            check("fourth request → quota (3 a minute)", got.get("status") == 429, got)
            run.browser("forget-gateway")
            seen = run.browser("signin")
            got = run.browser("get:/api/obs")
            check("signing in again doesn't reset the quota: one per person",
                  seen.get("back_to") and got.get("status") == 429, {"signin": seen, "get": got})

            print("\nRestart and renewal:")
            signed_in_at = time.time()
            e2e.docker("restart", f"{run.net}-gateway")
            run.wait_healthy()
            got = run.browser("get:/api/obs")
            check("after a gateway restart the session still works (quota counters reset)",
                  got.get("status") == 200 and (got.get("echo") or {}).get("headers", {}).get("x-fed-subject") == subject, got)
            wait = TOKEN_LIFETIME + 10 - (time.time() - signed_in_at)
            print(f"  … waiting {wait:.0f} s for the access token to expire")
            time.sleep(max(0, wait))
            got = run.browser("get:/api/obs")
            refreshes = [e for e in json.loads(run.kc("get", "events", "-r", "federation",
                                                      "-q", "type=REFRESH_TOKEN"))
                         if e.get("clientId") == "member-obs"]
            check("after the access token expires, the session renews it (Keycloak saw the refresh)",
                  got.get("status") == 200 and len(refreshes) >= 1, {"get": got, "refreshes": len(refreshes)})

            print("\nSigning out (#3):")
            out = run.browser("logout")
            check("logout with a session sends client_id and id_token_hint",
                  out.get("params") == ["client_id", "id_token_hint", "post_logout_redirect_uri"], out)
            check("…and Keycloak sends the browser back, no error page",
                  out.get("idp_status") == 302 and out.get("idp_to") == "https://web.gw.example.org/"
                  and not out.get("idp_error"), out)
            seen = run.browser("signin")
            check("signed out at Keycloak too: the next visit asks for the password again",
                  seen.get("form") is True and seen.get("back_to"), seen)
            run.browser("forget-gateway")
            out = run.browser("logout")
            check("logout without a session still names the client", out.get("params") == ["client_id", "post_logout_redirect_uri"], out)
            check("…and Keycloak asks to confirm, rather than 'Missing parameters: id_token_hint'",
                  not out.get("idp_error") and out.get("idp_status") in (200, 302), out)

            print("\nA token for another service:")
            mappers = json.loads(run.kc("get", f"client-scopes/{run.scope_uuid}/protocol-mappers/models", "-r", "federation"))
            run.kc("delete", f"client-scopes/{run.scope_uuid}/protocol-mappers/models/{mappers[0]['id']}", "-r", "federation")
            run.browser("forget-gateway")
            run.browser("signin")
            got = run.browser("get:/api/obs")
            check("a session whose token doesn't name obs is refused", got.get("status") == 403, got)
        finally:
            run.stop()

    if run.failures:
        print(f"\n{len(run.failures)} failed: {', '.join(run.failures)}")
        return 1
    print("\nAll sign-in door checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

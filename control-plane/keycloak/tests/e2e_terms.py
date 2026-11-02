#!/usr/bin/env python3
"""End-to-end: the terms-and-conditions step after sign-in, against a real Keycloak.

One Keycloak, built from control-plane/keycloak/Dockerfile (so the provider and theme are
the ones that ship), with two realms: "upstream" stands in for GitHub, and "federation"
brokers it, with keycloak/terms-flow.sh run against it exactly as bootstrap.sh runs it.
A scripted browser (terms_browser.py) signs in through the broker.

Run from the repository root (about three minutes):

  docker build -t federation-keycloak:test control-plane/keycloak
  python3 control-plane/keycloak/tests/e2e_terms.py [--image federation-keycloak:test]

Needs docker, bash and python3 on the host.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TERMS_FLOW = HERE.parent / "terms-flow.sh"
PYTHON = "python:3.12.11-slim-bullseye"
COOKIE_SECRET = "c" * 40
BROKER_SECRET = "upstream-broker-secret-for-the-e2e-test"


class Run:
    def __init__(self, image: str, work: Path):
        self.image, self.work = image, work
        self.net = f"terms-e2e-{int(time.time())}"
        self.failures: list[str] = []
        self.kcadm = work / "kcadm"
        self.kcadm.write_text(
            "#!/bin/sh\n"
            "# kcadm.sh in the test's Keycloak; stdin only when it reads a file from it (-f -).\n"
            f'for a in "$@"; do [ "$a" = "-" ] && exec docker exec -i {self.net}-kc /opt/keycloak/bin/kcadm.sh "$@"; done\n'
            f'exec docker exec {self.net}-kc /opt/keycloak/bin/kcadm.sh "$@"\n')
        self.kcadm.chmod(0o755)

    def docker(self, *args: str, check: bool = True) -> str:
        return subprocess.run(["docker", *args], check=check, capture_output=True, text=True).stdout

    def kc(self, *args: str, stdin: str | None = None) -> str:
        return subprocess.run([str(self.kcadm), *args], input=stdin, capture_output=True,
                              text=True, check=True).stdout

    def start(self) -> None:
        self.docker("network", "create", self.net)
        self.docker("run", "-d", "--name", f"{self.net}-kc", "--network", self.net,
                    "--network-alias", "kc", "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
                    "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin-e2e",
                    "-e", f"FED_TERMS_COOKIE_SECRET={COOKIE_SECRET}", self.image, "start-dev")
        for _ in range(90):
            try:
                self.kc("config", "credentials", "--server", "http://localhost:8080",
                        "--realm", "master", "--user", "admin", "--password", "admin-e2e")
                return
            except subprocess.CalledProcessError:
                time.sleep(2)
        sys.exit("Keycloak never came up:\n" + self.docker("logs", f"{self.net}-kc", check=False)[-3000:])

    def realms(self) -> None:
        """upstream (the stand-in for GitHub) and federation, which brokers it."""
        self.kc("create", "realms", "-s", "realm=upstream", "-s", "enabled=true")
        for user in ("alice", "bob"):
            self.kc("create", "users", "-r", "upstream", "-s", f"username={user}", "-s", "enabled=true",
                    "-s", f"email={user}@example.org", "-s", "emailVerified=true",
                    "-s", f"firstName={user.title()}", "-s", "lastName=Tester")
            self.kc("set-password", "-r", "upstream", "--username", user, "--new-password", f"{user}-pass")
        self.kc("create", "clients", "-r", "upstream", "-f", "-", stdin=json.dumps({
            "clientId": "federation-broker", "publicClient": False, "secret": BROKER_SECRET,
            "standardFlowEnabled": True,
            "redirectUris": ["http://kc:8080/realms/federation/broker/upstream/endpoint"]}))
        self.kc("create", "realms", "-s", "realm=federation", "-s", "enabled=true")
        base = "http://kc:8080/realms/upstream/protocol/openid-connect"
        self.kc("create", "identity-provider/instances", "-r", "federation", "-f", "-", stdin=json.dumps({
            "alias": "upstream", "providerId": "oidc", "enabled": True, "trustEmail": True,
            "firstBrokerLoginFlowAlias": "first broker login",
            "config": {"authorizationUrl": f"{base}/auth", "tokenUrl": f"{base}/token",
                       "jwksUrl": f"{base}/certs", "useJwksUrl": "true", "validateSignature": "true",
                       "issuer": "http://kc:8080/realms/upstream", "clientId": "federation-broker",
                       "clientSecret": BROKER_SECRET, "clientAuthMethod": "client_secret_post",
                       "defaultScope": "openid profile email", "syncMode": "FORCE"}}))
        # As bootstrap.sh sets it on the real realm: attributes outside the declared user
        # profile, such as fed_terms_version, are kept and visible to admins.
        profile = json.loads(self.kc("get", "users/profile", "-r", "federation"))
        profile["unmanagedAttributePolicy"] = "ENABLED"
        self.kc("update", "users/profile", "-r", "federation", "-f", "-", stdin=json.dumps(profile))
        self.kc("create", "clients", "-r", "federation", "-f", "-", stdin=json.dumps({
            "clientId": "test-app", "publicClient": True, "standardFlowEnabled": True,
            "redirectUris": ["http://app.example/cb"]}))

    def terms_flow(self, **settings: str) -> str:
        env = {**os.environ, "KCADM": str(self.kcadm), "REALM": "federation",
               "TERMS_VERSION": "v1", "TERMS_MODE": "every-sign-in", "TERMS_COOKIE_DAYS": "365",
               **settings}
        env.pop("TERMS_TEXT", None)   # the script's default, "Try not to break the testbed."
        result = subprocess.run(["bash", str(TERMS_FLOW)], env=env, capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f"terms-flow.sh failed:\n{result.stdout}\n{result.stderr}")
        return result.stdout

    def browser(self, *phase: str) -> dict:
        out = subprocess.run(["docker", "run", "--rm", "--network", self.net, "-v", f"{self.work}:/w",
                              PYTHON, "python3", "/w/terms_browser.py", "/w/state.json", *phase],
                             capture_output=True, text=True)
        try:
            return json.loads(out.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            return {"error": out.stdout[-600:] + out.stderr[-600:]}

    def attribute(self, user: str, name: str) -> str | None:
        users = json.loads(self.kc("get", "users", "-r", "federation", "-q", f"username={user}"))
        return ((users[0].get("attributes") or {}).get(name) or [None])[0] if users else None

    def check(self, label: str, ok: bool, detail=None) -> None:
        print(f"  {'✓' if ok else '✗'} {label}" + ("" if ok else f"\n      {detail}"))
        if not ok:
            self.failures.append(label)

    def stop(self) -> None:
        self.docker("rm", "-f", f"{self.net}-kc", check=False)
        self.docker("network", "rm", self.net, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="federation-keycloak:test")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="terms-e2e-") as tmp:
        work = Path(tmp)
        shutil.copy(HERE / "terms_browser.py", work / "terms_browser.py")
        run = Run(args.image, work)
        check, b = run.check, run.browser
        try:
            print("Starting Keycloak (about a minute)...")
            run.start()
            run.realms()
            run.terms_flow()

            print("\nEvery sign-in (the testbed's setting):")
            seen = b("signin", "alice")
            check("after signing in upstream, the terms page", seen.get("outcome") == "terms", seen)
            check("…with the text, the version, and how to withdraw",
                  seen.get("text_shown") and seen.get("version_shown") == "v1" and seen.get("withdraw_note"), seen)
            check("…and the optional cookie offered", seen.get("remember_offered") is True, seen)
            seen = b("reload")
            check("reloading the page shows it again, with no error", seen.get("outcome") == "terms"
                  and not seen.get("tick_message"), seen)
            seen = b("submit", "none")
            check("continuing without ticking shows the page again, with a message",
                  seen.get("outcome") == "terms" and seen.get("tick_message"), seen)
            seen = b("submit", "cancel")
            check("cancel refuses the sign-in", seen.get("outcome") == "denied" and seen.get("declined_message"), seen)
            check("…and records nothing", run.attribute("alice", "fed_terms_version") is None)

            b("forget-sessions")
            b("signin", "alice")
            seen = b("submit", "agree")
            check("agreeing lets the user in", seen.get("outcome") == "in", seen)
            check("…sets no cookie when not asked to", seen.get("fed_terms_cookie") is None, seen)
            check("…and records the version and time on the user",
                  run.attribute("alice", "fed_terms_version") == "v1"
                  and run.attribute("alice", "fed_terms_accepted_at"))

            b("forget-sessions")
            seen = b("signin", "alice")
            check("the next sign-in asks again", seen.get("outcome") == "terms", seen)
            seen = b("submit", "agree+remember")
            raw = (seen.get("fed_terms_set_cookie") or "").lower()
            check("agreeing and remembering sets the cookie", seen.get("outcome") == "in" and seen.get("fed_terms_cookie"), seen)
            check("…HttpOnly, SameSite=Lax, for this realm, for a year",
                  "httponly" in raw and "samesite=lax" in raw and "path=/realms/federation/" in raw
                  and "max-age=31536000" in raw, raw)

            b("forget-sessions")
            seen = b("signin", "alice")
            check("with the cookie, the next sign-in skips the page", seen.get("outcome") == "in", seen)

            b("forget-sessions")
            seen = b("signin", "bob")
            check("another person on the same browser is asked", seen.get("outcome") == "terms", seen)
            b("submit", "agree")

            state = json.loads((work / "state.json").read_text())
            for c in state["cookies"]:
                if c["name"] == "FED_TERMS":
                    c["value"] = c["value"][:-2] + ("AA" if not c["value"].endswith("AA") else "BB")
            (work / "state.json").write_text(json.dumps(state))
            b("forget-sessions")
            seen = b("signin", "alice")
            check("a tampered cookie is ignored: asked again", seen.get("outcome") == "terms", seen)
            b("submit", "agree+remember")

            print("\nA new version of the terms:")
            run.terms_flow(TERMS_VERSION="v2")
            b("forget-sessions")
            seen = b("signin", "alice")
            check("a remembered v1 agreement doesn't cover v2", seen.get("outcome") == "terms"
                  and seen.get("version_shown") == "v2", seen)
            b("submit", "agree")

            print("\nOnce per version (what a real service would use):")
            run.terms_flow(TERMS_VERSION="v3", TERMS_MODE="once-per-version")
            b("forget-all")
            seen = b("signin", "alice")
            check("a new version is asked for once", seen.get("outcome") == "terms", seen)
            check("…with no cookie offered", seen.get("remember_offered") is False, seen)
            b("submit", "agree")
            b("forget-all")
            seen = b("signin", "alice")
            check("…and not again, even from a fresh browser", seen.get("outcome") == "in", seen)

            print("\nThe setup script:")
            before = run.kc("get", "authentication/flows/federation%20terms/executions", "-r", "federation")
            run.terms_flow(TERMS_VERSION="v3", TERMS_MODE="once-per-version")
            after = run.kc("get", "authentication/flows/federation%20terms/executions", "-r", "federation")
            check("rerunning it changes nothing (one step, same config)",
                  len(json.loads(after)) == 1 and json.loads(before) == json.loads(after), after)
            idp = json.loads(run.kc("get", "identity-provider/instances/upstream", "-r", "federation"))
            theme = json.loads(run.kc("get", "realms/federation"))["loginTheme"]
            check("every identity provider runs it after sign-in, with the federation theme",
                  idp.get("postBrokerLoginFlowAlias") == "federation terms" and theme == "federation",
                  {"idp": idp.get("postBrokerLoginFlowAlias"), "theme": theme})
        finally:
            run.stop()

    if run.failures:
        print(f"\n{len(run.failures)} failed: {', '.join(run.failures)}")
        return 1
    print("\nAll terms-and-conditions checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

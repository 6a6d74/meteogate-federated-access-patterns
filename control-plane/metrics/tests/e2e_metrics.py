#!/usr/bin/env python3
"""End-to-end: the usage metrics, against a real Keycloak.

A stock Keycloak with the realm's event settings from keycloak/realm-federation.json,
keycloak/metrics.sh run against it as bootstrap.sh runs it, and the exporter image from
metrics/exporter. People sign in, refresh, use a machine credential, and an account is
created and deleted; then the scrape is compared with what happened.

Run from the repository root (about two minutes):

  docker build -t fed-metrics-exporter:test control-plane/metrics/exporter
  python3 control-plane/metrics/tests/e2e_metrics.py [--image fed-metrics-exporter:test]

Needs docker, bash and python3 on the host.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL = HERE.parents[1]
METRICS_SH = CONTROL / "keycloak" / "metrics.sh"
REALM_JSON = CONTROL / "keycloak" / "realm-federation.json"
KEYCLOAK = "quay.io/keycloak/keycloak:26.4"
ADMIN = "urn:meteogate:testbed:entitlement:admin"
EXPORTER_SECRET = "exporter-secret-for-the-e2e-test"
CREDENTIAL_SECRET = "credential-secret-for-the-e2e-test"
SERVICES = [{"audience": a, "name": a.title()} for a in ("birds", "meteocore", "fed-metrics")]

# Run inside the exporter's container, which has python and is on the test network.
HTTP = """
import json, sys, urllib.error, urllib.parse, urllib.request
method, url, form, headers = json.loads(sys.argv[1])
data = urllib.parse.urlencode(form).encode() if form is not None else None
req = urllib.request.Request(url, data=data, method=method, headers=headers)
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        print(json.dumps({"status": r.status, "type": r.headers.get("Content-Type"), "body": r.read().decode()}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "type": "", "body": e.read().decode()}))
"""


class Run:
    def __init__(self, image: str, work: Path):
        self.image, self.work = image, work
        self.net = f"metrics-e2e-{int(time.time())}"
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

    def start_keycloak(self) -> None:
        self.docker("network", "create", self.net)
        self.docker("run", "-d", "--name", f"{self.net}-kc", "--network", self.net,
                    "--network-alias", "kc", "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
                    "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin-e2e",
                    # As docker-compose.yml sets them.
                    "-e", "KC_METRICS_ENABLED=true", "-e", "KC_FEATURES=user-event-metrics",
                    "-e", "KC_EVENT_METRICS_USER_ENABLED=true",
                    "-e", "KC_EVENT_METRICS_USER_TAGS=realm,clientId", KEYCLOAK, "start-dev")
        for _ in range(90):
            try:
                self.kc("config", "credentials", "--server", "http://localhost:8080",
                        "--realm", "master", "--user", "admin", "--password", "admin-e2e")
                return
            except subprocess.CalledProcessError:
                time.sleep(2)
        sys.exit("Keycloak never came up:\n" + self.docker("logs", f"{self.net}-kc", check=False)[-3000:])

    def realm(self) -> None:
        """The federation realm, with the real realm's event settings."""
        real = json.loads(REALM_JSON.read_text())
        self.kc("create", "realms", "-f", "-", stdin=json.dumps({
            "realm": "federation", "enabled": True,
            **{k: real[k] for k in ("eventsEnabled", "eventsExpiration", "enabledEventTypes",
                                    "adminEventsEnabled", "adminEventsDetailsEnabled")}}))
        profile = json.loads(self.kc("get", "users/profile", "-r", "federation"))
        profile["unmanagedAttributePolicy"] = "ENABLED"
        self.kc("update", "users/profile", "-r", "federation", "-f", "-", stdin=json.dumps(profile))
        scopes = []
        for s in SERVICES:
            self.kc("create", "client-scopes", "-r", "federation", "-s", f"name=service:{s['audience']}",
                    "-s", "protocol=openid-connect")
            scopes.append(f"service:{s['audience']}")
        # Password sign-in stands in for the browser: same events, by the same rules.
        self.kc("create", "clients", "-r", "federation", "-f", "-", stdin=json.dumps({
            "clientId": "test-cli", "publicClient": True, "directAccessGrantsEnabled": True,
            "standardFlowEnabled": False, "optionalClientScopes": scopes}))
        for user in ("alice", "bob"):
            self.kc("create", "users", "-r", "federation", "-s", f"username={user}", "-s", "enabled=true",
                    "-s", f"email={user}@example.org", "-s", "emailVerified=true",
                    "-s", f"firstName={user.title()}", "-s", "lastName=Tester")
            self.kc("set-password", "-r", "federation", "--username", user, "--new-password", f"{user}-pass")
        # A credential alice minted in the portal, as the portal makes one.
        self.kc("create", "clients", "-r", "federation", "-f", "-", stdin=json.dumps({
            "clientId": "svc-alice-1a2b3c", "publicClient": False, "secret": CREDENTIAL_SECRET,
            "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "optionalClientScopes": scopes,
            "attributes": {"fed_owner_sub": self.user_id("alice"), "fed_secret_expires": "2099-01-01"}}))

    def user(self, username: str) -> dict:
        users = json.loads(self.kc("get", "users", "-r", "federation", "-q", f"username={username}",
                                   "-q", "exact=true", "-q", "briefRepresentation=false"))
        return users[0] if users else {}

    def user_id(self, username: str) -> str:
        return self.user(username)["id"]

    def entitlements(self, username: str) -> list[str]:
        return sorted((self.user(username).get("attributes") or {}).get("eduperson_entitlement") or [])

    def credential_entitlements(self, client_id: str) -> list[str]:
        uuid = json.loads(self.kc("get", "clients", "-r", "federation", "-q", f"clientId={client_id}"))[0]["id"]
        account = json.loads(self.kc("get", f"clients/{uuid}/service-account-user", "-r", "federation"))
        return sorted((account.get("attributes") or {}).get("eduperson_entitlement") or [])

    def metrics_sh(self, entitlements: dict) -> subprocess.CompletedProcess:
        env = {**os.environ, "KCADM": str(self.kcadm), "REALM": "federation",
               "FED_METRICS_EXPORTER_SECRET": EXPORTER_SECRET,
               "FEDERATION_ENTITLEMENTS": json.dumps(entitlements)}
        result = subprocess.run(["bash", str(METRICS_SH)], env=env, capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f"metrics.sh failed:\n{result.stdout}\n{result.stderr}")
        return result

    def start_exporter(self) -> None:
        self.docker("rm", "-f", f"{self.net}-exporter", check=False)
        self.docker("run", "-d", "--name", f"{self.net}-exporter", "--network", self.net,
                    "-e", "KC_INTERNAL_URL=http://kc:8080", "-e", "KC_MANAGEMENT_URL=http://kc:9000",
                    "-e", "KC_REALM=federation", "-e", f"EXPORTER_CLIENT_SECRET={EXPORTER_SECRET}",
                    "-e", f"FEDERATION_SERVICES={json.dumps(SERVICES)}", "-e", "BIRDS_AUDIENCE=birds",
                    "-e", "FED_ACTIVE_WINDOWS=15m,1d", "-e", "POLL_SECONDS=2", self.image)
        for _ in range(30):
            if "fed_registered_users" in self.scrape():
                return
            time.sleep(1)
        sys.exit("The exporter never published:\n" + self.docker("logs", f"{self.net}-exporter", check=False))

    def http(self, method: str, url: str, form: dict | None = None, headers: dict | None = None) -> dict:
        out = subprocess.run(["docker", "exec", f"{self.net}-exporter", "python3", "-c", HTTP,
                              json.dumps([method, url, form, headers or {}])],
                             capture_output=True, text=True)
        try:
            return json.loads(out.stdout)
        except ValueError:
            return {"status": 0, "type": "", "body": out.stdout + out.stderr}

    def token(self, form: dict) -> dict:
        r = self.http("POST", "http://kc:8080/realms/federation/protocol/openid-connect/token", form)
        if r["status"] != 200:
            sys.exit(f"token request failed: {r}")
        return json.loads(r["body"])

    def scrape(self, path: str = "/metrics", accept: str = "") -> str:
        r = self.http("GET", f"http://localhost:9100{path}", headers={"Accept": accept} if accept else {})
        return r["body"] if r["status"] == 200 else ""

    def check(self, label: str, ok: bool, detail=None) -> None:
        print(f"  {'✓' if ok else '✗'} {label}" + ("" if ok else f"\n      {detail}"))
        if not ok:
            self.failures.append(label)

    def stop(self) -> None:
        self.docker("rm", "-f", f"{self.net}-exporter", f"{self.net}-kc", check=False)
        self.docker("network", "rm", self.net, check=False)


def sample(text: str, name: str, **labels: str) -> float:
    """One sample's value from the Prometheus text format; 0 if absent."""
    for line in text.splitlines():
        m = re.fullmatch(r"([a-z_]+)(?:\{(.*)\})? (\S+)", line)
        if not m or m[1] != name:
            continue
        have = dict(re.findall(r'(\w+)="([^"]*)"', m[2] or ""))
        if have == labels:
            return float(m[3])
    return 0.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="fed-metrics-exporter:test")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="metrics-e2e-") as tmp:
        run = Run(args.image, Path(tmp))
        check = run.check
        try:
            print("Starting Keycloak (about a minute)...")
            run.start_keycloak()
            run.realm()

            print("\nmetrics.sh, as bootstrap.sh runs it:")
            result = run.metrics_sh({"alice": [ADMIN], "nobody-yet": [ADMIN]})
            realm = json.loads(run.kc("get", "realms/federation"))
            check("events are kept 35 days", realm.get("eventsExpiration") == 35 * 86400,
                  realm.get("eventsExpiration"))
            check("the exporter's client exists, with a service account",
                  json.loads(run.kc("get", "clients", "-r", "federation", "-q", "clientId=fed-metrics-exporter"))
                  [0].get("serviceAccountsEnabled") is True)
            roles = run.kc("get-roles", "-r", "federation", "--uusername", "service-account-fed-metrics-exporter",
                           "--cclientid", "realm-management", "--effective")
            check("…which may view events, users and clients, and not manage them",
                  all(f'"{r}"' in roles for r in ("view-events", "view-users", "view-clients"))
                  and '"manage-users"' not in roles, roles)
            check("alice holds the admin entitlement", run.entitlements("alice") == [ADMIN],
                  run.entitlements("alice"))
            check("…and so does her credential",
                  run.credential_entitlements("svc-alice-1a2b3c") == [ADMIN],
                  run.credential_entitlements("svc-alice-1a2b3c"))
            check("bob holds none", run.entitlements("bob") == [])
            check("someone not yet signed in is reported, not failed", "nobody-yet" in result.stderr,
                  result.stderr)

            print("\nThe exporter, then activity:")
            run.start_exporter()
            alice = run.token({"grant_type": "password", "client_id": "test-cli", "username": "alice",
                               "password": "alice-pass", "scope": "openid service:meteocore"})
            run.token({"grant_type": "refresh_token", "client_id": "test-cli",
                       "refresh_token": alice["refresh_token"]})
            run.token({"grant_type": "password", "client_id": "test-cli", "username": "bob",
                       "password": "bob-pass", "scope": "openid service:birds"})
            run.token({"grant_type": "client_credentials", "client_id": "svc-alice-1a2b3c",
                       "client_secret": CREDENTIAL_SECRET, "scope": "service:fed-metrics"})
            run.kc("create", "users", "-r", "federation", "-s", "username=carol", "-s", "enabled=true")
            run.kc("delete", f"users/{run.user_id('carol')}", "-r", "federation")
            time.sleep(8)
            text = run.scrape()

            check("sign-ins, by service", sample(text, "fed_signins_total", service="meteocore", method="password") == 1
                  and sample(text, "fed_signins_total", service="birds", method="password") == 1, text)
            check("tokens, by service and grant",
                  sample(text, "fed_tokens_issued_total", service="meteocore", grant="password") == 1
                  and sample(text, "fed_tokens_issued_total", service="meteocore", grant="refresh_token") == 1
                  and sample(text, "fed_tokens_issued_total", service="birds", grant="password") == 1
                  and sample(text, "fed_tokens_issued_total", service="fed-metrics", grant="client_credentials") == 1)
            check("…not the exporter's own", sample(text, "fed_tokens_issued_total",
                                                   service="none", grant="client_credentials") == 0)
            check("a registration and a deregistration",
                  sample(text, "fed_registrations_total", via="allow_list") == 1
                  and sample(text, "fed_deregistrations_total", via="admin") == 1,
                  run.kc("get", "admin-events", "-r", "federation", "-q", "resourceTypes=USER"))
            check("distinct people and machines in the last 15 minutes",
                  sample(text, "fed_active_users", service="meteocore", kind="person", window="15m") == 1
                  and sample(text, "fed_active_users", service="birds", kind="person", window="15m") == 1
                  and sample(text, "fed_active_users", service="fed-metrics", kind="machine", window="15m") == 1)
            check("accounts and credentials", sample(text, "fed_registered_users", enabled="true") == 2
                  and sample(text, "fed_credentials", state="active") == 1)
            ids = [run.user_id(u) for u in ("alice", "bob")]
            check("no username or user id anywhere",
                  not any(s in text for s in ("alice", "bob", "carol", *ids)))
            om = run.http("GET", "http://localhost:9100/usage",
                          headers={"Accept": "application/openmetrics-text; version=1.0.0"})
            check("OpenMetrics when asked for, at /usage too",
                  om["type"].startswith("application/openmetrics-text") and om["body"].rstrip().endswith("# EOF"),
                  om["type"])
            kc = run.scrape("/keycloak")
            check("Keycloak's own metrics passed through, its user events among them",
                  "keycloak_user_events_total" in kc, kc[:300])

            print("\nA restart:")
            run.start_exporter()
            time.sleep(4)
            text = run.scrape()
            check("counters start again from zero",
                  sample(text, "fed_tokens_issued_total", service="meteocore", grant="refresh_token") == 0)
            check("…but recent activity is read back from the stored events",
                  sample(text, "fed_active_users", service="meteocore", kind="person", window="15m") == 1, text)

            print("\nEntitlements taken away:")
            run.metrics_sh({})
            check("alice loses hers", run.entitlements("alice") == [])
            check("…and so does her credential", run.credential_entitlements("svc-alice-1a2b3c") == [])
        finally:
            if run.failures:
                print("\nExporter log:\n" + run.docker("logs", f"{run.net}-exporter", check=False)[-2000:])
            run.stop()

    print(f"\n{'All passed.' if not run.failures else f'{len(run.failures)} failed.'}")
    return 1 if run.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

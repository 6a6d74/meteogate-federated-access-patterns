#!/usr/bin/env python3
"""End-to-end: the gateway image, a stand-in identity provider, and a stand-in service.

Nothing leaves this machine. The identity provider is static files — a discovery
document and a key set — and the tokens are RS256 JWTs signed here with openssl, so the
gateway's token check runs for real: signature, issuer, audience, expiry.

Run from the repository root, after building the image:

  docker build -f member-gateway/Dockerfile -t member-gateway:test .
  python3 member-gateway/tests/e2e.py [--image member-gateway:test]

Needs docker, openssl and PyYAML on the host.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER = HERE.parent / "scripts" / "routes-helper.py"
ISSUER = "http://idp:8080/realms/federation"
AUDIENCE = "obs"

SERVICE = r'''
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "host": self.headers.get("Host"),
                           "subject": self.headers.get("X-Fed-Subject")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

HTTPServer(("", 8000), Echo).serve_forever()
'''

TARGETS = {
    "service": {"name": "Test Observations", "audience": AUDIENCE, "upstream": "http://svc:8000",
                "own_host_header": True, "contact": "ops@example.org"},
    "listen": {"host": "gw.example.org", "tls": False},
    "open_routes": "disabled",
    "default_quota": 60,
    "api_keys": [{"name": "partner-a"}],
    "targets": [
        {"name": "obs", "path": "/api/obs", "subtree": True, "methods": ["GET"],
         "federated": {"path": "/api/obs", "quota": 3},
         "apikey": {"path": "/local/api/obs", "quota": 60},
         "open": {"path": "/open/api/obs", "quota": 60}},
        {"name": "stations", "path": "/api/stations", "subtree": False, "methods": ["GET"],
         "open": {"path": "/open/api/stations", "quota": 0}},
    ],
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Keys:
    def __init__(self, work: Path):
        self.key = work / "signing.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(self.key), "2048"],
                       check=True, capture_output=True)
        modulus = subprocess.run(["openssl", "rsa", "-in", str(self.key), "-noout", "-modulus"],
                                 check=True, capture_output=True, text=True).stdout
        n = bytes.fromhex(modulus.strip().split("=", 1)[1])
        self.jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-1",
                    "n": b64url(n), "e": b64url((65537).to_bytes(3, "big"))}

    def token(self, **overrides) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": [AUDIENCE], "sub": "user-1",
                  "preferred_username": "tester", "iat": now, "exp": now + 300, **overrides}
        head = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "test-1"}).encode())
        body = b64url(json.dumps(claims).encode())
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key)],
                                   input=f"{head}.{body}".encode(), check=True,
                                   capture_output=True).stdout
        return f"{head}.{body}.{b64url(signature)}"


def write_idp(root: Path, keys: Keys) -> None:
    realm = root / "realms" / "federation"
    (realm / ".well-known").mkdir(parents=True)
    (realm / "protocol" / "openid-connect").mkdir(parents=True)
    (realm / ".well-known" / "openid-configuration").write_text(json.dumps({
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
        "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
        "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
    (realm / "protocol" / "openid-connect" / "certs").write_text(json.dumps({"keys": [keys.jwk]}))


def docker(*args: str, check: bool = True) -> str:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True).stdout


class Run:
    def __init__(self, image: str, work: Path):
        self.image, self.work = image, work
        self.net = f"mgw-e2e-{int(time.time())}"
        self.names: list[str] = []
        self.failures: list[str] = []

    def start(self) -> None:
        docker("network", "create", self.net)
        (self.work / "svc.py").write_text(SERVICE)
        self.container("idp", "-v", f"{self.work / 'idp'}:/srv:ro", "-w", "/srv",
                       "python:3.12.11-slim-bullseye", "python3", "-m", "http.server", "8080")
        self.container("svc", "-v", f"{self.work / 'svc.py'}:/svc.py:ro",
                       "python:3.12.11-slim-bullseye", "python3", "/svc.py")

    def container(self, name: str, *args: str) -> None:
        full = f"{self.net}-{name}"
        docker("run", "-d", "--name", full, "--network", self.net, "--network-alias", name, *args)
        self.names.append(full)

    def gateway(self, config: Path, env: Path) -> str:
        name = f"{self.net}-gateway"
        if name in self.names:
            docker("rm", "-f", name)
            self.names.remove(name)
        self.container("gateway", "-p", "127.0.0.1::9080",
                       "--env-file", str(self.work / "federation.env"), "--env-file", str(env),
                       "-v", f"{config}:/config:ro", self.image)
        for _ in range(60):
            health = docker("inspect", "-f", "{{.State.Health.Status}}", name, check=False).strip()
            if health == "healthy":
                break
            if docker("inspect", "-f", "{{.State.Running}}", name, check=False).strip() != "true":
                sys.exit("gateway exited:\n" + docker("logs", name, check=False))
            time.sleep(1)
        else:
            sys.exit("gateway never became healthy:\n" + docker("logs", name, check=False))
        port = docker("port", name, "9080/tcp").strip().rsplit(":", 1)[1]
        return f"http://127.0.0.1:{port}"

    def stop(self) -> None:
        for name in self.names:
            docker("rm", "-f", name, check=False)
        docker("network", "rm", self.net, check=False)

    def challenge(self, label: str, base: str, path: str, headers: dict[str, str], want: str) -> None:
        request = urllib.request.Request(base + path, headers={"Host": "gw.example.org", **headers})
        try:
            urllib.request.urlopen(request, timeout=10)
            got = "(no refusal)"
        except urllib.error.HTTPError as exc:
            got = exc.headers.get("WWW-Authenticate", "(none)")
        ok = want in got
        print(f"  {'✓' if ok else '✗'} {label}: WWW-Authenticate: {got}")
        if not ok:
            self.failures.append(label)

    def expect(self, label: str, base: str, path: str, status: int,
               headers: dict[str, str] | None = None, body_has: str = "") -> str:
        request = urllib.request.Request(base + path, headers={"Host": "gw.example.org",
                                                              **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                got, body = response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            got, body = exc.code, exc.read().decode()
        ok = got == status and body_has in body
        print(f"  {'✓' if ok else '✗'} {label}: {got}" + ("" if ok else f" (wanted {status}"
              + (f", body with {body_has!r}" if body_has else "") + f")\n      {body[:300]}"))
        if not ok:
            self.failures.append(label)
        return body


def render(work: Path, name: str, targets: dict) -> tuple[Path, Path]:
    import yaml
    config = work / name / "config"
    config.mkdir(parents=True)
    (config / "targets.yaml").write_text(yaml.safe_dump(targets, sort_keys=False))
    env = work / name / "gateway.env"
    subprocess.run([sys.executable, str(HELPER), "--render", "--config-dir", str(config),
                    "--env-file", str(env)], check=True, capture_output=True)
    return config, env


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="member-gateway:test")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="mgw-e2e-") as tmp:
        work = Path(tmp)
        keys = Keys(work)
        write_idp(work / "idp", keys)
        (work / "federation.env").write_text("\n".join([
            "CONTROL_BASE_URL=http://idp:8080", "KC_REALM=federation",
            "CONTROL_PORTAL_URL=https://portal.example.org/",
            "FEDERATION_CLI_CLIENT=federation-cli",
            "FEDERATION_ACCOUNT_NAME=meteogate",
            "FEDERATION_HELP_URL=https://help.example.org/cli", ""]))
        closed_config, closed_env = render(work, "closed", TARGETS)
        key = closed_env.read_text().split("LOCAL_API_KEY_PARTNER_A=", 1)[1].split()[0]

        run = Run(args.image, work)
        try:
            run.start()
            print("\nOpen routes disabled:")
            gw = run.gateway(closed_config, closed_env)
            print("  ✓ healthy: started and answering")
            good = {"Authorization": f"Bearer {keys.token()}"}
            body = run.expect("federated, valid token", gw, "/api/obs?x=1", 200, good, '"subject": "user-1"')
            run.expect("federated, subtree rewrite kept", gw, "/api/obs/42", 200, good, '"path": "/api/obs/42"')
            if '"host": "svc:8000"' not in body:
                run.failures.append("pass_host node")
                print(f"  ✗ service sees its own hostname: {body}")
            else:
                print("  ✓ service sees its own hostname (pass_host: node)")
            run.expect("federated, no token → JSON 401", gw, "/api/obs", 401, {}, '"help":')
            run.expect("federated, no token, browser → page linking the help URL", gw, "/api/obs",
                       401, {"Accept": "text/html"}, "https://help.example.org/cli")
            run.expect("…and the commands on it ask for this service's token", gw, "/api/obs",
                       401, {"Accept": "text/html"}, "oidc-token --scope=service:obs meteogate")
            # 403, not 401: a genuine token, just not one minted for the federation.
            run.expect("federated, wrong audience", gw, "/api/obs", 403,
                       {"Authorization": f"Bearer {keys.token(aud=['someone-else'])}"})
            # The point of per-service audiences: a genuine token for another member's
            # service — what a careless or hostile service would replay — is refused.
            run.expect("federated, a token for another member service", gw, "/api/obs", 403,
                       {"Authorization": f"Bearer {keys.token(aud='birds')}"})
            run.expect("federated, the old shared audience", gw, "/api/obs", 403,
                       {"Authorization": f"Bearer {keys.token(aud=['federation-services'])}"})
            run.challenge("401 names the scope to ask for", gw, "/api/obs", {},
                          'Bearer realm="federation", scope="service:obs"')
            run.challenge("403 says the scope is wrong", gw, "/api/obs",
                          {"Authorization": f"Bearer {keys.token(aud='birds')}"},
                          'scope="service:obs", error="insufficient_scope"')
            # Past the 120 s the token library allows for clock skew.
            run.expect("federated, expired", gw, "/api/obs", 401,
                       {"Authorization": f"Bearer {keys.token(exp=int(time.time()) - 600)}"})
            run.expect("federated, wrong issuer", gw, "/api/obs", 401,
                       {"Authorization": f"Bearer {keys.token(iss='http://evil/realms/federation')}"})
            forged = keys.token().rsplit(".", 1)[0] + "." + b64url(b"\0" * 256)
            run.expect("federated, bad signature", gw, "/api/obs", 401,
                       {"Authorization": f"Bearer {forged}"})
            # Quota 3/min, shared by /api/obs and /api/obs/* (group): 2 used above.
            other = {"Authorization": f"Bearer {keys.token(sub='user-2')}"}
            run.expect("user-2 has an allowance of its own", gw, "/api/obs", 200, other)
            run.expect("user-1, 3rd request (path and subtree share a counter)", gw, "/api/obs/1", 200, good)
            run.expect("user-1, 4th request → quota", gw, "/api/obs", 429, good, "Quota exceeded")
            run.expect("API key, none", gw, "/local/api/obs", 401, {}, "API key")
            run.expect("API key, wrong", gw, "/local/api/obs", 401, {"apikey": "nope"})
            run.expect("API key, valid, rewritten to the service path", gw, "/local/api/obs/7", 200,
                       {"apikey": key}, '"path": "/api/obs/7"')
            run.expect("open route is not served", gw, "/open/api/obs", 404)
            run.expect("open-only target is not served", gw, "/open/api/stations", 404)
            run.expect("a path nobody configured", gw, "/api/secret", 404)

            print("\nOpen routes enabled:")
            open_targets = {**TARGETS, "open_routes": "enabled"}
            open_config, open_env = render(work, "open", open_targets)
            gw = run.gateway(open_config, open_env)
            run.expect("open route served, rewritten", gw, "/open/api/obs/3", 200, {}, '"path": "/api/obs/3"')
            run.expect("open-only target served", gw, "/open/api/stations", 200, {}, '"path": "/api/stations"')
            run.expect("federated still needs a token", gw, "/api/obs", 401)
        finally:
            run.stop()

    if run.failures:
        print(f"\n{len(run.failures)} failed: {', '.join(run.failures)}")
        return 1
    print("\nAll end-to-end checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

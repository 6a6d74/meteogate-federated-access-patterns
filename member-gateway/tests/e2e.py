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
import copy
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
import json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        # ?sleep=N: answer after N seconds, like a service working up to its deadline.
        time.sleep(float(parse_qs(urlsplit(self.path).query).get("sleep", ["0"])[0]))
        body = json.dumps({"path": self.path, "host": self.headers.get("Host"),
                           "subject": self.headers.get("X-Fed-Subject"),
                           "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

ThreadingHTTPServer(("", 8000), Echo).serve_forever()
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

    def has(self, label: str, text: str, needle: str) -> None:
        ok = needle in text
        print(f"  {'✓' if ok else '✗'} {label}" + ("" if ok else f"\n      no {needle!r} in {text[-600:]}"))
        if not ok:
            self.failures.append(label)

    def lacks(self, label: str, text: str, needle: str) -> None:
        ok = needle not in text
        print(f"  {'✓' if ok else '✗'} {label}" + ("" if ok else f"\n      found {needle!r}"))
        if not ok:
            self.failures.append(label)

    def access_log(self) -> str:
        """Stops the gateway: nginx buffers the access log and writes it out on exit."""
        return self.logs()[0]

    def logs(self) -> tuple[str, str]:
        """(access log, error log), after stopping the gateway so both are complete."""
        docker("stop", f"{self.net}-gateway")
        result = subprocess.run(["docker", "logs", f"{self.net}-gateway"],
                                capture_output=True, text=True)
        return result.stdout, result.stderr

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
            # The key and the token stop at the gateway (#8); identity comes from headers
            # the gateway sets, and a client can't supply its own.
            # Removing the key rebuilds the query string, so the order may change.
            body = run.expect("API key in the query string, passed on without it", gw,
                              f"/local/api/obs?a=1&apikey={key}&b=2", 200, {}, '"path": "/api/obs?')
            path = json.loads(body)["path"]
            run.has("…the other parameters are kept", " ".join(sorted(path.split("?", 1)[1].split("&"))),
                    "a=1 b=2")
            run.lacks("…and the service never sees the key", body, key)
            run.has("…but knows which key holder called", body, '"x-consumer-username": "partner-a"')
            body = run.expect("API key in the header", gw, "/local/api/obs", 200,
                              {"apikey": key, "X-Fed-Subject": "forged", "X-Userinfo": "forged"})
            run.lacks("…the header isn't passed on", body, key)
            run.lacks("…nor a client's own identity headers", body, "forged")
            token = keys.token(sub="user-3")  # user-1 has used its quota
            body = run.expect("federated, the token isn't passed on", gw, "/api/obs", 200,
                              {"Authorization": f"Bearer {token}", "X-Consumer-Username": "forged"})
            run.lacks("…no Authorization header reaches the service", body, '"authorization"')
            run.lacks("…nor a forged consumer header", body, "forged")
            run.has("…the verified claims do", body, '"x-userinfo"')
            run.expect("open route is not served", gw, "/open/api/obs", 404)
            run.expect("open-only target is not served", gw, "/open/api/stations", 404)
            run.expect("a path nobody configured", gw, "/api/secret", 404)
            # Refused requests are where nginx's error log would copy the request line,
            # key and all: a wrong key, and a valid one over its quota.
            run.expect("a wrong key in the query string", gw, "/local/api/obs?apikey=wrong-key-e2e", 401)
            log, errors = run.logs()
            run.lacks("access log never holds the key", log, key)
            run.lacks("error log never holds a key", errors, key)
            run.lacks("…nor a wrong one", errors, "wrong-key-e2e")
            run.has("…logs the query with the key masked", log, '"uri":"/local/api/obs?a=1&apikey=-&b=2"')
            run.has("…a key in the query is logged as an API key", log,
                    '"cred":"apikey","key":"partner-a"')
            run.has("…a bearer token is still logged as one", log, '"cred":"bearer"')

            print("\nOpen routes enabled:")
            open_targets = {**TARGETS, "open_routes": "enabled"}
            open_config, open_env = render(work, "open", open_targets)
            gw = run.gateway(open_config, open_env)
            run.expect("open route served, rewritten", gw, "/open/api/obs/3", 200, {}, '"path": "/api/obs/3"')
            run.expect("open-only target served", gw, "/open/api/stations", 200, {}, '"path": "/api/stations"')
            run.expect("federated still needs a token", gw, "/api/obs", 401)

            # Behind a proxy (#12). Requests from this machine reach the gateway from the
            # Docker network's gateway address, which stands in for a proxy here.
            tight = copy.deepcopy(open_targets)
            tight["targets"][0]["open"]["quota"] = 2
            print("\nX-Forwarded-For from an untrusted address:")
            config, env = render(work, "untrusted", tight)
            gw = run.gateway(config, env)
            for n, client in enumerate(["203.0.113.1", "203.0.113.2"]):
                run.expect(f"open, claiming to be {client}", gw, "/open/api/obs", 200,
                           {"X-Forwarded-For": client})
            run.expect("…a third address shares the same quota", gw, "/open/api/obs", 429,
                       {"X-Forwarded-For": "203.0.113.3"})

            print("\nBehind a trusted proxy:")
            subnet = docker("network", "inspect", "-f", "{{(index .IPAM.Config 0).Subnet}}",
                            run.net).strip()
            behind = copy.deepcopy(tight)
            behind["listen"]["trusted_proxies"] = [subnet]
            config, env = render(work, "behind", behind)
            gw = run.gateway(config, env)
            for n in range(2):
                run.expect(f"open, client 203.0.113.1, request {n + 1}", gw, "/open/api/obs", 200,
                           {"X-Forwarded-For": "203.0.113.1"})
            run.expect("…its third → quota", gw, "/open/api/obs", 429, {"X-Forwarded-For": "203.0.113.1"})
            run.expect("another client has a quota of its own", gw, "/open/api/obs", 200,
                       {"X-Forwarded-For": "203.0.113.2"})
            # A client's own X-Forwarded-For is on the left; the proxy appends the address
            # it saw. Only the rightmost untrusted address counts.
            run.expect("a forged address on the left doesn't help", gw, "/open/api/obs", 429,
                       {"X-Forwarded-For": "198.51.100.9, 203.0.113.1"})
            log = run.access_log()
            run.has("the access log shows the client's address", log, '"ip":"203.0.113.2"')

            print("\nThe service's own timeout (#11):")
            slow = copy.deepcopy(open_targets)
            slow["service"]["timeout"] = {"read": 2}
            config, env = render(work, "slow", slow)
            gw = run.gateway(config, env)
            run.expect("an answer inside the timeout", gw, "/open/api/obs?sleep=1", 200)
            run.expect("an answer after it → the gateway's 504", gw, "/open/api/obs?sleep=3", 504)
        finally:
            run.stop()

    if run.failures:
        print(f"\n{len(run.failures)} failed: {', '.join(run.failures)}")
        return 1
    print("\nAll end-to-end checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

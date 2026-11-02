#!/usr/bin/env python3
"""The federation's usage metrics, per member service, from Keycloak's stored events.

Keycloak's own metrics (its /metrics, with user-event metrics on) count events by
client, which says nothing about *which service* a token was for: the CLI and machine
credentials ask for any service's scope. Keycloak's stored events do record that scope,
so this reads them, every POLL_SECONDS, through a client with only view-events,
view-users and view-clients.

  GET /metrics    these metrics (Prometheus text, or OpenMetrics if asked for)
  GET /keycloak   Keycloak's own metrics, passed through (one upstream for the gateway)

No metric carries a user ID, hashed or not. Distinct users are counted here, in memory,
and only the counts are published (fed_active_users).

Settings (environment):
  KC_INTERNAL_URL           http://keycloak:8080
  KC_MANAGEMENT_URL         http://keycloak:9000   (its /metrics)
  KC_REALM                  federation
  EXPORTER_CLIENT_ID        fed-metrics-exporter
  EXPORTER_CLIENT_SECRET    (required)
  FEDERATION_SERVICES       the member list, JSON, as for bootstrap.sh
  BIRDS_AUDIENCE            the audience of the testbed's own birds-* clients
  FED_ACTIVE_WINDOWS        15m,1h,1d,7d,30d
  POLL_SECONDS              30
  PORT                      9100
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prometheus_client import CollectorRegistry, Counter, Gauge
from prometheus_client.exposition import choose_encoder

SERVICE_SCOPE = re.compile(r"(?:^|\s)service:([a-z0-9][a-z0-9-]{0,62})(?:\s|$)")
UNITS = {"m": 60, "h": 3600, "d": 86400}

# Event type → the grant it issued a token by.
TOKEN_EVENTS = {
    "CODE_TO_TOKEN": "authorization_code",
    "REFRESH_TOKEN": "refresh_token",
    "CLIENT_LOGIN": "client_credentials",
    "OAUTH2_DEVICE_CODE_TO_TOKEN": "device_code",
}


def windows(spec: str) -> dict[str, int]:
    """'15m,1d' → {'15m': 900, '1d': 86400}."""
    out = {}
    for part in filter(None, (p.strip() for p in spec.split(","))):
        m = re.fullmatch(r"(\d+)([mhd])", part)
        if not m:
            raise ValueError(f"FED_ACTIVE_WINDOWS: {part!r} is not like 15m, 1h or 7d")
        out[part] = int(m[1]) * UNITS[m[2]]
    return out


class Mapping:
    """Which member service an event was for."""

    def __init__(self, services: list[dict], birds_audience: str):
        self.audiences = {s["audience"] for s in services}
        self.birds = birds_audience

    def service(self, event: dict) -> str:
        scope = (event.get("details") or {}).get("scope", "")
        found = [a for a in SERVICE_SCOPE.findall(scope) if a in self.audiences]
        if found:
            return found[0]
        client = event.get("clientId") or ""
        if client in ("birds-web", "birds-gateway") and self.birds in self.audiences:
            return self.birds
        if client.startswith("member-") and client[7:] in self.audiences:
            return client[7:]
        return "none"


def kind(event: dict) -> str:
    """A person, or a machine credential (client credentials, a service account)."""
    details = event.get("details") or {}
    if event.get("type") == "CLIENT_LOGIN" or details.get("username", "").startswith("service-account-"):
        return "machine"
    return "person"


def client_label(client_id: str) -> str:
    """Minted credentials are svc-<username>-…: one label for them all, no usernames."""
    return "credentials" if client_id.startswith("svc-") else client_id


class Metrics:
    def __init__(self, registry: CollectorRegistry, mapping: Mapping, active_windows: dict[str, int]):
        self.mapping, self.windows = mapping, active_windows
        self.signins = Counter("fed_signins", "Sign-ins, by the service they were for.",
                               ["service", "method"], registry=registry)
        self.tokens = Counter("fed_tokens_issued", "Tokens issued, by service and grant.",
                              ["service", "grant"], registry=registry)
        self.registrations = Counter("fed_registrations", "Accounts created.", ["via"], registry=registry)
        self.deregistrations = Counter("fed_deregistrations", "Accounts deleted.", ["via"], registry=registry)
        self.active = Gauge("fed_active_users",
                            "Distinct users issued a token for the service within the window.",
                            ["service", "kind", "window"], registry=registry)
        self.sessions = Gauge("fed_sessions", "Keycloak's sessions, by client.",
                              ["client", "kind"], registry=registry)
        self.users = Gauge("fed_registered_users", "Accounts, by whether enabled.", ["enabled"],
                           registry=registry)
        self.credentials = Gauge("fed_credentials", "Minted machine credentials, by state.", ["state"],
                                 registry=registry)
        self.last_event = Gauge("fed_exporter_last_event_time_seconds",
                                "When the newest event read was recorded.", registry=registry)
        self.errors = Counter("fed_exporter_poll_errors", "Polls that failed.", registry=registry)
        # (service, kind) → user ID → last time (s). Never published; only counted.
        self.seen: dict[tuple[str, str], dict[str, float]] = {}

    # ── events ────────────────────────────────────────────────────────────────────
    def note_activity(self, event: dict) -> None:
        user = event.get("userId")
        if not user:
            return
        key = (self.mapping.service(event), kind(event))
        t = event.get("time", 0) / 1000
        users = self.seen.setdefault(key, {})
        users[user] = max(users.get(user, 0), t)

    def count_user_event(self, event: dict) -> None:
        """One new user event: counters, and activity."""
        etype = event.get("type")
        details = event.get("details") or {}
        service = self.mapping.service(event)
        if etype == "LOGIN":
            grant = details.get("grant_type")
            self.signins.labels(service, grant or "browser").inc()
            if grant:     # a direct grant issues its token in the LOGIN itself
                self.tokens.labels(service, grant).inc()
        elif etype in TOKEN_EVENTS:
            self.tokens.labels(service, TOKEN_EVENTS[etype]).inc()
        elif etype == "IDENTITY_PROVIDER_FIRST_LOGIN":
            self.registrations.labels("first_signin").inc()
        elif etype == "DELETE_ACCOUNT":
            self.deregistrations.labels("account_console").inc()
        if etype == "LOGIN" or etype in TOKEN_EVENTS:
            self.note_activity(event)

    def count_admin_event(self, event: dict, clients: dict[str, str] | None = None) -> None:
        """clients: this realm's clients, internal id → clientId. An admin event names the
        client by internal id, and the realm the admin signed in to: the operator's, when
        it isn't this one (the allow-list, the admin console)."""
        if event.get("resourceType") != "USER":
            return
        path = event.get("resourcePath") or ""
        if not re.fullmatch(r"users/[0-9a-f-]{36}", path):
            return        # a user's sub-resources (role mappings, …), not the user
        auth = event.get("authDetails") or {}
        operator = bool(auth.get("realmId")) and auth.get("realmId") != event.get("realmId")
        by = "" if operator else (clients or {}).get(auth.get("clientId", ""), "")
        via = "portal" if by == "portal-admin" else "admin"
        if event.get("operationType") == "CREATE":
            self.registrations.labels("allow_list" if operator else via).inc()
        elif event.get("operationType") == "DELETE":
            self.deregistrations.labels(via).inc()

    def refresh_active(self, now: float) -> None:
        longest = max(self.windows.values(), default=0)
        for key, users in list(self.seen.items()):
            for user, t in list(users.items()):
                if now - t > longest:
                    del users[user]
            service, k = key
            for name, seconds in self.windows.items():
                self.active.labels(service, k, name).set(sum(1 for t in users.values() if now - t <= seconds))


class Keycloak:
    def __init__(self, base: str, realm: str, client_id: str, secret: str):
        self.base, self.realm, self.client_id, self.secret = base.rstrip("/"), realm, client_id, secret
        self.token, self.expires = None, 0.0

    def _token(self) -> str:
        if self.token and time.time() < self.expires - 30:
            return self.token
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                       "client_secret": self.secret}).encode()
        url = f"{self.base}/realms/{self.realm}/protocol/openid-connect/token"
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=20) as r:
            doc = json.load(r)
        self.token, self.expires = doc["access_token"], time.time() + doc.get("expires_in", 60)
        return self.token

    def get(self, path: str, **query):
        url = f"{self.base}/admin/realms/{self.realm}/{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._token()}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def events_since(self, kind: str, since_ms: int, page: int = 500) -> list[dict]:
        """Every stored event of `kind` ("events" or "admin-events") newer than since_ms,
        oldest first. Keycloak returns newest first, a page at a time."""
        day = time.strftime("%Y-%m-%d", time.gmtime(since_ms / 1000))
        out, first = [], 0
        while True:
            batch = self.get(kind, first=first, max=page, dateFrom=day)
            newer = [e for e in batch if e.get("time", 0) > since_ms]
            out.extend(newer)
            if len(batch) < page or len(newer) < len(batch):
                break
            first += page
        return sorted(out, key=lambda e: e.get("time", 0))


class Exporter:
    def __init__(self, kc: Keycloak, metrics: Metrics):
        self.kc, self.m = kc, metrics
        self.cursor = {"events": 0, "admin-events": 0}
        self.seen_ids: set[str] = set()
        self.clients: dict[str, str] = {}      # internal id → clientId, from levels()

    def start(self) -> None:
        """Fill the activity windows from history; count only what happens from now on.
        (Counters start at zero after a restart, which Prometheus expects. Replaying old
        events into them would show the whole history as a spike.)"""
        now_ms = int(time.time() * 1000)
        since = now_ms - max(self.m.windows.values(), default=0) * 1000
        for event in self.kc.events_since("events", since):
            if event.get("clientId") == self.kc.client_id:
                continue
            if event.get("type") == "LOGIN" or event.get("type") in TOKEN_EVENTS:
                self.m.note_activity(event)
        self.cursor = {"events": now_ms, "admin-events": now_ms}
        self.levels()

    def poll(self) -> None:
        for kind, count in (("events", self.m.count_user_event),
                            ("admin-events", lambda e: self.m.count_admin_event(e, self.clients))):
            for event in self.kc.events_since(kind, self.cursor[kind] - 1):
                ident = event.get("id") or f"{kind}:{event.get('time')}:{json.dumps(event, sort_keys=True)}"
                if ident in self.seen_ids:
                    continue
                self.seen_ids.add(ident)
                self.cursor[kind] = max(self.cursor[kind], event.get("time", 0))
                # Not the exporter's own sign-ins to read these: one per token lifetime.
                if event.get("clientId") != self.kc.client_id:
                    count(event)
                self.m.last_event.set(max(self.cursor.values()) / 1000)
        if len(self.seen_ids) > 100_000:
            self.seen_ids.clear()
        self.m.refresh_active(time.time())
        self.levels()

    def levels(self) -> None:
        """Gauges read straight from Keycloak: sessions, accounts, credentials."""
        sessions: dict[tuple[str, str], int] = {}
        credentials = {"active": 0, "expired": 0, "disabled": 0}
        today = time.strftime("%Y-%m-%d", time.gmtime())
        first = 0
        while True:
            clients = self.kc.get("clients", first=first, max=200)
            for c in clients:
                self.clients[c["id"]] = c.get("clientId", "")
                label = client_label(c.get("clientId", ""))
                for k, path in (("online", "session-count"), ("offline", "offline-session-count")):
                    n = self.kc.get(f"clients/{c['id']}/{path}").get("count", 0)
                    sessions[(label, k)] = sessions.get((label, k), 0) + n
                owner = (c.get("attributes") or {}).get("fed_owner_sub")
                if owner:
                    expires = (c.get("attributes") or {}).get("fed_secret_expires", "")
                    state = ("disabled" if not c.get("enabled", True)
                             else "expired" if expires and expires[:10] < today else "active")
                    credentials[state] += 1
            if len(clients) < 200:
                break
            first += 200
        for (label, k), n in sessions.items():
            self.m.sessions.labels(label, k).set(n)
        for state, n in credentials.items():
            self.m.credentials.labels(state).set(n)
        enabled = {"true": 0, "false": 0}
        first = 0
        while True:
            users = self.kc.get("users", first=first, max=500, briefRepresentation="true")
            for u in users:
                enabled["true" if u.get("enabled", True) else "false"] += 1
            if len(users) < 500:
                break
            first += 500
        for k, n in enabled.items():
            self.m.users.labels(k).set(n)


def serve(registry: CollectorRegistry, management: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0].rstrip("/")
            # /usage is the path behind the fed-metrics gateway; /metrics, the usual one.
            if path in ("/metrics", "/usage"):
                encoder, content_type = choose_encoder(self.headers.get("Accept"))
                body, status = encoder(registry), 200
            elif path == "/keycloak":
                try:
                    with urllib.request.urlopen(f"{management}/metrics", timeout=20) as r:
                        body, content_type, status = r.read(), r.headers.get("Content-Type", "text/plain"), 200
                except (urllib.error.URLError, OSError) as exc:
                    body, content_type, status = f"keycloak metrics unavailable: {exc}\n".encode(), "text/plain", 502
            else:
                body, content_type, status = b"not found\n", "text/plain", 404
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ThreadingHTTPServer(("", port), Handler).serve_forever()


def main() -> int:
    env = os.environ
    secret = env.get("EXPORTER_CLIENT_SECRET", "")
    if not secret:
        print("EXPORTER_CLIENT_SECRET is not set", file=sys.stderr)
        return 1
    services = json.loads(env.get("FEDERATION_SERVICES") or "[]")
    registry = CollectorRegistry()
    metrics = Metrics(registry, Mapping(services, env.get("BIRDS_AUDIENCE", "birds")),
                      windows(env.get("FED_ACTIVE_WINDOWS", "15m,1h,1d,7d,30d")))
    kc = Keycloak(env.get("KC_INTERNAL_URL", "http://keycloak:8080"), env.get("KC_REALM", "federation"),
                  env.get("EXPORTER_CLIENT_ID", "fed-metrics-exporter"), secret)
    exporter = Exporter(kc, metrics)
    interval = int(env.get("POLL_SECONDS", "30"))

    def loop():
        started = False
        while True:
            try:
                if not started:
                    exporter.start()
                    started = True
                exporter.poll()
            except Exception as exc:      # keep serving; the error counter says so
                metrics.errors.inc()
                print(f"poll failed: {exc}", file=sys.stderr, flush=True)
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True).start()
    serve(registry, env.get("KC_MANAGEMENT_URL", "http://keycloak:9000"), int(env.get("PORT", "9100")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

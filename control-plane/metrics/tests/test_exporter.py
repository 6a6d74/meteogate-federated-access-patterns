"""The exporter's event handling, without Keycloak.

  python3 -m pytest control-plane/metrics/tests     (needs pytest and prometheus-client)
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry

spec = importlib.util.spec_from_file_location(
    "exporter", Path(__file__).resolve().parents[1] / "exporter" / "exporter.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)

SERVICES = [{"audience": "birds", "name": "Birds"}, {"audience": "meteocore", "name": "MeteoCore"},
            {"audience": "fed-metrics", "name": "Metrics"}]
NOW = 1_800_000_000.0


def event(etype, *, client="federation-cli", user="u1", scope=None, t=NOW, **details):
    d = dict(details)
    if scope is not None:
        d["scope"] = scope
    return {"type": etype, "clientId": client, "userId": user, "time": int(t * 1000), "details": d}


@pytest.fixture
def m():
    registry = CollectorRegistry()
    metrics = exporter.Metrics(registry, exporter.Mapping(SERVICES, "birds"),
                               exporter.windows("15m,1d"))
    metrics.registry = registry
    return metrics


def value(m, name, **labels):
    return m.registry.get_sample_value(name, labels) or 0


def test_windows():
    assert exporter.windows("15m,1h,7d") == {"15m": 900, "1h": 3600, "7d": 604800}
    with pytest.raises(ValueError):
        exporter.windows("15 minutes")


@pytest.mark.parametrize("ev, service", [
    (event("REFRESH_TOKEN", scope="openid service:meteocore email"), "meteocore"),
    (event("CLIENT_LOGIN", scope="profile service:birds"), "birds"),
    (event("CODE_TO_TOKEN", client="birds-web", scope="openid profile"), "birds"),
    (event("CODE_TO_TOKEN", client="member-meteocore"), "meteocore"),
    (event("LOGIN", client="federation-portal"), "none"),
    (event("REFRESH_TOKEN", scope="service:not-a-member"), "none"),
])
def test_which_service(ev, service):
    assert exporter.Mapping(SERVICES, "birds").service(ev) == service


def test_person_or_machine():
    assert exporter.kind(event("CLIENT_LOGIN")) == "machine"
    assert exporter.kind(event("REFRESH_TOKEN", username="service-account-x")) == "machine"
    assert exporter.kind(event("REFRESH_TOKEN", username="alice")) == "person"


def test_counts(m):
    m.count_user_event(event("LOGIN", client="birds-web"))
    m.count_user_event(event("LOGIN", grant_type="password", scope="openid service:meteocore"))
    m.count_user_event(event("CODE_TO_TOKEN", client="birds-web"))
    m.count_user_event(event("REFRESH_TOKEN", scope="service:meteocore"))
    m.count_user_event(event("CLIENT_LOGIN", scope="service:fed-metrics", user="sa"))
    m.count_user_event(event("IDENTITY_PROVIDER_FIRST_LOGIN"))
    m.count_user_event(event("DELETE_ACCOUNT"))
    assert value(m, "fed_signins_total", service="birds", method="browser") == 1
    assert value(m, "fed_signins_total", service="meteocore", method="password") == 1
    assert value(m, "fed_tokens_issued_total", service="birds", grant="authorization_code") == 1
    assert value(m, "fed_tokens_issued_total", service="meteocore", grant="refresh_token") == 1
    assert value(m, "fed_tokens_issued_total", service="meteocore", grant="password") == 1
    assert value(m, "fed_tokens_issued_total", service="fed-metrics", grant="client_credentials") == 1
    assert value(m, "fed_registrations_total", via="first_signin") == 1
    assert value(m, "fed_deregistrations_total", via="account_console") == 1


def test_admin_events(m):
    uid = "0123abcd-0123-0123-0123-0123456789ab"
    realm, master = "realm-uuid", "master-uuid"
    clients = {"portal-uuid": "portal-admin"}

    def admin(op, path=f"users/{uid}", signed_in=realm, client="portal-uuid"):
        m.count_admin_event({"resourceType": "USER", "operationType": op, "resourcePath": path,
                             "realmId": realm, "authDetails": {"realmId": signed_in, "clientId": client}},
                            clients)

    admin("DELETE")                                         # the portal's "delete my registration"
    admin("CREATE", signed_in=master, client="admin-cli-uuid")   # the operator's allow-list
    admin("DELETE", signed_in=master, client="admin-cli-uuid")   # the operator
    admin("UPDATE")
    admin("DELETE", path=f"users/{uid}/role-mappings/realm")
    assert value(m, "fed_deregistrations_total", via="portal") == 1
    assert value(m, "fed_registrations_total", via="allow_list") == 1
    assert value(m, "fed_deregistrations_total", via="admin") == 1


def test_distinct_users_per_window_with_no_ids_published(m):
    m.count_user_event(event("REFRESH_TOKEN", user="alice-id", scope="service:meteocore", t=NOW - 60))
    m.count_user_event(event("REFRESH_TOKEN", user="alice-id", scope="service:meteocore", t=NOW - 30))
    m.count_user_event(event("REFRESH_TOKEN", user="bob-id", scope="service:meteocore", t=NOW - 3600))
    m.count_user_event(event("CLIENT_LOGIN", user="sa-id", scope="service:meteocore", t=NOW - 60))
    m.refresh_active(NOW)
    assert value(m, "fed_active_users", service="meteocore", kind="person", window="15m") == 1
    assert value(m, "fed_active_users", service="meteocore", kind="person", window="1d") == 2
    assert value(m, "fed_active_users", service="meteocore", kind="machine", window="15m") == 1
    from prometheus_client import generate_latest
    text = generate_latest(m.registry).decode()
    assert "alice-id" not in text and "bob-id" not in text and "sa-id" not in text


def test_old_activity_is_forgotten(m):
    m.note_activity(event("REFRESH_TOKEN", user="old", scope="service:birds", t=NOW - 2 * 86400))
    m.refresh_active(NOW)
    assert m.seen[("birds", "person")] == {}


def test_credentials_get_one_label_not_usernames():
    assert exporter.client_label("svc-alice-1a2b3c") == "credentials"
    assert exporter.client_label("member-meteocore") == "member-meteocore"


class FakeKeycloak:
    client_id = "fed-metrics-exporter"

    def __init__(self, events):
        self.events = events

    def events_since(self, kind, since_ms):
        return [e for e in self.events if kind == "events" and e["time"] > since_ms]

    def get(self, path, **query):
        return []


def test_the_exporters_own_sign_ins_are_not_counted(m):
    import time
    now = time.time()
    kc = FakeKeycloak([event("CLIENT_LOGIN", client="fed-metrics-exporter", t=now + 1),
                       event("CLIENT_LOGIN", client="svc-x", user="sa", scope="service:birds", t=now + 2)])
    e = exporter.Exporter(kc, m)
    e.start()
    e.poll()
    e.poll()       # the same events again: counted once
    assert value(m, "fed_tokens_issued_total", service="none", grant="client_credentials") == 0
    assert value(m, "fed_tokens_issued_total", service="birds", grant="client_credentials") == 1

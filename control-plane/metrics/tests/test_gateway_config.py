"""The fed-metrics gateway's committed gateway.yaml is what its targets.yaml renders to."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
GATEWAY = ROOT / "control-plane" / "metrics" / "gateway"

spec = importlib.util.spec_from_file_location(
    "routes_helper", ROOT / "member-gateway" / "scripts" / "routes-helper.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def test_gateway_yaml_is_rendered_from_targets_yaml():
    targets = yaml.safe_load((GATEWAY / "targets.yaml").read_text())
    committed = yaml.safe_load((GATEWAY / "gateway.yaml").read_text())
    assert committed == helper.render(targets), "run `make metrics-gateway` in control-plane/"


def test_the_federated_door_needs_the_admin_entitlement():
    committed = yaml.safe_load((GATEWAY / "gateway.yaml").read_text())
    assert committed["auth"]["audience"] == "fed-metrics"
    federated = [r for r in committed["routes"] if r["auth"] == "federated"]
    assert federated and all(r.get("require_entitlement") == "urn:meteogate:testbed:entitlement:admin"
                             for r in federated)

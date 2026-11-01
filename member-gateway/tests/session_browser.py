#!/usr/bin/env python3
"""A scripted browser for e2e_session.py. Runs in a container on the test's network.

  session_browser.py STATE PHASE

Keeps its cookies in STATE (JSON) between phases, one jar per host, and prints one JSON
object: what the phase saw. The gateway answers for https://web.gw.example.org, which
the test reaches as http://gateway:9080 with that Host; Keycloak is http://kc:8080.
"""

from __future__ import annotations

import html
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

WEB = "web.gw.example.org"
GATEWAY = "http://gateway:9080"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def load(path: str) -> dict:
    try:
        return json.load(open(path))
    except FileNotFoundError:
        return {"jars": {}}


def request(state: dict, url: str, data: dict | None = None, headers: dict | None = None):
    """One request, no redirects followed. Public https://web… URLs go to the gateway."""
    parts = urllib.parse.urlsplit(url)
    host = parts.netloc
    target = url
    if host == WEB:
        target = GATEWAY + parts.path + (f"?{parts.query}" if parts.query else "")
    jar = state["jars"].setdefault(host, {})
    h = {"Host": host, "Accept": "text/html", **(headers or {})}
    if jar:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(target, data=body, headers=h, method="POST" if body else "GET")
    try:
        response = OPENER.open(req, timeout=20)
        status, rh, text = response.status, response.headers, response.read().decode()
    except urllib.error.HTTPError as exc:
        status, rh, text = exc.code, exc.headers, exc.read().decode(errors="replace")
    for cookie in rh.get_all("Set-Cookie") or []:
        name, _, rest = cookie.partition("=")
        value = rest.split(";", 1)[0]
        if "Max-Age=0" in cookie or "expires=Thu, 01 Jan 1970" in cookie.lower() or value == "":
            jar.pop(name.strip(), None)
        else:
            jar[name.strip()] = value
    location = rh.get("Location")
    if location:
        location = urllib.parse.urljoin(url, location)
    return status, location, text


def sign_in(state: dict, path: str) -> dict:
    status, location, _ = request(state, f"https://{WEB}{path}")
    seen = {"first": status, "to_idp": bool(location and location.startswith("http://kc:8080/"))}
    if not seen["to_idp"]:
        return seen
    seen["asked_scope"] = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("scope", [""])[0]
    status, location, page = request(state, location)
    # While Keycloak's own session lives, it skips the form and goes straight back.
    seen["form"] = not (status == 302 and location and location.startswith(f"https://{WEB}/"))
    if seen["form"]:
        form = re.search(r'<form[^>]+action="([^"]+)"', page)
        if not form:
            return {**seen, "error": "no login form", "page": page[:300]}
        status, location, page = request(state, html.unescape(form.group(1)),
                                         {"username": "tester", "password": "tester-pass"})
    seen["callback"] = bool(location and location.startswith(f"https://{WEB}/session/callback"))
    if not seen["callback"]:
        return {**seen, "error": f"login answered {status}", "page": page[:300]}
    status, location, _ = request(state, location)
    seen["back_to"] = location
    return seen


def get(state: dict, path: str, headers: dict | None = None) -> dict:
    status, location, text = request(state, f"https://{WEB}{path}", headers=headers)
    out = {"status": status, "location": location}
    try:
        out["echo"] = json.loads(text)
    except ValueError:
        out["text"] = text[:300]
    return out


def logout(state: dict) -> dict:
    status, location, _ = request(state, f"https://{WEB}/session/logout")
    out = {"status": status, "to": location}
    if location and location.startswith("http://kc:8080/"):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
        out["params"] = sorted(query)
        status, after, page = request(state, location)
        out["idp_status"], out["idp_to"] = status, after
        out["idp_error"] = "Missing parameters" in page or "We are sorry" in page
        out["idp_confirm"] = "logout" in page.lower() and status == 200
    return out


def main() -> int:
    path, phase = sys.argv[1], sys.argv[2]
    state = load(path)
    if phase == "signin":
        result = sign_in(state, "/api/obs")
    elif phase.startswith("get:"):
        result = get(state, phase[4:])
    elif phase == "forged":
        forged = "e30.eyJzdWIiOiJtYWxsb3J5IiwiYXVkIjoib2JzIn0.x"   # {"sub":"mallory","aud":"obs"}
        result = get(state, "/api/obs", {"X-Access-Token": forged, "X-Fed-Subject": "mallory",
                                         "Authorization": f"Bearer {forged}"})
    elif phase == "logout":
        result = logout(state)
    elif phase == "forget-gateway":
        state["jars"].pop(WEB, None)
        result = {}
    else:
        print(json.dumps({"error": f"unknown phase {phase}"}))
        return 2
    json.dump(state, open(path, "w"))
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

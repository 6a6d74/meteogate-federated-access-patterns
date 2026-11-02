#!/usr/bin/env python3
"""A scripted browser for e2e_terms.py. Runs in a container on the test's network.

  terms_browser.py STATE PHASE [ARG]

Cookies are kept in STATE between phases, by name and path, as a browser does: both
realms live on one host (http://kc:8080) and use the same cookie names under different
paths. Prints one JSON object describing what the phase saw.

Phases:
  signin USER        start a sign-in to the federation realm through its "upstream"
                     identity provider, as USER; stops at the terms page or the app
  submit CHOICE      answer the terms page: agree | agree+remember | none | cancel
  reload             load the terms page again (a GET), as a browser's reload does
  forget-sessions    drop every cookie except FED_TERMS (a new sign-in, same browser)
  forget-all         drop every cookie (another browser)
"""

from __future__ import annotations

import html
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = "http://kc:8080"
APP = "http://app.example/cb"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def load(path):
    try:
        return json.load(open(path))
    except FileNotFoundError:
        return {"cookies": [], "set_cookie": {}, "page": None}


def cookie_header(state, url):
    path = urllib.parse.urlsplit(url).path or "/"
    sent = [f"{c['name']}={c['value']}" for c in state["cookies"] if path.startswith(c["path"])]
    return "; ".join(sent)


def store(state, headers):
    for raw in headers.get_all("Set-Cookie") or []:
        parts = [p.strip() for p in raw.split(";")]
        name, _, value = parts[0].partition("=")
        attrs = {p.partition("=")[0].lower(): p.partition("=")[2] for p in parts[1:]}
        path = attrs.get("path", "/") or "/"
        state["cookies"] = [c for c in state["cookies"] if not (c["name"] == name and c["path"] == path)]
        gone = attrs.get("max-age") == "0" or "1970" in attrs.get("expires", "") or value == ""
        if not gone:
            state["cookies"].append({"name": name, "path": path, "value": value})
        state["set_cookie"][name] = raw


def request(state, url, data=None):
    headers = {"Accept": "text/html"}
    cookies = cookie_header(state, url)
    if cookies:
        headers["Cookie"] = cookies
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body else "GET")
    try:
        response = OPENER.open(req, timeout=20)
        status, h, text = response.status, response.headers, response.read().decode()
    except urllib.error.HTTPError as exc:
        status, h, text = exc.code, exc.headers, exc.read().decode(errors="replace")
    store(state, h)
    location = h.get("Location")
    return status, (urllib.parse.urljoin(url, location) if location else None), text


def follow(state, url, data=None, user=None):
    """Follow redirects within Keycloak, answering the upstream login form if it appears.

    Ends at the app (signed in), the terms page, or an error page."""
    status, location, text = request(state, url, data)
    for _ in range(25):
        if location and location.startswith(APP):
            return {"outcome": "in", "code": "code=" in location}
        if location:
            status, location, text = request(state, location)
            continue
        if 'id="fed-terms-form"' in text:
            action = html.unescape(re.search(r'id="fed-terms-form"[^>]*action="([^"]+)"', text).group(1))
            state["page"] = action
            return {"outcome": "terms", "status": status,
                    "remember_offered": 'name="remember"' in text,
                    "version_shown": re.search(r"Version ([^<]+)<", text).group(1).strip()
                    if re.search(r"Version ([^<]+)<", text) else None,
                    "text_shown": "Try not to break the testbed." in text,
                    "tick_message": "Tick the box" in text,
                    "withdraw_note": "delete your registration" in text}
        if 'id="kc-form-login"' in text and user:
            action = html.unescape(re.search(r'id="kc-form-login"[^>]*action="([^"]+)"', text).group(1))
            status, location, text = request(state, action, {"username": user, "password": f"{user}-pass"})
            user = None
            continue
        return {"outcome": "denied" if status == 403 else "other", "status": status,
                "declined_message": "You need to agree" in text, "page": text[:300]}
    return {"outcome": "loop"}


def main():
    path, phase = sys.argv[1], sys.argv[2]
    arg = sys.argv[3] if len(sys.argv) > 3 else None
    state = load(path)
    if phase == "signin":
        query = urllib.parse.urlencode({"client_id": "test-app", "response_type": "code",
                                        "scope": "openid", "redirect_uri": APP,
                                        "kc_idp_hint": "upstream", "state": "s"})
        result = follow(state, f"{KC}/realms/federation/protocol/openid-connect/auth?{query}", user=arg)
    elif phase == "submit":
        form = {"agree": {"agree": "on", "accept": ""},
                "agree+remember": {"agree": "on", "remember": "on", "accept": ""},
                "none": {"accept": ""},
                "cancel": {"cancel": ""}}[arg]
        result = follow(state, state["page"], form)
    elif phase == "reload":
        result = follow(state, state["page"])
    elif phase == "forget-sessions":
        state["cookies"] = [c for c in state["cookies"] if c["name"] == "FED_TERMS"]
        result = {"kept": [c["name"] for c in state["cookies"]]}
    elif phase == "forget-all":
        state["cookies"] = []
        result = {}
    else:
        result = {"error": f"unknown phase {phase}"}
    result["fed_terms_cookie"] = next((c["value"] for c in state["cookies"] if c["name"] == "FED_TERMS"), None)
    result["fed_terms_set_cookie"] = state["set_cookie"].get("FED_TERMS")
    json.dump(state, open(path, "w"))
    print(json.dumps(result))


if __name__ == "__main__":
    main()

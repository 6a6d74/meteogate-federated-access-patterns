#!/usr/bin/env python3
"""Watch gateway traffic live, one line per request.

Run this in a second window and send requests in the first. Each line shows what the
gateway decided and why — which credential was presented, which of the four front doors
was used, whose subject it resolved to, and what the quota did.

    ./scripts/watch-traffic.py              API traffic only
    ./scripts/watch-traffic.py --all        including pages, assets and probes
    ./scripts/watch-traffic.py --errors     add the gateway's own error log
    ./scripts/watch-traffic.py --filter 21  only lines whose URI contains "21"
    ./scripts/watch-traffic.py --tail 50    replay the last 50 lines first

The gateway emits one JSON object per request; this only formats them. The format is
defined in apisix/config.yaml, and deliberately carries no credential — only which kind
was presented. A log that quotes the bearer token is a log that grants access to whoever
reads it.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# ── Colour ────────────────────────────────────────────────────────────────────────
# Applied only when writing to a terminal, so piping this into a file or grep gives
# plain text rather than escape sequences.
class C:
    def __init__(self, on: bool):
        self.on = on

    def __call__(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def dim(self, t):    return self("2", t)
    def bold(self, t):   return self("1", t)
    def green(self, t):  return self("32", t)
    def amber(self, t):  return self("33", t)
    def red(self, t):    return self("31", t)
    def cyan(self, t):   return self("36", t)
    def mag(self, t):    return self("35", t)


# ── Interpretation ────────────────────────────────────────────────────────────────

# Which front door a request came through. Derived from the path rather than read from
# the log, because APISIX's route name is Lua-side context that nginx's log_format
# cannot see — see the comment in apisix/config.yaml.
def door(uri: str) -> tuple[str, str]:
    path = uri.split("?", 1)[0]
    if path.startswith("/local/"):        return "operator", "the operator's own API key"
    if path.startswith("/session/"):      return "session",  "browser session cookie"
    if path.startswith("/open/"):         return "open",     "no credential required"
    if path.startswith("/api/birds"):     return "federated", "federation token"
    if path in ("/healthz", "/openapi.json") or path.startswith("/docs"):
        return "discovery", "unmetered by design"
    if path.startswith(("/birds", "/help")):
        return "web", "static page or asset"
    return "other", ""


def is_api(uri: str) -> bool:
    return door(uri)[0] in ("federated", "operator", "session", "open")


def verdict(status: int, cred: str, c: C) -> str:
    if status == 429:                 return c.red("quota exhausted")
    if status == 401:                 return c.amber("refused — no valid credential")
    if status == 403:                 return c.amber("refused — credential insufficient")
    if status in (301, 302, 303, 307):return c.cyan("redirected to sign in")
    if status == 304:                 return c.dim("not modified")
    if 500 <= status:                 return c.red("upstream or gateway error")
    if 200 <= status < 300:           return c.green("allowed")
    return str(status)


def colour_status(status: int, c: C) -> str:
    if status == 429 or status >= 500:  return c.red(f"{status}")
    if status >= 400:                   return c.amber(f"{status}")
    if status >= 300:                   return c.cyan(f"{status}")
    return c.green(f"{status}")


def cred_label(raw: str) -> str:
    """Tidy the credential kind.

    The nginx map concatenates, so a request carrying more than one credential arrives
    as "bearercookie". That happens on the session routes: the browser sends the cookie,
    and the OIDC plugin injects an Authorization header for the upstream before the log
    phase runs. The cookie is what actually authorised the request, so it wins.
    """
    if not raw or raw == "none":
        return "none"
    for kind in ("cookie", "apikey", "bearer"):
        if kind in raw:
            return kind
    return raw[:8]


def identity(row: dict) -> str:
    """Who the gateway decided this was.

    `sub` is written by the gateway's own subject extractor before verification, and is
    only meaningful once openid-connect has accepted the token — which it has, for any
    status that is not a 401. "anonymous" is the extractor's value when no bearer token
    was present at all.
    """
    user = row.get("user") or ""
    sub = row.get("sub") or ""
    if user:
        return user
    if sub and sub != "anonymous":
        return sub[:8] + "…"
    return "—"


def pad_quota(row: dict, c: C, width: int = 7) -> str:
    """Pad to width first, then colour — see the note where this is printed."""
    limit, left = row.get("q_limit") or "", row.get("q_left") or ""
    if not limit:
        return c.dim(f"{'—':<{width}}")
    try:
        left_n, limit_n = int(left), int(limit)
    except ValueError:
        return f"{left}/{limit}".ljust(width)
    text = f"{left_n}/{limit_n}".ljust(width)
    if left_n == 0:
        return c.red(text)
    if left_n <= max(1, limit_n // 5):
        return c.amber(text)
    return text



# ── Main ──────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true",
                    help="include pages, assets and health probes, not just API calls")
    ap.add_argument("--errors", action="store_true",
                    help="also show the gateway's own error log lines")
    ap.add_argument("--filter", metavar="TEXT",
                    help="only show requests whose URI contains TEXT")
    ap.add_argument("--tail", type=int, default=0, metavar="N",
                    help="replay the last N request lines before following (default 0)")
    ap.add_argument("--no-colour", action="store_true", help="plain text output")
    ap.add_argument("--no-legend", action="store_true",
                    help="skip the DOOR legend printed at startup")
    args = ap.parse_args()

    c = C(sys.stdout.isatty() and not args.no_colour and os.environ.get("TERM") != "dumb")

    root = Path(__file__).resolve().parent.parent      # data-plane/
    if not (root / "docker-compose.yml").exists():
        print("Run this from the data-plane directory of the testbed.", file=sys.stderr)
        return 2

    print()
    print(c.bold("  Gateway traffic") + c.dim("   — Ctrl-C to stop"))
    scope = ("everything"
             if args.all else
             "API routes only  ·  add pages, assets and probes with:  make watch ARGS=--all")
    print(c.dim(f"  showing: {scope}"))
    # Say this up front: nginx flushes its access log every three seconds, so a request
    # you have just sent can take that long to appear. Without the warning it reads as
    # a broken watcher.
    print(c.dim("  note:    lines can lag up to 3s — nginx flushes its access log on a timer"))
    print()
    # A legend, because "DOOR" needs one: it names which of the gateway's front doors
    # a request came through, and the whole point of the testbed is that the same data
    # sits behind several of them demanding different credentials.
    if not args.no_legend:
        print(c.dim("  DOOR — which front door, i.e. what credential the route demands:"))
        for name, path, meaning in (
            ("federated", "/api/birds*",        "a federation token — works at every member service"),
            ("operator",  "/local/api/birds*",  "this operator's own API key — federated nowhere"),
            ("session",   "/session/api/birds*","a browser session cookie, for the address bar"),
            ("open",      "/open/api/birds*",   "none — the unprotected comparison"),
            ("web",       "/birds/*  /help/*",  "pages and assets"),
            ("discovery", "/healthz  /openapi.json", "none, and unmetered by design"),
        ):
            print(c.dim(f"    {name:<10} {path:<24} {meaning}"))
        print()

    header = (f"  {'TIME':<8} {'CODE':<4} {'DOOR':<10} {'CRED':<6} {'WHO':<13} "
              f"{'QUOTA':<7} {'ms':>4}  {'REQUEST':<44} VERDICT")
    print(c.dim(header))
    print(c.dim("  " + "─" * (len(header) - 2)))

    cmd = ["docker", "compose", "logs", "-f", "--no-log-prefix",
           "--tail", str(args.tail) if args.tail else "0", "apisix"]
    proc = subprocess.Popen(cmd, cwd=root, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1)

    # Let the child see the interrupt too, so Ctrl-C stops the follow rather than
    # leaving an orphaned docker process attached to the log stream.
    signal.signal(signal.SIGINT, lambda *_: (proc.terminate(), sys.exit(0)))

    # Filtering silently is indistinguishable from being broken: you load a page, see
    # nothing, and cannot tell whether the watcher is working. Count what is hidden and
    # say so, so an empty screen always means "no traffic" and never "wrong flag".
    hidden = 0
    hidden_reported = 0
    last_note = 0.0

    def note_hidden(force: bool = False) -> None:
        nonlocal hidden_reported, last_note
        now = time.monotonic()
        if hidden == hidden_reported:
            return
        if not force and now - last_note < 1.5:
            return
        n = hidden - hidden_reported
        what = "request" if n == 1 else "requests"
        print(c.dim(f"  … {n} non-API {what} hidden (a page, an asset or a probe) "
                    f"— show with:  make watch ARGS=--all"))
        sys.stdout.flush()
        hidden_reported, last_note = hidden, now

    try:
        for line in proc.stdout:
            line = line.strip()
            note_hidden()
            if not line:
                continue

            if not line.startswith("{"):
                if args.errors and any(k in line for k in ("[error]", "[warn]", "[emerg]")):
                    print("  " + c.mag(line[:200]))
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            uri = row.get("uri", "")
            if not args.all and not is_api(uri):
                hidden += 1
                note_hidden()
                continue
            if args.filter and args.filter not in uri:
                continue

            status = int(row.get("status", 0))
            name, _ = door(uri)
            when = (row.get("t") or "")[11:19]
            millis = int(float(row.get("rt") or 0) * 1000)

            # Pad before colouring: escape sequences count towards a format width but
            # occupy no columns, so padding a coloured string misaligns the table.
            print(f"  {c.dim(f'{when:<8}')}"
                  f" {colour_status(status, c)}"
                  f" {name:<10}"
                  f" {cred_label(row.get('cred') or ''):<6}"
                  f" {identity(row):<13}"
                  f" {pad_quota(row, c):<7}"
                  f" {millis:>4}  "
                  f"{uri[:44]:<44}"
                  f" {verdict(status, row.get('cred') or '', c)}")
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        note_hidden(force=True)
        proc.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

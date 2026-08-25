# A ten-minute walkthrough

Assumes both planes are up. Each step is something you can show someone; the point of
each is stated so you can skip the ones that do not serve the audience in front of you.

**Open a second window first** and leave this running in it:

```bash
cd data-plane && make watch
```

One line per request, showing which front door it came through, which kind of credential
was presented, whose identity the gateway resolved, what the quota did, and the verdict.
Most steps below are considerably more convincing when the audience can watch the gateway
decide.

Two things to know before you wonder whether it is working:

- **It shows API traffic only by default.** Loading a page such as `/birds/` pulls the
  HTML, a script and a stylesheet, which drown the interesting lines. Those are counted
  and reported rather than dropped silently, but to see them use
  `make watch ARGS=--all`.
- **Lines can lag up to three seconds.** nginx flushes its access log on a timer.

---

## 1. The service is closed (20 seconds)

Open the URL from the service's own documentation:

**<https://data.example.org/api/birds?q=finch&limit=3>**

You get a page, not a stack trace: *"You need a credential to read this"*, with the
link to the Federation Portal, the setup command for `oidc-agent`, and the exact
`curl` for the URL
you tried.

Now the same URL from a terminal:

```bash
curl 'https://data.example.org/api/birds?q=finch&limit=3'
```

JSON, and a non-zero exit. Same route, same status code, two audiences.

> **The point.** A gateway that refuses a request has to answer a person and a script
> differently. Content negotiation on the error path is cheap and almost nobody does it.

---

## 2. Register through GitHub (2 minutes)

Open the **Federation Portal** — <https://identity.example.org/portal/> — and choose
*Continue with GitHub*.

There is no password field anywhere. There is no "create an account" form. You are sent
straight to GitHub — the login form is never shown, because no account in this realm
could satisfy it.

Come back and you have a registration: your GitHub login, your email, the subject
identifier that will appear in every token.

> **The point.** MeteoGate already brokers social identity; this is that, working. Note
> what is *missing*: no verified affiliation, no assurance level, no way for an institute
> to revoke this. That gap is the whole subject of the brokering review.

---

## 3. Use it from the browser (1 minute)

**<https://data.example.org/birds/>** → *Sign in* → *Go*.

Birds. Note the quota pips in the toolbar counting down from 5.

Open the *"What this page is actually doing"* section at the bottom.

> **The point.** Every request on that page — including each illustration — is
> `fetch()` with the header attached in JavaScript, because `<img src>` sends no
> `Authorization` header. That is not a workaround; it is the constraint that makes a
> web client or a gateway session necessary in the first place.

---

## 4. Exhaust the quota (30 seconds)

Press **Go** six times.

The sixth gives you a panel: quota exhausted, how many seconds until the window resets,
and the fact that quotas are counted per credential at each service. The number of
seconds is read off the response headers, not guessed.

Or from a terminal:

```bash
cd data-plane && ./scripts/burn-quota.sh
```

Then open the same URL in a browser to see the HTML version of the same refusal.

> **The point.** The gateway does policy the service knows nothing about. The birds
> service has no idea there is a quota.

---

## 5. The terminal, via device flow (2 minutes)

```bash
fed-login
```

A short code, a URL, and a QR rendered in the terminal. Scan it with a phone — a
different device entirely, on the tailnet — approve, and the terminal has a credential.

```bash
fed-curl 'https://data.example.org/api/birds?q=kingfisher&limit=2'
fed-token --status
```

> **The point.** This is the grant the brokering review identifies as the only one that gives a command line a
> brokered identity. The browser leg is an ordinary authorization code flow, so it goes
> through GitHub — and would go through an institutional IdP with no change to the CLI.
>
> **Use `fed-login` for the demo, not for real work.** It exists to make RFC 8628 legible
> — you can read the whole grant in about eighty lines. For anyone actually using the
> federation, recommend `oidc-agent`, which is installed alongside and does the same
> thing without leaving a refresh token in a file:
>
> ```bash
> curl --oauth2-bearer "$(oidc-token meteogate)" \
>   'https://data.example.org/api/birds?q=finch&limit=3'
> ```
>
> Worth showing both back to back — the gateway cannot tell them apart.
>
> **Also point at the consent screen.** It is required even though this is a first-party
> client, because the only thing separating a device-code phishing attack from legitimate
> use is that the victim did not start the session. The screen has to make that
> answerable.

---

## 6. Paste a URL into the address bar (1 minute)

Open **<https://data.example.org/session/api/birds?q=finch&limit=3>**

You get bird JSON in the browser, from a URL you simply typed. No header, no token, no
web client, no extension.

**If it appeared instantly, that is the demonstration succeeding, not failing.** The
gateway did send you to Keycloak, on to GitHub and back — but a browser already signed
in to GitHub completes every hop without stopping, so there is nothing to watch. Four
redirects, well under a second.

To see that it really happened, open the browser's network panel with *Preserve log*
enabled and reload:

```
gateway/session/api/birds…      302 →  Keycloak authorisation endpoint
identity/realms/…/auth           303 →  Keycloak's GitHub broker
identity/realms/…/broker/github  303 →  github.com/login/oauth/authorize
github.com/…                 302 →  back to Keycloak, then to gateway/session/callback
gateway/session/api/birds…      200     the JSON
```

To see the sign-in screens themselves you need a browser with no GitHub session at all.
**A new Chrome incognito window will not give you one:** every incognito window shares a
single session until you close all of them. Close the lot, or use a different browser,
or sign out of GitHub first.

Ending the gateway session alone is easier, and is a demonstration in itself:

**<https://data.example.org/session/logout>**

That drops the cookie and signs you out of Keycloak too, returning you to the web client.
Reload the session URL afterwards and the redirect chain runs again — still without
stopping, because your GitHub session is untouched. Three separate sessions are in play
here: the gateway's cookie, Keycloak's, and GitHub's, and they end independently.

Now paste the other session URL — an illustration, which needs no client either:

**<https://data.example.org/session/api/birds/21/image?pose=p>**

A PNG, in the address bar, from a protected route. The session cookie carries it.

> **The point.** This is the correction set out in the device-flow note, implemented:
> authorization code with PKCE and a session cookie, run by the gateway. It is why no
> `?token=` query parameter is offered — tokens in URLs end up in server logs, browser
> history and `Referer` headers, and this costs nothing by comparison.
>
> Note what the gateway is doing here that the web client in step 3 cannot: the
> credential is a cookie, so the *browser* attaches it to a plain navigation. That is the
> one thing a header-based token can never do.

---

## 7. The operator's own key (30 seconds)

In the web client, switch the credential toggle to **API key** and paste the value of
`LOCAL_API_KEY_ACME` from `data-plane/.env`.

Or:

```bash
curl -H "apikey: $LOCAL_API_KEY_ACME" \
  'https://data.example.org/local/api/birds?q=finch&limit=3'
```

> **The point.** Joining a federation does not mean surrendering control. This operator
> still issues and manages their own keys, on their own terms, with their own quotas —
> 5/minute for one partner, 120/minute for another — alongside the federated route to
> exactly the same data.

---

## 8. The credential lifecycle (2 minutes)

Back at the **Federation Portal** — <https://identity.example.org/portal/> —
where you registered in step 2:

- **Create credential** → a client id and secret, shown once. The
  `client_credentials` path, for unattended jobs.
- **Rotate secret** → the old one stops working immediately.
- **Revoke all grants** → kills the offline token `fed-login` created. Try
  `fed-curl` again: *"credential rejected. Run fed-login."*
- **Delete my registration** → account and credential both gone. Register again
  through GitHub and you are a new subject with a new quota.

Then, on the control-plane host:

```bash
cd control-plane && make audit
```

> **The point.** The brokering review calls client-secret lifecycle the most urgent surviving
> concern: a secret decoupled from the identity that created it never dies. Here every
> secret has a recorded owner, an expiry, and a sweep that enforces it — and it dies with
> the registration.
>
> **Be honest about the limit.** If the owner's GitHub account is disabled tomorrow,
> Keycloak never finds out. The 7-day offline session maximum is the only backstop, and
> it is set deliberately for that reason.

---

## 9. The centre is not in the path (1 minute)

The closing argument, and the one that matters most.

```bash
# On the control-plane host — take the entire control plane down.
cd control-plane && docker compose stop keycloak
```

Now, on any device:

```bash
fed-curl 'https://data.example.org/api/birds?q=finch&limit=3'
```

It still works. The gateway downloaded the federation's public signing keys once and
validates every token itself. No request consults the centre.

What *does* break: getting a **new** token. Once the current access token expires, the
refresh fails — because that is a control-plane operation, and correctly so.

```bash
docker compose start keycloak
```

> **The point.** This is the architecture in one command. The centre issues identity;
> it does not stand between users and data. Twenty-nine more services would each hold
> their own cached copy of the same public keys, and the centre's load would not change.

---

## What to say if someone asks "so is this ready?"

No, and `docs/architecture.md` section 9 says why in more detail. The short version:
one service rather than thirty, GitHub rather than institutional IdPs, an attribute
authority that is a placeholder, no assurance framework, and deprovisioning that is
still unsolved on the social path — which is exactly the argument the brokering review makes.

What it does establish is that the *shape* is right: local JWKS validation, a direct
data plane, a distributable gateway package, and a configuration layer an operator can
actually read.

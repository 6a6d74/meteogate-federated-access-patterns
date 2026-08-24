# Two CLI clients, one realm

The testbed carries two ways to get a federation credential at a terminal. They are
installed side by side so the difference can be demonstrated rather than asserted.

```bash
# the recommended client
curl --oauth2-bearer "$(oidc-token meteogate)" \
  'https://data.example.org/api/birds?q=finch&limit=3'

# the bundled demonstration scripts
fed-curl 'https://data.example.org/api/birds?q=finch&limit=3'
```

Both produce a `200`. Both tokens carry the same `sub`, the same `azp`
(`federation-cli`), and the same `aud` (`federation-services`). Verified:

```
  oidc-agent  sub=dffebacd  azp=federation-cli  status=200
  bespoke     sub=dffebacd  azp=federation-cli  status=200
```

The realm cannot tell them apart, and neither can the gateway. **Everything that
differs is on the client side.**

---

## What actually differs

| | `fed-login` / `fed-curl` | `oidc-agent` |
|---|---|---|
| Origin | Written for this testbed — four short shell scripts, a few hundred lines in total | Karlsruhe Institute of Technology / INDIGO-DataCloud, v5.3.6, MIT |
| Install | `./cli/install.sh` — symlinks, no dependencies | Homebrew, or a package on Linux |
| Token at rest | **Plaintext** in `~/.federation/refresh`, mode 600 | **Encrypted**, unlocked into an agent |
| Token handed out via | Reading the file | Agent socket, on the `ssh-agent` model |
| Survives reboot | Yes, unattended | Yes, but the account must be reloaded |
| Readable in one sitting | Yes — that is why it exists | No |
| Used elsewhere | Nowhere | EGI, EOSC — users may already have it |

The storage row is the one that matters, and it is the reason the device-flow note
recommends evaluating `oidc-agent` **before** building anything bespoke. A refresh
token in a file is a long-lived bearer credential readable by anything running as you.
The agent model does not eliminate that risk — the agent can still be asked for a token
by anything running as you — but it removes the token from disk in the clear, and gives
it a lifetime bounded by the agent process rather than by the filesystem.

## Why the bespoke scripts still exist here

Not because they are better. Because a testbed's job is to make a mechanism legible, and
`fed-login` implements RFC 8628 in about eighty readable lines: the device authorization
request, the `authorization_pending` and `slow_down` polling states, the QR rendered by
the control plane so the CLI needs no QR library, and the offline token written to disk.
`oidc-agent` does all of that better and none of it visibly.

Keep both for demonstrating; recommend `oidc-agent` for anyone actually using the
federation.

---

## Setup

```bash
./cli/oidc-agent-setup.sh            # install, start the agent, register the account
./cli/oidc-agent-setup.sh --status   # what is installed, running and loaded
./cli/oidc-agent-setup.sh --reload   # after a reboot
```

Registration runs the same device flow as `fed-login`, against the same public client,
so you approve a code in a browser exactly as before.

### Three things that cost time, recorded so they do not cost it twice

**The default prompter on macOS is a GUI window.** It ignores stdin, so a scripted
`oidc-add` does not fail — it hangs indefinitely on a dialog you may not have noticed
opening. `--pw-prompt=cli` is what makes unattended loading work.

**`--pw-cmd` did not take effect for `oidc-add`** in 5.3.6, though it is documented and
does work for `oidc-gen`. `--pw-file` works. The setup script uses the file form.

**`oidc-agent-service use` starts its own agent** on a socket under a temp directory. If
the launchd service is already running, you now have two agents, and an account loaded
into one is invisible to the other. This setup uses a single agent at a fixed path
(`~/Library/Caches/oidc-agent/oidc-agent.sock`) started by `brew services`, with
`OIDC_SOCK` exported from `~/.zshenv` — *not* `~/.zshrc`, which zsh reads only for
interactive shells, so a script or a cron job would never see it.

### The encryption password

`oidc-gen` encrypts the stored account config with a password. The setup script
generates one into `~/.federation/oidc-agent-pw` (mode 600) so that reloading after a
reboot is unattended.

That is a deliberate trade and worth naming: it converts "encrypted at rest, unlocked by
something you know" into "encrypted at rest, unlocked by a file sitting next to it".
Against an attacker who can read your home directory it buys nothing over the bespoke
scripts. Against casual disclosure — a backup, a synced folder, a shared screen — it
still helps. For a testbed that must come back up without a human, it is the right
choice; for a real user, delete that file and type the password.

#!/usr/bin/env bash
#
# Set up oidc-agent (KIT) against the federation realm, alongside the bespoke scripts.
#
# The device-flow note recommends evaluating oidc-agent before building bespoke
# CLI tooling. This script is that evaluation made repeatable. Both clients end up
# talking to the same realm, the same public client, and the same user — the difference
# is entirely in how the credential is stored:
#
#   fed-login   refresh token in ~/.federation/refresh, plaintext, mode 600
#   oidc-agent  encrypted at rest, handed out over an agent socket (the ssh-agent model)
#
# Usage:
#   ./oidc-agent-setup.sh            install, start the agent, register the account
#   ./oidc-agent-setup.sh --reload   reload the account after a reboot or agent restart
#   ./oidc-agent-setup.sh --status   what is installed, running and loaded
#
set -uo pipefail

ACCOUNT="${OIDC_ACCOUNT:-meteogate}"
ISSUER="${FED_ISSUER:-https://identity.example.org/realms/federation}"
CLIENT="${FED_CLIENT_ID:-federation-cli}"
SCOPE="${FED_SCOPE:-openid profile email offline_access}"

STATE_DIR="${FED_HOME:-$HOME/.federation}"
PW_FILE="$STATE_DIR/oidc-agent-pw"
SOCK="$HOME/Library/Caches/oidc-agent/oidc-agent.sock"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "This script assumes macOS. On Linux, install
oidc-agent from your package manager and use oidc-agent-service instead of brew services."

export OIDC_SOCK="$SOCK"

# ---------------------------------------------------------------------------
# Load the account into a running agent, without any interactive prompt.
#
# Two flags matter and both are easy to get wrong:
#   --pw-file    supplies the encryption password (--pw-cmd is documented but did not
#                take effect here; the file form does)
#   --pw-prompt=cli
#                oidc-agent's default prompter on macOS is a GUI window. It ignores
#                stdin, so a scripted load hangs forever on an invisible dialog rather
#                than failing. Forcing cli is what makes this usable unattended.
# ---------------------------------------------------------------------------
load_account() {
  [[ -f "$PW_FILE" ]] || die "No password file at $PW_FILE — run without --reload first."
  oidc-add "$ACCOUNT" --pw-file="$PW_FILE" --pw-prompt=cli
}

status() {
  printf '\n\033[1moidc-agent\033[0m\n'
  printf '  binary       %s\n' "$(command -v oidc-token || echo 'NOT INSTALLED')"
  printf '  socket       %s\n' "$([[ -S $SOCK ]] && echo "$SOCK" || echo 'not present')"
  printf '  daemon       %s\n' "$(pgrep -f 'oidc-agent -a' >/dev/null && echo running || echo 'not running')"
  printf '  account      %s\n' "$([[ -f "$HOME/.config/oidc-agent/$ACCOUNT" ]] && echo "$ACCOUNT configured" || echo 'not configured')"
  if oidc-token "$ACCOUNT" </dev/null >/dev/null 2>&1; then
    printf '  loaded       yes — oidc-token works\n'
  else
    printf '  loaded       no — run: %s --reload\n' "$0"
  fi
  printf '\n\033[1mbespoke CLI\033[0m\n'
  printf '  credential   %s\n' "$([[ -f "$STATE_DIR/refresh" ]] && echo "$STATE_DIR/refresh" || echo 'not logged in')"
  echo
}

case "${1:-}" in
  --status) status; exit 0 ;;
  --reload) say "Reloading $ACCOUNT"; load_account && status; exit $? ;;
  "")       ;;
  *)        die "unknown option: $1" ;;
esac

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
if ! command -v oidc-gen >/dev/null; then
  command -v brew >/dev/null || die "Homebrew is required to install oidc-agent."
  say "Installing oidc-agent from the upstream tap (indigo-dc)"
  brew tap indigo-dc/oidc-agent
  # Homebrew gates third-party taps behind an explicit trust decision. This is the
  # project's own tap — github.com/indigo-dc/homebrew-oidc-agent — and the formula
  # builds github.com/indigo-dc/oidc-agent, which is the tool the architecture note
  # names. Verify that yourself before running this if you would rather not take it
  # on trust.
  brew trust indigo-dc/oidc-agent
  brew install oidc-agent || die "oidc-agent install failed."
fi
say "oidc-agent $(oidc-gen --version 2>&1 | awk '{print $2}') present"

# ---------------------------------------------------------------------------
# Daemon
#
# One agent, at a predictable path, started by launchd. `oidc-agent-service use` is the
# upstream alternative, but it starts an agent on a temp-directory socket — which is how
# you end up with an account loaded into an agent that nothing else is talking to.
# ---------------------------------------------------------------------------
if ! pgrep -f 'oidc-agent -a' >/dev/null; then
  say "Starting the agent as a launchd service"
  brew services start oidc-agent >/dev/null || die "Could not start oidc-agent."
  for _ in $(seq 1 20); do [[ -S "$SOCK" ]] && break; sleep 1; done
fi
[[ -S "$SOCK" ]] || die "Agent socket never appeared at $SOCK"
say "Agent listening on $SOCK"

# OIDC_SOCK must be exported for every shell, not just interactive ones — a script or a
# cron job reads .zshenv, never .zshrc.
if ! grep -q OIDC_SOCK "$HOME/.zshenv" 2>/dev/null; then
  say "Exporting OIDC_SOCK from ~/.zshenv"
  cat >> "$HOME/.zshenv" <<EOF

# oidc-agent socket. In .zshenv rather than .zshrc: zsh reads .zshrc only for
# INTERACTIVE shells, so a script would not find the agent.
export OIDC_SOCK="$SOCK"
EOF
fi

# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
if [[ -f "$HOME/.config/oidc-agent/$ACCOUNT" ]]; then
  say "Account '$ACCOUNT' already configured — loading it"
  load_account && status
  exit 0
fi

umask 077
mkdir -p "$STATE_DIR"
[[ -f "$PW_FILE" ]] || openssl rand -base64 24 > "$PW_FILE"
chmod 600 "$PW_FILE"

say "Registering '$ACCOUNT' against $ISSUER"
echo
warn "This runs the device flow: a code will be printed for you to approve in a browser."
warn "Approve it only because you started it here."
echo

# --manual because federation-cli is already registered in the realm; without it,
# oidc-gen attempts dynamic client registration, which Keycloak will refuse.
oidc-gen "$ACCOUNT" \
  --manual \
  --iss="$ISSUER" \
  --client-id="$CLIENT" \
  --client-secret="" \
  --scope="$SCOPE" \
  --flow=device \
  --pw-cmd="cat $PW_FILE" \
  --confirm-yes || die "oidc-gen failed."

status

cat <<EOF
Use it exactly as you would the bespoke CLI:

  curl --oauth2-bearer "\$(oidc-token $ACCOUNT)" \\
    'https://data.example.org/api/birds?q=finch&limit=3'

After a reboot the agent restarts empty. Reload with:

  $0 --reload

EOF

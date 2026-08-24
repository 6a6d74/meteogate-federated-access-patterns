#!/usr/bin/env bash
#
# Push the control plane to the control-plane host and bring it up.
#
# The control plane runs on a different machine from the data plane deliberately — the
# whole architecture rests on the two being separable, and running them on one host
# would let a mistake go unnoticed. This script is the only thing that crosses between
# them, and it crosses over SSH, not at runtime.
#
# Everything it does is idempotent. Run it again after editing anything under
# control-plane/ and it syncs, rebuilds what changed, and re-applies the realm config.
#
# Usage:
#   deploy-control-plane.sh                 sync, build, start, bootstrap
#   deploy-control-plane.sh --sync-only     just copy the files
#   deploy-control-plane.sh --logs          follow the logs afterwards

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
local_dir="$here/control-plane"

# The remote account is not necessarily the local one, so read it from .env rather
# than assuming $USER — an assumption that fails with a bare "Permission denied" and
# no hint that the username was the problem.
if [[ -f "$local_dir/.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "$local_dir/.env"; set +a
fi

REMOTE_HOST="${CONTROL_SSH_HOST:-${CONTROL_HOST:-identity.example.org}}"
REMOTE_USER="${CONTROL_SSH_USER:-$USER}"
REMOTE_DIR="${CONTROL_REMOTE_DIR:-~/federation-control-plane}"

SYNC_ONLY=0
FOLLOW_LOGS=0
for arg in "$@"; do
  case "$arg" in
    --sync-only) SYNC_ONLY=1 ;;
    --logs)      FOLLOW_LOGS=1 ;;
    -h|--help)   sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# A login shell, deliberately. `ssh host "cmd"` runs a NON-login shell, which on macOS
# skips /etc/zprofile and therefore path_helper — so /usr/local/bin is missing and Docker
# Desktop's CLI appears not to be installed at all. The failure looks like a missing
# dependency rather than a PATH problem, which costs time every single occasion.
remote() { ssh -o ConnectTimeout=10 "${REMOTE_USER}@${REMOTE_HOST}" "zsh -lc $(printf '%q' "$*")"; }

# ── Preflight ─────────────────────────────────────────────────────────────────────
say "Checking $REMOTE_HOST..."
if ! remote true 2>/dev/null; then
  # Three distinct failures all surface as the same "Permission denied" line, so
  # separate them here rather than making the next person bisect it.
  detail=$(ssh -v -o BatchMode=yes -o ConnectTimeout=10 \
             "${REMOTE_USER}@${REMOTE_HOST}" true 2>&1 || true)

  if grep -q "Server accepts key" <<<"$detail"; then
    die "SSH to ${REMOTE_USER}@${REMOTE_HOST} failed, but the key WAS accepted.

That means the private key is passphrase-protected and not loaded in the agent.
Load it once — the passphrase is then remembered in the keychain:

  ssh-add --apple-use-keychain ~/.ssh/id_ed25519      # macOS
  ssh-add ~/.ssh/id_ed25519                           # elsewhere"
  fi

  die "Cannot SSH to ${REMOTE_USER}@${REMOTE_HOST}.

Check the account name first — CONTROL_SSH_USER in control-plane/.env is
'${REMOTE_USER}', and it need not match your local username.

Then authorise this machine's key, logged in as that account on the remote host:

  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  echo '$(cat ~/.ssh/id_ed25519.pub 2>/dev/null || echo '<your public key>')' >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys && chmod go-w ~

Remote Login must be on (System Settings → General → Sharing). If it is limited to
specific users, add the account:

  sudo dseditgroup -o edit -a ${REMOTE_USER} -t user com.apple.access_ssh"
fi

remote 'command -v docker >/dev/null' \
  || die "docker is not on PATH on $REMOTE_HOST, even in a login shell. Install Docker Desktop."
remote 'docker compose version >/dev/null 2>&1' \
  || die "docker compose v2 is not available on $REMOTE_HOST."

# Docker Desktop on macOS is a GUI app: the CLI can be present while the daemon is not
# running. Start it and wait, rather than failing with advice the script could act on.
if ! remote 'docker info >/dev/null 2>&1'; then
  say "Docker daemon is not running on $REMOTE_HOST — starting Docker Desktop"
  remote 'open -a Docker' || die "Could not launch Docker Desktop on $REMOTE_HOST."
  for attempt in $(seq 1 40); do
    remote 'docker info >/dev/null 2>&1' && break
    [[ $attempt -eq 40 ]] && die "Docker daemon did not come up on $REMOTE_HOST within 200s."
    sleep 5
  done
  say "Docker daemon is up."
fi

[[ -f "$local_dir/.env" ]] || die "No control-plane/.env. Run: (cd control-plane && make secrets)"

# The remote .env is authoritative for the deployment, but the local one is where it is
# edited, so it is synced. Warn if GitHub is still unset — everything else will come up,
# but nobody will be able to register.
if grep -qE '^GITHUB_CLIENT_ID=\s*$' "$local_dir/.env"; then
  warn "GITHUB_CLIENT_ID is empty in control-plane/.env — registration will not work."
  warn "Fill it in and re-run this script (or just 'make bootstrap' on the control-plane host) when ready."
fi

# ── Sync ──────────────────────────────────────────────────────────────────────────
say "Syncing to ${REMOTE_HOST}:${REMOTE_DIR}"
remote "mkdir -p ${REMOTE_DIR}"

# --delete keeps the remote a faithful copy, but certs/ is generated on the control-plane host (the
# Tailscale certificate is issued for the remote host's own name, and can only be requested
# there) so it must survive the sync.
rsync -az --delete \
  --exclude '.git' \
  --exclude 'certs/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  "$local_dir/" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

remote "chmod +x ${REMOTE_DIR}/scripts/*.sh ${REMOTE_DIR}/keycloak/*.sh"

if [[ $SYNC_ONLY -eq 1 ]]; then
  say "Synced. Nothing started (--sync-only)."
  exit 0
fi

# ── Build and start ───────────────────────────────────────────────────────────────
say "Building and starting on $REMOTE_HOST (this takes a few minutes the first time)"
remote "cd ${REMOTE_DIR} && make up"

# ── Verify from here, over the tailnet, exactly as a user would ───────────────────
say "Verifying from this machine"
control_host=$(grep -E '^CONTROL_HOST=' "$local_dir/.env" | cut -d= -f2)
realm=$(grep -E '^KC_REALM=' "$local_dir/.env" | cut -d= -f2)

for attempt in $(seq 1 30); do
  if curl -sf --max-time 5 \
       "https://${control_host}/realms/${realm}/.well-known/openid-configuration" >/dev/null; then
    break
  fi
  if [[ $attempt -eq 30 ]]; then
    # Distinguish "not up" from "up but the TLS certificate is not acceptable" —
    # they look identical through curl's exit code and waste a lot of time.
    tls_error=$(curl -sS -o /dev/null --max-time 5 \
      "https://${control_host}/realms/${realm}/.well-known/openid-configuration" 2>&1 || true)
    if grep -qi "certificate" <<<"$tls_error"; then
      die "The control plane is answering, but its TLS certificate is not acceptable:
  ${tls_error}

On this host the certificate belongs to the reverse proxy, not to this stack. Renew it
there. For a tailnet name that means \`tailscale cert\`, which cannot use ACME because
the host is not reachable from the public internet."
    fi
    die "Discovery document never became reachable at https://${control_host}"
  fi
  sleep 3
done

# curl fetches, python only parses. A framework Python on macOS often has no CA
# bundle of its own, so urllib fails to verify a perfectly valid certificate — a
# confusing way for a successful deployment to report failure.
curl -sf --max-time 10 \
  "https://${control_host}/realms/${realm}/.well-known/openid-configuration" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
print("\n  issuer            ", doc["issuer"])
print("  authorization     ", doc["authorization_endpoint"])
print("  token             ", doc["token_endpoint"])
print("  device            ", doc.get("device_authorization_endpoint", "MISSING"))
print("  jwks              ", doc["jwks_uri"])
grants = doc.get("grant_types_supported", [])
device = "urn:ietf:params:oauth:grant-type:device_code"
print("  device grant      ", "advertised" if device in grants else "NOT ADVERTISED")
print()
'

say "Control plane is up."
portal_path=$(grep -E '^PORTAL_PATH=' "$local_dir/.env" | cut -d= -f2)
echo "  Portal        https://${control_host}${portal_path:-/}"
echo "  Admin console https://${control_host}/admin/"
echo

if [[ $FOLLOW_LOGS -eq 1 ]]; then
  remote "cd ${REMOTE_DIR} && docker compose logs -f"
fi

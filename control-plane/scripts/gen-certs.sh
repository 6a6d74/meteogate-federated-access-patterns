#!/usr/bin/env bash
# Ensure certs/server.crt and certs/server.key exist for Traefik to terminate TLS with.
#
#   1. `tailscale cert`  — a real Let's Encrypt certificate for a ts.net hostname.
#                          Publicly trusted, so clients need no CA installed. This
#                          matters more than usual here: Keycloak's issuer URL ends up
#                          in every token, and curl must trust it without -k.
#   2. self-signed       — fallback only. Browsers warn, and the CLI needs --insecure.
#
# Pass --force to reissue. Let's Encrypt certificates last 90 days.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
certs="$root/certs"
mkdir -p "$certs"

if [[ -f "$root/.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "$root/.env"; set +a
fi
host="${CONTROL_HOST:-localhost}"

if [[ -f "$certs/server.crt" && -f "$certs/server.key" && "${1:-}" != "--force" ]]; then
  expires="$(openssl x509 -in "$certs/server.crt" -noout -enddate | cut -d= -f2)"
  echo "Certificate already present in $certs (expires $expires). Use --force to reissue."
  exit 0
fi

tailscale_bin=""
for candidate in "$(command -v tailscale 2>/dev/null || true)" \
                 /Applications/Tailscale.app/Contents/MacOS/Tailscale \
                 /usr/bin/tailscale; do
  [[ -n "$candidate" && -x "$candidate" ]] && { tailscale_bin="$candidate"; break; }
done

if [[ -n "$tailscale_bin" && "$host" == *.ts.net ]]; then
  echo "Requesting a Let's Encrypt certificate for $host via Tailscale..."
  # Written via stdout rather than by passing --cert-file/--key-file paths.
  #
  # On macOS the Tailscale CLI is sandboxed, and when it is spawned from an SSH session
  # it cannot create files in an arbitrary directory — it fails with "operation not
  # permitted" on its own temp file, which reads like a permissions bug in this script
  # rather than a sandbox restriction. Taking the PEM on stdout and splitting it here
  # keeps all file creation in this script, where it is allowed.
  #
  # Output order is the certificate chain first, then the private key.
  bundle="$("$tailscale_bin" cert --cert-file - --key-file - "$host")" || {
    echo "tailscale cert failed for $host" >&2
    exit 1
  }
  # Plain substring match: macOS ships BWK awk, which rejects the empty alternative in
  # an ERE like (RSA |EC |). This covers RSA, EC and PKCS#8 headers alike.
  printf '%s\n' "$bundle" | awk '
    index($0, "PRIVATE KEY-----") { inkey = 1 }
    inkey { print > keyfile; next }
          { print > crtfile }
  ' keyfile="$certs/server.key" crtfile="$certs/server.crt"

  # A silent half-write here would surface much later as a TLS handshake failure.
  openssl x509 -in "$certs/server.crt" -noout -subject >/dev/null 2>&1 \
    || { echo "certificate did not parse — refusing to continue" >&2; exit 1; }
  openssl pkey -in "$certs/server.key" -noout >/dev/null 2>&1 \
    || { echo "private key did not parse — refusing to continue" >&2; exit 1; }
else
  echo "Tailscale unavailable, or $host is not a ts.net name — falling back to self-signed."
  echo "Browsers will warn, and the CLI scripts will need FED_INSECURE=1."
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$certs/server.key" -out "$certs/server.crt" -days 825 \
    -subj "/CN=$host/O=Federation testbed" \
    -addext "subjectAltName=DNS:$host,DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null
fi

chmod 644 "$certs/server.crt"
chmod 600 "$certs/server.key"
echo "Certificate for $host written to $certs."

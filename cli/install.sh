#!/usr/bin/env bash
# Symlink the federation CLI into a directory on PATH.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${1:-$HOME/.local/bin}"
mkdir -p "$target"

for tool in fed-login fed-token fed-curl fed-logout; do
  chmod +x "$here/$tool"
  ln -sf "$here/$tool" "$target/$tool"
  echo "  $target/$tool -> $here/$tool"
done

echo
case ":$PATH:" in
  *":$target:"*) echo "$target is on PATH." ;;
  *) echo "Add $target to PATH:  export PATH=\"$target:\$PATH\"" ;;
esac

#!/usr/bin/env bash
# Deploy site sources to CroviaTrust-1 over SSH (tar stream, atomic per file, backup of overwritten files).
#
#   site/deploy.sh                  # deploy everything under site/ (except this script and README)
#   site/deploy.sh registry/tacet   # deploy one subtree
#
# Requires: CROVIA_SSH (a command that opens an ssh session to the host, e.g. the helper used by the
# operator: `ssh -i key user@host`), sudo NOPASSWD on the host. Mapping:
#   site/index.html, site/assets/**   -> /var/www/crovia/...
#   site/registry/**                  -> /var/www/registry/...
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SSH="${CROVIA_SSH:-/tmp/crovia-secrets/ssh.sh}"
SUB="${1:-.}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

cd "$HERE"
tar --exclude='deploy.sh' --exclude='README.md' -cf - "$SUB" | $SSH "cat > /tmp/site-$STAMP.tar"
$SSH "sudo bash -s $STAMP" <<'REMOTE'
set -euo pipefail
STAMP="$1"
TMP="$(mktemp -d /tmp/site-deploy.XXXXXX)"
tar -xf "/tmp/site-$STAMP.tar" -C "$TMP" && rm -f "/tmp/site-$STAMP.tar"
BK="/opt/crovia/site-backups/$STAMP"; mkdir -p "$BK"
n=0
while IFS= read -r -d '' f; do
  rel="${f#$TMP/}"; rel="${rel#./}"
  case "$rel" in
    registry/*) dest="/var/www/$rel" ;;
    *)          dest="/var/www/crovia/$rel" ;;
  esac
  mkdir -p "$(dirname "$dest")"
  if [ -f "$dest" ] && ! cmp -s "$f" "$dest"; then mkdir -p "$BK/$(dirname "$rel")"; cp -p "$dest" "$BK/$rel"; fi
  install -m 0644 "$f" "$dest.tmp" && mv "$dest.tmp" "$dest"
  n=$((n+1))
done < <(find "$TMP" -type f -print0)
rm -rf "$TMP"
echo "deployed $n files; backups of replaced files in $BK"
REMOTE

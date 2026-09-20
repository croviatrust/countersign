#!/usr/bin/env bash
# Re-publish Crovia's MCP server entry to the official MCP Registry (run on the server as root).
# Auth: HTTP method, domain croviatrust.com; the Ed25519 key lives in /opt/crovia/keys/mcp-registry-auth.pem
# and its public half is served at https://croviatrust.com/.well-known/mcp-registry-auth.
# Bump "version" in server.json before running; the registry rejects duplicate versions.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KEY="${MCP_REGISTRY_KEY:-/opt/crovia/keys/mcp-registry-auth.pem}"
BIN="${MCP_PUBLISHER:-/opt/crovia/bin/mcp-publisher}"
if [ ! -x "$BIN" ]; then
  mkdir -p "$(dirname "$BIN")"
  curl -sL "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_linux_amd64.tar.gz" | tar xz -C "$(dirname "$BIN")" mcp-publisher
fi
PRIV_HEX="$(openssl pkey -in "$KEY" -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')"
cd "$HERE"
"$BIN" validate
"$BIN" login http --domain croviatrust.com --private-key "$PRIV_HEX"
"$BIN" publish

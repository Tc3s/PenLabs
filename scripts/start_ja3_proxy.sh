#!/usr/bin/env bash
set -euo pipefail

LISTEN="${JA3_PROXY_LISTEN:-127.0.0.1:${JA3_PROXY_PORT:-1080}}"
PROFILE="${JA3_PROFILE:-chrome120}"

cd "$(dirname "$0")/.."
exec python3 -m proxy.ja3_proxy --listen "$LISTEN" --profile "$PROFILE"

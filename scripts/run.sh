#!/usr/bin/env bash
# scripts/run.sh - Builds, regenerates fixtures, and runs the SecureFileGuard server.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT"

# Check if running under /mnt/c or other DrvFS mounts
CUR_DIR="$(pwd)"
if [[ "$CUR_DIR" =~ ^/mnt/[a-z] ]]; then
  echo "WARNING: Running on a Windows mount (/mnt/*). Symlinks and FIFOs break or behave differently on DrvFS." >&2
  echo "Please run this project on the native Linux filesystem inside WSL (e.g. ~/SecureFileGuard-Web)." >&2
fi

PORT="${PORT:-8000}"
HOST="${HOST:-127.0.0.1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      PORT="$2"
      shift 2
      ;;
    --host)
      HOST="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: ./scripts/run.sh [--port 8000] [--host 127.0.0.1]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# Check if port is already in use
if ! python3 -c "import socket, sys; s = socket.socket(); (s.bind(('$HOST', int('$PORT'))), s.close())" 2>/dev/null; then
  echo "Error: Port $PORT ($HOST) is already in use." >&2
  echo "Specify a different port (e.g. ./scripts/run.sh --port 8080) or stop the existing service." >&2
  exit 1
fi

echo "==> Building project..."
make

echo "==> Regenerating fixtures..."
bash tools/make_fixtures.sh runtime/fixtures

echo "==> Starting SecureFileGuard server on http://$HOST:$PORT..."
exec python3 server/app.py --host "$HOST" --port "$PORT"

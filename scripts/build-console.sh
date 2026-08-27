#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/console"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to build the console" >&2
  exit 1
fi

npm ci
npm run build

echo "Console built to console/dist"

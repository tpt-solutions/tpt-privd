#!/usr/bin/env bash
# I6: build and run the CapEff before/after harness in Docker (Linux CI).
# Requires: docker, repo root as parent of tpt-privd/ + tpt-linux-sandbox/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(dirname "$ROOT")"
TAG="tpt-privd-caps-harness:local"

if [[ ! -d "$PARENT/tpt-linux-sandbox" ]]; then
  echo "ERROR: expected sibling checkout at $PARENT/tpt-linux-sandbox" >&2
  exit 1
fi

echo "Building $TAG from $PARENT …"
docker build \
  -f "$ROOT/packaging/Dockerfile.caps-harness" \
  -t "$TAG" \
  "$PARENT"

echo "Running caps_probe as root …"
docker run --rm "$TAG"

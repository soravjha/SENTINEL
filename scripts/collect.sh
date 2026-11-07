#!/usr/bin/env sh
# Run a collector once inside the running stack:  ./scripts/collect.sh urlhaus
set -eu
exec docker compose run --rm api python -m app.cli collect "${1:?usage: collect.sh <source>}"

#!/usr/bin/env bash
# Everything CI runs, locally. Run this before pushing.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== format ==";       cargo fmt --all --check
echo "== clippy ==";       cargo clippy --workspace --all-targets -- -D warnings
echo "== test ==";         cargo test --workspace
echo "== layering ==";     ./scripts/check-layering.sh
echo "== supply chain =="; cargo deny check
echo "== msrv (1.88) ==";  cargo +1.88.0 build --workspace
echo
echo "All checks passed."

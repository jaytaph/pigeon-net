#!/usr/bin/env bash
# Enforces the crate layering of docs/pigeonnet-architecture.md §34.1.
#
# These boundaries are not stylistic. `core`, `crypto`, `proto` and `bundle` are
# the crates that must stay pure so that validation is reproducible in a test and
# fuzzable without a network. A stray async or I/O dependency there costs that
# property silently -- nothing fails, the code just stops being testable the way
# the architecture assumes.
set -euo pipefail

fail=0

# crate -> space-separated list of dependencies that must not appear in its tree
check() {
    local crate="$1"; shift
    for banned in "$@"; do
        if cargo tree -p "$crate" -e normal 2>/dev/null | grep -q "^[^a-z]*${banned} v"; then
            echo "FAIL  $crate depends on $banned (architecture §34.1)"
            fail=1
        else
            echo "ok    $crate has no $banned"
        fi
    done
}

# The pure core: no async runtime, no sockets, no filesystem-backed storage.
for c in pigeonnet-core pigeonnet-crypto pigeonnet-proto pigeonnet-bundle; do
    check "$c" tokio rusqlite anyhow
done

# The node core reaches transports through a trait, never through tokio types.
check pigeonnet-node tokio anyhow

# anyhow is permitted in nodectl only (§34.2).
check pigeonnet-store anyhow
check pigeonnet-net anyhow

if [ "$fail" -ne 0 ]; then
    echo
    echo "Crate layering violated. See docs/pigeonnet-architecture.md §34.1."
    exit 1
fi
echo
echo "Layering intact."

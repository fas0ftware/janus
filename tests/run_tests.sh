#!/usr/bin/env bash
# Test runner for Janus.
# For now it only checks that the binary runs. Later milestones will
# start local listeners (nc / python3 http.server) and verify scan results.

set -euo pipefail

BINARY="./janus"
failures=0

check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "PASS: $name"
    else
        echo "FAIL: $name (expected '$expected', got '$actual')"
        failures=$((failures + 1))
    fi
}

check "binary prints its name" "Janus" "$("$BINARY")"

if [[ $failures -gt 0 ]]; then
    echo "$failures test(s) failed"
    exit 1
fi
echo "All tests passed"

#!/usr/bin/env bash
# Test runner for Janus.
# Starts a local listener with python3 http.server, then checks that
# Janus reports the listening port as open and an unused port as closed.

set -euo pipefail

BINARY="./janus"
HOST="127.0.0.1"
OPEN_PORT=47800    # a listener is started here
CLOSED_PORT=47801  # nothing listens here
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

# Start the listener in the background and always stop it on exit.
python3 -m http.server "$OPEN_PORT" --bind "$HOST" >/dev/null 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT

# Wait (max ~2 seconds) until the listener accepts connections.
for _ in $(seq 20); do
    if (exec 3<>"/dev/tcp/$HOST/$OPEN_PORT") 2>/dev/null; then
        break
    fi
    sleep 0.1
done

check "listening port is open" "$HOST:$OPEN_PORT open" "$("$BINARY" "$HOST" "$OPEN_PORT")"
check "unused port is closed" "$HOST:$CLOSED_PORT closed" "$("$BINARY" "$HOST" "$CLOSED_PORT")"

if [[ $failures -gt 0 ]]; then
    echo "$failures test(s) failed"
    exit 1
fi
echo "All tests passed"

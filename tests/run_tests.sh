#!/usr/bin/env bash
# Test runner for Janus.
# Starts local listeners on 127.0.0.1, runs Janus against them and checks
# the results. Only localhost is ever scanned.

set -uo pipefail

BINARY="${JANUS_BINARY:-./janus}"
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="127.0.0.1"
OPEN_PORT=47800     # http.server listens here
CLOSED_PORT=47801   # nothing listens here
FILTERED_PORT=47810 # full accept queue: SYNs are silently dropped
passed=0
failed=0

pass() { echo "PASS: $1"; passed=$((passed + 1)); }
fail() { echo "FAIL: $1"; failed=$((failed + 1)); }

# expect_exit <name> <expected code> <command...>
expect_exit() {
    local name="$1" expected="$2"
    shift 2
    "$@" >/dev/null 2>&1
    local actual=$?
    if [[ $actual -eq $expected ]]; then pass "$name"; else fail "$name (exit $actual, expected $expected)"; fi
}

# expect_output <name> <grep -E pattern> <command...>
expect_output() {
    local name="$1" pattern="$2"
    shift 2
    local output
    output="$("$@" 2>&1)"
    if grep -qE -- "$pattern" <<<"$output"; then
        pass "$name"
    else
        fail "$name (pattern '$pattern' not found)"
        sed 's/^/    | /' <<<"$output"
    fi
}

wait_for_port() {
    for _ in $(seq 30); do
        (exec 3<>"/dev/tcp/$HOST/$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# ---- start listeners --------------------------------------------------------
ready_file="$(mktemp -u)"
python3 -m http.server "$OPEN_PORT" --bind "$HOST" >/dev/null 2>&1 &
server_pid=$!
python3 "$TESTS_DIR/filtered_listener.py" "$FILTERED_PORT" "$ready_file" &
filtered_pid=$!
trap 'kill "$server_pid" "$filtered_pid" 2>/dev/null; rm -f "$ready_file"' EXIT

wait_for_port "$OPEN_PORT" || { echo "listener on $OPEN_PORT did not start"; exit 1; }
for _ in $(seq 30); do [[ -f "$ready_file" ]] && break; sleep 0.1; done

# ---- command-line validation ------------------------------------------------
expect_exit "--help exits with 0" 0 "$BINARY" --help
expect_output "--help shows the authorized-use warning" "Authorized use only" "$BINARY" --help
expect_exit "--version exits with 0" 0 "$BINARY" --version
expect_exit "missing target is a usage error" 2 "$BINARY"
expect_exit "unknown option is a usage error" 2 "$BINARY" -t "$HOST" --bogus
expect_exit "stray argument is a usage error" 2 "$BINARY" -t "$HOST" extra
for bad_ports in 0 65536 99999999999999999999 80-22 abc "1,,2" "," "-5" "80-" "+80" " 80" ""; do
    expect_exit "rejects port spec '$bad_ports'" 2 "$BINARY" -t "$HOST" -p "$bad_ports"
done
for bad_timeout in 0 60001 -1 abc 99999999999999999999 ""; do
    expect_exit "rejects timeout '$bad_timeout'" 2 "$BINARY" -t "$HOST" --timeout "$bad_timeout"
done
for bad_threads in 0 257 -3 x; do
    expect_exit "rejects thread count '$bad_threads'" 2 "$BINARY" -t "$HOST" --threads "$bad_threads"
done
expect_exit "unresolvable host is a scan error" 1 "$BINARY" -t no-such-host.invalid -p 80

# ---- scanning ---------------------------------------------------------------
expect_output "open port is listed" "^$OPEN_PORT/tcp +open" \
    "$BINARY" -t "$HOST" -p "$OPEN_PORT"
expect_output "closed port is counted" "1 port\(s\).*0 open, 1 closed" \
    "$BINARY" -t "$HOST" -p "$CLOSED_PORT"
expect_output "silent port is filtered" "0 open, 0 closed, 1 filtered" \
    "$BINARY" -t "$HOST" -p "$FILTERED_PORT" --timeout 300
# 47801 + 47800-47802 + 47800 -> duplicates removed -> 3 unique ports
expect_output "list and range are combined without duplicates" "3 port\(s\).*1 open, 2 closed" \
    "$BINARY" -t "$HOST" -p "$CLOSED_PORT,$OPEN_PORT-$((OPEN_PORT + 2)),$OPEN_PORT"
expect_output "host names are resolved" "\($HOST\)" "$BINARY" -t localhost -p "$OPEN_PORT"

# ---- summary ----------------------------------------------------------------
echo
echo "$passed passed, $failed failed"
[[ $failed -eq 0 ]]

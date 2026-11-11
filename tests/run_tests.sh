#!/usr/bin/env bash
# Test runner for Janus.
# Starts local listeners on 127.0.0.1, runs Janus against them and checks
# the results. Only localhost is ever scanned.

set -uo pipefail

BINARY="${JANUS_BINARY:-./janus}"
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="127.0.0.1"
# Test ports stay below Linux's ephemeral range (32768-60999 by default).
# Ports in that range are also used as source ports for outgoing
# connections, so a recent full scan can leave one in TIME_WAIT and make
# binding a test listener fail with "Address already in use".
OPEN_PORT=29800     # http.server listens here
CLOSED_PORT=29801   # nothing listens here
FILTERED_PORT=29810 # full accept queue: SYNs are silently dropped
BANNER_PORT=29820   # greets every client with an SSH-style banner
EVIL_PORT=29821     # greets with terminal escape codes
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
python3 "$TESTS_DIR/banner_listener.py" "$HOST" "$BANNER_PORT" 'SSH-2.0-JanusTest_1.0\r\n' &
banner_pid=$!
python3 "$TESTS_DIR/banner_listener.py" "$HOST" "$EVIL_PORT" '\x1b]0;pwned\x07\x1b[2Jowned\r\n' &
evil_pid=$!
v6_pid=""
if python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.bind(("::1", 0))' 2>/dev/null; then
    python3 "$TESTS_DIR/banner_listener.py" "::1" "$BANNER_PORT" 'SSH-2.0-V6\r\n' &
    v6_pid=$!
fi
trap 'kill "$server_pid" "$filtered_pid" "$banner_pid" "$evil_pid" $v6_pid 2>/dev/null; rm -f "$ready_file"' EXIT

wait_for_port "$OPEN_PORT" || { echo "listener on $OPEN_PORT did not start"; exit 1; }
wait_for_port "$BANNER_PORT" || { echo "listener on $BANNER_PORT did not start"; exit 1; }
wait_for_port "$EVIL_PORT" || { echo "listener on $EVIL_PORT did not start"; exit 1; }
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
# 29801 + 29800-29802 + 29800 -> duplicates removed -> 3 unique ports
expect_output "list and range are combined without duplicates" "3 port\(s\).*1 open, 2 closed" \
    "$BINARY" -t "$HOST" -p "$CLOSED_PORT,$OPEN_PORT-$((OPEN_PORT + 2)),$OPEN_PORT"
expect_output "host names are resolved" "\($HOST\)" "$BINARY" -t localhost -p "$OPEN_PORT"

# ---- threads ----------------------------------------------------------------
range="$((OPEN_PORT - 20))-$((OPEN_PORT + 9))" # 30 ports, one of them open
expect_output "1 thread scans the range" "30 port\(s\).*1 open, 29 closed" \
    "$BINARY" -t "$HOST" -p "$range" --threads 1
expect_output "8 threads give the same result" "30 port\(s\).*1 open, 29 closed" \
    "$BINARY" -t "$HOST" -p "$range" --threads 8
expect_output "more threads than ports is fine" "^$OPEN_PORT/tcp +open" \
    "$BINARY" -t "$HOST" -p "$OPEN_PORT" --threads 256

# ---- Ctrl+C and write errors ------------------------------------------------
# The filtered port with a 10 s timeout keeps Janus busy; SIGINT must stop it fast.
"$BINARY" -t "$HOST" -p "$CLOSED_PORT,$FILTERED_PORT" --timeout 10000 --threads 1 --json \
    >"$ready_file.out" 2>/dev/null &
janus_pid=$!
sleep 0.5
kill -INT "$janus_pid"
SECONDS=0
wait "$janus_pid"
interrupt_exit=$?
if [[ $interrupt_exit -eq 130 && $SECONDS -le 2 ]] &&
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["interrupted"] and d["summary"]["not_scanned"] == 1' \
        "$ready_file.out"; then
    pass "Ctrl+C stops the scan quickly with exit code 130 and partial JSON"
else
    fail "Ctrl+C stops the scan quickly (exit $interrupt_exit after ${SECONDS}s)"
fi
rm -f "$ready_file.out"

if [[ -w /dev/full ]]; then
    # /dev/full rejects every write with "No space left on device".
    expect_exit "write error on stdout is reported" 1 \
        bash -c '"$0" -t "$1" -p "$2" >/dev/full' "$BINARY" "$HOST" "$CLOSED_PORT"
fi

# ---- JSON output ------------------------------------------------------------
json_output="$("$BINARY" -t localhost -p "$CLOSED_PORT,$OPEN_PORT" --json 2>/dev/null)"
if python3 -c '
import json, sys
data = json.loads(sys.argv[1])
assert data["scanner"] == "janus", data
assert data["target"] == "localhost" and data["ip"] == "127.0.0.1", data
assert [p["port"] for p in data["open_ports"]] == [int(sys.argv[2])], data
assert data["open_ports"][0]["protocol"] == "tcp", data
assert data["ports_requested"] == 2 and data["ports_scanned"] == 2 and data["summary"]["closed"] == 1, data
assert isinstance(data["duration_ms"], int) and data["interrupted"] is False, data
assert data["timestamp"].endswith("Z"), data
' "$json_output" "$OPEN_PORT"; then
    pass "JSON output is valid and complete"
else
    fail "JSON output is valid and complete"
    sed 's/^/    | /' <<<"$json_output"
fi

no_open_json="$("$BINARY" -t "$HOST" -p "$CLOSED_PORT" --json 2>/dev/null)"
if python3 -c 'import json,sys; assert json.loads(sys.argv[1])["open_ports"] == []' "$no_open_json"; then
    pass "JSON with no open ports is valid"
else
    fail "JSON with no open ports is valid"
fi

if [[ -n "${JSON_TEST:-}" ]]; then
    if "$JSON_TEST" | python3 -c '
import json, sys
expected = [
    "plain",
    "quote \" inside",
    "back\\slash",
    "new\nline and tab\t and cr\r",
    "bell \a and escape \x1b and unit separator \x1f",
    "backspace \b and form feed \f",
    "utf-8: \u011f\u00fc\u015f",
    "",
]
actual = json.loads(sys.stdin.buffer.read().decode("utf-8"))
assert actual == expected, actual
'; then
        pass "JSON string escaping round-trips"
    else
        fail "JSON string escaping round-trips"
    fi
fi

# ---- v1.1: banners, top ports, multiple targets, CIDR, IPv6 ---------------------
expect_output "--banner shows the service greeting" "^$BANNER_PORT/tcp +open .*SSH-2.0-JanusTest_1.0$" \
    "$BINARY" -t "$HOST" -p "$BANNER_PORT" --banner
evil_out="$("$BINARY" -t "$HOST" -p "$EVIL_PORT" --banner 2>&1)"
if [[ "$evil_out" != *$'\x1b'* && "$evil_out" != *$'\x07'* && "$evil_out" == *"owned"* ]]; then
    pass "--banner never prints terminal escape codes"
else
    fail "--banner never prints terminal escape codes"
fi
banner_json="$("$BINARY" -t "$HOST" -p "$BANNER_PORT,$EVIL_PORT,$OPEN_PORT" --banner --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1]); b = {p["port"]: p["banner"] for p in d["open_ports"]}
assert b[int(sys.argv[2])] == "SSH-2.0-JanusTest_1.0", b
assert all(c.isprintable() for v in b.values() for c in v), b
' "$banner_json" "$BANNER_PORT"; then
    pass "JSON carries sanitized banners"
else
    fail "JSON carries sanitized banners"
fi
expect_output "--top-ports 20 scans 20 ports" "Scanned 20 port\(s\)" "$BINARY" -t "$HOST" --top-ports 20 --timeout 300
expect_exit "--top-ports and -p together are a usage error" 2 "$BINARY" -t "$HOST" -p 80 --top-ports 10
for bad_top in 0 101 x; do
    expect_exit "rejects --top-ports '$bad_top'" 2 "$BINARY" -t "$HOST" --top-ports "$bad_top"
done
expect_exit "-4 and -6 together are a usage error" 2 "$BINARY" -t "$HOST" -4 -6
expect_exit "CIDR larger than /20 is a usage error" 2 "$BINARY" -t 10.0.0.0/16
expect_exit "IPv6 CIDR is a usage error" 2 "$BINARY" -t fe80::/64
expect_output "a list of hosts is scanned host by host" "Scanned 2 host\(s\).*1 with open ports" \
    "$BINARY" -t "$HOST,127.0.0.2" -p "$OPEN_PORT"
expect_output "CIDR blocks expand to hosts" "Scanned 6 host\(s\)" "$BINARY" -t 127.0.0.0/29 -p "$CLOSED_PORT"
open_only="$("$BINARY" -t 127.0.0.0/29 -p "$OPEN_PORT" --open 2>&1)"
if [[ "$(grep -c '^127\.' <<<"$open_only")" -eq 1 && "$open_only" == *"127.0.0.1: 1 open"* ]]; then
    pass "--open hides hosts without open ports"
else
    fail "--open hides hosts without open ports"
    sed 's/^/    | /' <<<"$open_only"
fi
expect_output "unresolvable hosts are reported, not fatal, in a list" "no-such-host.invalid: could not be resolved" \
    "$BINARY" -t "$HOST,no-such-host.invalid" -p "$OPEN_PORT"
multi_json="$("$BINARY" -t "$HOST,127.0.0.2,no-such-host.invalid" -p "$OPEN_PORT" --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert d["summary"] == {"hosts": 3, "hosts_with_open_ports": 1}, d["summary"]
hosts = {h["target"]: h for h in d["hosts"]}
assert hosts["127.0.0.1"]["open_ports"][0]["port"] == int(sys.argv[2])
assert hosts["no-such-host.invalid"]["resolved"] is False
' "$multi_json" "$OPEN_PORT"; then
    pass "multi-host JSON is valid and complete"
else
    fail "multi-host JSON is valid and complete"
    sed 's/^/    | /' <<<"$multi_json"
fi
if [[ -n "$v6_pid" ]]; then
    wait_for_port_v6() { for _ in $(seq 30); do python3 -c 'import socket,sys; socket.create_connection(("::1", int(sys.argv[1])), 1)' "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
    wait_for_port_v6 "$BANNER_PORT"
    expect_output "IPv6 literal is scanned" "^$BANNER_PORT/tcp +open .*SSH-2.0-V6" \
        "$BINARY" -t ::1 -p "$BANNER_PORT" --banner
    expect_output "-6 resolves localhost to ::1" "\(::1\)" "$BINARY" -6 -t localhost -p "$BANNER_PORT"
    expect_output "-4 resolves localhost to 127.0.0.1" "\(127\.0\.0\.1\)" "$BINARY" -4 -t localhost -p "$BANNER_PORT"
else
    echo "SKIP: IPv6 tests (no ::1 on this machine)"
fi

# ---- summary ----------------------------------------------------------------
echo
echo "$passed passed, $failed failed"
[[ $failed -eq 0 ]]

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
UDP_REPLY_PORT=29830  # UDP: answers every datagram
UDP_SILENT_PORT=29831 # UDP: receives but never answers
UDP_CLOSED_PORT=29832 # UDP: nothing listens here
UDP_PAYLOAD_PORT=29833 # UDP: answers only non-empty datagrams
SV_TLS_PORT=29840     # --sv: a real TLS server (needs the openssl command for its certificate)
SV_REDIS_PORT=29841   # --sv: answers any request like Redis answers an unknown command
SV_MYSQL_PORT=29842   # --sv: sends a MariaDB handshake greeting
SV_SILENT_PORT=29843  # --sv: accepts, reads, never answers
SV_TLS13_PORT=29844   # --sv: TLS server that accepts only TLS 1.3 (its certificate stays encrypted)
STARTTLS_PORT=29850   # 29850-29854: SMTP, IMAP, POP3 and FTP with STARTTLS, SMTP without
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
udp_ready="$(mktemp -u)"
python3 "$TESTS_DIR/udp_listener.py" "$HOST" "$UDP_REPLY_PORT" reply "$udp_ready.reply" &
udp_reply_pid=$!
python3 "$TESTS_DIR/udp_listener.py" "$HOST" "$UDP_SILENT_PORT" silent "$udp_ready.silent" &
udp_silent_pid=$!
python3 "$TESTS_DIR/udp_listener.py" "$HOST" "$UDP_PAYLOAD_PORT" payload "$udp_ready.payload" &
udp_payload_pid=$!
# SSDP's real port, if it is free on this machine (otherwise the SSDP probe test is skipped).
python3 "$TESTS_DIR/udp_listener.py" "$HOST" 1900 payload "$udp_ready.ssdp" 2>/dev/null &
udp_ssdp_pid=$!
v6_pid=""
if python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.bind(("::1", 0))' 2>/dev/null; then
    python3 "$TESTS_DIR/banner_listener.py" "::1" "$BANNER_PORT" 'SSH-2.0-V6\r\n' &
    v6_pid=$!
fi
python3 "$TESTS_DIR/service_listener.py" "$HOST" "$SV_REDIS_PORT" reply "-ERR unknown command 'HEAD'\r\n" &
sv_redis_pid=$!
python3 "$TESTS_DIR/banner_listener.py" "$HOST" "$SV_MYSQL_PORT" \
    '\x30\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB-0+deb12u1\x00\x2a\x00\x00\x00' &
sv_mysql_pid=$!
python3 "$TESTS_DIR/service_listener.py" "$HOST" "$SV_SILENT_PORT" silent &
sv_silent_pid=$!
cert_dir="$(mktemp -d)"
sv_tls_pid=""
sv_tls13_pid=""
# Two certificates: clients that send SNI "localhost" get the second one, everyone else the first.
if command -v openssl >/dev/null &&
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/O=Janus Tests/CN=janus-default" \
        -keyout "$cert_dir/key.pem" -out "$cert_dir/cert.pem" >/dev/null 2>&1 &&
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -keyout "$cert_dir/sni-key.pem" -out "$cert_dir/sni-cert.pem" >/dev/null 2>&1; then
    python3 "$TESTS_DIR/service_listener.py" "$HOST" "$SV_TLS_PORT" tls "$cert_dir/cert.pem" "$cert_dir/key.pem" \
        localhost "$cert_dir/sni-cert.pem" "$cert_dir/sni-key.pem" &
    sv_tls_pid=$!
    python3 "$TESTS_DIR/service_listener.py" "$HOST" "$SV_TLS13_PORT" tls13 "$cert_dir/cert.pem" "$cert_dir/key.pem" &
    sv_tls13_pid=$!
    offset=0
    for proto in smtp imap pop3 ftp smtp-plain; do
        python3 "$TESTS_DIR/service_listener.py" "$HOST" "$((STARTTLS_PORT + offset))" starttls "$proto" \
            "$cert_dir/sni-cert.pem" "$cert_dir/sni-key.pem" &
        sv_tls13_pid="$sv_tls13_pid $!"
        offset=$((offset + 1))
    done
fi
trap 'kill "$server_pid" "$filtered_pid" "$banner_pid" "$evil_pid" "$udp_reply_pid" "$udp_silent_pid" "$udp_payload_pid" "$udp_ssdp_pid" "$sv_redis_pid" "$sv_mysql_pid" "$sv_silent_pid" $sv_tls_pid $sv_tls13_pid $v6_pid 2>/dev/null; rm -f "$ready_file" "$udp_ready".*; rm -rf "$cert_dir"' EXIT

wait_for_port "$OPEN_PORT" || { echo "listener on $OPEN_PORT did not start"; exit 1; }
wait_for_port "$BANNER_PORT" || { echo "listener on $BANNER_PORT did not start"; exit 1; }
wait_for_port "$EVIL_PORT" || { echo "listener on $EVIL_PORT did not start"; exit 1; }
for sv_port in "$SV_REDIS_PORT" "$SV_MYSQL_PORT" "$SV_SILENT_PORT" \
    ${sv_tls_pid:+"$SV_TLS_PORT" "$SV_TLS13_PORT" "$STARTTLS_PORT" "$((STARTTLS_PORT + 4))"}; do
    wait_for_port "$sv_port" || { echo "listener on $sv_port did not start"; exit 1; }
done
for _ in $(seq 30); do [[ -f "$ready_file" ]] && break; sleep 0.1; done
for _ in $(seq 30); do [[ -f "$udp_ready.reply" && -f "$udp_ready.silent" && -f "$udp_ready.payload" ]] && break; sleep 0.1; done
[[ -f "$udp_ready.reply" && -f "$udp_ready.silent" && -f "$udp_ready.payload" ]] || { echo "UDP listeners did not start"; exit 1; }

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

# ---- v1.2: host discovery (--discover) ------------------------------------------
# The silent port (dropped SYNs) makes 127.0.0.1 look like a host that does not answer.
# 127.0.0.2 gets an RST for the same port, so it counts as up: the two hosts show both outcomes.
for bad_probe in 0 65536 abc "1,,2" ""; do
    expect_exit "rejects --discover-ports '$bad_probe'" 2 "$BINARY" -t "$HOST" --discover-ports "$bad_probe"
done
expect_output "--discover scans a host that answers with an open probe port" "^$OPEN_PORT/tcp +open" \
    "$BINARY" -t "$HOST" -p "$OPEN_PORT" --discover --discover-ports "$OPEN_PORT"
expect_output "an RST on a closed probe port proves the host is up" "^$OPEN_PORT/tcp +open" \
    "$BINARY" -t "$HOST" -p "$OPEN_PORT" --discover --discover-ports "$CLOSED_PORT"
expect_output "--discover uses sensible default probe ports" "^$OPEN_PORT/tcp +open" \
    "$BINARY" -t "$HOST" -p "$OPEN_PORT" --discover
down_out="$("$BINARY" -t "$HOST" -p "$OPEN_PORT" --discover --discover-ports "$FILTERED_PORT" --timeout 300 2>&1)"
down_exit=$?
if [[ $down_exit -eq 0 && "$down_out" == *"Host seems down"* && "$down_out" != *"$OPEN_PORT/tcp"* ]]; then
    pass "a silent single host is reported down and not port-scanned (exit 0)"
else
    fail "a silent single host is reported down and not port-scanned (exit $down_exit)"
    sed 's/^/    | /' <<<"$down_out"
fi
expect_output "--discover-ports alone turns discovery on" "Host seems down" \
    "$BINARY" -t "$HOST" -p "$OPEN_PORT" --discover-ports "$FILTERED_PORT" --timeout 300
multi_down="$("$BINARY" -t "$HOST,127.0.0.2" -p "$OPEN_PORT" --discover-ports "$FILTERED_PORT" --timeout 300 2>&1)"
if [[ "$multi_down" == *"Scanned 2 host(s)"*"1 up, 1 down, 0 with open ports"* && "$multi_down" != *"127.0.0.1:"* ]]; then
    pass "down hosts are counted in the summary and skipped (even if they have open ports)"
else
    fail "down hosts are counted in the summary and skipped"
    sed 's/^/    | /' <<<"$multi_down"
fi
discover_json="$("$BINARY" -t "$HOST,127.0.0.2,no-such-host.invalid" -p "$OPEN_PORT" --discover-ports "$FILTERED_PORT" \
    --timeout 300 --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert d["summary"] == {"hosts": 3, "hosts_with_open_ports": 0, "hosts_up": 1, "hosts_down": 1}, d["summary"]
hosts = {h["target"]: h for h in d["hosts"]}
assert hosts["127.0.0.1"]["status"] == "down" and hosts["127.0.0.1"]["ports_scanned"] == 0, hosts["127.0.0.1"]
assert hosts["127.0.0.1"]["open_ports"] == [], hosts["127.0.0.1"]
assert hosts["127.0.0.2"]["status"] == "up" and hosts["127.0.0.2"]["ports_scanned"] == 1, hosts["127.0.0.2"]
assert "status" not in hosts["no-such-host.invalid"] and hosts["no-such-host.invalid"]["resolved"] is False
' "$discover_json"; then
    pass "discovery JSON carries per-host status and up/down counts"
else
    fail "discovery JSON carries per-host status and up/down counts"
    sed 's/^/    | /' <<<"$discover_json"
fi
plain_json="$("$BINARY" -t "$HOST,127.0.0.2" -p "$OPEN_PORT" --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert "hosts_up" not in d["summary"] and all("status" not in h for h in d["hosts"]), d
' "$plain_json"; then
    pass "without --discover the JSON has no status fields"
else
    fail "without --discover the JSON has no status fields"
fi
expect_output "--discover works on a CIDR block" "Scanned 14 host\(s\).*13 up, 1 down" \
    "$BINARY" -t 127.0.0.0/28 -p "$OPEN_PORT" --discover-ports "$FILTERED_PORT" --timeout 300

# Ctrl+C while the probes are still waiting (10 s timeout on the silent port).
"$BINARY" -t "$HOST" -p "$OPEN_PORT" --discover-ports "$FILTERED_PORT" --timeout 10000 --threads 1 --json \
    >"$ready_file.out" 2>/dev/null &
janus_pid=$!
sleep 0.5
kill -INT "$janus_pid"
SECONDS=0
wait "$janus_pid"
interrupt_exit=$?
if [[ $interrupt_exit -eq 130 && $SECONDS -le 2 ]] &&
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["interrupted"] and "status" not in d and d["ports_scanned"] == 0, d' \
        "$ready_file.out"; then
    pass "Ctrl+C during discovery stops quickly and does not mark hosts down"
else
    fail "Ctrl+C during discovery stops quickly (exit $interrupt_exit after ${SECONDS}s)"
    sed 's/^/    | /' "$ready_file.out"
fi
rm -f "$ready_file.out"

# ---- v1.3: UDP scanning (--udp) ---------------------------------------------------
# closed = ICMP port unreachable (ECONNREFUSED), open = a reply, open|filtered = silence.
expect_output "--udp: a port that answers is open" "^$UDP_REPLY_PORT/udp +open +[a-z]" \
    "$BINARY" -t "$HOST" --udp -p "$UDP_REPLY_PORT" --timeout 400
expect_output "--udp: no listener means closed (ICMP port unreachable)" "1 port\(s\).*0 open, 0 open\|filtered, 1 closed" \
    "$BINARY" -t "$HOST" --udp -p "$UDP_CLOSED_PORT" --timeout 400
expect_output "--udp: a listener that stays silent is open|filtered" "^$UDP_SILENT_PORT/udp +open\|filtered" \
    "$BINARY" -t "$HOST" --udp -p "$UDP_SILENT_PORT" --timeout 300
expect_output "-u is the short form of --udp" "^$UDP_REPLY_PORT/udp +open" \
    "$BINARY" -t "$HOST" -u -p "$UDP_REPLY_PORT" --timeout 400
udp_json="$("$BINARY" -t "$HOST" --udp -p "$UDP_REPLY_PORT,$UDP_SILENT_PORT,$UDP_CLOSED_PORT" --timeout 400 --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1]); reply, silent = int(sys.argv[2]), int(sys.argv[3])
assert d["protocol"] == "udp", d
assert [p["port"] for p in d["open_ports"]] == [reply] and d["open_ports"][0]["protocol"] == "udp", d
assert [p["port"] for p in d["open_filtered_ports"]] == [silent], d
assert d["summary"] == {"open": 1, "open_filtered": 1, "closed": 1, "filtered": 0, "error": 0, "not_scanned": 0}, d["summary"]
' "$udp_json" "$UDP_REPLY_PORT" "$UDP_SILENT_PORT"; then
    pass "UDP JSON has protocol, open_ports, open_filtered_ports and counts"
else
    fail "UDP JSON has protocol, open_ports, open_filtered_ports and counts"
    sed 's/^/    | /' <<<"$udp_json"
fi
tcp_json="$("$BINARY" -t "$HOST" -p "$CLOSED_PORT" --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert d["protocol"] == "tcp" and "open_filtered_ports" not in d and "open_filtered" not in d["summary"], d
' "$tcp_json"; then
    pass "TCP JSON says protocol tcp and has no UDP-only keys"
else
    fail "TCP JSON says protocol tcp and has no UDP-only keys"
fi
# Most real services ignore an empty datagram. Janus sends a real probe only to well-known ports.
expect_output "--udp: an empty probe does not wake a service that needs a real request" \
    "^$UDP_PAYLOAD_PORT/udp +open\|filtered" "$BINARY" -t "$HOST" --udp -p "$UDP_PAYLOAD_PORT" --timeout 300
if [[ -f "$udp_ready.ssdp" ]]; then
    expect_output "--udp: the SSDP port gets a real M-SEARCH probe and answers" "^1900/udp +open +[a-z]" \
        "$BINARY" -t "$HOST" --udp -p 1900 --timeout 400
else
    echo "SKIP: SSDP probe test (UDP port 1900 is in use on this machine)"
fi
expect_exit "--udp with --banner is a usage error" 2 "$BINARY" -t "$HOST" --udp --banner
expect_exit "--udp --top-ports above the UDP table is a usage error" 2 "$BINARY" -t "$HOST" --udp --top-ports 21
expect_output "--udp --top-ports 5 scans 5 ports" "Scanned 5 port\(s\)" "$BINARY" -t "$HOST" --udp --top-ports 5 --timeout 300
expect_output "--udp without ports scans the common UDP ports" "Scanned 20 port\(s\)" "$BINARY" -t "$HOST" --udp --timeout 300
expect_output "--udp works on several hosts" "Scanned 2 host\(s\).*1 with open ports" \
    "$BINARY" -t "$HOST,127.0.0.2" --udp -p "$UDP_REPLY_PORT" --timeout 400
expect_output "--udp combines with --discover (TCP probes, UDP scan)" "^$UDP_REPLY_PORT/udp +open" \
    "$BINARY" -t "$HOST" --udp --discover -p "$UDP_REPLY_PORT" --timeout 400

# Ctrl+C while a UDP probe waits for a reply that never comes.
"$BINARY" -t "$HOST" --udp -p "$UDP_SILENT_PORT" --timeout 10000 --threads 1 --json >"$ready_file.out" 2>/dev/null &
janus_pid=$!
sleep 0.5
kill -INT "$janus_pid"
SECONDS=0
wait "$janus_pid"
interrupt_exit=$?
if [[ $interrupt_exit -eq 130 && $SECONDS -le 2 ]] &&
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["interrupted"] and d["summary"]["not_scanned"] == 1, d' \
        "$ready_file.out"; then
    pass "Ctrl+C stops a UDP scan quickly with exit code 130"
else
    fail "Ctrl+C stops a UDP scan quickly (exit $interrupt_exit after ${SECONDS}s)"
fi
rm -f "$ready_file.out"

# ---- v1.4: one worker pool for all hosts ------------------------------------------
# "localhost" and "127.1" are different strings for the same machine, so each counts as its own host.
# Every host has one silent port (1 s timeout): three hosts take about 1 s in parallel, 3 s one by one.
start_ns=$(date +%s%N)
parallel_out="$("$BINARY" -t "$HOST,localhost,127.1" -p "$FILTERED_PORT" --timeout 1000 2>&1)"
elapsed_ms=$(( ($(date +%s%N) - start_ns) / 1000000 ))
if [[ "$parallel_out" == *"Scanned 3 host(s)"* && $elapsed_ms -lt 2200 ]]; then
    pass "hosts with few ports are scanned in parallel (${elapsed_ms} ms for 3 hosts x 1 s)"
else
    fail "hosts with few ports are scanned in parallel (${elapsed_ms} ms)"
    sed 's/^/    | /' <<<"$parallel_out"
fi
duration_json="$("$BINARY" -t "$HOST,127.0.0.2" -p "$FILTERED_PORT" --timeout 600 --threads 4 --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
hosts = {h["target"]: h for h in d["hosts"]}
slow, fast = hosts["127.0.0.1"], hosts["127.0.0.2"]
assert slow["duration_ms"] >= 500 and slow["summary"]["filtered"] == 1, slow
assert fast["duration_ms"] < 400 and fast["summary"]["closed"] == 1, fast
' "$duration_json"; then
    pass "per-host duration_ms is measured per host, not for the whole run"
else
    fail "per-host duration_ms is measured per host, not for the whole run"
    sed 's/^/    | /' <<<"$duration_json"
fi
# The test server listens on 127.0.0.1 only, so exactly one of the 14 hosts has an open port.
many_out="$("$BINARY" -t 127.0.0.0/28 -p "$OPEN_PORT,$CLOSED_PORT" --threads 64 --timeout 300 2>&1)"
if [[ "$many_out" == *"Scanned 14 host(s)"*"1 with open ports"* && "$many_out" == *"127.0.0.1: 1 open"* ]]; then
    pass "many hosts with a few ports each give complete results"
else
    fail "many hosts with a few ports each give complete results"
    sed 's/^/    | /' <<<"$many_out"
fi
# Ctrl+C in a multi-host scan: one thread is stuck on a 10 s timeout and must stop within ~0.1 s.
"$BINARY" -t "$HOST,localhost,127.1" -p "$FILTERED_PORT" --timeout 10000 --threads 1 >"$ready_file.out" 2>"$ready_file.err" &
janus_pid=$!
sleep 0.5
kill -INT "$janus_pid"
SECONDS=0
wait "$janus_pid"
interrupt_exit=$?
if [[ $interrupt_exit -eq 130 && $SECONDS -le 2 ]] && grep -q "scan interrupted after" "$ready_file.err"; then
    pass "Ctrl+C stops a multi-host scan quickly with exit code 130"
else
    fail "Ctrl+C stops a multi-host scan quickly (exit $interrupt_exit after ${SECONDS}s)"
    sed 's/^/    | /' "$ready_file.err"
fi
rm -f "$ready_file.out" "$ready_file.err"

# ---- v1.6: service and version detection (--sv) ---------------------------------
expect_output "--sv: SSH greeting gives product and version" "^$BANNER_PORT/tcp +open +ssh +JanusTest 1\.0$" \
    "$BINARY" -t "$HOST" -p "$BANNER_PORT" --sv
expect_output "--sv: HTTP on an unusual port is found and named" "^$OPEN_PORT/tcp +open +http +SimpleHTTP 0\.6 \(Python/" \
    "$BINARY" -t "$HOST" -p "$OPEN_PORT" --sv
if [[ -n "$sv_tls_pid" ]]; then
    expect_output "--sv: TLS server shows protocol version and cipher" "^$SV_TLS_PORT/tcp +open +tls +TLS 1\.[23], [A-Z]" \
        "$BINARY" -t "$HOST" -p "$SV_TLS_PORT" --sv
    expect_output "--sv: certificate of a TLS 1.3 server is read through a TLS 1.2 probe" \
        "^ +cert: janus-default, self-signed, valid until 20[0-9-]{8}, RSA 2048$" \
        "$BINARY" -t "$HOST" -p "$SV_TLS_PORT" --sv
    expect_output "--sv: a host name is sent as SNI and picks the server's matching certificate" \
        "^ +cert: localhost, self-signed, valid until 20[0-9-]{8}, RSA 2048$" \
        "$BINARY" -t localhost -p "$SV_TLS_PORT" --sv
    expect_output "--sv: subjectAltName entries are listed" "^ +names: localhost, 127\.0\.0\.1$" \
        "$BINARY" -t localhost -p "$SV_TLS_PORT" --sv
    tls_json="$("$BINARY" -t localhost -p "$SV_TLS_PORT,$SV_TLS13_PORT" --sv --json 2>/dev/null)"
    if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
ports = {p["port"]: p["detected"] for p in d["open_ports"]}
c = ports[int(sys.argv[2])]["certificate"]
assert c["subject"] == "localhost" and c["self_signed"] is True and c["key"] == "RSA 2048", c
assert c["names"] == ["localhost", "127.0.0.1"] and c["expired"] is False and c["not_yet_valid"] is False, c
assert c["not_before"] < d["timestamp"] < c["not_after"] and c["not_after"].endswith("Z"), (c, d["timestamp"])
only13 = ports[int(sys.argv[3])]
assert only13["info"].startswith("TLS 1.3") and only13["certificate"] is None, only13
' "$tls_json" "$SV_TLS_PORT" "$SV_TLS13_PORT"; then
        pass "--sv JSON: certificate details; null when TLS 1.3 keeps it encrypted"
    else
        fail "--sv JSON: certificate details; null when TLS 1.3 keeps it encrypted"
        sed 's/^/    | /' <<<"$tls_json"
    fi
    starttls_out="$("$BINARY" -t localhost -p "$STARTTLS_PORT-$((STARTTLS_PORT + 4))" --sv 2>&1)"
    for entry in "0 smtp" "1 imap" "2 pop3" "3 ftp"; do
        set -- $entry
        port=$((STARTTLS_PORT + $1))
        if grep -qE "^$port/tcp +open +$2 " <<<"$starttls_out" &&
            grep -A2 -E "^$port/tcp" <<<"$starttls_out" | grep -qE "^ +starttls: TLS 1\.[23], " &&
            grep -A3 -E "^$port/tcp" <<<"$starttls_out" | grep -qE "^ +cert: localhost, self-signed"; then
            pass "--sv: $2 STARTTLS upgrade shows TLS version and certificate"
        else
            fail "--sv: $2 STARTTLS upgrade shows TLS version and certificate"
            sed 's/^/    | /' <<<"$starttls_out"
        fi
    done
    expect_output "--sv: a mail server without STARTTLS is flagged" \
        "^ +starttls: NOT OFFERED \(logins travel in clear text\)$" "$BINARY" -t "$HOST" -p "$((STARTTLS_PORT + 4))" --sv
    starttls_json="$("$BINARY" -t localhost -p "$STARTTLS_PORT,$((STARTTLS_PORT + 4)),$BANNER_PORT" --sv --json 2>/dev/null)"
    if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
ports = {p["port"]: p["detected"] for p in d["open_ports"]}
smtp, plain, ssh = ports[int(sys.argv[2])], ports[int(sys.argv[2]) + 4], ports[int(sys.argv[3])]
assert smtp["starttls"]["offered"] is True and smtp["starttls"]["tls"].startswith("TLS 1."), smtp
assert smtp["certificate"]["subject"] == "localhost", smtp
assert plain["starttls"] == {"offered": False} and plain["certificate"] is None, plain
assert ssh["starttls"] is None and ssh["certificate"] is None, ssh
' "$starttls_json" "$STARTTLS_PORT" "$BANNER_PORT"; then
        pass "--sv JSON: starttls object (offered or not), null where it does not apply"
    else
        fail "--sv JSON: starttls object (offered or not), null where it does not apply"
        sed 's/^/    | /' <<<"$starttls_json"
    fi
else
    echo "SKIP: TLS detection tests (no openssl command to make a certificate)"
fi
expect_output "--sv: Redis is recognized by its reply to HEAD" "^$SV_REDIS_PORT/tcp +open +redis +Redis$" \
    "$BINARY" -t "$HOST" -p "$SV_REDIS_PORT" --sv
expect_output "--sv: MariaDB version comes from the handshake" "^$SV_MYSQL_PORT/tcp +open +mysql +MariaDB 10\.11\.6 \(0\+deb12u1\)$" \
    "$BINARY" -t "$HOST" -p "$SV_MYSQL_PORT" --sv
start_ns=$(date +%s%N)
expect_output "--sv: a silent unknown service stays unknown" "^$SV_SILENT_PORT/tcp +open +unknown +-$" \
    "$BINARY" -t "$HOST" -p "$SV_SILENT_PORT" --sv --timeout 300
elapsed_ms=$(( ($(date +%s%N) - start_ns) / 1000000 ))
if (( elapsed_ms < 1500 )); then
    pass "--sv: a silent port costs three short waits, not more (${elapsed_ms} ms at --timeout 300)"
else
    fail "--sv: a silent port costs three short waits (${elapsed_ms} ms at --timeout 300)"
fi
expect_output "--sv: closed ports are not probed" "0 open, 1 closed" "$BINARY" -t "$HOST" -p "$CLOSED_PORT" --sv
expect_output "--sv with --banner shows the banner under the port" "^ +banner: SSH-2\.0-JanusTest_1\.0$" \
    "$BINARY" -t "$HOST" -p "$BANNER_PORT" --sv --banner
sv_evil_out="$("$BINARY" -t "$HOST" -p "$EVIL_PORT" --sv --banner 2>&1)"
if [[ "$sv_evil_out" != *$'\x1b'* && "$sv_evil_out" != *$'\x07'* && "$sv_evil_out" == *"$EVIL_PORT/tcp"* ]]; then
    pass "--sv never prints terminal escape codes"
else
    fail "--sv never prints terminal escape codes"
fi
sv_json="$("$BINARY" -t localhost -p "$BANNER_PORT,$OPEN_PORT,$SV_MYSQL_PORT,$SV_SILENT_PORT,$CLOSED_PORT" --sv --timeout 300 --json 2>/dev/null)"
if python3 -c '
import json, sys
d = json.loads(sys.argv[1])
ports = {p["port"]: p for p in d["open_ports"]}
ssh, http, mysql, silent = (ports[int(x)] for x in sys.argv[2:6])
expected = {"service": "ssh", "product": "JanusTest", "version": "1.0", "info": "", "starttls": None, "certificate": None}
assert ssh["detected"] == expected, ssh
assert http["detected"]["service"] == "http" and http["detected"]["product"] == "SimpleHTTP", http
assert mysql["detected"]["product"] == "MariaDB" and mysql["detected"]["version"] == "10.11.6", mysql
assert silent["detected"] is None, silent
assert all("service" in p and "banner" not in p for p in d["open_ports"]), d
' "$sv_json" "$BANNER_PORT" "$OPEN_PORT" "$SV_MYSQL_PORT" "$SV_SILENT_PORT"; then
    pass "--sv JSON has a detected object per open port (null if unknown)"
else
    fail "--sv JSON has a detected object per open port (null if unknown)"
    sed 's/^/    | /' <<<"$sv_json"
fi
if python3 -c 'import json,sys; assert all("detected" not in p for p in json.loads(sys.argv[1])["open_ports"])' \
    "$("$BINARY" -t "$HOST" -p "$BANNER_PORT" --json 2>/dev/null)"; then
    pass "without --sv the JSON has no detected key"
else
    fail "without --sv the JSON has no detected key"
fi
expect_output "--service-version is the long form of --sv" "ssh +JanusTest 1\.0" \
    "$BINARY" -t "$HOST" -p "$BANNER_PORT" --service-version
if [[ -n "$v6_pid" ]]; then
    expect_output "--sv works over IPv6" "^$BANNER_PORT/tcp +open +ssh +V6$" "$BINARY" -t ::1 -p "$BANNER_PORT" --sv
fi
expect_output "--sv on several hosts keeps the VERSION column" "^$BANNER_PORT/tcp +open +ssh +JanusTest 1\.0$" \
    "$BINARY" -t "$HOST,127.0.0.2" -p "$BANNER_PORT" --sv --timeout 300
expect_output "--sv --udp: an unknown reply is open with no version" "^$UDP_REPLY_PORT/udp +open +[a-z-]+ +-$" \
    "$BINARY" -t "$HOST" --udp -p "$UDP_REPLY_PORT" --sv --timeout 300
# Ctrl+C while --sv waits on a service that never answers.
"$BINARY" -t "$HOST" -p "$SV_SILENT_PORT" --sv --timeout 10000 --json >"$ready_file.out" 2>/dev/null &
janus_pid=$!
sleep 0.5
kill -INT "$janus_pid"
SECONDS=0
wait "$janus_pid"
interrupt_exit=$?
if [[ $interrupt_exit -eq 130 && $SECONDS -le 2 ]] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$ready_file.out"; then
    pass "Ctrl+C stops --sv probing quickly with exit code 130"
else
    fail "Ctrl+C stops --sv probing quickly (exit $interrupt_exit after ${SECONDS}s)"
fi
rm -f "$ready_file.out"

# ---- summary ----------------------------------------------------------------
echo
echo "$passed passed, $failed failed"
[[ $failed -eq 0 ]]

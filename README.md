# Janus

A small, dependency-free **TCP connect port scanner** for Linux, written in C11
with plain POSIX sockets and pthreads.

Named after Janus, the Roman god of gates and doorways. Ports are doors.

> ## ⚠️ Authorized use only
>
> Janus is a defensive learning tool. Scan **only** your own devices, your own
> network, or systems you have explicit written permission to test. Scanning
> systems without permission may be illegal where you live and is against the
> terms of most networks. Janus deliberately has no stealth, evasion or exploit
> features.

## Features

- Full TCP connect scan: **open**, **closed** and **filtered** (timeout) detection
- Non-blocking `connect()` + `poll()` with a per-port timeout
- Port lists and ranges: `80`, `22,80,443`, `1-1024`, `22,80-90,8000`
- Parallel scanning with a pthread work queue (`--threads`, max 256)
- Service names from `/etc/services` (`22` → `ssh`)
- Human-readable table or **JSON** output for other programs
- Clean `Ctrl+C`: stops within ~0.1 s and prints partial results
- Strict input validation, zero compiler warnings, clean under valgrind,
  AddressSanitizer, UBSan and ThreadSanitizer

## Build

Requirements: Linux, `gcc`, `make`. Tests also need `python3`; `make check`
needs `valgrind`.

```sh
make            # release build  -> ./janus
make debug      # ASan + UBSan   -> ./janus-debug
make test       # run the test suite against local listeners
make check      # tests under sanitizers, valgrind leak check, ThreadSanitizer
make clean      # remove build output
```

## Usage

```
Usage: janus -t <target> [options]

  -t, --target <host>   host name or IPv4 address to scan (required)
  -p, --ports <list>    ports: 80 | 22,80,443 | 1-1024 | 22,80-90 (default 1-1024)
      --timeout <ms>    wait per port in milliseconds, 1-60000 (default 1000)
      --threads <n>     parallel workers, 1-256 (default 16)
      --json            print the result as JSON (open ports only)
  -h, --help            show this help and exit
  -v, --version         show the version and exit
```

### Examples

Scan the first 10000 ports of your own machine:

```console
$ ./janus -t localhost -p 1-10000 --threads 32
Janus scan report for localhost (127.0.0.1)
Started: 2026-11-11T17:55:00Z

PORT       STATE    SERVICE
22/tcp     open     ssh
631/tcp    open     ipp
8000/tcp   open     unknown

Scanned 10000 port(s) in 0.03 s: 3 open, 9997 closed, 0 filtered
```

Check a few ports on a device in your home network with a short timeout:

```console
$ ./janus -t 192.168.1.1 -p 22,53,80,443 --timeout 300
```

JSON output, e.g. for another program to consume:

```console
$ ./janus -t localhost -p 22,80,443,631,8000 --json
{
  "scanner": "janus",
  "version": "1.0.0",
  "target": "localhost",
  "ip": "127.0.0.1",
  "timestamp": "2026-11-11T17:55:00Z",
  "duration_ms": 0,
  "ports_requested": 5,
  "ports_scanned": 5,
  "interrupted": false,
  "open_ports": [
    {"port": 22, "protocol": "tcp", "service": "ssh"},
    {"port": 631, "protocol": "tcp", "service": "ipp"},
    {"port": 8000, "protocol": "tcp", "service": "unknown"}
  ],
  "summary": {"open": 3, "closed": 2, "filtered": 0, "error": 0, "not_scanned": 0}
}
```

Reading it from Python:

```python
import json, subprocess

completed = subprocess.run(
    ["./janus", "-t", "localhost", "-p", "1-1024", "--json"],
    capture_output=True, text=True,
)
report = json.loads(completed.stdout)
print([p["port"] for p in report["open_ports"]])
```

### Output and exit codes

Results go to **stdout**; warnings and errors go to **stderr**, so JSON on
stdout is never mixed with messages.

| Exit code | Meaning                                                      |
|-----------|--------------------------------------------------------------|
| 0         | scan finished                                                |
| 1         | runtime error (host cannot be resolved, output write failed) |
| 2         | invalid command-line input                                   |
| 130       | interrupted with Ctrl+C (partial results were printed)       |

## How it works

For every port Janus opens a TCP socket in non-blocking mode and calls
`connect()`. The kernel sends a **SYN**:

- **SYN-ACK** comes back → handshake completes → **open**
- **RST** comes back → "connection refused" → **closed**
- nothing comes back before `--timeout` → **filtered** (usually a firewall
  dropping packets)

`poll()` waits for the answer, and `getsockopt(SO_ERROR)` tells which of the
cases happened. The socket is closed right after, which sends FIN (or RST) to
the target. See [docs/how-it-works.md](docs/how-it-works.md) for the details,
including what happens on the wire.

## Project structure

```
src/
  main.c        entry point: parse options, resolve, scan, print, clean up
  cli.c/.h      getopt_long parsing, port list parser, input validation, help
  scanner.c/.h  resolve_target, connect_with_timeout, thread work queue
  services.c/.h port number -> service name (getservbyport)
  output.c/.h   text table and hand-written JSON with string escaping
  utils.c/.h    error printing, monotonic clock, UTC timestamps
tests/
  run_tests.sh          end-to-end tests against local listeners
  filtered_listener.py  simulates a filtered port without root
  test_json_escape.c    unit test for JSON string escaping
docs/
  how-it-works.md       TCP connect scanning explained
```

## Limitations

- IPv4 only; one target host per run (no CIDR ranges yet)
- TCP connect scan only: every open port sees a full connection, so the
  target's logs will show it (this is intentional, Janus is not stealthy)
- "filtered" means "no answer in time": a slow or overloaded host can look
  filtered if the timeout is too short
- Service names come from `/etc/services`; Janus does not talk to the service
  to identify what really runs there
- Linux only

## Roadmap

- UDP scanning
- CIDR ranges (`192.168.1.0/24`) and multiple targets
- IPv6 support
- Integration as the scanning engine of `network-monitor` (via `--json`)

## License

[MIT](LICENSE)

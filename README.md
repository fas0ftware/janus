# Janus

[![CI](https://github.com/fas0ftware/janus/actions/workflows/ci.yml/badge.svg)](https://github.com/fas0ftware/janus/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-1.3.0-blue)
![C11](https://img.shields.io/badge/C11-POSIX%20%2B%20pthreads-555)
![Checks](https://img.shields.io/badge/ASan%20%C2%B7%20UBSan%20%C2%B7%20TSan%20%C2%B7%20valgrind-clean-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A small, dependency-free **TCP connect and UDP port scanner** for Linux, written
in C11 with plain POSIX sockets and pthreads.

![Janus 1.1: banners, CIDR and IPv6](docs/demo.svg)

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
- **UDP scan** (`--udp`, no root): a reply means **open**, an ICMP "port
  unreachable" means **closed**, silence means **open|filtered**. DNS and NTP
  get a real query so they answer; the default is the 20 most common UDP ports
- Non-blocking `connect()` + `poll()` with a per-port timeout
- **IPv4 and IPv6** (`-4` / `-6` to force a family when resolving names)
- **Several targets per run:** lists (`host1,host2`) and IPv4 **CIDR blocks**
  (`192.168.1.0/24`, from /20 to /32), with `--open` to list only hosts that
  have open ports
- **Host discovery** (`--discover`): probes all hosts in parallel first and
  port-scans only those that answer, so a mostly empty `/24` no longer costs
  one full timeout per port for every silent host. Works without root
- Port lists and ranges: `80`, `22,80,443`, `1-1024`, `22,80-90,8000`, or
  `--top-ports N` for the N most commonly open ports (up to 100)
- **Banner grabbing** (`--banner`): the first line a service sends (SSH, FTP,
  SMTP...), or the HTTP status line on web ports. Output is reduced to
  printable ASCII, so a hostile service cannot inject terminal escape codes
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

  -t, --target <spec>   host name, IPv4/IPv6 address, list (a,b,c) or IPv4
                        CIDR block /20-/32, e.g. 192.168.1.0/24 (required)
  -p, --ports <list>    ports: 80 | 22,80,443 | 1-1024 | 22,80-90 (default 1-1024)
      --top-ports <n>   the n most common ports, 1-100 (instead of -p)
  -u, --udp             scan UDP instead of TCP (no root needed). Default ports:
                        the 20 most common UDP ports; --top-ports takes 1-20
                        Silent ports are reported as open|filtered
      --timeout <ms>    wait per port in milliseconds, 1-60000 (default 1000)
      --threads <n>     parallel workers, 1-256 (default 16)
      --banner          read a short greeting from open ports (HTTP ports
                        get a HEAD request); nothing else is sent
      --open            with several hosts, list only hosts with open ports
      --discover        first find which hosts answer (TCP probes, no root
                        needed) and port-scan only those; down hosts are skipped
      --discover-ports <list>
                        ports to probe for --discover (default 22,80,443,445,8080);
                        implies --discover
  -4 / -6               use only IPv4 / only IPv6 when resolving names
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

Your own subnet, the 100 most common ports, short timeout, only hosts with
something open:

```console
$ ./janus -t 192.168.1.0/24 --top-ports 100 --timeout 300 --open
```

Hosts are scanned one after another (ports of one host in parallel). Without
`--discover`, a host that is down makes every port wait for the full timeout,
so keep `--timeout` short and the port list small for whole subnets, or let
Janus skip the silent hosts first:

```console
$ ./janus -t 192.168.1.0/24 --top-ports 100 --timeout 300 --discover
192.168.1.1: 2 open
PORT       STATE    SERVICE
53/tcp     open     domain
80/tcp     open     http

192.168.1.23: no open ports

Scanned 254 host(s) in 6.41 s: 2 up, 252 down, 1 with open ports
```

(Illustrative output.) Hosts that are down are counted in the summary, not
listed. With a single host, a silent target prints `Host seems down` and exits
with 0; run without `--discover` to scan it anyway. If your devices ignore the
default probe ports, probe others: `--discover-ports 22,80,443,3389,5353`.

UDP scan of your own machine or router (silent ports show as `open|filtered`):

```console
$ ./janus -t 192.168.1.1 --udp --timeout 500
```

```text
PORT       STATE          SERVICE
53/udp     open           domain
1900/udp   open|filtered  unknown
```

(Illustrative output.) UDP is connectionless, so Janus can only be certain
about a port when something answers (open) or the kernel reports an ICMP
error (closed). A service that ignores Janus' probe looks the same as a
firewall that drops it: both are `open|filtered`.

JSON output, e.g. for another program to consume (with several targets the
document has a `hosts` array instead, plus `summary.hosts_with_open_ports`; with
`--discover` every host also gets `"status": "up"` or `"down"`, and the summary
gains `hosts_up` and `hosts_down`). Every document says `"protocol": "tcp"` or
`"udp"`; UDP scans add an `open_filtered_ports` array and `summary.open_filtered`:

```console
$ ./janus -t localhost -p 22,80,443,631,8000 --json
{
  "scanner": "janus",
  "version": "1.2.0",
  "timestamp": "2026-11-11T17:55:00Z",
  "target": "localhost",
  "ip": "127.0.0.1",
  "protocol": "tcp",
  "resolved": true,
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
  scanner.c/.h  resolve_target (IPv4/IPv6), connect_with_timeout, banners, work queue
  targets.c/.h  target lists, CIDR expansion, top-ports table
  discovery.c/.h  --discover: parallel TCP probes that decide which hosts are up
  udp_scan.c/.h   --udp: datagram probes, ICMP errors via ECONNREFUSED, DNS/NTP payloads
  services.c/.h port number -> service name (getservbyport)
  output.c/.h   text table and hand-written JSON with string escaping
  utils.c/.h    error printing, monotonic clock, UTC timestamps
tests/
  run_tests.sh          end-to-end tests against local listeners
  filtered_listener.py  simulates a filtered port without root
  banner_listener.py    greets clients with a banner (also hostile escape codes)
  udp_listener.py       UDP listener that answers or stays silent
  test_udp.c            unit tests: UDP probe payloads
  test_json_escape.c    unit test for JSON string escaping
  test_targets.c        unit tests: lists, CIDR edge cases, banner sanitizing
docs/
  how-it-works.md       TCP connect scanning explained
```

## Tests and checks

`make test` runs 31 C unit checks (target lists, CIDR edge cases such as /31,
/32 and oversized blocks, banner sanitizing, UDP probe payloads) and 89 end-to-end checks against
local listeners: open/closed/filtered, threads, Ctrl+C, write errors, JSON,
banners (including a listener that sends terminal escape codes), top ports,
lists, CIDR, `--open`, unresolvable hosts in a list, IPv6 and `-4`/`-6`, and
host discovery (up, down, JSON status, Ctrl+C while probing) and UDP (open,
closed, open|filtered, JSON, Ctrl+C).

![make test](docs/test-results.svg)

`make check` repeats the suite under AddressSanitizer + UBSan, runs valgrind
with leak checking (including a CIDR + IPv6 + banner scan) and
ThreadSanitizer. CI builds with gcc **and** clang using `-Werror`, runs all of
it, plus cppcheck.

![make check](docs/check.svg)

<details><summary>JSON output with banners</summary>

![JSON](docs/json.svg)

</details>

## Limitations

- IPv6 targets must be single addresses or names (IPv6 CIDR blocks are not
  expanded); hosts are scanned one at a time
- TCP connect scan only: every open port sees a full connection, so the
  target's logs will show it (this is intentional, Janus is not stealthy)
- `--discover` is a TCP probe, not an ARP or ICMP ping: a host that drops every
  packet on all probe ports looks down and is skipped. Probe more ports with
  `--discover-ports` when that matters
- UDP: most services ignore an empty datagram, so many open UDP ports show up
  as `open|filtered`. Only DNS and NTP get a protocol-specific probe. Linux
  also rate-limits ICMP errors (about one per second per remote host), so a
  fast UDP scan of a *remote* host can report closed ports as `open|filtered`
  (localhost is exempt). Use a longer `--timeout` and fewer `--threads` there
- "filtered" means "no answer in time": a slow or overloaded host can look
  filtered if the timeout is too short
- Service names come from `/etc/services`; Janus does not talk to the service
  to identify what really runs there
- Linux only

## Roadmap

- More UDP service probes (mDNS, SSDP, SNMP)
- Scanning the ports of several hosts in parallel
- Integration as the scanning engine of `network-monitor` (via `--json`)

## Changelog

- **1.3.0** – `--udp` / `-u`: unprivileged UDP scan (open, closed, open|filtered),
  DNS and NTP probes, 20 common UDP ports by default, `protocol` and
  `open_filtered_ports` in the JSON output, UDP listeners in the tests.
- **1.2.0** – `--discover` / `--discover-ports`: parallel host discovery with
  plain TCP probes (no root), hosts that do not answer are skipped, `status`,
  `hosts_up` and `hosts_down` in the JSON output, new tests, valgrind and
  ThreadSanitizer runs for the discovery code.
- **1.1.0** – IPv6, `-4`/`-6`, target lists and IPv4 CIDR blocks, `--open`,
  `--top-ports`, `--banner` with sanitized output, multi-host JSON, more unit
  and end-to-end tests, GitHub Actions CI (gcc + clang, sanitizers, valgrind,
  TSan, cppcheck).
- **1.0.0** – IPv4 TCP connect scan with threads, JSON, clean Ctrl+C.

## License

[MIT](LICENSE)

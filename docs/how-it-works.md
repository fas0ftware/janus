# How Janus Works

This page explains what a **TCP connect scan** is and what happens on the wire
when Janus checks one port.

## 1. Ports are doors

A TCP connection is identified by four numbers: source IP, source port,
destination IP, destination port. A program that offers a service (an SSH
server, a web server) asks the kernel to **listen** on one port. A port scan
simply asks, port by port: *is anybody listening behind this door?*

## 2. The TCP three-way handshake

Every TCP connection starts with three packets:

```
 client (Janus)                       server
      |  ---- SYN ------------------->  |   "I want to connect"
      |  <--- SYN-ACK ----------------  |   "OK, I am listening"
      |  ---- ACK ------------------->  |   "Great, connected"
```

The handshake is done by the **kernels** on both sides. The server program
(for example `python3 -m http.server`) is not involved until it calls
`accept()`. That is why a connect scan does not need to speak HTTP, SSH or any
other protocol.

## 3. The three possible answers

| What comes back                  | Meaning                                   | Janus says |
|----------------------------------|-------------------------------------------|------------|
| SYN-ACK                          | a program listens on the port             | `open`     |
| RST                              | the host is up, but nobody listens        | `closed`   |
| nothing (before the timeout)     | packets are dropped, usually by a firewall| `filtered` |
| ICMP "host unreachable"          | a router or firewall rejected the packet  | `filtered` |

A closed port is an **active refusal**: the target's kernel answers with RST.
A filtered port is **silence**.

## 4. What Janus does for one port

1. `socket(AF_INET, SOCK_STREAM, 0)`: ask the kernel for a TCP socket. The
   result is a *file descriptor*, a small integer that refers to the socket.
2. `fcntl(fd, F_SETFL, O_NONBLOCK)`: switch the socket to non-blocking mode.
3. `connect()`: the kernel sends the SYN. In non-blocking mode the call returns
   immediately with `EINPROGRESS` ("started, result comes later").
4. `poll()` with `POLLOUT`: sleep until the socket becomes writable (the
   handshake finished, successfully or not) or the timeout expires. Janus polls
   in 100 ms slices so it can react to Ctrl+C quickly.
5. `getsockopt(fd, SOL_SOCKET, SO_ERROR, ...)`: ask how the handshake ended.
   `0` means connected (open), `ECONNREFUSED` means RST (closed).
6. `close(fd)`: release the file descriptor. Because the connection was
   established, closing it sends a FIN to the target, which ends the connection
   politely.

### Why not a blocking connect?

A blocking `connect()` waits until the kernel itself gives up. On Linux the
kernel retries the SYN 6 times (`net.ipv4.tcp_syn_retries`) with growing
delays, which takes **about two minutes** per filtered port. Scanning 1000
filtered ports that way would take more than a day. With non-blocking mode and
`poll()`, Janus decides how long to wait.

## 5. On the wire: one open port

Scanning port 8000 on localhost while `python3 -m http.server 8000` runs:

```
Janus  -> 127.0.0.1:8000   SYN
Janus  <- 127.0.0.1:8000   SYN, ACK          connect() succeeds -> "open"
Janus  -> 127.0.0.1:8000   ACK
Janus  -> 127.0.0.1:8000   FIN, ACK          close()
Janus  <- 127.0.0.1:8000   FIN, ACK / ACK    the connection is torn down
```

You can watch this yourself with:

```sh
sudo tcpdump -i lo -n 'tcp port 8000'
```

Note that the connection was really established. A service that logs
connections (sshd, for example) will see the scan. This is the main difference
from a "SYN scan", which never completes the handshake but needs raw sockets
and root privileges. Janus intentionally stays with the simple, honest
connect scan.

## 6. Many ports at once

Most of the time is spent waiting for answers, not computing. Janus therefore
starts several worker threads (`--threads`). They share one list of jobs, where
a job is one port on one host, numbered host by host. A single atomic counter
(`atomic_fetch_add`) hands out the next job number, so two threads can never
take the same job and no mutex is needed. Each result is written by exactly one
thread, into its own slot, so results need no lock.

Because the queue spans all hosts, a `/24` with only 20 ports per host still
keeps every thread busy; with one queue per host, 16 threads would wait on a
20-port list and then start over for the next host. Each host counts its
unfinished ports, and the thread that finishes the last one records how long
the host took.

## 7. Skipping hosts that are down

A whole subnet is mostly empty. For a silent host every port waits for the
full timeout, so scanning 1000 ports of a host that is not there would take as
long as the timeout allows, times the ports, divided by the threads. With
`--discover`, Janus first runs a few connection attempts per host (default
ports 22, 80, 443, 445 and 8080) and treats the host as **up** if any of them
gets an answer: a SYN-ACK (open) **or** an RST (closed). A refused connection
is still proof that a machine is there. Only hosts that stay completely silent
are marked **down** and skipped.

The probes are queued port by port across all hosts and run on the same kind of
worker threads as the port scan. As soon as a host has answered, its remaining
probe ports are skipped, so only the silent hosts pay for every probe.

The trade-off: a real ping would use ICMP or ARP, which needs raw sockets and
root. A TCP probe stays unprivileged, but a host that drops packets on all the
probe ports looks the same as a host that is off. Use `--discover-ports` to
probe the ports your devices actually use.

## 8. UDP: answers are rare

UDP has no handshake, so there is no SYN-ACK to wait for. Janus opens a UDP
socket, calls `connect()` on it (which sends nothing, it only fixes the peer),
and sends one datagram. Then it waits:

- a datagram comes back: something listens, the port is **open**
- the kernel reports `ECONNREFUSED`: the target sent an ICMP "port unreachable",
  the port is **closed**. The `connect()` in the first step is what makes Linux
  hand this ICMP error to the socket, without root or raw sockets
- ICMP "host unreachable" or "administratively prohibited": **filtered**
- nothing at all: **open|filtered**. An open port whose service ignores the
  probe and a firewall that drops it look exactly the same

Because UDP packets get lost, the probe is sent twice inside the timeout.
Most services only answer a correctly formed request, so DNS (53) and NTP (123)
get a minimal query; every other port gets an empty datagram, which is enough
to make a *closed* port answer with ICMP but rarely makes an open one talk.

Linux limits how fast it sends ICMP errors (`icmp_ratelimit`, roughly one per
second per remote host). Against a remote host a fast scan can lose some of
them, and those closed ports then show up as `open|filtered`. Loopback is
exempt from the limit, which is why the tests can use closed UDP ports.

## 9. Stopping cleanly

`Ctrl+C` sends `SIGINT`. Janus' signal handler only sets an atomic flag (doing
more inside a signal handler is unsafe). Workers check the flag before taking a
new port and between `poll()` slices, so the scan stops within about 100 ms,
prints what it has, and exits with code 130.

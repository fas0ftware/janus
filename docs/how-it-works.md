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
starts several worker threads (`--threads`). They share one list of ports and a
counter `next_index` that says which port is next. The counter is protected by
a **mutex**, so two threads can never take the same port. Each result is
written by exactly one thread, into its own slot, so results need no lock.

## 7. Stopping cleanly

`Ctrl+C` sends `SIGINT`. Janus' signal handler only sets an atomic flag (doing
more inside a signal handler is unsafe). Workers check the flag before taking a
new port and between `poll()` slices, so the scan stops within about 100 ms,
prints what it has, and exits with code 130.

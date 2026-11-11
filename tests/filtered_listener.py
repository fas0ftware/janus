#!/usr/bin/env python3
"""Simulate a "filtered" port on localhost without root or firewall rules.

A listening socket with backlog 0 that never calls accept() has room for
only one pending connection. Once that slot is used, Linux silently drops
new SYN packets for that port, which looks exactly like a firewall that
drops traffic: no SYN-ACK and no RST, only a timeout.

Usage: filtered_listener.py <port> <ready_file>
The ready file is created once the accept queue is full.
"""

import pathlib
import socket
import sys
import time

HOST = "127.0.0.1"


def main() -> None:
    port = int(sys.argv[1])
    ready_file = pathlib.Path(sys.argv[2])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, port))
    listener.listen(0)

    # Fill the accept queue. Extra attempts are harmless: their SYNs are dropped.
    fillers = []
    for _ in range(3):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setblocking(False)
        client.connect_ex((HOST, port))
        fillers.append(client)
    time.sleep(0.3)  # give the kernel time to finish the first handshake

    ready_file.touch()
    time.sleep(120)  # keep everything open; the test runner kills us


if __name__ == "__main__":
    main()

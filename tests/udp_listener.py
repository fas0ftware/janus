#!/usr/bin/env python3
"""UDP listener for the Janus tests.

Usage: udp_listener.py <host> <port> <reply|silent|payload> <ready_file>

  reply    answers every datagram with "pong"   -> Janus reports the port as open
  silent   receives datagrams but never answers -> Janus reports open|filtered
  payload  answers only datagrams that are not empty, like most real services
           -> open for ports where Janus sends a real probe (53, 123, 137, 1900,
           5353), open|filtered where it sends an empty datagram

A port with no listener at all is "closed": the kernel answers with an ICMP
"port unreachable". The ready file is created once the socket is bound.
"""

import pathlib
import socket
import sys


def main() -> None:
    host, port, mode, ready_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], pathlib.Path(sys.argv[4])
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((host, port))
    ready_file.touch()
    while True:
        data, peer = sock.recvfrom(2048)
        if mode == "reply" or (mode == "payload" and data):
            sock.sendto(b"pong", peer)


if __name__ == "__main__":
    main()

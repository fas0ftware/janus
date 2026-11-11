#!/usr/bin/env python3
"""Local test listener: greets every client with a fixed banner, then closes.

usage: banner_listener.py HOST PORT BANNER   (BANNER may use \\r \\n \\x1b escapes)
Binds only to the given loopback address.
"""
import socket
import sys

host, port, banner = sys.argv[1], int(sys.argv[2]), sys.argv[3]
data = banner.encode("latin-1").decode("unicode_escape").encode("latin-1")
family = socket.AF_INET6 if ":" in host else socket.AF_INET
server = socket.socket(family, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(64)
while True:
    conn, _ = server.accept()
    try:
        conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()

#!/usr/bin/env python3
"""Local listeners that behave like real services, for the --sv tests.

usage: service_listener.py HOST PORT reply REPLY   answer the first data a client
                                                   sends with REPLY (\\r \\n \\x.. escapes),
                                                   like Redis answering an unknown command
       service_listener.py HOST PORT tls CERT KEY [NAME CERT2 KEY2]
                                                   a real TLS server (Python ssl module); a
                                                   client that sends SNI NAME gets CERT2
       service_listener.py HOST PORT tls13 CERT KEY  the same, but refuses anything below TLS 1.3
       service_listener.py HOST PORT silent        accept, read, never answer

Binds only to the given loopback address.
"""
import socket
import ssl
import sys
import threading


def unescape(text: str) -> bytes:
    return text.encode("latin-1").decode("unicode_escape").encode("latin-1")


def handle(conn: socket.socket, mode: str, args: list, context) -> None:
    conn.settimeout(5)
    try:
        if mode == "reply":
            if conn.recv(4096):
                conn.sendall(unescape(args[0]))
        elif mode in ("tls", "tls13"):
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)  # the probe never finishes the handshake; this just waits
        elif mode == "silent":
            while conn.recv(4096):
                pass
    except (OSError, ssl.SSLError):
        pass
    finally:
        conn.close()


def main() -> None:
    host, port, mode, args = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4:]
    context = None
    if mode in ("tls", "tls13"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args[0], args[1])
        if mode == "tls13":
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        if len(args) == 5:
            named = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            named.load_cert_chain(args[3], args[4])

            def pick_certificate(sock, server_name, _context):
                if server_name == args[2]:
                    sock.context = named

            context.sni_callback = pick_certificate
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(64)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn, mode, args, context), daemon=True).start()


if __name__ == "__main__":
    main()

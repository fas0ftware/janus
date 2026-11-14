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
       service_listener.py HOST PORT starttls PROTO CERT KEY
                                                   a mail/FTP server (PROTO: smtp, imap, pop3,
                                                   ftp, smtp-plain) that switches to TLS on
                                                   its STARTTLS command; smtp-plain offers none

Binds only to the given loopback address.
"""
import socket
import ssl
import sys
import threading


def unescape(text: str) -> bytes:
    return text.encode("latin-1").decode("unicode_escape").encode("latin-1")


# greeting, command that starts TLS, reply that agrees
STARTTLS = {
    "smtp": (b"220 mail.test ESMTP Postfix\r\n", b"STARTTLS", b"220 2.0.0 Ready to start TLS\r\n"),
    "smtp-plain": (b"220 mail.test ESMTP Postfix\r\n", None, None),
    "imap": (b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n", b"J1 STARTTLS",
             b"* NOTE untagged line first\r\nJ1 OK Begin TLS negotiation now.\r\n"),
    "pop3": (b"+OK Dovecot ready.\r\n", b"STLS", b"+OK Begin TLS negotiation now.\r\n"),
    "ftp": (b"220-Welcome\r\n220 (vsFTPd 3.0.5)\r\n", b"AUTH TLS", b"234 Proceed with negotiation.\r\n"),
}


def read_line(conn: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data.strip()


def serve_starttls(conn: socket.socket, proto: str, context) -> None:
    greeting, command, agree = STARTTLS[proto]
    conn.sendall(greeting)
    while True:
        line = read_line(conn)
        if not line:
            return
        if line.upper().startswith(b"EHLO"):
            extensions = b"250-STARTTLS\r\n" if command else b""
            conn.sendall(b"250-mail.test\r\n" + extensions + b"250 8BITMIME\r\n")
        elif command and line.upper() == command:
            conn.sendall(agree)
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
            return
        else:
            conn.sendall(b"502 5.5.2 Error: command not recognized\r\n")


def handle(conn: socket.socket, mode: str, args: list, context) -> None:
    conn.settimeout(5)
    try:
        if mode == "reply":
            if conn.recv(4096):
                conn.sendall(unescape(args[0]))
        elif mode in ("tls", "tls13"):
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)  # the probe never finishes the handshake; this just waits
        elif mode == "starttls":
            serve_starttls(conn, args[0], context)
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
    if mode == "starttls":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args[1], args[2])
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

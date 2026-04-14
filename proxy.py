#python proxy.py --port 8800

import socket
import threading
import argparse
import logging
import sys
from urllib.parse import urlparse
from datetime import datetime


class _TimeFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        return f"[{ts}] {record.getMessage()}"


logger = logging.getLogger("proxy")
logger.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(_TimeFormatter())
logger.addHandler(_h)

BLACKLIST_FILE = "blacklist.txt"


def load_blacklist(path: str) -> set:
    entries = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line.lower())
    except FileNotFoundError:
        pass
    return entries


def is_blocked(host: str, full_url: str, blacklist: set) -> bool:
    host = host.lower()
    full_url = full_url.lower()
    for entry in blacklist:
        if host == entry or host.endswith("." + entry):
            return True
        if full_url.startswith(entry):
            return True
    return False


BUFFER_SIZE = 65536

BLOCK_PAGE_TEMPLATE = """\
HTTP/1.1 403 Forbidden\r
Content-Type: text/html; charset=utf-8\r
Connection: close\r
\r
<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><title>Доступ заблокирован</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #f5f5f5;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; margin: 0; }}
  .box {{ background: #fff; border-radius: 8px; padding: 40px 50px;
          box-shadow: 0 2px 12px rgba(0,0,0,.15); max-width: 520px;
          text-align: center; }}
  h1 {{ color: #d32f2f; margin-bottom: 12px; }}
  p  {{ color: #555; line-height: 1.6; }}
  code {{ background: #eee; padding: 2px 6px; border-radius: 4px; }}
</style>
</head>
<body>
  <div class="box">
    <h1>&#128683; Доступ заблокирован</h1>
    <p>Запрошенный ресурс находится в чёрном списке прокси-сервера.</p>
    <p><code>{url}</code></p>
  </div>
</body>
</html>
"""

BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n502 Bad Gateway\n"
NOT_IMPLEMENTED = b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n501 Only HTTP (not HTTPS) is supported\n"


def send_all(sock: socket.socket, data: bytes):
    try:
        sock.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass


def recv_request_head(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def parse_request_line(raw: bytes):
    header_section = raw.split(b"\r\n\r\n", 1)[0]
    first_line = header_section.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    parts = first_line.split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"Malformed request line: {first_line!r}")
    method, url, version = parts
    return method.upper(), url, version


def build_upstream_request(method: str, url: str, version: str, raw_headers: bytes) -> bytes:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    header_section = raw_headers.split(b"\r\n\r\n", 1)[0]
    lines = header_section.split(b"\r\n")
    lines[0] = f"{method} {path} HTTP/1.0".encode()

    filtered = []
    for line in lines:
        if line.lower().startswith(b"proxy-connection:"):
            continue
        if line.lower().startswith(b"connection:"):
            filtered.append(b"Connection: close")
            continue
        filtered.append(line)

    return b"\r\n".join(filtered) + b"\r\n\r\n"


def pipe(src: socket.socket, dst: socket.socket):
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass


def forward_response(upstream: socket.socket, client: socket.socket, url: str):
    response_head = b""
    while b"\r\n\r\n" not in response_head:
        chunk = upstream.recv(4096)
        if not chunk:
            break
        response_head += chunk

    first_line = response_head.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    status = first_line[9:].strip() if len(first_line) > 9 else "???"
    logger.info(f"{url} -> {status}")

    send_all(client, response_head)
    pipe(upstream, client)


def handle_client(client_sock: socket.socket, client_addr, blacklist: set):
    try:
        raw = recv_request_head(client_sock)
        if not raw:
            return

        try:
            method, url, version = parse_request_line(raw)
        except ValueError as exc:
            logger.warning(f"Bad request from {client_addr}: {exc}")
            return

        if method == "CONNECT":
            send_all(client_sock, NOT_IMPLEMENTED)
            return

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80

        if not host:
            send_all(client_sock, BAD_GATEWAY)
            return

        if blacklist and is_blocked(host, url, blacklist):
            page = BLOCK_PAGE_TEMPLATE.format(url=url).encode("utf-8")
            send_all(client_sock, page)
            logger.info(f"{url} -> 403 Forbidden (blacklisted)")
            return

        upstream_request = build_upstream_request(method, url, version, raw)

        try:
            upstream_sock = socket.create_connection((host, port), timeout=15)
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.warning(f"{url} -> 502 Bad Gateway ({exc})")
            send_all(client_sock, BAD_GATEWAY)
            return

        upstream_sock.settimeout(None)

        try:
            upstream_sock.sendall(upstream_request)
            forward_response(upstream_sock, client_sock, url)
        finally:
            upstream_sock.close()

    except Exception as exc:
        logger.error(f"Unhandled error for {client_addr}: {exc}")
    finally:
        client_sock.close()


def run_proxy(port: int, blacklist: set):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("", port))
    server.listen(256)
    logger.info(f"Proxy listening on port {port}")
    if blacklist:
        logger.info(f"Blacklist loaded: {len(blacklist)} entries")

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr, blacklist),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Shutting down proxy.")
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(description="Simple HTTP Proxy Server")
    parser.add_argument(
        "--port", type=int, default=8888,
        help="Port to listen on (default: 8888)"
    )
    parser.add_argument(
        "--blacklist", type=str, default=BLACKLIST_FILE,
        help=f"Path to blacklist file (default: {BLACKLIST_FILE})"
    )
    args = parser.parse_args()

    blacklist = load_blacklist(args.blacklist)
    run_proxy(args.port, blacklist)


if __name__ == "__main__":
    main()
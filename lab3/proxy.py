import socket
import threading
import select
import sys

BUFFER_SIZE = 4096

def recv_until_header_end(sock):
    """
    Read from sock until we see the end of HTTP headers.
    Returns (header_bytes, remaining_bytes).
    """
    data = b""
    while True:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            # connection closed before full header; may be partial
            break
        data += chunk
        # Look for CRLFCRLF first, then LFLF as a fallback (be lenient)
        idx = data.find(b"\r\n\r\n")
        if idx != -1:
            idx += 4
            return data[:idx], data[idx:]
        idx = data.find(b"\n\n")
        if idx != -1:
            idx += 2
            return data[:idx], data[idx:]
    return data, b""


def parse_host_port(host_header, uri, default_scheme="http"):
    """
    Given the value after 'Host:' and the uri from the request line,
    return (host, port).
    """
    host_header = host_header.strip()
    host = host_header
    port = None

    # If Host header includes ":port" at the end, extract it.
    if ":" in host_header:
        # Simple hostname:port / IPv4:port parsing
        h, p = host_header.rsplit(":", 1)
        if p.isdigit():
            host = h
            port = int(p)

    # Infer scheme from URI if possible
    scheme = default_scheme
    if uri.lower().startswith("http://"):
        scheme = "http"
    elif uri.lower().startswith("https://"):
        scheme = "https"

    if port is None:
        if scheme == "https":
            port = 443
        else:
            port = 80

    return host, port


def rewrite_request_header(header_bytes):
    """
    Lower HTTP version to 1.0 and adjust Connection / Proxy-Connection headers.
    Returns (new_header_bytes, method, uri, is_connect, host, port).
    """
    try:
        header_text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError:
        header_text = header_bytes.decode("utf-8", errors="replace")

    lines = header_text.splitlines()
    if not lines:
        return header_bytes, None, None, False, None, None

    # Request line: METHOD URI VERSION
    request_line = lines[0]
    parts = request_line.split()
    if len(parts) < 2:
        return header_bytes, None, None, False, None, None

    method = parts[0]
    uri = parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.0"

    is_connect = (method.upper() == "CONNECT")

    # Find Host header (case-insensitive)
    host_header_value = None
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host_header_value = line.split(":", 1)[1]
            break

    default_scheme = "https" if is_connect else "http"

    # Compute host/port
    host = None
    port = None
    if is_connect:
        # CONNECT uri is usually "host:port"
        target = uri
        if ":" in target:
            h, p = target.rsplit(":", 1)
            host = h
            if p.isdigit():
                port = int(p)
        if port is None:
            port = 443
    else:
        if host_header_value is not None:
            host, port = parse_host_port(host_header_value, uri, default_scheme)
        else:
            # Fallback; spec says HTTP/1.1 should always give Host:
            host = "localhost"
            port = 80

    # Required log line
    print(f">>> {method} {uri}", flush=True)

    # Rewrite request line with HTTP/1.0
    new_request_line = f"{method} {uri} HTTP/1.0"

    new_lines = [new_request_line]
    saw_proxy_connection = False

    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith("connection:"):
            # Drop any existing Connection header
            continue
        elif lower.startswith("proxy-connection:"):
            # Force proxy connection to close
            new_lines.append("Proxy-Connection: close")
            saw_proxy_connection = True
        else:
            new_lines.append(line)

    # Make sure we discourage keep-alive
    new_lines.append("Connection: close")
    if not saw_proxy_connection:
        new_lines.append("Proxy-Connection: close")

    new_header_text = "\r\n".join(new_lines) + "\r\n\r\n"
    new_header_bytes = new_header_text.encode("iso-8859-1")

    return new_header_bytes, method, uri, is_connect, host, port


def rewrite_response_header(header_bytes):
    """
    Lower HTTP version to 1.0 and adjust Connection / Proxy-Connection headers.
    """
    try:
        header_text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError:
        header_text = header_bytes.decode("utf-8", errors="replace")

    lines = header_text.splitlines()
    if not lines:
        return header_bytes

    status_line = lines[0]
    parts = status_line.split()
    if parts and parts[0].startswith("HTTP/"):
        parts[0] = "HTTP/1.0"
        new_status_line = " ".join(parts)
    else:
        new_status_line = status_line

    new_lines = [new_status_line]
    saw_proxy_connection = False

    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith("connection:"):
            # Drop server's Connection header
            continue
        elif lower.startswith("proxy-connection:"):
            new_lines.append("Proxy-Connection: close")
            saw_proxy_connection = True
        else:
            new_lines.append(line)

    new_lines.append("Connection: close")
    if not saw_proxy_connection:
        new_lines.append("Proxy-Connection: close")

    new_header_text = "\r\n".join(new_lines) + "\r\n\r\n"
    return new_header_text.encode("iso-8859-1")


def tunnel(client_sock, server_sock, initial_client_to_server=b""):
    """
    Bi-directional copy between client_sock and server_sock until EOF.
    Used for CONNECT (HTTPS) tunnels.
    """
    try:
        # If client already sent some bytes after CONNECT header, forward them first.
        if initial_client_to_server:
            server_sock.sendall(initial_client_to_server)

        sockets = [client_sock, server_sock]
        while True:
            readable, _, _ = select.select(sockets, [], [])
            if client_sock in readable:
                data = client_sock.recv(BUFFER_SIZE)
                if not data:
                    break
                server_sock.sendall(data)
            if server_sock in readable:
                data = server_sock.recv(BUFFER_SIZE)
                if not data:
                    break
                client_sock.sendall(data)
    finally:
        # Best effort shutdown
        for s in (client_sock, server_sock):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def handle_client(client_sock, client_addr):
    try:
        # 1. Read client's HTTP header
        header_bytes, rest = recv_until_header_end(client_sock)
        if not header_bytes:
            client_sock.close()
            return

        new_header_bytes, method, uri, is_connect, host, port = rewrite_request_header(header_bytes)

        if host is None or port is None:
            client_sock.close()
            return

        # 2. Connect to the destination server
        try:
            server_sock = socket.create_connection((host, port))
        except OSError:
            if is_connect:
                # CONNECT must send 502 on failure
                resp = b"HTTP/1.0 502 Bad Gateway\r\nConnection: close\r\n\r\n"
                try:
                    client_sock.sendall(resp)
                except OSError:
                    pass
            client_sock.close()
            return

        if is_connect:
            # CONNECT: send 200 to client, then tunnel arbitrary bytes
            success_resp = b"HTTP/1.0 200 Connection Established\r\n\r\n"
            client_sock.sendall(success_resp)
            tunnel(client_sock, server_sock, initial_client_to_server=rest)
            return

        # 3. Non-CONNECT: forward modified request header and any already-read body bytes
        server_sock.sendall(new_header_bytes)
        if rest:
            server_sock.sendall(rest)

        # 4. Read response header from server
        resp_header_bytes, resp_rest = recv_until_header_end(server_sock)

        if resp_header_bytes:
            new_resp_header = rewrite_response_header(resp_header_bytes)
            client_sock.sendall(new_resp_header)
        else:
            # No recognizable header; just stream everything we have
            if resp_rest:
                client_sock.sendall(resp_rest)
            while True:
                chunk = server_sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                client_sock.sendall(chunk)
            server_sock.close()
            client_sock.close()
            return

        # 5. Send any part of the response body that arrived along with the header
        if resp_rest:
            client_sock.sendall(resp_rest)

        # 6. Stream the rest of the response body until the server closes the connection
        while True:
            chunk = server_sock.recv(BUFFER_SIZE)
            if not chunk:
                break
            client_sock.sendall(chunk)

    except Exception:
        pass
    finally:
        try:
            client_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client_sock.close()
        except OSError:
            pass
        # server_sock is closed in the normal paths above


def serve(port):
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow quick restart of the proxy
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("", port))
    listen_sock.listen(100)
    print(f"Proxy listening on port {port}")
    try:
        while True:
            client_sock, client_addr = listen_sock.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        listen_sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)
    serve(int(sys.argv[1]))

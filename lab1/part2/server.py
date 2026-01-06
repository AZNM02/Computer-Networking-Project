import argparse
import os
import random
import socket
import struct
import threading
import time
from typing import Tuple


# Header: 12 bytes: [payload_len:4][psecret:4][step:2][student_last3:2], big-endian
HDR_FMT = "!I I H H"
HDR_LEN = 12


def pad4(n: int) -> int:
    return (-n) & 0x3


def build_header(payload_len: int, psecret: int, step: int, student_last3: int) -> bytes:
    return struct.pack(HDR_FMT, payload_len, psecret & 0xFFFFFFFF, step & 0xFFFF, student_last3 & 0xFFFF)


def parse_header(b: bytes) -> Tuple[int, int, int, int]:
    if len(b) < HDR_LEN:
        raise ValueError("short header")
    return struct.unpack(HDR_FMT, b[:HDR_LEN])


def send_packet_udp(sock: socket.socket, addr, psecret: int, step: int, student_last3: int, payload: bytes) -> None:
    payload_len = len(payload)
    header = build_header(payload_len, psecret, step, student_last3)
    pad = b"\x00" * pad4(payload_len)
    sock.sendto(header + payload + pad, addr)


def send_packet_tcp(sock: socket.socket, psecret: int, step: int, student_last3: int, payload: bytes) -> None:
    payload_len = len(payload)
    header = build_header(payload_len, psecret, step, student_last3)
    pad = b"\x00" * pad4(payload_len)
    sock.sendall(header + payload + pad)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet_tcp(sock: socket.socket) -> Tuple[Tuple[int, int, int, int], bytes]:
    hdr = recv_exact(sock, HDR_LEN)
    payload_len, psecret, step, stu = parse_header(hdr)
    aligned_len = payload_len + pad4(payload_len)
    payload = recv_exact(sock, aligned_len)
    return (payload_len, psecret, step, stu), payload[:payload_len]


def verify_udp_datagram(data: bytes) -> Tuple[Tuple[int, int, int, int], bytes]:
    if len(data) < HDR_LEN:
        raise ValueError("udp datagram too short for header")
    payload_len, psecret, step, stu = parse_header(data)
    actual_payload_len = len(data) - HDR_LEN
    expected_aligned = payload_len + pad4(payload_len)
    if actual_payload_len != expected_aligned:
        raise ValueError("udp payload length/padding mismatch")
    return (payload_len, psecret, step, stu), data[HDR_LEN:HDR_LEN + payload_len]


def rand_uint32() -> int:
    return random.getrandbits(32)


def bind_udp(port: int = 0) -> Tuple[socket.socket, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    return s, s.getsockname()[1]


def bind_tcp_listener(port: int = 0) -> Tuple[socket.socket, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    return s, s.getsockname()[1]


class ClientSession(threading.Thread):
    def __init__(self, a_sock: socket.socket, client_addr, student_last3: int, a_payload: bytes):
        super().__init__(daemon=True)
        self.a_sock = a_sock
        self.client_addr = client_addr
        self.student_last3 = student_last3 & 0xFFFF
        self.a_payload = a_payload

    def run(self) -> None:
        try:
            self.handle_session()
        except Exception:
            # Best-effort: do not crash server; close any sockets inside
            return

    def handle_session(self) -> None:
        # STAGE a1 validation
        if self.a_payload != ("hello world" + "\0").encode("utf-8"):
            return

        # Generate random parameters and open per-session sockets
        num = random.randint(20, 50)
        # len chosen so that client payload = 4 + len, can be any non-negative; keep modest size
        length = random.randint(8, 64)
        secretA = rand_uint32()

        b_sock, udp_port = bind_udp(0)
        try:
            # a2: send response over initial UDP socket
            a2_payload = struct.pack("!I I I I", num, length, udp_port, secretA)
            send_packet_udp(self.a_sock, self.client_addr, psecret=0, step=2, student_last3=self.student_last3, payload=a2_payload)

            # STAGE b1: receive num packets in order on b_sock
            b_sock.settimeout(3.0)
            expected_id = 0
            ack_dropped_once = False
            zeros = b"\x00" * length
            start_ts = time.time()
            while expected_id < num:
                try:
                    data, addr = b_sock.recvfrom(65536)
                except socket.timeout:
                    return
                # must be from same client IP (port may change for UDP, allow addr[0] match)
                if addr[0] != self.client_addr[0]:
                    continue
                try:
                    (payload_len, psecret, step, stu), payload = verify_udp_datagram(data)
                except Exception:
                    return
                if psecret != secretA or step != 1 or (stu & 0xFFFF) != self.student_last3:
                    return
                if payload_len != (4 + length):
                    return
                if len(payload) < 4:
                    return
                (pkt_id,) = struct.unpack("!I", payload[:4])
                if pkt_id != expected_id:
                    # Only accept in-order packets; client should retransmit
                    continue
                if payload[4:] != zeros:
                    return

                # decide to ack or drop; ensure at least one drop overall
                send_ack = True
                if not ack_dropped_once:
                    # force a single drop the first time we see the expected packet id
                    ack_dropped_once = True
                    send_ack = False
                else:
                    # randomize subsequent acks
                    send_ack = random.random() < 0.8

                if send_ack:
                    ack_payload = struct.pack("!I", pkt_id)
                    send_packet_udp(b_sock, addr, psecret=secretA, step=2, student_last3=self.student_last3, payload=ack_payload)
                    expected_id += 1
                # reset inactivity timer on any valid packet
                start_ts = time.time()
                if time.time() - start_ts > 3.0:
                    return

            # STAGE b2: after all received, send tcp_port + secretB on a_sock to original addr
            tcp_listener, tcp_port = bind_tcp_listener(0)
            try:
                secretB = rand_uint32()
                b2_payload = struct.pack("!I I", tcp_port, secretB)
                send_packet_udp(self.a_sock, self.client_addr, psecret=secretA, step=2, student_last3=self.student_last3, payload=b2_payload)

                # STAGE c1: accept TCP within 3 seconds
                tcp_listener.settimeout(3.0)
                try:
                    conn, addr = tcp_listener.accept()
                except socket.timeout:
                    return
                with conn:
                    conn.settimeout(3.0)
                    # STAGE c2: send num2, len2, secretC, c (1 byte)
                    num2 = random.randint(5, 15)
                    len2 = random.randint(16, 64)
                    secretC = rand_uint32()
                    c_byte = bytes([random.randint(65, 90)])  # ASCII A-Z
                    c2_payload = struct.pack("!I I I", num2, len2, secretC) + c_byte
                    send_packet_tcp(conn, psecret=secretB, step=2, student_last3=self.student_last3, payload=c2_payload)

                    # STAGE d1: receive num2 payloads of len2 all == c_byte
                    received = 0
                    while received < num2:
                        try:
                            hdr, payload = recv_packet_tcp(conn)
                        except socket.timeout:
                            return
                        payload_len, psecret, step, stu = hdr
                        if psecret != secretC or step != 1 or (stu & 0xFFFF) != self.student_last3:
                            return
                        if payload_len != len2:
                            return
                        if payload != (c_byte * len2):
                            return
                        received += 1

                    # STAGE d2: send secretD and finish
                    secretD = rand_uint32()
                    d2_payload = struct.pack("!I", secretD)
                    send_packet_tcp(conn, psecret=secretC, step=2, student_last3=self.student_last3, payload=d2_payload)
            finally:
                try:
                    tcp_listener.close()
                except Exception:
                    pass
        finally:
            try:
                b_sock.close()
            except Exception:
                pass


def main() -> None:
    ap = argparse.ArgumentParser(description="CSE461 Part2 Server (Python)")
    ap.add_argument("server", help="Server hostname (unused; for autograder API)")
    ap.add_argument("port", type=int, help="UDP port for stage a1 listener")
    args = ap.parse_args()

    random.seed(os.getpid() ^ int(time.time()))

    # Stage a1 UDP listener
    a_sock, a_port = bind_udp(args.port)
    try:
        a_sock.settimeout(1.0)
        while True:
            try:
                data, addr = a_sock.recvfrom(65536)
            except socket.timeout:
                continue
            # Parse and validate header for a1: psecret=0, step=1; student_last3 can be any
            try:
                (payload_len, psecret, step, stu), payload = verify_udp_datagram(data)
            except Exception:
                # Ignore malformed
                continue
            if step != 1 or psecret != 0:
                # Ignore packets not starting session properly
                continue
            # Spawn session thread per client
            session = ClientSession(a_sock, addr, stu, payload)
            session.start()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            a_sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()



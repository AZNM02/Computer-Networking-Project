import argparse
import socket
import struct
import sys
import time
from typing import Tuple

# Header: 12 bytes: [payload_len:4][psecret:4][step:2][student_last3:2], big-endian
HDR_FMT = "!I I H H"
HDR_LEN = 12

def pad4(n: int) -> int:
    return (-n) & 0x3

def build_header(payload_len: int, psecret: int, step: int, student_last3: int) -> bytes:
    return struct.pack(HDR_FMT, payload_len, psecret & 0xFFFFFFFF, step & 0xFFFF, student_last3 & 0xFFFF)

def parse_header(b: bytes) -> Tuple[int,int,int,int]:
    if len(b) < HDR_LEN:
        raise ValueError("short header")
    return struct.unpack(HDR_FMT, b[:HDR_LEN])

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)

def recv_packet_tcp(sock: socket.socket) -> Tuple[Tuple[int,int,int,int], bytes]:
    # read header
    hdr = recv_exact(sock, HDR_LEN)
    payload_len, psecret, step, stu = parse_header(hdr)
    # read payload and padding 
    aligned_len = payload_len + pad4(payload_len)
    payload = recv_exact(sock, aligned_len)
    return (payload_len, psecret, step, stu), payload[:payload_len]

def send_packet_udp(sock: socket.socket, addr, psecret: int, step: int, student_last3: int, payload: bytes):
    payload_len = len(payload)
    header = build_header(payload_len, psecret, step, student_last3)
    pad = b"\x00" * pad4(payload_len)
    sock.sendto(header + payload + pad, addr)

def send_packet_tcp(sock: socket.socket, psecret: int, step: int, student_last3: int, payload: bytes):
    payload_len = len(payload)
    header = build_header(payload_len, psecret, step, student_last3)
    pad = b"\x00" * pad4(payload_len)
    sock.sendall(header + payload + pad)

def stage_a(server_host: str, port: int, student_last3: int, timeout=3.0):
    
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)

    a1_payload = ("hello world" + "\0").encode("utf-8")
    send_packet_udp(udp, (server_host, port), psecret=0, step=1, student_last3=student_last3, payload=a1_payload)

    # receive response
    data, _ = udp.recvfrom(4096)
    if len(data) < HDR_LEN + 16:
        raise ValueError("Stage a2: response too short")
    # verify header fields; server uses psecret=0, step=2
    payload_len, psecret, step, stu = parse_header(data)
    if step != 2:
        raise ValueError(f"Stage a2: expected step=2, got {step}")
    payload = data[HDR_LEN:HDR_LEN+payload_len]
    num, length, udp_port, secretA = struct.unpack("!I I I I", payload[:16])

    return udp, num, length, udp_port, secretA

def stage_b(udp: socket.socket, server_host: str, udp_port: int, secretA: int, num: int, length: int, student_last3: int, timeout=3.5):
    
    udp.settimeout(0.3)  
    server_addr = (server_host, udp_port)

    # track unacked packets
    payload_zeros = b"\x00" * length
    start = time.time()
    INACTIVITY_GUARD = 60.0

    for pkt_id in range(num):
        payload = struct.pack("!I", pkt_id) + payload_zeros
        # reset timer per packet
        start = time.time()

        while True:
            send_packet_udp(udp, server_addr, psecret=secretA, step=1, student_last3=student_last3, payload=payload)
            try:
                data, _ = udp.recvfrom(4096)
            except socket.timeout:
                # server closes after 60s of not receiving anything
                if time.time() - start > INACTIVITY_GUARD:
                    raise TimeoutError("Stage b1 taking too long")
                # timeout, retry
                continue

            # we got something, reset inactivity timer
            start = time.time()

            if len(data) < HDR_LEN + 4:
                continue
            payload_len, psecret, step, stu = parse_header(data)
            if psecret != secretA or step != 2 or payload_len < 4:
                continue

            ack_payload = data[HDR_LEN:HDR_LEN + payload_len]
            try:
                (acked_id,) = struct.unpack("!I", ack_payload[:4])
            except struct.error:
                continue
            
            if acked_id == pkt_id:
                # ack for the current packet, proceed to next packet
                break
            else:
                # ack for a different packet (or duplicate), ignore and keep waiting/resending
                continue

    # b2: wait for tcp_port + secretB on the SAME UDP socket
    udp.settimeout(timeout)
    data, _ = udp.recvfrom(4096)
    payload_len, psecret, step, stu = parse_header(data)
    if step != 2 or psecret != secretA or payload_len < 8:
        raise ValueError("Stage b2: invalid header or payload")
    payload = data[HDR_LEN:HDR_LEN+payload_len]
    tcp_port, secretB = struct.unpack("!I I", payload[:8])
    return tcp_port, secretB

def stage_c_d(server_host: str, tcp_port: int, secretB: int, student_last3: int):
 
    with socket.create_connection((server_host, tcp_port), timeout=3.0) as s:
        s.settimeout(10.0)

        hdr, payload = recv_packet_tcp(s)
        payload_len, psecret, step, stu = hdr
        if psecret != secretB or step != 2 or payload_len < (4+4+4+1):
            raise ValueError("Stage c2: invalid header/payload")
        num2, len2, secretC = struct.unpack("!I I I", payload[:12])
        c = payload[12:13]
        if len(c) != 1:
            raise ValueError("Stage c2: missing char c")
        # d1: send num2 payloads, each len2 of byte c
        block = c * len2
        for _ in range(num2):
            send_packet_tcp(s, psecret=secretC, step=1, student_last3=student_last3, payload=block)
        # d2: receive secretD (1 uint32)
        hdr2, payload2 = recv_packet_tcp(s)
        payload_len2, psecret2, step2, stu2 = hdr2
        if psecret2 != secretC or step2 != 2 or payload_len2 < 4:
            raise ValueError("Stage d2: invalid response")
        (secretD,) = struct.unpack("!I", payload2[:4])

        return secretC, secretD, num2, len2, c

def main():
    ap = argparse.ArgumentParser(description="CSE461 Part1 Client (Python)")
    ap.add_argument("server", help="Server hostname/IP for stage a1")
    ap.add_argument("port", type=int, help="UDP port for stage a1")
    ap.add_argument("--python", default=f"{sys.version_info.major}.{sys.version_info.minor}", help=argparse.SUPPRESS)
    args = ap.parse_args()

    student_last3 = 534

    # Stage a
    udp, num, length, udp_port, secretA = stage_a(args.server, args.port, student_last3)
    # Stage b
    tcp_port, secretB = stage_b(udp, args.server, udp_port, secretA, num, length, student_last3)
    udp.close()
    # Stage c & d
    secretC, secretD, num2, len2, c = stage_c_d(args.server, tcp_port, secretB, student_last3)

    print(f"A: {secretA}")
    print(f"B: {secretB}")
    print(f"C: {secretC}")
    print(f"D: {secretD}")

if __name__ == "__main__":
    main()

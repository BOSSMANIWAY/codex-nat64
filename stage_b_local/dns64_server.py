#!/usr/bin/env python3
"""Minimal DNS server that emulates a DNS64 resolver (RFC 6147) inside the netns.

Deterministic answers, no upstream recursion:
  web.internal.corp.       AAAA -> 64:ff9b::a14:a   (RFC 6052 WKP + private 10.20.0.10, synthesized)
                           A    -> NODATA           (forces the NAT64 path)
  plainv4.internal.corp.   A    -> 10.20.0.10       (plain IPv4-only intranet name, no AAAA)
  publicnat.internal.corp. AAAA -> 64:ff9b::808:808 (WKP + public 8.8.8.8, legitimate NAT64)
  anything else            -> NXDOMAIN

Binds UDP+TCP port 53 on 0.0.0.0 so the hijacked resolver addresses
(added on lo inside the netns) are answered.
"""
import socket
import struct
import threading

QTYPE_A = 1
QTYPE_AAAA = 28

NAMES = {
    "web.internal.corp.": {QTYPE_AAAA: "64:ff9b::a14:a"},
    "plainv4.internal.corp.": {QTYPE_A: "10.20.0.10"},
    "publicnat.internal.corp.": {QTYPE_AAAA: "64:ff9b::808:808"},
}


def decode_name(query: bytes, start: int):
    """Decode a DNS QNAME into dotted form. Returns (name, offset_of_terminator)."""
    labels = []
    i = start
    while query[i] != 0:
        ln = query[i]
        labels.append(query[i + 1 : i + 1 + ln].decode("ascii").lower())
        i += 1 + ln
    return ".".join(labels) + ".", i


def summarize(query: bytes) -> str:
    try:
        name, i = decode_name(query, 12)
        qtype = struct.unpack("!H", query[i + 1 : i + 3])[0]
        tname = {1: "A", 28: "AAAA"}.get(qtype, str(qtype))
        return f"{tname}? {name}"
    except Exception:
        return "<malformed>"


def question_range(query: bytes):
    qs, qe, qend = 12, 0, 0
    _, qe = decode_name(query, qs)
    qend = qe + 5
    return qs, qe, qend


def build_response(query: bytes) -> bytes:
    tid = query[:2]
    try:
        qs, qe, qend = question_range(query)
        qname, _ = decode_name(query, qs)
        qtype, qclass = struct.unpack("!HH", query[qe + 1 : qend])
    except Exception:
        return tid + struct.pack("!HHIH", 0x8402, 0, 0, 0, 0)

    qname = qname.lower()
    name = qname if qname.endswith(".") else qname + "."
    rec = NAMES.get(name)
    if rec is None:
        # NXDOMAIN, echo the question
        return tid + struct.pack("!HHHHH", 0x8403, 1, 0, 0, 0) + query[qs:qend]

    ip = rec.get(qtype)
    if ip is None:
        # NOERROR / NODATA
        return tid + struct.pack("!HHHHH", 0x8400, 1, 0, 0, 0) + query[qs:qend]

    rdata = (
        socket.inet_pton(socket.AF_INET6, ip)
        if qtype == QTYPE_AAAA
        else socket.inet_pton(socket.AF_INET, ip)
    )
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, qclass, 60, len(rdata)) + rdata
    return tid + struct.pack("!HHHHH", 0x8400, 1, 1, 0, 0) + query[qs:qend] + answer


def serve_udp(sock):
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            print(f"[udp {addr[0]}] {summarize(data)}", flush=True)
            sock.sendto(build_response(data), addr)
        except Exception as e:
            print(f"[udp] error: {e}", flush=True)


def serve_tcp(conn, addr):
    try:
        data = conn.recv(4096)
        if len(data) >= 2:
            ln = struct.unpack("!H", data[:2])[0]
            print(f"[tcp {addr[0]}] {summarize(data[2 : 2 + ln])}", flush=True)
            resp = build_response(data[2 : 2 + ln])
            conn.sendall(struct.pack("!H", len(resp)) + resp)
    except Exception as e:
        print(f"[tcp] error: {e}", flush=True)
    finally:
        conn.close()


def main():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("0.0.0.0", 53))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", 53))
    tcp.listen(8)

    threading.Thread(target=serve_udp, args=(udp,), daemon=True).start()

    def accept_loop():
        while True:
            conn, addr = tcp.accept()
            threading.Thread(target=serve_tcp, args=(conn, addr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    print("dns64 server ready on :53 (udp+tcp)", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fake intra-VPC backend for the Stage B differential test.

Three listeners, all serving the same marker body:
  10.20.0.10:80          plain private IPv4 (the "intranet" target)
  [64:ff9b::a14:a]:80    RFC 6052 WKP embedding 10.20.0.10 (DNS64/NAT64 path)
  [64:ff9b::808:808]:80  RFC 6052 WKP embedding public 8.8.8.8 (legitimate NAT64)

Body reports which address the request came in on, so a 200 response proves
the request really reached the private backend through that route.
"""
import http.server
import socket
import threading

BODY_FMT = "Intra-VPC Connectivity Verified! backend=10.20.0.10 route={route}\n"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Host header as seen by the backend == destination route the client used.
        route = (self.headers.get("Host") or "unknown").strip().strip("[]")
        body = BODY_FMT.format(route=route).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"{self.command} {self.path} host={route} -> 200", flush=True)

    def log_message(self, *args):
        pass


class V6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def main():
    for host, port in [("10.20.0.10", 80), ("64:ff9b::a14:a", 80), ("64:ff9b::808:808", 80)]:
        cls = V6Server if ":" in host else http.server.ThreadingHTTPServer
        srv = cls((host, port), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"backend listening on {host}:{port}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()

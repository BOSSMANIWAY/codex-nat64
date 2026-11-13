#!/usr/bin/env bash
# Stage B: end-to-end differential test of the real codex-network-proxy binary
# inside a user+network namespace (unshare -rn), emulating an intra-VPC NAT64
# environment:
#
#   * fake DNS64 resolver  (dns64_server.py, hijacked resolver IPs on lo:53)
#   * fake intranet backend (backend.py on 10.20.0.10:80 and the WKP v6 addrs)
#   * `ip -6 route add local 64:ff9b::/96 dev lo` makes the whole RFC 6052
#     Well-Known Prefix locally routable, so 64:ff9b::a14:a really connects
#     to the private backend - exactly what a NAT64 gateway does in the wild.
#
# Env:
#   STAGEB_BIN  path to the codex-network-proxy binary under test
#   STAGEB_MODE label (vulnerable | fixed)
#   STAGEB_OUT  output directory for logs and response bodies
#
# Tests (all through the proxy on 127.0.0.1:8080, all target hosts are on the
# allowlist in cfg.json):
#   T1_direct_private_ipv4  http://10.20.0.10/            -> expect BLOCKED in both variants
#   T2_dns64_synthesized    http://web.internal.corp/     -> vulnerable: 200 BYPASS / fixed: BLOCKED
#   T3_plain_A_private      http://plainv4.internal.corp/ -> expect BLOCKED in both variants
#   T4_dns64_public         http://publicnat.internal.corp/ -> expect 200 in both variants (no false positive)
set -euo pipefail

STAGEB_HERE="$(cd "$(dirname "$0")" && pwd)"
: "${STAGEB_BIN:?set STAGEB_BIN to the proxy binary}"
: "${STAGEB_MODE:?set STAGEB_MODE}"
: "${STAGEB_OUT:?set STAGEB_OUT}"
export STAGEB_BIN STAGEB_MODE STAGEB_OUT STAGEB_HERE

unshare -rn bash -s <<'INSIDE'
set -uo pipefail
export STAGEB_BIN STAGEB_MODE STAGEB_OUT STAGEB_HERE
OUT="$STAGEB_OUT"

echo "== [1] netns setup =="
ip link set lo up

# Hijack the host resolver addresses inside this namespace: add them on lo,
# then run our DNS64 emulator on :53. The proxy keeps using the unmodified
# /etc/resolv.conf - it simply resolves via our fake DNS64 server.
RESOLVERS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf | sort -u)
for r in $RESOLVERS; do
  if [[ "$r" == *:* ]]; then ip -6 addr add "$r/128" dev lo 2>/dev/null || true
  else ip -4 addr add "$r/32" dev lo 2>/dev/null || true; fi
done
echo "resolver IPs hijacked locally: $RESOLVERS"
echo "nameservers used by proxy (unchanged): $(grep -c '^nameserver' /etc/resolv.conf) entries in /etc/resolv.conf (NOT modified)"

# The intra-VPC targets:
ip -4 addr add 10.20.0.10/32 dev lo
ip -6 addr add 64:ff9b::a14:a/128 dev lo
ip -6 addr add 64:ff9b::808:808/128 dev lo
# Make the entire RFC 6052 WKP locally routable (NAT64 flow emulation).
ip -6 route add local 64:ff9b::/96 dev lo

echo "== [2] services =="
python3 "$STAGEB_HERE/dns64_server.py" > "$OUT/dns.log" 2>&1 &
DNSPID=$!
python3 "$STAGEB_HERE/backend.py" > "$OUT/backend.log" 2>&1 &
BKDPID=$!
sleep 0.5

# Sanity check: backend reachable directly, bypassing the proxy.
DIRECT=$(curl -sS --max-time 5 http://10.20.0.10/ -o /dev/null -w "%{http_code}" || echo FAIL)
echo "backend direct reachability check (bypassing proxy): HTTP $DIRECT"
if [ "$DIRECT" != "200" ]; then echo "FATAL: backend not reachable"; kill $DNSPID $BKDPID 2>/dev/null; exit 1; fi

echo "== [3] tests through the proxy (127.0.0.1:8080) =="
RUST_LOG=info "$STAGEB_BIN" --config "$STAGEB_HERE/cfg.json" > "$OUT/proxy.log" 2>&1 &
PXDPID=$!

for i in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then exec 3>&- 3<&-; break; fi
  sleep 0.2
  if [ "$i" = 100 ]; then echo "FATAL: proxy did not listen on 8080"; cat "$OUT/proxy.log"; kill $DNSPID $BKDPID 2>/dev/null; exit 1; fi
done
sleep 0.5

req() {
  local name="$1" url="$2"
  echo "---- TEST ${name}: GET ${url} ----"
  curl -sS --max-time 15 --proxy http://127.0.0.1:8080 "$url" -o "$OUT/body_${name}.txt" -w "HTTP_CODE=%{http_code}\n"
}

req T1_direct_private_ipv4  "http://10.20.0.10/"
req T2_dns64_synthesized    "http://web.internal.corp/"
req T3_plain_A_private      "http://plainv4.internal.corp/"
req T4_dns64_public         "http://publicnat.internal.corp/"

kill $PXDPID $DNSPID $BKDPID 2>/dev/null || true
sleep 0.3

echo "== [4] decision log (proxy) =="
grep -E 'blocked|upstream' "$OUT/proxy.log" | sed 's/\r$//' || true

echo "== [5] done (mode=$STAGEB_MODE) =="
echo
echo "===== RESULT BODIES ====="
for f in "$OUT"/body_T*.txt; do
  echo "[$(basename "$f" .txt | sed 's/body_//')] $(head -c 300 "$f")"
done
INSIDE

#!/usr/bin/env bash
# SentinelFlow Phase 4 — closed-loop verification (nftables backend).
#
#   sensor -r <capture>  ->  ZMQ  ->  daemon.py --scorer onnx --mitigate nftables
#                                         |
#                                         v  nft set in namespace sf_host
#   then real packets from flagged_peer / normal_peer into sf_host.
#
# Everything happens in two throwaway network namespaces; the host's own
# nftables ruleset is never touched. Namespaces, the daemon and the nft
# table are removed on exit (also on failure). Outputs go to a temp dir.
#
# Usage (from sentinel-flow/):   sudo bash tests/verify_closed_loop.sh
# Options (environment):
#   CAPTURE       replayed capture (default: holdout 2023-11-20 case)
#   FLAGGED_PEER  address expected to be blocked (default 45.154.98.21)
#   NORMAL_PEER   address that must keep working (default 203.0.113.10)
#   NDPI_LIB      directory with libndpi.so (default ~<user>/nDPI/src/lib)
#   PY_DAEMON     interpreter for daemon.py; must import numpy + onnxruntime
#                 as root (default engine-ml/.venv-runtime/bin/python, created
#                 by: make runtime-venv)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo -E bash "$0" "$@"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN_USER=${SUDO_USER:-$(id -un)}
USER_HOME=$(getent passwd "$RUN_USER" | cut -d: -f6)
CAPTURE=${CAPTURE:-$ROOT/engine-ml/datasets/mta_holdout/2023-11-20/2023-11-20-DarkGate-infection-traffic.pcap}
FLAGGED_PEER=${FLAGGED_PEER:-45.154.98.21}
NORMAL_PEER=${NORMAL_PEER:-203.0.113.10}
NDPI_LIB=${NDPI_LIB:-$USER_HOME/nDPI/src/lib}
NS_HOST=sf_host
NS_PEER=sf_peer
HOST_IP=192.168.50.10
GW_IP=192.168.50.1
PORT=9999
N=50
PAYLOAD=100
PY=/usr/bin/python3                       # stdlib-only helpers
PY_DAEMON=${PY_DAEMON:-$ROOT/engine-ml/.venv-runtime/bin/python}
WORK=$(mktemp -d /tmp/sf_closed_loop.XXXXXX)
DAEMON_PID=""

log() { printf '[verify] %s\n' "$*"; }

cleanup() {
    set +e
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null
    fi
    ip netns del "$NS_HOST" 2>/dev/null
    ip netns del "$NS_PEER" 2>/dev/null
    chown -R "$RUN_USER" "$WORK" 2>/dev/null
    log "cleanup: namespaces removed: $(ip netns list | grep -c '^sf_' || true) left; outputs kept in $WORK"
}
trap cleanup EXIT

[[ -f "$CAPTURE" ]] || { echo "capture not found: $CAPTURE (run: make fetch-data)"; exit 1; }
[[ -x "$ROOT/sensor-c/build/sensor" ]] || { echo "build the sensor first: make sensor"; exit 1; }
# Preflight: the daemon's interpreter must load the ONNX models as root
# (a user-only site-packages path is not visible under sudo).
if ! "$PY_DAEMON" -c "import sys; sys.path.insert(0, '$ROOT/engine-ml'); import daemon; daemon.OnnxScorer()" 2> "$WORK/preflight.log"; then
    echo "PY_DAEMON=$PY_DAEMON cannot load the ONNX models as root:"
    tail -2 "$WORK/preflight.log"
    echo "fix: make runtime-venv   (or set PY_DAEMON to an interpreter with numpy + onnxruntime)"
    exit 1
fi

# ── Helpers (UDP sender / listener) ────────────────────────────────────
cat > "$WORK/send.py" <<'EOF'
import socket, sys
src, dst, port, n, size = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, 0))
for _ in range(n): s.sendto(b"x" * size, (dst, port))
EOF
cat > "$WORK/listen.py" <<'EOF'
import socket, sys, collections, time, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", int(sys.argv[1])))
s.settimeout(0.2); seen = collections.Counter(); end = time.time() + float(sys.argv[2])
while time.time() < end:
    try:
        _, (ip, _) = s.recvfrom(4096); seen[ip] += 1
    except socket.timeout:
        pass
print(json.dumps(seen))
EOF

wave() {  # wave <label>  -> prints {"ip": received, ...}
    ip netns exec "$NS_HOST" "$PY" "$WORK/listen.py" "$PORT" 3 > "$WORK/$1.json" &
    local lp=$!
    sleep 0.5
    ip netns exec "$NS_PEER" "$PY" "$WORK/send.py" "$FLAGGED_PEER" "$HOST_IP" "$PORT" "$N" "$PAYLOAD"
    ip netns exec "$NS_PEER" "$PY" "$WORK/send.py" "$NORMAL_PEER"  "$HOST_IP" "$PORT" "$N" "$PAYLOAD"
    wait "$lp"
    cat "$WORK/$1.json"
}

nft_counter() {  # prints "<packets> <bytes>" for FLAGGED_PEER, or "absent"
    local j
    j=$(ip netns exec "$NS_HOST" nft -j list set inet sentinel blocked_ipv4 2>/dev/null || true)
    printf '%s' "$j" | "$PY" -c '
import json, sys
ip = sys.argv[1]
raw = sys.stdin.read()
if not raw.strip():
    print("absent"); sys.exit()
for item in json.loads(raw).get("nftables", []):
    for e in item.get("set", {}).get("elem", []) or []:
        e = e.get("elem", e) if isinstance(e, dict) else {"val": e}
        if e.get("val") == ip:
            c = e.get("counter", {}); print(c.get("packets", 0), c.get("bytes", 0)); sys.exit()
print("absent")' "$FLAGGED_PEER"
}

received() { "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], 0))' "$1" "$2"; }

# ── Lab topology ──────────────────────────────────────────────────────
ip netns del "$NS_HOST" 2>/dev/null || true
ip netns del "$NS_PEER" 2>/dev/null || true
ip netns add "$NS_HOST"
ip netns add "$NS_PEER"
ip link add veth-h netns "$NS_HOST" type veth peer name veth-p netns "$NS_PEER"
ip netns exec "$NS_HOST" ip addr add "$HOST_IP/24" dev veth-h
ip netns exec "$NS_PEER" ip addr add "$GW_IP/24" dev veth-p
ip netns exec "$NS_PEER" ip addr add "$FLAGGED_PEER/32" dev veth-p
ip netns exec "$NS_PEER" ip addr add "$NORMAL_PEER/32" dev veth-p
for ns_dev in "$NS_HOST veth-h" "$NS_PEER veth-p"; do
    set -- $ns_dev
    ip netns exec "$1" ip link set "$2" up
    ip netns exec "$1" ip link set lo up
done
ip netns exec "$NS_HOST" ip route add "$FLAGGED_PEER/32" via "$GW_IP"
ip netns exec "$NS_HOST" ip route add "$NORMAL_PEER/32" via "$GW_IP"
log "namespaces $NS_HOST ($HOST_IP) <-> $NS_PEER (flagged_peer=$FLAGGED_PEER, normal_peer=$NORMAL_PEER)"

# ── Baseline: both peers reach the host ───────────────────────────────
log "baseline (no blocks): received at host: $(wave baseline)"

# ── Wave 1: replay -> score -> automatic block ─────────────────────────
export LD_LIBRARY_PATH="$NDPI_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$PY_DAEMON" "$ROOT/engine-ml/daemon.py" -e "ipc://$WORK/flows.sock" \
    --backend sqlite --db "$WORK/flows.db" --jsonl "$WORK/flows.jsonl" \
    --rejected "$WORK/rejected.jsonl" --mitigations-jsonl "$WORK/mitigations.jsonl" \
    --scorer onnx --mitigate nftables --mitigate-netns "$NS_HOST" \
    2> "$WORK/daemon.log" &
DAEMON_PID=$!
for _ in $(seq 100); do grep -q " ready" "$WORK/daemon.log" && break; sleep 0.1; done
if ! kill -0 "$DAEMON_PID" 2>/dev/null || ! grep -q " ready" "$WORK/daemon.log"; then
    echo "daemon.py did not start; last lines of $WORK/daemon.log:"
    tail -5 "$WORK/daemon.log"
    exit 1
fi
grep -E "scorer:|mitigation:" "$WORK/daemon.log" | sed 's/^/  /' || true

log "wave 1: sensor -r $(basename "$CAPTURE") -A 0"
"$ROOT/sensor-c/build/sensor" -r "$CAPTURE" -A 0 -z "ipc://$WORK/flows.sock" 2> "$WORK/sensor.log"
grep -E "Packets processed|Flows exported|Flows dropped" "$WORK/sensor.log" | tr -s ' ║' ' ' | sed 's/^/  /' || true

for _ in $(seq 60); do [[ $(nft_counter) != absent ]] && break; sleep 0.5; done
grep -E "flushed|BLOCK" "$WORK/daemon.log" | sed 's/^/  /' || true
log "nft set in $NS_HOST after wave 1:"
ip netns exec "$NS_HOST" nft list set inet sentinel blocked_ipv4 | sed 's/^/  /' || true
BEFORE=$(nft_counter)
log "counter for flagged_peer before wave 2: $BEFORE"

# ── Wave 2: real packets from both peers ──────────────────────────────
W2=$(wave wave2)
AFTER=$(nft_counter)
log "wave 2: sent $N from each peer; received at host: $W2"
log "counter for flagged_peer after wave 2: $AFTER"

sleep 11   # daemon refreshes kernel counters every 10 s
kill -TERM "$DAEMON_PID" 2>/dev/null || echo "  (daemon had already exited; see $WORK/daemon.log)"
wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""
log "daemon audit for flagged_peer:"
grep "\"$FLAGGED_PEER\"" "$WORK/mitigations.jsonl" | sed 's/^/  /' || true
"$PY" - "$WORK/flows.db" "$FLAGGED_PEER" <<'EOF' | sed 's/^/  /'
import sqlite3, sys
r = sqlite3.connect(sys.argv[1]).execute(
    "SELECT ip, backend, status, reason, round(score,3), dropped_pkts, dropped_bytes, flow "
    "FROM blocked_ips WHERE ip=?", (sys.argv[2],)).fetchone()
print("blocked_ips row:", r)
EOF

# ── Verdict ───────────────────────────────────────────────────────────
GOT_FLAGGED=$(received "$WORK/wave2.json" "$FLAGGED_PEER")
GOT_NORMAL=$(received "$WORK/wave2.json" "$NORMAL_PEER")
EXP_BYTES=$(( N * (20 + 8 + PAYLOAD) ))
read -r PK0 BY0 <<< "${BEFORE/absent/x x}"
read -r PK1 BY1 <<< "${AFTER/absent/x x}"
ok() { if [[ "$1" == "$2" ]]; then echo "PASS"; else echo "FAIL"; fi; }
echo
echo "=== CLOSED-LOOP RESULT ($(date -u +%FT%TZ)) ==="
echo "wave 1  flagged_peer in nft set after replay           : $([[ $BEFORE != absent ]] && echo PASS || echo FAIL)"
echo "wave 2  flagged_peer packets delivered   $GOT_FLAGGED / $N (want 0)  : $(ok "$GOT_FLAGGED" 0)"
echo "wave 2  normal_peer packets delivered    $GOT_NORMAL / $N (want $N) : $(ok "$GOT_NORMAL" "$N")"
if [[ $BEFORE != absent && $AFTER != absent ]]; then
    echo "wave 2  nft counter delta packets        $((PK1 - PK0)) (want $N)      : $(ok $((PK1 - PK0)) "$N")"
    echo "wave 2  nft counter delta bytes          $((BY1 - BY0)) (want $EXP_BYTES)  : $(ok $((BY1 - BY0)) "$EXP_BYTES")"
fi
echo "outputs: $WORK"

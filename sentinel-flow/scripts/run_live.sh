#!/usr/bin/env bash
# SentinelFlow — live capture on one interface: sensor + daemon (+ optional web dashboard).
#
#   bash scripts/run_live.sh -i enp0s8 -a 192.168.56.1            # log decisions only (dry-run)
#   bash scripts/run_live.sh -i enp0s8 -a 192.168.56.1 --serve    # + dashboard on 127.0.0.1:8080
#   bash scripts/run_live.sh -i enp0s8 -a 192.168.56.1 --block    # really block with nftables
#
# Options:
#   -i IFACE         interface to capture on (required; list them with: ip -br addr)
#   -a IP|CIDR       never block this address (repeatable), e.g. your own admin machine
#   -A SEC           active timeout for long flows (default 60)
#   --block          enforce with nftables (daemon runs as root; blocks expire after 15 min)
#   --serve          also serve the dashboard on 127.0.0.1:8080 (reach it via an SSH tunnel)
#   --data-dir DIR   write flows, SQLite, mitigations and logs here (default engine-ml/data)
#   --no-clickhouse  don't write to ClickHouse even if it is running (SQLite + JSONL only)
#
# Ctrl+C stops the sensor (which flushes open flows), then the daemon and dashboard.
# Logs: engine-ml/data/logs/   Results: engine-ml/data/ (flows, mitigations.jsonl, SQLite)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IFACE="" ACTIVE=60 BLOCK=0 SERVE=0 DATA="" BACKEND=auto
ALLOW=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) IFACE=$2; shift ;;
        -a) ALLOW+=(--allowlist "$2"); shift ;;
        -A) ACTIVE=$2; shift ;;
        --block) BLOCK=1 ;;
        --serve) SERVE=1 ;;
        --data-dir) DATA=$2; shift ;;
        --no-clickhouse) BACKEND=sqlite ;;
        -h|--help) sed -n '2,/^set -euo/{/^set -euo/!p}' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (see --help)"; exit 2 ;;
    esac
    shift
done

die() { echo "error: $*" >&2; exit 1; }
[[ -n "$IFACE" ]] || die "-i IFACE is required (interfaces: $(ip -br link | awk '{print $1}' | tr '\n' ' '))"
ip link show "$IFACE" >/dev/null 2>&1 || die "no such interface: $IFACE"
PY="$ROOT/engine-ml/.venv-runtime/bin/python"
[[ -x "$PY" ]] || die "runtime venv missing: run scripts/install_deps.sh (or make runtime-venv)"
[[ -x "$ROOT/sensor-c/build/sensor" ]] || die "sensor not built: run scripts/install_deps.sh (or make sensor)"
NDPI_LIB=${NDPI_LIB:-$HOME/nDPI/src/lib}
[[ -f "$NDPI_LIB/libndpi.so" ]] || die "libndpi not found in $NDPI_LIB (set NDPI_LIB)"
[[ ${#ALLOW[@]} -gt 0 ]] || echo "note: no -a given; consider allowlisting your own admin machine's IP"

DATA=$(realpath -m "${DATA:-$ROOT/engine-ml/data}")
LOGS="$DATA/logs"
mkdir -p "$LOGS"
STAMP=$(date +%Y%m%d-%H%M%S)
export LD_LIBRARY_PATH="$NDPI_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
PIDS=() DAEMON_PID=""
# Background services run in their own session (setsid) so Ctrl+C reaches only
# the sensor; they are stopped by cleanup() after the sensor has flushed.

# kill for the processes we started (the daemon runs as root with --block).
signal() { if [[ $BLOCK -eq 1 ]]; then sudo kill "$@"; else kill "$@"; fi; }

# A root daemon (--block) creates its output files as root; a later normal
# run could then not write them. Give any such files back to this user.
OUTPUTS=("$DATA/sentinel_flows.db" "$DATA/sentinel_flows.db-wal" "$DATA/sentinel_flows.db-shm"
         "$DATA/flows.jsonl" "$DATA/rejected.jsonl" "$DATA/mitigations.jsonl")
take_back_outputs() {
    local f stale=()
    for f in "${OUTPUTS[@]}"; do
        if [[ -e "$f" && ! -O "$f" ]]; then stale+=("$f"); fi
    done
    if [[ ${#stale[@]} -gt 0 ]]; then
        echo "giving root-owned files back to $(id -un): ${stale[*]##*/}"
        sudo chown "$(id -u):$(id -g)" "${stale[@]}"
    fi
}

cleanup() {
    trap - EXIT INT TERM
    sleep 2                      # let the daemon take the sensor's final flush
    for p in "${PIDS[@]}"; do signal -TERM "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    # The daemon is not always our child (see PIDFILE below): wait for it by PID.
    if [[ -n "$DAEMON_PID" ]]; then
        for _ in $(seq 50); do signal -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.2; done
    fi
    take_back_outputs || true
    echo
    echo "--- stopped. Last daemon lines ($LOGS/daemon-$STAMP.log):"
    tail -4 "$LOGS/daemon-$STAMP.log" 2>/dev/null || true
    echo "--- results: $PY $ROOT/engine-ml/query_dashboard.py --db $DATA/sentinel_flows.db"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

DAEMON=("$PY" "$ROOT/engine-ml/daemon.py" --scorer onnx --backend "$BACKEND" "${ALLOW[@]}"
        --db "$DATA/sentinel_flows.db" --jsonl "$DATA/flows.jsonl"
        --rejected "$DATA/rejected.jsonl" --mitigations-jsonl "$DATA/mitigations.jsonl")
# sudo can start its command as a process-group leader (use_pty, the default
# since sudo 1.9.14); setsid then forks, so $! is not the daemon and Ctrl+C
# would leave a root daemon running. The daemon's shell writes its own PID to
# a file just before it becomes the daemon (exec), and cleanup() signals that.
PIDFILE="$LOGS/daemon-$STAMP.pid"
WRITE_PID=(sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$PIDFILE")
take_back_outputs
if [[ $BLOCK -eq 1 ]]; then
    echo "mode: BLOCK (nftables, table inet sentinel); daemon runs as root"
    sudo -v
    sudo setsid "${WRITE_PID[@]}" env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "${DAEMON[@]}" \
        --mitigate nftables 2> "$LOGS/daemon-$STAMP.log" &
else
    echo "mode: dry-run (decisions are logged to $DATA/mitigations.jsonl, nothing is blocked)"
    setsid "${WRITE_PID[@]}" "${DAEMON[@]}" --mitigate dry-run 2> "$LOGS/daemon-$STAMP.log" &
fi
for _ in $(seq 50); do [[ -s "$PIDFILE" ]] && break; sleep 0.1; done
DAEMON_PID=$(cat "$PIDFILE" 2>/dev/null || true)
if [[ -n "$DAEMON_PID" ]]; then PIDS+=("$DAEMON_PID"); fi
for _ in $(seq 100); do grep -q " ready" "$LOGS/daemon-$STAMP.log" 2>/dev/null && break; sleep 0.1; done
grep -q " ready" "$LOGS/daemon-$STAMP.log" || { tail -5 "$LOGS/daemon-$STAMP.log"; die "daemon did not start"; }
grep -E "scorer:|mitigation:" "$LOGS/daemon-$STAMP.log" | sed 's/^/  /'

if [[ $SERVE -eq 1 ]]; then
    setsid "$PY" "$ROOT/engine-ml/query_dashboard.py" --db "$DATA/sentinel_flows.db" --serve --port 8080 2> "$LOGS/dashboard-$STAMP.log" &
    PIDS+=($!)
    sleep 1                      # it exits at once if port 8080 is taken or the DB is missing
    if kill -0 "$!" 2>/dev/null; then
        echo "dashboard: http://127.0.0.1:8080 on this machine (from another machine: ssh -L 8080:127.0.0.1:8080 ...)"
    else
        echo "warning: dashboard did not start: $(tail -1 "$LOGS/dashboard-$STAMP.log")"
    fi
fi

echo "capturing on $IFACE (active timeout ${ACTIVE}s) — Ctrl+C to stop"
sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$ROOT/sensor-c/build/sensor" -i "$IFACE" -A "$ACTIVE" \
    2> "$LOGS/sensor-$STAMP.log" || true
tail -9 "$LOGS/sensor-$STAMP.log" | grep -E "Packets|tracked|exported|dropped|Snapshot" || true

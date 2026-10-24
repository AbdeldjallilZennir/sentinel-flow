#!/usr/bin/env bash
# SentinelFlow — rebuild the dataset and retrain on Google Colab (or any
# Ubuntu machine where you are root), then package the model.
#
# In a Colab code cell:
#   !git clone -q https://github.com/AbdeldjallilZennir/sentinel-flow.git /root/cv_work
#   !bash /root/cv_work/sentinel-flow/scripts/colab_train.sh
# then download /root/sentinel_model.zip:
#   from google.colab import files; files.download("/root/sentinel_model.zip")
#
# Same pipeline as `make fetch-data dataset train holdout`. Data: 40
# malware-traffic-analysis.net cases (17 original + 23 added in Part 7) and
# the nDPI test corpus; the 5 holdout cases are never trained on.
#
# Steps: build -> score the CURRENT model on the holdout (baseline) -> fetch
# + build the dataset -> check every MTA case got malicious flows -> train ->
# holdout again -> before/after comparison. Install/build output:
# /root/setup.log. The zip also holds the dataset summary and the comparison.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

ROOT=$(cd "$(dirname "$0")/.." && pwd)        # sentinel-flow/
NDPI=${NDPI_DIR:-/root/nDPI}
NDPI_REF=90eb617a4
LOG=/root/setup.log
OUT=/root/sentinel_model.zip
: > "$LOG"

[[ $EUID -eq 0 ]] || { echo "run as root (Colab cells already are)"; exit 1; }
step() { echo; echo "==> $*"; }
fail() { echo "FAILED: $*"; echo "--- last lines of $LOG:"; tail -30 "$LOG"; exit 1; }

step "packages"
echo "wireshark-common wireshark-common/install-setuid boolean false" \
    | debconf-set-selections
apt-get update -qq >>"$LOG" 2>&1 || true
apt-get install -y -qq --no-install-recommends \
    build-essential cmake pkg-config git autoconf automake libtool \
    libpcap-dev libzmq3-dev tshark p7zip-full sqlite3 zip \
    >>"$LOG" 2>&1 || fail "apt-get install"

step "repository: $(git -C "$ROOT" log --oneline -1)"

step "nDPI at $NDPI_REF"
if [[ ! -f "$NDPI/src/lib/libndpi.so" ]]; then
    rm -rf "$NDPI"
    git clone -q https://github.com/ntop/nDPI.git "$NDPI" >>"$LOG" 2>&1 \
        || fail "nDPI clone"
    git -C "$NDPI" checkout -q "$NDPI_REF"
    ( cd "$NDPI" && ./autogen.sh && { [[ -f Makefile ]] || ./configure; } \
        && make -C src/lib -j"$(nproc)" ) >>"$LOG" 2>&1 || fail "nDPI build"
fi
ls "$NDPI"/src/lib/libndpi.so.*.*.*

step "sensor"
cmake -S "$ROOT/sensor-c" -B "$ROOT/sensor-c/build" -DNDPI_ROOT="$NDPI" \
    >>"$LOG" 2>&1 || fail "cmake"
make -C "$ROOT/sensor-c/build" -j"$(nproc)" >>"$LOG" 2>&1 || fail "sensor build"
export LD_LIBRARY_PATH="$NDPI/src/lib"

step "Python packages ($(python3 --version))"
pip install -q -r "$ROOT/engine-ml/requirements-train.txt" >>"$LOG" 2>&1 \
    || fail "pip install (pinned versions in engine-ml/requirements-train.txt)"

step "quick checks"
( cd "$ROOT/sensor-c/build" && ./test_flow | tail -1 && ./test_stats | tail -1 )
python3 "$ROOT/engine-ml/tests/test_daemon.py" 2>&1 | tail -1

step "holdout captures (~100 MB)"
{ python3 "$ROOT/engine-ml/datasets/fetch_mta.py" --holdout | grep -v "^\[skip\]" || true; } | tail -6

step "baseline: current model on the holdout"
python3 "$ROOT/engine-ml/models/evaluate_holdout.py" 2>&1 | grep -v "daemon ready" | tail -8
cp "$ROOT/engine-ml/models/evaluation_holdout.json" /root/holdout_before.json

step "training data (40 MTA cases, ~700 MB)"
python3 "$ROOT/engine-ml/datasets/fetch_mta.py" | grep -vE "^\[(skip|ok)\]" || true
echo "MTA cases on disk: $(ls "$ROOT/engine-ml/datasets/mta" | wc -l) (expected 40)"

step "dataset"
python3 "$ROOT/engine-ml/models/build_dataset.py" --no-clickhouse 2>&1 \
    | grep -vE "^\[(mta|ndpi|repo)\] " | tail -30

step "label check (every MTA case should have malicious flows)"
python3 - "$ROOT/engine-ml/data/training/summary.json" <<'PY'
import collections, json, sys
s = json.load(open(sys.argv[1]))
per = collections.defaultdict(lambda: collections.Counter())
for p in s["per_pcap"]:
    if p["source"] == "mta":
        per[p["group"]].update({k: p.get(k, 0) for k in ("malicious", "benign", "ambiguous")})
empty = [g for g, c in sorted(per.items()) if not c["malicious"]]
print(f"{len(per)} MTA cases, {sum(c['malicious'] for c in per.values())} malicious flows")
for g, c in sorted(per.items()):
    print(f"  {g:16s} malicious={c['malicious']:6d} benign={c['benign']:6d} ambiguous={c['ambiguous']:5d}")
if empty:
    print("WARNING: no malicious flows in", ", ".join(empty), "- check mta_labels.json")
PY

step "training (5 seeds, a few minutes)"
python3 "$ROOT/engine-ml/models/train_pipeline.py" 2>&1 \
    | grep -vE "UserWarning|warnings.warn|VerifyOutputSizes" | tail -40

step "holdout evaluation (new model)"
python3 "$ROOT/engine-ml/models/evaluate_holdout.py" 2>&1 | grep -v "daemon ready" | tail -12

step "before / after on the holdout (the like-for-like comparison)"
python3 "$ROOT/engine-ml/models/compare_holdout.py" /root/holdout_before.json \
    "$ROOT/engine-ml/models/evaluation_holdout.json" | tee /root/holdout_compare.txt

step "package"
cp "$ROOT/engine-ml/data/training/summary.json" /root/dataset_summary.json
( cd "$ROOT/engine-ml/models" && rm -f "$OUT" && zip -q "$OUT" \
    c2_detector.onnx anomaly_iforest.onnx model_meta.json \
    evaluation.json evaluation_holdout.json )
( cd /root && zip -q "$OUT" holdout_before.json holdout_compare.txt dataset_summary.json )
python3 -c "import json; m=json.load(open('$ROOT/engine-ml/models/model_meta.json')); print('model:', m['model_version'])"
ls -la "$OUT"
echo "download: from google.colab import files; files.download('$OUT')"

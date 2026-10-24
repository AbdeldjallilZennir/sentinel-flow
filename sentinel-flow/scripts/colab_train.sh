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
# Same pipeline and data as `make fetch-data dataset train holdout`
# (MTA cases + nDPI test corpus). Install/build output: /root/setup.log
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

step "training data (~380 MB)"
python3 "$ROOT/engine-ml/datasets/fetch_mta.py" | tail -3
python3 "$ROOT/engine-ml/datasets/fetch_mta.py" --holdout | tail -2

step "dataset"
python3 "$ROOT/engine-ml/models/build_dataset.py" --no-clickhouse 2>&1 | tail -25

step "training (5 seeds, a few minutes)"
python3 "$ROOT/engine-ml/models/train_pipeline.py" 2>&1 \
    | grep -vE "UserWarning|warnings.warn|VerifyOutputSizes" | tail -40

step "holdout evaluation"
python3 "$ROOT/engine-ml/models/evaluate_holdout.py" 2>&1 | tail -10

step "package"
( cd "$ROOT/engine-ml/models" && rm -f "$OUT" && zip -q "$OUT" \
    c2_detector.onnx anomaly_iforest.onnx model_meta.json \
    evaluation.json evaluation_holdout.json )
python3 -c "import json; m=json.load(open('$ROOT/engine-ml/models/model_meta.json')); print('model:', m['model_version'])"
ls -la "$OUT"
echo "download: from google.colab import files; files.download('$OUT')"

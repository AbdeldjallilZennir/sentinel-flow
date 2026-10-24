#!/usr/bin/env bash
# SentinelFlow — install dependencies and build on a fresh Ubuntu / Debian / Kali machine.
#
# Run as your normal user from anywhere inside the repo; sudo is used only
# for apt. (In a container where you are already root and sudo is absent,
# it runs apt directly.)
#
#   bash sentinel-flow/scripts/install_deps.sh                 # core: sensor + daemon + ONNX scoring + tests
#   bash sentinel-flow/scripts/install_deps.sh --all           # everything below
#
# Options:
#   --with-training   ML training virtualenv (lightgbm, scikit-learn, onnx tooling)
#   --with-data       tools to rebuild the dataset: tshark (labeling), 7z (archives)
#   --with-docker     Docker + Compose for ClickHouse / Grafana
#   --with-xdp        clang/llvm for the experimental XDP sources (not attached; see docs/REPORT.md, Part 4 §6)
#   --ndpi-dir DIR    where to clone/build nDPI (default: ~/nDPI, the path the sensor build expects)
#   --ndpi-ref REF    nDPI commit to build (default: the commit the project was verified with)
#   --skip-tests      don't run the test suites at the end
#
# Non-interactive use (e.g. over ssh without a terminal): set SUDO_ASKPASS to a
# program that prints the sudo password; the script then uses "sudo -A".
#
# What it does:
#   1. apt: compiler toolchain, cmake, libpcap, libzmq, Python venv, nftables, iproute2
#   2. clones nDPI, checks out the pinned commit, builds libndpi
#   3. builds the C sensor (sensor-c/build)
#   4. creates engine-ml/.venv-runtime (numpy + onnxruntime 1.31.0) for the ONNX scorer
#   5. runs make test-sensor and make test-engine
set -euo pipefail

NDPI_REPO=https://github.com/ntop/nDPI.git
NDPI_REF=90eb617a4                 # nDPI 6.1.0-dev used for every report in this repo
NDPI_DIR="$HOME/nDPI"
WITH_TRAINING=0 WITH_DATA=0 WITH_DOCKER=0 WITH_XDP=0 RUN_TESTS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-training) WITH_TRAINING=1 ;;
        --with-data)     WITH_DATA=1 ;;
        --with-docker)   WITH_DOCKER=1 ;;
        --with-xdp)      WITH_XDP=1 ;;
        --all)           WITH_TRAINING=1; WITH_DATA=1; WITH_DOCKER=1; WITH_XDP=1 ;;
        --ndpi-dir)      NDPI_DIR=$2; shift ;;
        --ndpi-ref)      NDPI_REF=$2; shift ;;
        --skip-tests)    RUN_TESTS=0 ;;
        -h|--help)       sed -n '2,/^set -euo/{/^set -euo/!p}' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (see --help)"; exit 2 ;;
    esac
    shift
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── Environment checks ─────────────────────────────────────────────────
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)                       # sentinel-flow/
[[ -f "$ROOT/sensor-c/CMakeLists.txt" ]] || die "run this script from the SentinelFlow repository"

. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*|*" kali "*) ;;
    *) die "supported: Ubuntu, Debian, Kali (found: ${PRETTY_NAME:-unknown})" ;;
esac

if [[ $EUID -eq 0 ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        die "run as your normal user (not with sudo); the script calls sudo for apt only"
    fi
    SUDO=""                                              # real root, e.g. a container
else
    command -v sudo >/dev/null || die "sudo is required to install packages"
    SUDO="sudo"
    [[ -n "${SUDO_ASKPASS:-}" ]] && SUDO="sudo -A"
fi
export DEBIAN_FRONTEND=noninteractive
APT="$SUDO env DEBIAN_FRONTEND=noninteractive apt-get"

step "System: ${PRETTY_NAME}, kernel $(uname -r), user $(id -un)"

# ── 1. Packages ─────────────────────────────────────────────────────────
PKGS=(build-essential cmake pkg-config git ca-certificates curl
      autoconf automake libtool
      libpcap-dev libzmq3-dev
      python3 python3-venv python3-pip
      nftables iproute2 sqlite3)
(( WITH_DATA ))  && PKGS+=(tshark p7zip-full)
(( WITH_XDP ))   && PKGS+=(clang llvm)

step "apt: installing ${#PKGS[@]} packages"
$APT update -q
if (( WITH_DATA )); then
    # tshark asks whether non-root users may capture; answer "no" up front.
    echo "wireshark-common wireshark-common/install-setuid boolean false" | $SUDO debconf-set-selections
fi
$APT install -y -q --no-install-recommends "${PKGS[@]}"

if (( WITH_DOCKER )); then
    step "apt: Docker + Compose"
    $APT install -y -q docker.io
    $APT install -y -q docker-compose-v2 2>/dev/null \
        || $APT install -y -q docker-compose-plugin 2>/dev/null \
        || $APT install -y -q docker-compose \
        || echo "warning: no Compose package found; install Docker Compose manually"
    if [[ -n "$SUDO" ]]; then
        $SUDO usermod -aG docker "$(id -un)" && echo "added $(id -un) to the docker group (log out and back in)"
    fi
fi

# ── 2. nDPI ─────────────────────────────────────────────────────────────
step "nDPI: $NDPI_DIR at $NDPI_REF"
if [[ ! -d "$NDPI_DIR/.git" ]]; then
    git clone --quiet "$NDPI_REPO" "$NDPI_DIR"
fi
git -C "$NDPI_DIR" fetch --quiet origin || true
if [[ "$(git -C "$NDPI_DIR" rev-parse --short=9 HEAD)" != "${NDPI_REF:0:9}" ]]; then
    if [[ -n "$(git -C "$NDPI_DIR" status --porcelain --untracked-files=no)" ]]; then
        die "$NDPI_DIR has local changes; commit/stash them or use --ndpi-dir"
    fi
    git -C "$NDPI_DIR" checkout --quiet "$NDPI_REF"
fi
if [[ ! -f "$NDPI_DIR/src/lib/libndpi.so" ]]; then
    # At the pinned commit autogen.sh only regenerates the build system; it
    # does not run configure, so do that when no Makefile was produced.
    ( cd "$NDPI_DIR" && ./autogen.sh >/dev/null \
        && { [[ -f Makefile ]] || ./configure >/dev/null; } \
        && make -C src/lib -j"$(nproc)" >/dev/null )
fi
[[ -f "$NDPI_DIR/src/lib/libndpi.so" ]] || die "libndpi build failed"
echo "libndpi: $(ls "$NDPI_DIR"/src/lib/libndpi.so.*.*.* 2>/dev/null | head -1)"

# ── 3. Sensor ──────────────────────────────────────────────────────────
step "Sensor build"
cmake -S "$ROOT/sensor-c" -B "$ROOT/sensor-c/build" -DNDPI_ROOT="$NDPI_DIR" >/dev/null
make -C "$ROOT/sensor-c/build" -j"$(nproc)" 2>&1 | grep -E "warning|error|Built target" || true
[[ -x "$ROOT/sensor-c/build/sensor" ]] || die "sensor build failed"

# ── 4. Python environments ──────────────────────────────────────────────
step "Python runtime venv (engine-ml/.venv-runtime: numpy + onnxruntime 1.31.0)"
python3 -m venv "$ROOT/engine-ml/.venv-runtime"
"$ROOT/engine-ml/.venv-runtime/bin/pip" install -q --upgrade pip
"$ROOT/engine-ml/.venv-runtime/bin/pip" install -q "onnxruntime==1.31.0" numpy
"$ROOT/engine-ml/.venv-runtime/bin/python" -c "
import sys; sys.path.insert(0, '$ROOT/engine-ml'); import daemon
print('ONNX scorer loads:', daemon.OnnxScorer().name)"

if (( WITH_TRAINING )); then
    step "Python training venv (engine-ml/.venv-train)"
    python3 -m venv "$ROOT/engine-ml/.venv-train"
    "$ROOT/engine-ml/.venv-train/bin/pip" install -q --upgrade pip
    "$ROOT/engine-ml/.venv-train/bin/pip" install -q -r "$ROOT/engine-ml/requirements-train.txt"
fi

# ── 5. Tests ────────────────────────────────────────────────────────────
export LD_LIBRARY_PATH="$NDPI_DIR/src/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if (( RUN_TESTS )); then
    step "Tests"
    make -s -C "$ROOT" test-sensor
    make -s -C "$ROOT" test-engine
fi

step "Done"
cat <<EOF
Add this to your shell profile so the sensor finds libndpi:
  export LD_LIBRARY_PATH=$NDPI_DIR/src/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}

Next steps (from $ROOT):
  make verify-closed-loop                     # closed-loop nftables test (uses sudo)
  engine-ml/.venv-runtime/bin/python engine-ml/daemon.py --scorer onnx &
  ./sensor-c/build/sensor -r capture.pcap     # then: make dashboard
EOF
(( WITH_DOCKER )) && echo "  docker compose up -d                        # ClickHouse + Grafana on 127.0.0.1"
(( WITH_DATA ))   && echo "  make fetch-data dataset                     # rebuild the labeled dataset"
(( WITH_TRAINING )) && echo "  make train holdout                          # retrain + holdout evaluation"
exit 0

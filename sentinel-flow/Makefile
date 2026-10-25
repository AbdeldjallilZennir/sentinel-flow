# SentinelFlow — Makefile (Phases 1-3)

.PHONY: all build clean sensor test test-http test-tls help daemon dashboard dashboard-web stack-up stack-down test-engine test-sensor fetch-data dataset train holdout phase3 runtime-venv verify-closed-loop

# Extra options for the daemon / dashboard targets, e.g.
#   make daemon ARGS="--mitigate dry-run"     make dashboard ARGS="--show-sql"
ARGS ?=

# daemon.py's ONNX scorer needs numpy + onnxruntime: use the runtime venv
# (make runtime-venv) when it exists, otherwise the system python3.
RUNTIME_PY := $(if $(wildcard engine-ml/.venv-runtime/bin/python),engine-ml/.venv-runtime/bin/python,python3)

# ── Build targets ─────────────────────────────────────────────────────

all: sensor

sensor:
	@mkdir -p sensor-c/build
	@cd sensor-c/build && cmake .. && $(MAKE) -j$$(nproc)
	@echo ""
	@echo "✅ Sensor built: sensor-c/build/sensor"

build: sensor

# ── Test targets ──────────────────────────────────────────────────────

test: sensor
	@echo "Running sensor on test PCAP..."
	@sensor-c/build/sensor -r pcaps/test_dns.pcap

test-http: sensor
	@sensor-c/build/sensor -r pcaps/test_http.pcapng

test-tls: sensor
	@sensor-c/build/sensor -r pcaps/test_tls.pcap

# ── Phase 2: ingestion & analytics ────────────────────────────────────

daemon: sensor
	@$(RUNTIME_PY) engine-ml/daemon.py $(ARGS)

dashboard:
	@python3 engine-ml/query_dashboard.py $(ARGS)

dashboard-web:
	@python3 engine-ml/query_dashboard.py --serve --port 8080 $(ARGS)

test-engine:
	@python3 engine-ml/tests/test_daemon.py
	@python3 engine-ml/tests/test_mitigator.py

test-sensor: sensor
	@cd sensor-c/build && ./test_flow | tail -1 && ./test_stats | tail -1
	@python3 sensor-c/tests/test_sensor_pcaps.py

# ── Phase 3: ML pipeline ──────────────────────────────────────────────

TRAIN_PY ?= engine-ml/.venv-train/bin/python

fetch-data:
	@python3 engine-ml/datasets/fetch_mta.py
	@python3 engine-ml/datasets/fetch_mta.py --holdout

dataset: sensor
	@LD_LIBRARY_PATH=$(HOME)/nDPI/src/lib python3 engine-ml/models/build_dataset.py

train:
	@$(TRAIN_PY) engine-ml/models/train_pipeline.py

holdout: sensor
	@LD_LIBRARY_PATH=$(HOME)/nDPI/src/lib python3 engine-ml/models/evaluate_holdout.py

phase3: dataset train holdout

# Self-contained interpreter for daemon.py's ONNX scorer (works under sudo).
runtime-venv:
	@python3 -m venv engine-ml/.venv-runtime
	@engine-ml/.venv-runtime/bin/pip install -q "onnxruntime==1.31.0" numpy
	@engine-ml/.venv-runtime/bin/python -c "import onnxruntime as o; print('runtime venv ok, onnxruntime', o.__version__)"

verify-closed-loop: sensor
	@sudo bash tests/verify_closed_loop.sh

stack-up:
	@docker compose up -d

stack-down:
	@docker compose down

# ── Cleanup ───────────────────────────────────────────────────────────

clean:
	@rm -rf sensor-c/build
	@echo "✅ Build artifacts removed"

# ── Help ──────────────────────────────────────────────────────────────

help:
	@echo "SentinelFlow — Makefile (run from sentinel-flow/; never 'sudo make')"
	@echo ""
	@echo "Build:"
	@echo "  make / make sensor   Build sensor, zmq_sink and the C unit tests (sensor-c/build)"
	@echo "  make clean           Delete sensor-c/build (next build starts from scratch)"
	@echo "  make runtime-venv    Create engine-ml/.venv-runtime (numpy + onnxruntime) for the ML model"
	@echo "Run:"
	@echo "  make daemon          Daemon with default options; ARGS=\"...\" adds options"
	@echo "  make dashboard       Dashboard tables in the terminal (SQLite); ARGS=\"...\" adds options"
	@echo "  make dashboard-web   Dashboard web page on http://127.0.0.1:8080"
	@echo "  make stack-up        Start ClickHouse + Grafana (docker compose up -d)"
	@echo "  make stack-down      Stop them (data is kept)"
	@echo "Test:"
	@echo "  make test-sensor     C unit tests + PCAP regression tests"
	@echo "  make test-engine     Daemon + mitigator unit tests"
	@echo "  make verify-closed-loop  Replay -> model -> nftables block, in throwaway namespaces (sudo)"
	@echo "  make test / test-http / test-tls   Run the sensor on one test capture"
	@echo "Model:"
	@echo "  make fetch-data      Download MTA training + holdout captures (large: use Colab)"
	@echo "  make dataset         Build the labeled training set (sensor -> zmq_sink)"
	@echo "  make train           Train, cross-validate, export ONNX (TRAIN_PY=...)"
	@echo "  make holdout         Evaluate on the 5 held-out captures through the daemon"
	@echo "  make phase3          dataset + train + holdout"
	@echo ""
	@echo "Full explanation: README.md, section 'How to run it'."

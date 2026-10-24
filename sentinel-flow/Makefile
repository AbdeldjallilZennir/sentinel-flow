# SentinelFlow — Makefile (Phases 1-3)

.PHONY: all build clean sensor test help daemon dashboard dashboard-web stack-up stack-down test-engine test-sensor fetch-data dataset train holdout phase3 runtime-venv verify-closed-loop

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
	@python3 engine-ml/daemon.py

dashboard:
	@python3 engine-ml/query_dashboard.py

dashboard-web:
	@python3 engine-ml/query_dashboard.py --serve --port 8080

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
	@echo "SentinelFlow — Makefile (Phases 1-3)"
	@echo ""
	@echo "Targets:"
	@echo "  make              Build the C sensor"
	@echo "  make test         Run sensor on test DNS PCAP"
	@echo "  make test-http    Run sensor on test HTTP PCAP"
	@echo "  make test-tls     Run sensor on test TLS PCAP"
	@echo "  make daemon       Run the Phase 2 ingestion daemon"
	@echo "  make dashboard    Print the 6 query panels (SQLite)"
	@echo "  make dashboard-web  Serve the panels on http://127.0.0.1:8080"
	@echo "  make test-engine  Run daemon unit tests"
	@echo "  make stack-up     Start ClickHouse + Grafana (docker compose)"
	@echo "  make test-sensor  Sensor unit + PCAP regression tests"
	@echo "  make fetch-data   Download MTA training + holdout captures"
	@echo "  make dataset      Build labeled training set (sensor -> ZMQ)"
	@echo "  make train        Train, cross-validate, export ONNX"
	@echo "  make holdout      End-to-end evaluation on held-out captures"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Manual usage:"
	@echo "  ./sensor-c/build/sensor -r file.pcap"
	@echo "  ./sensor-c/build/sensor -i eth0"
	@echo "  ./sensor-c/build/sensor -h"

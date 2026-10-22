# SentinelFlow — Makefile for Phase 1

.PHONY: all build clean sensor test help

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

# ── Cleanup ───────────────────────────────────────────────────────────

clean:
	@rm -rf sensor-c/build
	@echo "✅ Build artifacts removed"

# ── Help ──────────────────────────────────────────────────────────────

help:
	@echo "SentinelFlow — Phase 1 Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make              Build the C sensor"
	@echo "  make test         Run sensor on test DNS PCAP"
	@echo "  make test-http    Run sensor on test HTTP PCAP"
	@echo "  make test-tls     Run sensor on test TLS PCAP"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Manual usage:"
	@echo "  ./sensor-c/build/sensor -r file.pcap"
	@echo "  ./sensor-c/build/sensor -i eth0"
	@echo "  ./sensor-c/build/sensor -h"

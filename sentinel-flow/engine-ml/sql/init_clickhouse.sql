-- SentinelFlow Phase 2 — ClickHouse schema.
-- Loaded automatically by clickhouse-server from /docker-entrypoint-initdb.d/
-- on first start (see docker-compose.yml). Safe to re-run.
--
-- Column order = the 23 sensor fields in emission order, then the 3
-- enrichment columns added by engine-ml/daemon.py.

CREATE DATABASE IF NOT EXISTS sentinel;

CREATE TABLE IF NOT EXISTS sentinel.network_flows
(
    -- 5-tuple (first packet seen = orig direction)
    src_ip               String,
    dst_ip               String,
    src_port             UInt16,
    dst_port             UInt16,
    protocol             UInt8,

    -- nDPI classification
    app_protocol         LowCardinality(String),
    ja4_client           String,
    ndpi_risk_mask       UInt64,
    ndpi_risk_str        String,

    -- volume
    pkt_count            UInt64,
    bytes_up             UInt64,
    bytes_down           UInt64,

    -- timing / shape statistics (Welford, microseconds for IAT)
    flow_duration_ms     Float64,
    iat_mean             Float64,
    iat_stddev           Float64,
    iat_min              Float64,
    iat_max              Float64,
    pkt_len_mean         Float64,
    pkt_len_stddev       Float64,
    bytes_up_down_ratio  Float64,
    small_pkt_ratio      Float64,

    -- capture timestamps, integer microseconds since epoch
    first_seen_us        UInt64,
    last_seen_us         UInt64,

    -- Phase 2 / 3 enrichment
    ingested_at_us       UInt64,
    ml_anomaly_score     Float64,
    is_alert             UInt8,

    -- Phase 3 model outputs (-1 = not computed, i.e. heuristic scorer)
    ml_c2_proba          Float64 DEFAULT -1,
    ml_iforest_score     Float64 DEFAULT -1,
    ml_model             LowCardinality(String) DEFAULT ''
)
ENGINE = MergeTree()
ORDER BY (first_seen_us, app_protocol, src_ip);

-- Phase 4: every mitigation action (block / unblock / expire / counters /
-- skip_protected / error) written by engine-ml/mitigator.py.
CREATE TABLE IF NOT EXISTS sentinel.mitigations
(
    ts_us          UInt64,
    action         LowCardinality(String),
    ip             String,
    backend        LowCardinality(String),
    reason         LowCardinality(String),
    detail         String,
    score          Float64,
    flow           String,
    ml_model       LowCardinality(String),
    timeout_s      Int64,
    dropped_pkts   UInt64,
    dropped_bytes  UInt64
)
ENGINE = MergeTree()
ORDER BY (ts_us, ip);

-- Upgrade path for tables created with the Phase 2 schema (no-ops otherwise).
-- daemon.py also runs these on startup when ClickHouse is reachable.
ALTER TABLE sentinel.network_flows ADD COLUMN IF NOT EXISTS ml_c2_proba      Float64 DEFAULT -1;
ALTER TABLE sentinel.network_flows ADD COLUMN IF NOT EXISTS ml_iforest_score Float64 DEFAULT -1;
ALTER TABLE sentinel.network_flows ADD COLUMN IF NOT EXISTS ml_model         LowCardinality(String) DEFAULT '';

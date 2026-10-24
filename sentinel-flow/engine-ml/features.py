"""
SentinelFlow feature vector (shared by training and live inference).

Turns one validated 23-field sensor record into a fixed-length list of
floats. train_pipeline.py and daemon.py both import this module, so the
model sees exactly the same transformation offline and online.
Standard library only.

Deliberately NOT used as features: IP addresses and timestamps. They
identify specific hosts and captures, so a model could memorize them
instead of learning traffic behaviour.
"""

import math

FEATURE_VERSION = 1

# nDPI risk enum values (ndpi_typedefs.h, ndpi_risk_enum); bit = 1 << value.
RISK_BITS = {
    "known_proto_nonstd_port": 5,
    "tls_selfsigned": 6,
    "tls_obsolete": 7,
    "tls_weak_cipher": 8,
    "tls_cert_mismatch": 10,
    "http_susp_user_agent": 11,
    "numeric_ip_host": 12,
    "http_susp_url": 13,
    "http_susp_header": 14,
    "tls_not_https": 15,
    "susp_dga": 16,
    "unsafe_protocol": 22,
    "dns_susp_traffic": 23,
    "tls_missing_sni": 24,
    "risky_asn": 26,
    "risky_domain": 27,
    "malicious_fingerprint": 28,
    "malicious_sha1_cert": 29,
    "tls_uncommon_alpn": 31,
    "susp_entropy": 35,
    "unidirectional": 46,
    "tcp_issues": 50,
    "unresolved_hostname": 51,
    "binary_data_transfer": 54,
    "probing_attempt": 55,
    "obfuscated_traffic": 56,
}

# Risks that point at known-bad infrastructure or content rather than at
# protocol hygiene; used by the optional "severe" alert-on-risk policy.
SEVERE_RISKS = {
    "susp_dga": 16, "risky_domain": 27, "malicious_fingerprint": 28,
    "malicious_sha1_cert": 29, "possible_exploit": 40, "malware_host_contacted": 53,
}
SEVERE_MASK = sum(1 << b for b in SEVERE_RISKS.values())

TLS_FAMILY = {"TLS", "DTLS", "QUIC", "IMAPS", "POPS", "SMTPS", "FTPS", "DoH_DoT"}

FEATURE_NAMES = (
    ["protocol", "service_port", "service_port_wellknown",
     "log_pkt_count", "log_bytes_up", "log_bytes_down", "log_bytes_total",
     "bytes_per_pkt", "log_duration_ms",
     "log_iat_mean", "log_iat_stddev", "log_iat_min", "log_iat_max", "iat_cv",
     "pkt_len_mean", "pkt_len_stddev", "pkt_len_cv",
     "log_up_down_ratio", "small_pkt_ratio", "unidirectional_bytes",
     "risk_count", "has_risk"]
    + [f"risk_{n}" for n in RISK_BITS]
    + ["app_tls", "app_quic", "app_http", "app_dns", "app_unknown", "app_has_subprotocol",
       "ja4_present", "ja4_quic", "ja4_tls_version", "ja4_sni_domain",
       "ja4_n_ciphers", "ja4_n_extensions", "ja4_alpn"]
)
N_FEATURES = len(FEATURE_NAMES)


def _log1p(x):
    return math.log1p(max(float(x), 0.0))


def _ja4_parts(ja4):
    """Parse JA4_a, e.g. 't13d1516h2' -> (quic, version, sni, ciphers, ext, alpn).

    Returns None when absent/unparseable. nDPI occasionally emits a
    non-alphanumeric ALPN pair (seen: 't13i0311/0'); that maps to 'other'.
    """
    if not ja4 or ja4 == "N/A" or len(ja4) < 10:
        return None
    a = ja4[:10]
    try:
        ciphers, ext = int(a[4:6]), int(a[6:8])
    except ValueError:
        return None
    ver = {"13": 1.3, "12": 1.2, "11": 1.1, "10": 1.0, "s3": 0.3, "s2": 0.2,
           "d1": 1.0, "d2": 1.2, "d3": 1.3}.get(a[1:3], 0.0)
    alpn = {"h2": 2.0, "h1": 1.0, "h3": 3.0, "00": 0.0}.get(a[8:10], 4.0)
    return (1.0 if a[0] == "q" else 0.0, ver, 1.0 if a[3] == "d" else 0.0,
            float(ciphers), float(ext), alpn)


def extract(r):
    """Feature list (len N_FEATURES) for one validated flow record."""
    up, down, pkts = r["bytes_up"], r["bytes_down"], r["pkt_count"]
    sp, dp = r["src_port"], r["dst_port"]
    service = min(sp, dp) if sp and dp else max(sp, dp)
    iat_mean, iat_sd = r["iat_mean"], r["iat_stddev"]
    len_mean, len_sd = r["pkt_len_mean"], r["pkt_len_stddev"]
    mask = int(r["ndpi_risk_mask"])
    app = r["app_protocol"]
    master = app.split(".")[0]
    ja4 = _ja4_parts(r["ja4_client"])

    f = [
        float(r["protocol"]), float(service), 1.0 if 0 < service < 1024 else 0.0,
        _log1p(pkts), _log1p(up), _log1p(down), _log1p(up + down),
        (up + down) / pkts if pkts else 0.0,
        _log1p(r["flow_duration_ms"]),
        _log1p(iat_mean), _log1p(iat_sd), _log1p(r["iat_min"]), _log1p(r["iat_max"]),
        iat_sd / iat_mean if iat_mean > 0 else 0.0,
        float(len_mean), float(len_sd), len_sd / len_mean if len_mean > 0 else 0.0,
        math.log10((up + 1.0) / (down + 1.0)), float(r["small_pkt_ratio"]),
        1.0 if (up == 0 or down == 0) else 0.0,
        float(bin(mask).count("1")), 1.0 if mask else 0.0,
    ]
    f += [1.0 if mask >> b & 1 else 0.0 for b in RISK_BITS.values()]
    f += [
        1.0 if master in TLS_FAMILY and master != "QUIC" else 0.0,
        1.0 if master == "QUIC" else 0.0,
        1.0 if master.startswith("HTTP") else 0.0,
        1.0 if master in ("DNS", "MDNS", "LLMNR") else 0.0,
        1.0 if master in ("Unknown", "") else 0.0,
        1.0 if "." in app else 0.0,
    ]
    f += [1.0, *ja4] if ja4 else [0.0] * 7
    assert len(f) == N_FEATURES
    return f

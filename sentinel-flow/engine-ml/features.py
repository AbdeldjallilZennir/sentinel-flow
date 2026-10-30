"""
SentinelFlow feature vector (shared by training and live inference).

Turns one validated 23-field sensor record into a fixed-length list of
floats. train_pipeline.py and daemon.py both import this module, so the
model sees exactly the same transformation offline and online.
Standard library only.

Version 2 adds conversation features: what this host's earlier
connections to the same server looked like (count, regular timing,
repeated sizes). A ConversationTracker computes them; both training and
the daemon feed it records in the order the sensor exported them, one
tracker per capture (training) or per daemon run (live).

Deliberately NOT used as features: IP addresses and timestamps. They
identify specific hosts and captures, so a model could memorize them
instead of learning traffic behaviour. (The tracker uses them as keys
and clocks, but only counts, gaps and size statistics reach the model.)
"""

import collections
import functools
import ipaddress
import math
import statistics

FEATURE_VERSION = 2

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

# ── Conversation features (fv2) ────────────────────────────────────────
# A conversation is (client ip, server ip, server port, protocol). Inside it,
# a connection is one client source port: the idle-timeout pieces of one
# long TCP connection (Chrome sends a keep-alive every 45 s, the sensor
# expires flows after 30 s idle) and the snapshots of one flow update the
# same connection instead of looking like many periodic connections.
CONV_HISTORY = 20                       # earlier connections kept per conversation
CONV_EXPIRE_US = 24 * 3600 * 1_000_000  # forget a conversation idle this long
CONV_MAX = 50_000                       # conversations kept (least recently used dropped)
PERIODIC_TOLERANCE = 0.20               # a gap within ±20 % of the median gap is "regular"

# The model only sees EVIDENCE of a rhythm or of repeated sizes: every
# feature is 0 when there is none, so "no earlier connections" and "earlier
# connections with no pattern" look the same. Counts and conversation age
# are deliberately left out: in the training captures benign flows rarely
# have history (short captures, mostly LAN) while C2 almost always does, so
# a model given "has history" learned "no history = benign" and missed
# servers contacted only once (see docs/REPORT.md, Part 9).
CONV_FEATURE_NAMES = [
    "conv_periodicity",           # (share of gaps within ±20 % of the median - 0.5) / 0.5,
                                  # 0 unless most gaps are regular (needs >= 3 gaps)
    "conv_log_beacon_interval_s", # log1p(median gap) when conv_periodicity > 0, else 0
    "conv_same_size_ratio",       # share of earlier connections with the most common
                                  # (bytes_up, bytes_down), 0 unless a pair repeats
    "conv_up_regularity",         # max(0, 1 - 4 * CV of bytes_up), needs >= 2 earlier
    "conv_pkt_regularity",        # same for pkt_count
]
CONV_NONE = [0.0] * len(CONV_FEATURE_NAMES)

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
    + CONV_FEATURE_NAMES
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


@functools.lru_cache(maxsize=65536)
def is_internet(ip):
    """True for a public unicast address: a real remote server.

    ipaddress's is_global alone counts multicast (224.0.0.251 mDNS,
    239.255.255.250 SSDP) as global; those are local group traffic.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


@functools.lru_cache(maxsize=65536)
def _is_lab_server(ip):
    """Lab mode: any unicast address except loopback, link-local and broadcast."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified
                or a.is_reserved or str(a) == "255.255.255.255")


class _Connection:
    __slots__ = ("start", "piece_start", "base", "cur")

    def __init__(self, start):
        self.start = start            # first_seen_us of the first piece
        self.piece_start = None       # first_seen_us of the current piece
        self.base = (0, 0, 0)         # (up, down, pkts) of finished pieces
        self.cur = (0, 0, 0)          # latest counters of the current piece

    def update(self, r):
        counters = (r["bytes_up"], r["bytes_down"], r["pkt_count"])
        if self.piece_start is not None and r["first_seen_us"] != self.piece_start:
            # a new idle-timeout piece: bank the previous one
            self.base = tuple(a + b for a, b in zip(self.base, self.cur))
        self.piece_start = r["first_seen_us"]
        self.cur = counters           # a snapshot replaces the piece's counters

    def totals(self):
        return tuple(a + b for a, b in zip(self.base, self.cur))


class _Conversation:
    __slots__ = ("first_start", "last_seen", "evicted", "conns")

    def __init__(self, start):
        self.first_start = start
        self.last_seen = start
        self.evicted = 0
        self.conns = collections.OrderedDict()   # src_port -> _Connection


def _cv(values):
    m = sum(values) / len(values)
    return statistics.pstdev(values) / m if m > 0 else 0.0


class ConversationTracker:
    """Conversation features for each record, from earlier connections only.

    observe(rec) must be called once per record, in the order the sensor
    exported them. Time comes from the records themselves (first_seen_us,
    last_seen_us), so replaying a capture gives the same features as
    seeing it live.

    lab=True also tracks private servers (a host-only lab has no Internet
    addresses). The model was trained with lab=False, so lab mode is for
    testing only.
    """

    def __init__(self, lab=False, history=CONV_HISTORY, expire_us=CONV_EXPIRE_US,
                 max_conversations=CONV_MAX):
        self.applies = _is_lab_server if lab else is_internet
        self.history = history
        self.expire_us = expire_us
        self.max_conversations = max_conversations
        self.convs = collections.OrderedDict()   # key -> _Conversation, LRU order
        self.now = 0

    def __len__(self):
        return len(self.convs)

    def observe(self, r):
        """Record r in the tracker; return its CONV_FEATURE_NAMES values."""
        if not self.applies(r["dst_ip"]):
            return list(CONV_NONE)
        start, last = r["first_seen_us"], r["last_seen_us"]
        self.now = max(self.now, last)
        self._expire()
        key = (r["src_ip"], r["dst_ip"], r["dst_port"], r["protocol"])
        conv = self.convs.get(key)
        if conv is not None and start - conv.last_seen > self.expire_us:
            conv = None
        if conv is None:
            conv = _Conversation(start)
            self.convs[key] = conv
            if len(self.convs) > self.max_conversations:
                self.convs.popitem(last=False)
        else:
            self.convs.move_to_end(key)
        conv.last_seen = max(conv.last_seen, last)
        conv.first_start = min(conv.first_start, start)

        c = conv.conns.get(r["src_port"])
        if c is None:
            c = _Connection(start)
            conv.conns[r["src_port"]] = c
            if len(conv.conns) > self.history:
                conv.conns.popitem(last=False)
                conv.evicted += 1
        else:
            conv.conns.move_to_end(r["src_port"])
        c.update(r)
        return self._features(conv, c)

    def _expire(self):
        while self.convs:
            oldest = next(iter(self.convs.values()))
            if self.now - oldest.last_seen <= self.expire_us:
                break
            self.convs.popitem(last=False)

    def _features(self, conv, c):
        st = self.stats(conv, c)
        p = st["periodicity"]
        periodic = max(0.0, (p - 0.5) / 0.5) if p is not None else 0.0
        same = st["same_size_ratio"] if st["same_size_repeats"] else 0.0
        reg = lambda cv: max(0.0, 1.0 - 4.0 * cv) if cv is not None else 0.0
        return [periodic, _log1p(st["median_gap_s"]) if periodic > 0 else 0.0,
                same, reg(st["cv_bytes_up"]), reg(st["cv_pkts"])]

    @staticmethod
    def stats(conv, c):
        """Raw statistics of connection c's conversation, earlier connections only."""
        earlier = [x for x in conv.conns.values() if x is not c and x.start < c.start]
        starts = sorted(x.start for x in earlier) + [c.start]
        gaps = [(b - a) / 1e6 for a, b in zip(starts, starts[1:])]
        st = {"n_prev": len(earlier) + conv.evicted,
              "n_60s": sum(1 for x in earlier if c.start - x.start <= 60_000_000),
              "n_300s": sum(1 for x in earlier if c.start - x.start <= 300_000_000),
              "age_s": (c.start - conv.first_start) / 1e6,
              "median_gap_s": statistics.median(gaps) if gaps else None,
              "periodicity": None, "mad_ratio": None, "same_size_ratio": None,
              "same_size_repeats": False, "cv_bytes_up": None, "cv_pkts": None}
        if len(gaps) >= 3:
            med = st["median_gap_s"]
            st["periodicity"] = sum(1 for g in gaps
                                    if abs(g - med) <= PERIODIC_TOLERANCE * med) / len(gaps)
            mad = statistics.median(abs(g - med) for g in gaps)
            st["mad_ratio"] = mad / med if med > 0 else (0.0 if mad == 0 else math.inf)
        if len(earlier) >= 2:
            sizes = [x.totals() for x in earlier]
            mode = collections.Counter((u, d) for u, d, _ in sizes).most_common(1)[0][1]
            st.update(same_size_ratio=mode / len(sizes), same_size_repeats=mode >= 2,
                      cv_bytes_up=_cv([u for u, _, _ in sizes]),
                      cv_pkts=_cv([p for _, _, p in sizes]))
        return st


def extract(r, conv):
    """Feature list (len N_FEATURES) for one validated flow record.

    conv: ConversationTracker.observe(r) for this record (CONV_NONE when
    no history is known).
    """
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
    f += conv
    assert len(f) == N_FEATURES
    return f

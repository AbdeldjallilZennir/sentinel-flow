#!/usr/bin/env python3
"""
SentinelFlow Phase 4 — mitigation.

This module turns scored flow records into block decisions. Part 1 (this
file, so far) is the policy: WHICH remote address to block and WHY.
Kernel backends (nftables, XDP) are added separately.

Policy (decide()):
  * Trigger, either of:
      - ml_anomaly_score >= threshold (default 0.80), from a trained model
        (records scored by the Phase 2 heuristic are not trusted to block)
      - ndpi_risk_mask has a "severe" bit (features.SEVERE_MASK:
        DGA domain, risky domain, malicious fingerprint, malicious cert
        SHA-1, possible exploit, malware host contacted)
    Any other nDPI risk never blocks on its own: in Phase 3 the "any risk"
    rule alerted on 18 % of real Windows background flows (Part3.md §8.4).
  * Target: the remote peer, never a protected address. The responder
    (dst_ip) is preferred; src_ip is used only if dst_ip is protected.
    If both endpoints are protected, nothing is blocked.
  * Protected addresses:
      - always (cannot be disabled): loopback, link-local, multicast,
        unspecified, reserved, broadcast
      - by default: RFC 1918 + 127.0.0.0/8 (--protected-cidr), so a LAN
        victim's own address is never blocked
      - --allow-private-blocks removes the RFC 1918 ranges (lab use)
      - --allowlist / --allowlist-file: addresses / CIDRs never blocked.
        The built-in list stays minimal on purpose; operators should add
        their own cloud/CDN/SaaS ranges (see Part4.md).
  * IPv4 only (the sensor and the XDP map are IPv4).
"""

import ipaddress
import json
import os
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import features  # noqa: E402  (SEVERE_RISKS / SEVERE_MASK)

ALERT_THRESHOLD = 0.80
RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
DEFAULT_PROTECTED = RFC1918 + ("127.0.0.0/8",)
UNTRUSTED_SCORERS = {"", "heuristic_v1"}

# Reason codes (also stored in the XDP map's block_entry.reason_code).
REASON_ML = 1
REASON_SEVERE_RISK = 2
REASON_MANUAL = 3
REASON_NAMES = {REASON_ML: "ml_score", REASON_SEVERE_RISK: "severe_risk",
                REASON_MANUAL: "manual"}


def load_allowlist_file(path):
    """One IP or CIDR per line; '#' starts a comment; blank lines ignored.
    Raises ValueError naming the file and line for anything else."""
    nets = []
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise ValueError(f"{path}:{n}: not an IP address or CIDR: {entry!r}") from None
    return nets


def parse_networks(items):
    """'a.b.c.d', 'a.b.c.d/n' or comma-separated lists -> list of networks."""
    nets = []
    for item in items or ():
        for part in str(item).split(","):
            part = part.strip()
            if part:
                nets.append(ipaddress.ip_network(part, strict=False))
    return nets


class Decision:
    """Outcome of decide(): action is "block" or "skip"."""

    __slots__ = ("action", "ip", "reason_code", "detail", "score")

    def __init__(self, action, ip=None, reason_code=0, detail="", score=None):
        self.action, self.ip, self.reason_code = action, ip, reason_code
        self.detail, self.score = detail, score

    @property
    def reason(self):
        return REASON_NAMES.get(self.reason_code, "")

    def __repr__(self):
        return (f"Decision({self.action}, ip={self.ip}, reason={self.reason}, "
                f"detail={self.detail!r})")


class BlockPolicy:
    def __init__(self, threshold=ALERT_THRESHOLD, use_severe_risk=True,
                 protected_cidrs=DEFAULT_PROTECTED, allowlist=(),
                 allow_private_blocks=False, trust_heuristic=False, allowlist_file=None):
        self.threshold = threshold
        self.use_severe_risk = use_severe_risk
        self.trust_heuristic = trust_heuristic
        protected = parse_networks(protected_cidrs)
        if allow_private_blocks:
            private = set(parse_networks(RFC1918))
            protected = [n for n in protected if n not in private]
        self.protected = protected
        self.allowlist = parse_networks(allowlist)
        if allowlist_file:
            self.allowlist += load_allowlist_file(allowlist_file)

    # ── address checks ─────────────────────────────────────────────────
    def why_protected(self, ip_str):
        """Reason this address must never be blocked, or None."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "not an IP address"
        if ip.version != 4:
            return "not IPv4"
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or \
                ip.is_unspecified or ip.is_reserved or ip == ipaddress.IPv4Address("255.255.255.255"):
            return "special-purpose address"
        for net in self.allowlist:
            if ip in net:
                return f"allowlisted ({net})"
        for net in self.protected:
            if ip in net:
                return f"protected ({net})"
        return None

    # ── decision ───────────────────────────────────────────────────────
    def trigger(self, rec):
        """(reason_code, detail) if this record warrants a block, else None."""
        score = rec.get("ml_anomaly_score")
        model = rec.get("ml_model", "")
        if score is not None and score >= self.threshold and \
                (self.trust_heuristic or model not in UNTRUSTED_SCORERS):
            return REASON_ML, f"ml_anomaly_score={score:.3f} ({model})"
        if self.use_severe_risk:
            severe = int(rec.get("ndpi_risk_mask", 0)) & features.SEVERE_MASK
            if severe:
                names = [n for n, b in features.SEVERE_RISKS.items() if severe >> b & 1]
                return REASON_SEVERE_RISK, "ndpi severe risk: " + ",".join(names)
        return None

    def decide(self, rec):
        trig = self.trigger(rec)
        if trig is None:
            return Decision("skip", detail="no trigger")
        code, detail = trig
        reasons = []
        for ip in (rec["dst_ip"], rec["src_ip"]):          # responder first
            why = self.why_protected(ip)
            if why is None:
                return Decision("block", ip, code, detail, rec.get("ml_anomaly_score"))
            reasons.append(f"{ip}: {why}")
        return Decision("skip", None, code,
                        f"{detail}; both endpoints protected ({'; '.join(reasons)})",
                        rec.get("ml_anomaly_score"))


# ═════════════════════════════════════════════════════════════════════════
# Backends
#   setup()                      create kernel state (idempotent)
#   block(ip, timeout_s, reason_code, comment) -> True if newly added
#   unblock(ip) -> True if it was present
#   list() -> {ip: {"expires_s": int|None, "packets": int, "bytes": int}}
#   teardown()                   remove everything this backend created
# ═════════════════════════════════════════════════════════════════════════
class BackendError(RuntimeError):
    pass


class DryRunBackend:
    """No kernel changes; remembers what would have been blocked."""
    name = "dry-run"

    def __init__(self):
        self.entries = {}

    def setup(self):
        pass

    def block(self, ip, timeout_s, reason_code, comment=""):
        now = time.time()
        self._expire(now)
        new = ip not in self.entries
        self.entries[ip] = now + timeout_s
        return new

    def unblock(self, ip):
        return self.entries.pop(ip, None) is not None

    def _expire(self, now):
        for ip in [i for i, t in self.entries.items() if t <= now]:
            del self.entries[ip]

    def list(self):
        now = time.time()
        self._expire(now)
        return {ip: {"expires_s": int(t - now), "packets": 0, "bytes": 0}
                for ip, t in self.entries.items()}

    def teardown(self):
        self.entries.clear()


class NftablesBackend:
    """Table `inet sentinel` with a timeout set and per-element counters.

        table inet sentinel {
          set blocked_ipv4 { type ipv4_addr; flags timeout; timeout 15m; counter; }
          chain prerouting { hook prerouting priority raw;    ip saddr @blocked_ipv4 drop }
          chain output     { hook output     priority filter; ip daddr @blocked_ipv4 drop }
          chain forward    { hook forward    priority filter; ip daddr @blocked_ipv4 drop }
        }

    Inbound packets FROM a blocked address are dropped before conntrack;
    packets TO it are dropped whether sent by this host (output) or
    routed through it (forward). Each element's counter accumulates the
    packets/bytes dropped for that address. Only this table is ever
    created or deleted; the rest of the ruleset is not touched.
    """
    name = "nftables"
    TABLE = "sentinel"
    SET = "blocked_ipv4"

    def __init__(self, default_timeout_s=900, netns=None, sudo=True, nft="nft"):
        self.default_timeout_s = int(default_timeout_s)
        prefix = []
        if sudo and os.geteuid() != 0:
            prefix += ["sudo", "-n"]
        if netns:
            prefix += ["ip", "netns", "exec", netns]
        self.cmd = prefix + [nft]
        self.netns = netns

    def _nft(self, args, stdin=None, check=True):
        p = subprocess.run(self.cmd + args, input=stdin, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise BackendError(f"{shlex.join(self.cmd + args)}: {p.stderr.strip()}")
        return p

    def setup(self):
        t, s = self.TABLE, self.SET
        script = f"""
table inet {t} {{
  set {s} {{ type ipv4_addr; flags timeout; timeout {self.default_timeout_s}s; counter; }}
  chain prerouting {{ type filter hook prerouting priority raw; policy accept;
    ip saddr @{s} drop comment "sentinelflow: from blocked C2"; }}
  chain output {{ type filter hook output priority filter; policy accept;
    ip daddr @{s} drop comment "sentinelflow: to blocked C2"; }}
  chain forward {{ type filter hook forward priority filter; policy accept;
    ip daddr @{s} drop comment "sentinelflow: to blocked C2 (routed)"; }}
}}
"""
        if self._nft(["list", "table", "inet", t], check=False).returncode == 0:
            return                                  # already set up; keep elements
        self._nft(["-f", "-"], stdin=script)

    def list(self):
        p = self._nft(["-j", "list", "set", "inet", self.TABLE, self.SET])
        out = {}
        for item in json.loads(p.stdout).get("nftables", []):
            for e in item.get("set", {}).get("elem", []) or []:
                e = e.get("elem", e) if isinstance(e, dict) else {"val": e}
                c = e.get("counter", {}) or {}
                out[e["val"]] = {"expires_s": e.get("expires"),
                                 "packets": int(c.get("packets", 0)),
                                 "bytes": int(c.get("bytes", 0))}
        return out

    def block(self, ip, timeout_s, reason_code, comment=""):
        if ip in self.list():
            return False
        ipaddress.IPv4Address(ip)                   # never pass non-IPs to nft
        note = f"{REASON_NAMES.get(reason_code, '?')}: {comment}"[:120].replace('"', "'")
        self._nft(["add", "element", "inet", self.TABLE, self.SET,
                   f'{{ {ip} timeout {int(timeout_s)}s comment "{note}" }}'])
        return True

    def unblock(self, ip):
        ipaddress.IPv4Address(ip)
        return self._nft(["delete", "element", "inet", self.TABLE, self.SET,
                          f"{{ {ip} }}"], check=False).returncode == 0

    def teardown(self):
        self._nft(["delete", "table", "inet", self.TABLE], check=False)


def make_backend(kind, timeout_s=900, netns=None):
    if kind == "dry-run":
        return DryRunBackend()
    if kind == "nftables":
        return NftablesBackend(timeout_s, netns=netns)
    raise ValueError(f"unknown mitigation backend {kind!r}")


# ═════════════════════════════════════════════════════════════════════════
# Mitigator: policy + backend + audit trail
# ═════════════════════════════════════════════════════════════════════════
EVENT_FIELDS = ["ts_us", "action", "ip", "backend", "reason", "detail", "score",
                "flow", "ml_model", "timeout_s", "dropped_pkts", "dropped_bytes"]
# action: block | unblock | expire | counters | skip_protected | error


class Mitigator:
    def __init__(self, policy, backend, timeout_s=900, sinks=(), refresh_s=10.0,
                 log_fn=None):
        self.policy, self.backend = policy, backend
        self.timeout_s = int(timeout_s)
        self.sinks = list(sinks)
        self.refresh_s = refresh_s
        self.log = log_fn or (lambda m: None)
        self.active = {}            # ip -> {"until": epoch, "packets": n, "bytes": n}
        self.last_refresh = 0.0
        self.stats = {"blocks": 0, "skips_protected": 0, "errors": 0}
        backend.setup()

    def _emit(self, **ev):
        row = {k: ev.get(k) for k in EVENT_FIELDS}
        row["ts_us"] = row["ts_us"] or time.time_ns() // 1000
        row["backend"] = self.backend.name
        for k in ("score", "timeout_s", "dropped_pkts", "dropped_bytes"):
            row[k] = row[k] if row[k] is not None else (-1.0 if k == "score" else 0)
        for k in ("ip", "reason", "detail", "flow", "ml_model"):
            row[k] = row[k] or ""
        for s in self.sinks:
            try:
                s.write_event(row)
            except Exception as e:  # an audit sink failing must not stop blocking
                self.log(f"mitigation audit sink {type(s).__name__} failed: {e}")
        return row

    def process(self, records):
        """Apply the policy to scored records; returns the events emitted."""
        events = []
        now = time.time()
        for r in records:
            d = self.policy.decide(r)
            flow = f"{r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']} {r.get('app_protocol', '')}"
            if d.action == "skip":
                if d.reason_code:          # trigger fired but endpoints protected
                    self.stats["skips_protected"] += 1
                    events.append(self._emit(action="skip_protected", reason=d.reason,
                                             detail=d.detail, score=d.score, flow=flow,
                                             ml_model=r.get("ml_model")))
                continue
            cur = self.active.get(d.ip)
            if cur and cur["until"] > now:
                continue                    # already blocked
            try:
                added = self.backend.block(d.ip, self.timeout_s, d.reason_code, d.detail)
            except Exception as e:
                self.stats["errors"] += 1
                events.append(self._emit(action="error", ip=d.ip, reason=d.reason,
                                         detail=f"block failed: {e}", flow=flow))
                continue
            self.active[d.ip] = {"until": now + self.timeout_s, "packets": 0, "bytes": 0}
            self.stats["blocks"] += 1
            events.append(self._emit(action="block", ip=d.ip, reason=d.reason,
                                     detail=d.detail + ("" if added else " (already in kernel set)"),
                                     score=d.score, flow=flow, ml_model=r.get("ml_model"),
                                     timeout_s=self.timeout_s))
            self.log(f"BLOCK {d.ip} ({d.reason}: {d.detail}) flow {flow}")
        if time.time() - self.last_refresh >= self.refresh_s:
            events += self.refresh()
        return events

    def refresh(self):
        """Read kernel counters; log changes and expiries."""
        self.last_refresh = time.time()
        events = []
        try:
            kernel = self.backend.list()
        except Exception as e:
            self.stats["errors"] += 1
            return [self._emit(action="error", detail=f"list failed: {e}")]
        for ip, k in kernel.items():
            cur = self.active.setdefault(ip, {"until": time.time() + (k["expires_s"] or 0),
                                              "packets": 0, "bytes": 0})
            if (k["packets"], k["bytes"]) != (cur["packets"], cur["bytes"]):
                cur["packets"], cur["bytes"] = k["packets"], k["bytes"]
                events.append(self._emit(action="counters", ip=ip,
                                         dropped_pkts=k["packets"], dropped_bytes=k["bytes"],
                                         timeout_s=k["expires_s"]))
        for ip in [i for i in self.active if i not in kernel]:
            cur = self.active.pop(ip)
            events.append(self._emit(action="expire", ip=ip, dropped_pkts=cur["packets"],
                                     dropped_bytes=cur["bytes"]))
        return events

    def unblock(self, ip, detail="manual"):
        ok = self.backend.unblock(ip)
        cur = self.active.pop(ip, {"packets": 0, "bytes": 0})
        return self._emit(action="unblock", ip=ip, detail=detail if ok else detail + " (not present)",
                          dropped_pkts=cur["packets"], dropped_bytes=cur["bytes"])


# ── Audit sinks ────────────────────────────────────────────────────────
class JsonlEventSink:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.fh = open(path, "a", buffering=1)

    def write_event(self, row):
        self.fh.write(json.dumps(row, separators=(",", ":")) + "\n")


class SqliteEventSink:
    """mitigation_events (every event) + blocked_ips (current state per IP)."""

    def __init__(self, path):
        import sqlite3
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS mitigation_events (
            ts_us INTEGER NOT NULL, action TEXT NOT NULL, ip TEXT NOT NULL, backend TEXT NOT NULL,
            reason TEXT NOT NULL, detail TEXT NOT NULL, score REAL NOT NULL, flow TEXT NOT NULL,
            ml_model TEXT NOT NULL, timeout_s INTEGER NOT NULL,
            dropped_pkts INTEGER NOT NULL, dropped_bytes INTEGER NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY, backend TEXT NOT NULL, status TEXT NOT NULL,
            reason TEXT NOT NULL, detail TEXT NOT NULL, score REAL NOT NULL, flow TEXT NOT NULL,
            first_blocked_us INTEGER NOT NULL, last_event_us INTEGER NOT NULL,
            dropped_pkts INTEGER NOT NULL, dropped_bytes INTEGER NOT NULL)""")
        self.db.commit()

    def write_event(self, row):
        with self.db:
            self.db.execute(f"INSERT INTO mitigation_events ({','.join(EVENT_FIELDS)}) "
                            f"VALUES ({','.join('?' * len(EVENT_FIELDS))})",
                            [row[k] for k in EVENT_FIELDS])
            a, ip, ts = row["action"], row["ip"], row["ts_us"]
            if a == "block":
                self.db.execute("""INSERT INTO blocked_ips VALUES (?,?,'active',?,?,?,?,?,?,0,0)
                    ON CONFLICT(ip) DO UPDATE SET status='active', backend=excluded.backend,
                      reason=excluded.reason, detail=excluded.detail, score=excluded.score,
                      flow=excluded.flow, last_event_us=excluded.last_event_us""",
                                (ip, row["backend"], row["reason"], row["detail"], row["score"],
                                 row["flow"], ts, ts))
            elif a in ("counters", "expire", "unblock") and ip:
                status = {"counters": "active", "expire": "expired", "unblock": "unblocked"}[a]
                self.db.execute("""UPDATE blocked_ips SET status=?, last_event_us=?,
                    dropped_pkts=MAX(dropped_pkts, ?), dropped_bytes=MAX(dropped_bytes, ?)
                    WHERE ip=?""", (status, ts, row["dropped_pkts"], row["dropped_bytes"], ip))


class ClickHouseEventSink:
    """sentinel.mitigations over HTTP (created if missing)."""
    DDL = """CREATE TABLE IF NOT EXISTS sentinel.mitigations (
        ts_us UInt64, action LowCardinality(String), ip String, backend LowCardinality(String),
        reason LowCardinality(String), detail String, score Float64, flow String,
        ml_model LowCardinality(String), timeout_s Int64, dropped_pkts UInt64, dropped_bytes UInt64
    ) ENGINE = MergeTree() ORDER BY (ts_us, ip)"""

    def __init__(self, ch_store):
        self.ch = ch_store                    # daemon.ClickHouseStore
        self.ch._post(self.DDL)

    def write_event(self, row):
        self.ch._post("INSERT INTO sentinel.mitigations FORMAT JSONEachRow",
                      (json.dumps(row) + "\n").encode())


# ═════════════════════════════════════════════════════════════════════════
# CLI:  mitigator.py [--backend nftables] [--netns NS] setup|list|block IP|unblock IP|teardown
# ═════════════════════════════════════════════════════════════════════════
def main():
    import argparse
    ap = argparse.ArgumentParser(description="SentinelFlow mitigation control")
    ap.add_argument("--backend", choices=["dry-run", "nftables"], default="nftables")
    ap.add_argument("--netns", help="run nft inside this network namespace")
    ap.add_argument("--timeout", type=int, default=900, help="block duration, seconds")
    ap.add_argument("--allowlist-file", help="IPs/CIDRs (one per line) that are never blocked")
    ap.add_argument("cmd", choices=["setup", "list", "block", "unblock", "teardown"])
    ap.add_argument("ip", nargs="?")
    args = ap.parse_args()
    b = make_backend(args.backend, args.timeout, args.netns)
    if args.cmd == "setup":
        b.setup(); print("ok")
    elif args.cmd == "teardown":
        b.teardown(); print("ok")
    elif args.cmd == "list":
        for ip, e in sorted(b.list().items()):
            print(f"{ip:16s} expires_in={e['expires_s']}s dropped_pkts={e['packets']} "
                  f"dropped_bytes={e['bytes']}")
    else:
        if not args.ip:
            ap.error(f"{args.cmd} needs an IP")
        if args.cmd == "block":
            why = BlockPolicy(allowlist_file=args.allowlist_file).why_protected(args.ip)
            if why:
                sys.exit(f"refusing to block {args.ip}: {why}")
            print("added" if b.block(args.ip, args.timeout, REASON_MANUAL, "manual") else "already present")
        else:
            print("removed" if b.unblock(args.ip) else "not present")


if __name__ == "__main__":
    main()

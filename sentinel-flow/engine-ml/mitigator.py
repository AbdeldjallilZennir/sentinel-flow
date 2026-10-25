#!/usr/bin/env python3
"""
SentinelFlow Phase 4 — mitigation.

This module turns scored flow records into block decisions. Part 1 (this
file, so far) is the policy: WHICH remote address to block and WHY.
Kernel backends (nftables, XDP) are added separately.

Policy (decisions() / decide()), decided per remote IP, not per flow:
  * Triggers that block the remote peer of the flow:
      - ml_score:    one flow with ml_anomaly_score >= high_threshold
                     (default 0.95), from a trained model
      - ml_repeat:   repeat_count flows (default 2) to the same remote IP
                     with ml_anomaly_score >= threshold (default 0.80)
                     within repeat_window_s (default 1 h). Active-timeout
                     snapshots of one connection count as one flow.
      - severe_risk: ndpi_risk_mask has a "severe" bit (features.SEVERE_MASK:
                     DGA domain, risky domain, malicious fingerprint,
                     malicious cert SHA-1, possible exploit, malware host)
    Records scored by the Phase 2 heuristic are not trusted to block.
    Any other nDPI risk never blocks on its own: in Phase 3 the "any risk"
    rule alerted on 18 % of real Windows background flows (docs/REPORT.md, Part 3 §8.4).
    On the out-of-fold training predictions, "one flow >= 0.80" blocked 44
    benign endpoints; "one >= 0.95 or two >= 0.80" blocked 15, keeping 15
    of the 16 infections caught (docs/REPORT.md, Part 6). high_threshold=0.80 with
    repeat_count=1 restores the per-flow rule.
  * Trigger that blocks the SOURCE of the flow (the scanner):
      - scan: one source reaches scan_ports distinct ports (default 50) on
              one host, or sweep_hosts distinct hosts (default 100) on one
              port with short flows (<= 3 packets), within scan_window_s
              (default 60 s). Benign training traffic peaks at 9 ports and
              40 hosts; the lab nmap session reached 1,000 ports.
              Fires at most once per (source, target) per scan_cooldown_s.
              The source address of a scan can be forged, so a scan "from"
              a server this network used within peer_memory_s (default
              24 h: a local host started a flow to it and it answered) is
              reported, not blocked. Otherwise anyone could cut the network
              off from its DNS resolver; a forged scan returns no results
              to the attacker. All other scanners are blocked at once.
    Time comes from the flow timestamps, so PCAP replays behave like live.
  * Target: the remote peer, never a protected address. For ML / severe
    triggers the responder (dst_ip) is preferred; src_ip is used only if
    dst_ip is protected. Scans only ever target the source.
    If the chosen endpoints are protected, nothing is blocked (the decision
    is still audited as skip_protected).
  * Protected addresses:
      - always (cannot be disabled): loopback, link-local, multicast,
        unspecified, reserved, broadcast, and this machine's own addresses
        (the daemon reads them with `ip addr`, also when they are public)
      - by default: RFC 1918 + 127.0.0.0/8 (--protected-cidr), so a LAN
        victim's own address is never blocked
      - --allow-private-blocks removes the RFC 1918 ranges (lab use)
      - --allowlist / --allowlist-file: addresses / CIDRs never blocked.
        The built-in list stays minimal on purpose; operators should add
        their own cloud/CDN/SaaS ranges (see docs/REPORT.md, Part 4).
  * IPv4 only (the sensor and the XDP map are IPv4).
"""

import collections
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
HIGH_THRESHOLD = 0.95
REPEAT_COUNT = 2
REPEAT_WINDOW_S = 3600
SCAN_PORTS = 50
SWEEP_HOSTS = 100
SWEEP_MAX_PKTS = 3
SCAN_WINDOW_S = 60
SCAN_COOLDOWN_S = 600
PEER_MEMORY_S = 24 * 3600   # how long a server this network used stays "known"
RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
DEFAULT_PROTECTED = RFC1918 + ("127.0.0.0/8",)
UNTRUSTED_SCORERS = {"", "heuristic_v1"}

# Reason codes (also stored in the XDP map's block_entry.reason_code).
REASON_ML = 1
REASON_SEVERE_RISK = 2
REASON_MANUAL = 3
REASON_ML_REPEAT = 4
REASON_SCAN = 5
REASON_NAMES = {REASON_ML: "ml_score", REASON_SEVERE_RISK: "severe_risk",
                REASON_MANUAL: "manual", REASON_ML_REPEAT: "ml_repeat",
                REASON_SCAN: "scan"}


class WindowDistinct:
    """Distinct values seen in the last `window_us` (by flow timestamp)."""

    __slots__ = ("window_us", "events", "counts", "newest")

    def __init__(self, window_us):
        self.window_us = window_us
        self.events = collections.deque()       # (t_us, value)
        self.counts = collections.Counter()
        self.newest = 0

    def add(self, t_us, value):
        self.newest = max(self.newest, t_us)
        self.events.append((t_us, value))
        self.counts[value] += 1
        cutoff = self.newest - self.window_us
        while self.events and self.events[0][0] < cutoff:
            _, v = self.events.popleft()
            self.counts[v] -= 1
            if not self.counts[v]:
                del self.counts[v]
        return len(self.counts)

    def clear(self):
        self.events.clear()
        self.counts.clear()


def flow_time_us(rec, field):
    t = rec.get(field)
    return int(t) if t else time.time_ns() // 1000


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


def local_ipv4_addresses(netns=None):
    """This machine's IPv4 addresses (all interfaces), from `ip -j addr`.
    Raises OSError / ValueError / subprocess.CalledProcessError on failure."""
    cmd = ["ip", "-j", "-4", "addr", "show"]
    if netns:
        cmd = ["ip", "-n", netns] + cmd[1:]
        if os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return sorted({a["local"] for iface in json.loads(out)
                   for a in iface.get("addr_info", [])
                   if a.get("family") == "inet" and a.get("local")})


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
    MAX_TRACKED = 100_000           # keys per tracker before stale ones are pruned

    def __init__(self, threshold=ALERT_THRESHOLD, use_severe_risk=True,
                 protected_cidrs=DEFAULT_PROTECTED, allowlist=(),
                 allow_private_blocks=False, trust_heuristic=False, allowlist_file=None,
                 high_threshold=HIGH_THRESHOLD, repeat_count=REPEAT_COUNT,
                 repeat_window_s=REPEAT_WINDOW_S, scan_ports=SCAN_PORTS,
                 sweep_hosts=SWEEP_HOSTS, scan_window_s=SCAN_WINDOW_S,
                 scan_cooldown_s=SCAN_COOLDOWN_S, sweep_max_pkts=SWEEP_MAX_PKTS,
                 own_addresses=(), peer_memory_s=PEER_MEMORY_S):
        if repeat_count < 1:
            raise ValueError("repeat_count must be >= 1")
        self.threshold = threshold
        self.high_threshold = max(high_threshold, threshold)
        self.repeat_count = int(repeat_count)
        self.repeat_window_us = int(repeat_window_s * 1e6)
        self.scan_ports = int(scan_ports)           # 0 disables
        self.sweep_hosts = int(sweep_hosts)         # 0 disables
        self.sweep_max_pkts = int(sweep_max_pkts)
        self.scan_window_us = int(scan_window_s * 1e6)
        self.scan_cooldown_us = int(scan_cooldown_s * 1e6)
        self.use_severe_risk = use_severe_risk
        self.trust_heuristic = trust_heuristic
        self._ml_hits = {}          # remote ip -> WindowDistinct of flow ids
        self._ports = {}            # (src, dst, proto) -> WindowDistinct of dst ports
        self._hosts = {}            # (src, dport, proto) -> WindowDistinct of dst ips
        self._scan_fired = {}       # (kind, key) -> t_us of the last scan trigger
        self._contacted = {}        # remote ip -> t_us this network last used it as a server
        self.peer_memory_us = int(peer_memory_s * 1e6)
        self._seq = 0
        self.set_own_addresses(own_addresses)
        protected = parse_networks(protected_cidrs)
        if allow_private_blocks:
            private = set(parse_networks(RFC1918))
            protected = [n for n in protected if n not in private]
        self.protected = protected
        self.allowlist = parse_networks(allowlist)
        if allowlist_file:
            self.allowlist += load_allowlist_file(allowlist_file)

    # ── address checks ─────────────────────────────────────────────────
    def set_own_addresses(self, addrs):
        """This machine's addresses: never blocked, whatever the CIDR lists say.
        Without this, an inbound flow on a host with a public address picked
        the host itself as the target (responder first) and not the attacker."""
        self.own = {ipaddress.ip_address(a) for a in addrs}

    def why_protected(self, ip_str):
        """Reason this address must never be blocked, or None."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "not an IP address"
        if ip.version != 4:
            return "not IPv4"
        if ip in self.own:
            return "this machine's own address"
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
    def _ml_suspect(self, rec):
        """Score if it is >= threshold and comes from a trusted model, else None."""
        score = rec.get("ml_anomaly_score")
        model = rec.get("ml_model", "")
        if score is not None and score >= self.threshold and \
                (self.trust_heuristic or model not in UNTRUSTED_SCORERS):
            return score
        return None

    def _severe(self, rec):
        if not self.use_severe_risk:
            return None
        severe = int(rec.get("ndpi_risk_mask", 0)) & features.SEVERE_MASK
        if not severe:
            return None
        names = [n for n, b in features.SEVERE_RISKS.items() if severe >> b & 1]
        return "ndpi severe risk: " + ",".join(names)

    def _flow_decision(self, rec):
        """ML / severe-risk decision for the flow's remote peer, or None."""
        score = self._ml_suspect(rec)
        severe = self._severe(rec)
        if score is None and severe is None:
            return None
        target, reasons = None, []
        for ip in (rec["dst_ip"], rec["src_ip"]):          # responder first
            why = self.why_protected(ip)
            if why is None:
                target = ip
                break
            reasons.append(f"{ip}: {why}")
        model = rec.get("ml_model", "")
        if score is not None and score >= self.high_threshold:
            code, detail = REASON_ML, f"ml_anomaly_score={score:.3f} >= {self.high_threshold:.2f} ({model})"
        elif severe is not None:
            code, detail = REASON_SEVERE_RISK, severe
        else:
            # threshold <= score < high_threshold: count flows per remote IP.
            code = REASON_ML_REPEAT
            n = 0
            if target is not None:
                hits = self._ml_hits.get(target)
                if hits is None:
                    hits = self._ml_hits[target] = WindowDistinct(self.repeat_window_us)
                n = hits.add(flow_time_us(rec, "last_seen_us"), self._flow_id(rec))
                self._prune(self._ml_hits, self.repeat_window_us)
            detail = (f"{n} flows with ml_anomaly_score >= {self.threshold:.2f} within "
                      f"{self.repeat_window_us // 1_000_000}s (latest {score:.3f}, {model})"
                      if target is not None else f"ml_anomaly_score={score:.3f} ({model})")
            if target is not None and n < self.repeat_count:
                return Decision("skip", target, 0, "watching: " + detail, score)
        if target is None:
            return Decision("skip", None, code,
                            f"{detail}; both endpoints protected ({'; '.join(reasons)})",
                            rec.get("ml_anomaly_score"))
        return Decision("block", target, code, detail, rec.get("ml_anomaly_score"))

    def _scan_decisions(self, rec):
        """Port-scan / host-sweep decisions against the flow's source."""
        if rec.get("protocol") not in (6, 17) or "dst_port" not in rec:
            return []
        t = flow_time_us(rec, "first_seen_us")
        src, dst, proto, dport = rec["src_ip"], rec["dst_ip"], rec["protocol"], rec["dst_port"]
        name = "TCP" if proto == 6 else "UDP"
        found = []
        if self.scan_ports:
            key = (src, dst, proto)
            w = self._ports.get(key)
            if w is None:
                w = self._ports[key] = WindowDistinct(self.scan_window_us)
            n = w.add(t, dport)
            if n >= self.scan_ports:
                found.append((("ports", key), w,
                              f"port scan: {n} {name} ports on {dst} within "
                              f"{self.scan_window_us // 1_000_000}s"))
            self._prune(self._ports, self.scan_window_us)
        if self.sweep_hosts and int(rec.get("pkt_count", 0)) <= self.sweep_max_pkts:
            key = (src, dport, proto)
            w = self._hosts.get(key)
            if w is None:
                w = self._hosts[key] = WindowDistinct(self.scan_window_us)
            n = w.add(t, dst)
            if n >= self.sweep_hosts:
                found.append((("hosts", key), w,
                              f"host sweep: {n} hosts on {name}/{dport} within "
                              f"{self.scan_window_us // 1_000_000}s"))
            self._prune(self._hosts, self.scan_window_us)
        out = []
        for fired_key, w, detail in found:
            last = self._scan_fired.get(fired_key)
            if last is not None and t - last < self.scan_cooldown_us:
                continue
            self._scan_fired[fired_key] = t
            w.clear()
            why = self.why_protected(src)
            used = self._contacted.get(src)
            if why is None and used is not None and t - used <= self.peer_memory_us:
                # The source address can be forged: blocking a server this
                # network depends on (its DNS resolver, say) would let anyone
                # cut it off. A real scanner gets no results from a forged
                # source, so reporting is enough here; other scanners are
                # still blocked at once.
                why = (f"a server this network used {max(t - used, 0) // 1_000_000}s ago; "
                       f"the source may be forged")
            if why is None:
                out.append(Decision("block", src, REASON_SCAN, detail))
            else:
                out.append(Decision("skip", None, REASON_SCAN,
                                    f"{detail}; scanner protected ({src}: {why})"))
        if len(self._scan_fired) > self.MAX_TRACKED:
            cutoff = t - self.scan_cooldown_us
            self._scan_fired = {k: v for k, v in self._scan_fired.items() if v >= cutoff}
        return out

    def _prune(self, table, window_us):
        """Drop trackers with nothing in their window once the table is large."""
        if len(table) <= self.MAX_TRACKED:
            return
        newest = max(w.newest for w in table.values())
        for k in [k for k, w in table.items() if w.newest < newest - window_us]:
            del table[k]

    def _flow_id(self, rec):
        """One value per connection: the sensor's active-timeout snapshots of a
        long connection repeat its 5-tuple and first_seen_us, so they count
        once. Records without those fields (tests, tools) count separately."""
        key = tuple(rec.get(k) for k in ("src_ip", "src_port", "dst_ip", "dst_port",
                                         "protocol", "first_seen_us"))
        if None in key:
            self._seq += 1
            return self._seq
        return key

    def _note_server(self, rec):
        """Remember remote servers this network uses: a local address started
        the flow and the remote side answered."""
        if not int(rec.get("bytes_down") or 0):
            return
        src, dst = rec.get("src_ip"), rec.get("dst_ip")
        if not src or not dst or self.why_protected(src) is None or \
                self.why_protected(dst) is not None:
            return
        t = flow_time_us(rec, "last_seen_us")
        if t > self._contacted.get(dst, 0):
            self._contacted[dst] = t
        if len(self._contacted) > self.MAX_TRACKED:
            cutoff = t - self.peer_memory_us
            self._contacted = {k: v for k, v in self._contacted.items() if v >= cutoff}

    def decisions(self, rec):
        """All decisions for this record ([] if nothing applies). Updates state."""
        self._note_server(rec)
        out = self._scan_decisions(rec)
        d = self._flow_decision(rec)
        if d is not None:                   # includes "watching" skips (reason_code 0)
            out.insert(0, d)
        return out

    def decide(self, rec):
        """First decision for this record (a block if any), or a no-trigger skip."""
        ds = self.decisions(rec)
        for d in ds:
            if d.action == "block":
                return d
        return ds[0] if ds else Decision("skip", detail="no trigger")


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
            flow = f"{r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']} {r.get('app_protocol', '')}"
            for d in self.policy.decisions(r):
                events += self._apply(d, r, flow, now)
        if time.time() - self.last_refresh >= self.refresh_s:
            events += self.refresh()
        return events

    def _apply(self, d, r, flow, now):
        if d.action == "skip":
            if not d.reason_code:              # e.g. "watching": below the repeat count
                return []
            self.stats["skips_protected"] += 1  # trigger fired but endpoint protected
            if d.reason_code == REASON_SCAN:
                self.log(f"SCAN (not blocked) {d.detail}")
            return [self._emit(action="skip_protected", reason=d.reason, detail=d.detail,
                               score=d.score, flow=flow, ml_model=r.get("ml_model"))]
        cur = self.active.get(d.ip)
        if cur and cur["until"] > now:
            return []                           # already blocked
        try:
            added = self.backend.block(d.ip, self.timeout_s, d.reason_code, d.detail)
        except Exception as e:
            self.stats["errors"] += 1
            return [self._emit(action="error", ip=d.ip, reason=d.reason,
                               detail=f"block failed: {e}", flow=flow)]
        self.active[d.ip] = {"until": now + self.timeout_s, "packets": 0, "bytes": 0}
        self.stats["blocks"] += 1
        self.log(f"BLOCK {d.ip} ({d.reason}: {d.detail}) flow {flow}")
        return [self._emit(action="block", ip=d.ip, reason=d.reason,
                           detail=d.detail + ("" if added else " (already in kernel set)"),
                           score=d.score, flow=flow, ml_model=r.get("ml_model"),
                           timeout_s=self.timeout_s)]

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

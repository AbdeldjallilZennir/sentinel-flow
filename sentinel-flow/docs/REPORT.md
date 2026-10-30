# SentinelFlow — Project Report (Parts 1–8)

All phase reports in one file, in the order they were written. Each part keeps its original text; only headings were moved one level down, cross-references were changed from file names (`Part3.md`) to part names (Part 3), and image paths were fixed. Numbers in an older part describe the code and model **at that time**; later parts say what changed.

For a plain-language explanation of the project and every tool, read [GUIDE.md](GUIDE.md). Planned next steps are in [NEXT_STEPS.md](NEXT_STEPS.md).

## Contents

- [Part 1](#part-1) — C packet-capture sensor: build, audit and first fixes (2026-10-21)
- [Part 1.2](#part-1-2) — Sensor follow-up: ZeroMQ delivery, timestamps, tests (2026-10-22)
- [Part 2](#part-2) — Ingestion and analytics: daemon, SQLite / ClickHouse, Grafana (2026-10-23)
- [Part 3](#part-3) — Audit of phases 1-3, labeled dataset, ML model, holdout test (2026-10-23)
- [Part 4](#part-4) — Kernel blocking with nftables, blocking policy, closed-loop test (2026-10-23)
- [Part 5](#part-5) — Packaging, VM install, first live nmap test, risk-mask fix, retrain (2026-10-24)
- [Part 6](#part-6) — Severe alert default, per-IP blocking rule, scan detection, dashboard events (2026-10-24)
- [Part 7](#part-7) — 23 more training cases, retrained model (2026-10-24)
- [Part 8](#part-8) — Code review: 15 bugs found and fixed (2026-10-25)
- [Part 9](#part-9) — Conversation timing features (`fv2`), retrain (2026-10-27)

---

<a id="part-1"></a>

## Part 1: C Packet Capture Sensor

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Component:** Part 1, C packet capture sensor
**Tree:** `/home/joe/cv_work/sentinel-flow/sensor-c/`
**Date:** October 21, 2026
**Status:** fixes applied, end-to-end delivery still blocked

> [!info] Scope
> This document replaces the previous Part 1 write-up. It covers only the C sensor: how it was built on this Kali host, the five fixes that were applied and compiled, the unit tests that actually ran, the three JSON records captured on stdout with `-v`, the partial ndpiReader cross-check, and the ZMQ path that is still broken. Nothing in this report is a throughput number, a valgrind result, or a claim that a downstream consumer received a message. Where a check was not run, it is listed as not run.

---

### 1. Executive summary

Part 1 is a userspace sensor. It reads packets with libpcap (offline PCAP or a live interface flag), keeps one `flow_entry_t` per bidirectional 5-tuple in a uthash table, asks nDPI 6.1 for an application label, a JA4 client string, and a risk mask, and emits one JSON object per finished flow. The object is handed to a ZeroMQ `PUSH` socket and, when `-v` is set, printed to stdout as well. Decryption is not part of the design. The features are metadata: addresses, ports, IP protocol, nDPI's label, JA4 when a TLS handshake was seen, byte and packet counts, inter-arrival and payload-length statistics, and two timestamps.

Five defects that were present in that pipeline have been changed in source and the tree has been rebuilt. The direction used for export is no longer the sorted hash key. Welford minima no longer stay at 0.0 after a `calloc`. Flows that end before nDPI sets `detection_completed` now pass through `ndpi_detection_giveup` at export. The process links one copy of cJSON, the copy compiled from `src/cJSON.c`, and does not also link `libcjson.so`. `ZMQ_LINGER` on the publisher is 1000 ms instead of 0. A small `zmq_sink` utility was added so a consumer could be pointed at `ipc:///tmp/ndpi_flows.sock`.

> [!success] What is actually shown to work
> `./test_stats` printed `=== Results: 24 passed, 0 failed ===`. `cmake .. -DCMAKE_BUILD_TYPE=Debug` followed by `make -j$(nproc)` produced `sensor`, `zmq_sink`, and `test_stats` with zero warnings under `-Wall -Wextra -Wpedantic -O2`. The sensor link line no longer contains `libcjson`. With `-v`, three offline captures produced one JSON object each: DNS (`app_protocol` `DNS`), HTTP (`HTTP.Google`), and a full TLS handshake (`TLS.ntop`) whose `ja4_client` is `t12d6707h2_2955a3196ffa_c83f907a73d3`. On the TLS file, ndpiReader also reported one flow, 109 packets, and protocol `ntop`.

> [!warning] What is not shown, and must not be claimed
> `zmq_sink` never received a message. Three wiring attempts all ended at zero messages, so `ZMQ_LINGER=1000` is compiled and unproven. The 23 keys present in the captured objects were checked on stdout, not on the socket. `src/zmq_sink.c` now calls `zmq_bind`, while the last binary that was successfully compiled was built from the `zmq_connect` variant, and `sensor` also binds. As the tree stands, both ends bind. Timestamps are emitted as JSON numbers and are already collapsing (`first_seen_us` and `last_seen_us` print identical while `flow_duration_ms` is not zero). valgrind was not run. No packets-per-second figure exists. Live `-i` capture was not executed. The 30-second expiry path and the signal flush path were not triggered. DNS and HTTP were not cross-checked with ndpiReader. No PCAP in this set produced a non-zero `ndpi_risk_mask`.

The previous status line that called the sensor "functional" with "quantitative validation pending" is withdrawn. The correct status is the one in the header: the fixes are in, the stdout export can be read, and end-to-end delivery is still blocked.

---

### 2. Where the work stands

| Item | State | Evidence |
|---|---|---|
| Canonical export direction (Fix 1) | Applied, compiled | `orig_*` stored on create; export and byte split use those fields. Direction unit test does not exist. |
| Welford `min_val` (Fix 2) | Applied, unit-tested | Case 1 expects `min_val == 42`, not `0`. Suite result: 24 passed, 0 failed. |
| IAT of packet 1 | Guarded | `welford_update` on IAT runs only when `pkt_count > 1`. |
| Protocol on short flows (Fix 3) | Applied, compiled | `export_flow` calls `ndpi_detection_giveup` when `detection_completed` is still false. |
| cJSON ABI (Fix 4a) | Applied, configure-checked | CMake status line: `cJSON: using embedded src/cJSON.c (system libcjson NOT linked)`. Sensor link line has no `libcjson`. |
| `ZMQ_LINGER` (Fix 4b) | Compiled, effect unverified | Source sets `int linger = 1000`. No consumer ever read a message. |
| `zmq_sink` (Fix 5) | Built | Binary exists. It received 0 messages. Source and that binary disagree on bind vs connect. |
| Stdout JSON (`-v`) | Captured | One DNS object, one HTTP object, one TLS object, quoted in §7. |
| JA4 populated | Observed once | TLS record only. Not compared with ndpiReader's JA4. Not tried on QUIC. |
| ndpiReader cross-check | Partial | TLS file only. DNS and HTTP greps produced nothing usable. |
| ZMQ delivery | Blocked | Three attempts, all 0 messages. Next change is identified and not written. |
| Timestamp encoding | Broken, not fixed | All three records print `first_seen_us` equal to `last_seen_us` in scientific-notation form. |
| valgrind | Not run | A double-free was fixed empirically earlier. Leak profile is unknown. |
| Throughput | Not run | No rate may be quoted. |
| Live `-i` | Compiled, not executed | Flag is in `usage()`. |
| 30 s expiry and signal flush | Not exercised | The PCAPs are short. |
| Direction / byte-accounting tests | Absent | `test_stats` covers `stats.h` only. |

> [!info] How to read the table
> "Applied, compiled" means the change is in the sources that `make` built, and the build reported zero warnings. It does not mean a packet-level assertion exists. Only the Welford suite has that kind of evidence. The TLS stdout record is the strongest end-to-end evidence the sensor has, and it never crossed the socket.

---

### 3. Environment, and why headers are vendored

#### 3.1 Host toolchain

The sensor was built on Kali Linux.

| Component | What was on the machine |
|---|---|
| Compiler | GCC 14.3.0 |
| Build system | CMake 4.3.4 |
| nDPI | 6.1.0-5906-90eb617, built from source at `/home/joe/nDPI` |
| nDPI header | `/home/joe/nDPI/src/include/ndpi_api.h` |
| nDPI library | `/home/joe/nDPI/src/lib/libndpi.so` |
| libpcap | 1.10.6, `/usr/include/pcap.h` present |
| libzmq | 4.3.5, runtime soname `libzmq.so.5` only |
| libcjson | 1.7.18, runtime soname `libcjson.so.1` only |

nDPI was never `make install`ed. The build points at the source tree with `NDPI_ROOT` (`$ENV{HOME}/nDPI` by default) and `find_library(ndpi ... NO_DEFAULT_PATH)` inside `/home/joe/nDPI/src/lib`. Anything that runs the sensor or ndpiReader against that library needs `LD_LIBRARY_PATH=/home/joe/nDPI/src/lib`. The ndpiReader cross-check in §7.4 was run that way.

#### 3.2 Apt could not supply `-dev` packages

> [!warning] No archive access
> `apt-get install -y libndpi-dev uthash-dev libcjson-dev libzmq3-dev` failed at the fetch stage. `kali.download` was unreachable and the IPv6 route was missing. No `-dev` package from that command was installed. The tree is shaped around that failure. Replacing the vendored headers with distro packages was not possible in this session, and this report does not assume a later `apt-get` succeeded.

Consequences, one library at a time:

- **libzmq.** The runtime loader can open `libzmq.so.5`. There was no `zmq.h`, and there was no `libzmq.so` development symlink. A symlink was created by hand so `-lzmq` resolves, and `src/zmq.h` was written by hand so the sensor compiles. That header is a project file, not a copy installed by the package manager.
- **libcjson.** Only `libcjson.so.1` was present. There was no development header. A symlink was created, and both the header and the implementation were embedded: `src/cJSON.h` and `src/cJSON.c`. Fix 4a then stopped the build from linking the system `.so` at all, so the embedded `.c` is the only cJSON in the process.
- **uthash.** No `uthash-dev` package. `src/uthash.h` was copied from `/home/joe/nDPI/src/lib/third_party/include/uthash.h`.
- **nDPI.** There is no installed `libndpi-dev`. Includes come from `/home/joe/nDPI/src/include` and `/home/joe/nDPI/src/lib/third_party/include`. The shared object is the one in the nDPI build tree.

libpcap is the exception: the header and the library were already usable, and CMake uses `find_library(pcap REQUIRED)`.

#### 3.3 What that means for the binary

The sensor is not a portable "link against distro nDPI" binary. It is tied to:

1. the nDPI 6.1 tree at `/home/joe/nDPI` (API and ABI of that build),
2. a hand-written `zmq.h` matched to libzmq 4.3.5 as present here,
3. the embedded cJSON, whose number printer is the one that emits the timestamps in §9,
4. a copied `uthash.h`.

> [!bug] Hand-written `zmq.h` is a standing risk
> The publisher and the sink both include `src/zmq.h`, not a system header. Socket-option constants and function prototypes in that file were not produced by the libzmq build. The delivery failure in §8 is explained by bind/connect timing, not by a proven header mismatch, but a hand-written header remains an unverified surface. This session did not diff `src/zmq.h` against upstream 4.3.5 headers, because those headers were not on the machine.

---

### 4. Source tree and build

#### 4.1 Files

`sensor-c/CMakeLists.txt` builds three targets.

| Target | Sources | Libraries |
|---|---|---|
| `sensor` | `src/main.c`, `src/flow_table.c`, `src/ndpi_wrapper.c`, `src/zmq_publisher.c`, `src/stats.c`, `src/cJSON.c` | libndpi, libpcap, libzmq, `libm`, `pthread`. Not libcjson. |
| `zmq_sink` | `src/zmq_sink.c` | libzmq only |
| `test_stats` | `src/test_stats.c` | `libm` only |

Headers and the extra translation units sitting next to those sources: `src/flow_table.h`, `src/ndpi_wrapper.h`, `src/zmq_publisher.h`, `src/stats.h`, `src/cJSON.h`, `src/zmq.h`, `src/uthash.h`.

A line count taken before `zmq_sink.c` and `test_stats.c` existed was **3,968 lines across 15 `.c`/`.h` files**. Those two files were added after that count. This report does not replace 3,968 with a new total.

`stats.h` holds the Welford functions as `static inline`. `test_stats.c` includes that header and does not link `stats.c`. `sensor` still compiles `src/stats.c` as its own translation unit.

#### 4.2 CMake facts that matter

Flags applied to every C file:

```text
add_compile_options(-Wall -Wextra -Wpedantic -O2)
```

The configure that was run was `cmake .. -DCMAKE_BUILD_TYPE=Debug`. The `-O2` above is unconditional in `CMakeLists.txt`; this report does not claim a separate Debug-flag audit beyond "zero warnings under those four flags."

cJSON is forced embedded:

```text
message(STATUS "cJSON: using embedded src/cJSON.c (system libcjson NOT linked)")
```

`find_library` is not called for cjson. `target_link_libraries(sensor ...)` comments that `libcjson` is omitted on purpose. The sensor install rule installs `sensor` and `zmq_sink` only; `test_stats` is a build-tree executable.

#### 4.3 Build result

> [!success] Build
> `cmake .. -DCMAKE_BUILD_TYPE=Debug` then `make -j$(nproc)` produced all three targets. The compiler reported zero warnings under `-Wall -Wextra -Wpedantic -O2`. The `sensor` link line does not contain `libcjson`.

That is the verification for "it compiles." It is not verification of ZMQ delivery, leak freedom, or packet rate.

---

### 5. The five fixes

Each subsection is symptom, root cause, the change as it stands in the tree, and what was actually used to check it.

#### 5.1 Fix 1 — canonical key vs export direction

**Symptom.** The hash key was sorted. Whenever the client address was numerically larger than the server address, `src_ip` / `dst_ip` in the key were the reverse of the packet that created the flow. Export used to read that key. A client could be reported as the server, and `bytes_up` / `bytes_down` followed the same inversion.

**Root cause.** One 5-tuple was being asked to do two jobs. uthash needs a single key so that both directions of a connection hit one bucket. Export needs a stable notion of "this side" and "the other side." Sorting the key is correct for the first job and wrong for the second if the sorted fields are also what gets printed.

**Change.** The sorted key remains the uthash key and nothing else. `flow_entry_t` carries the first packet's addresses and ports, written once, at creation:

```c
/* Original (initiator) 5-tuple.
 * Recorded from the FIRST packet seen for this flow.
 * Used in JSON export so src_ip/src_port always refer to the
 * sender of packet #1, regardless of canonical key direction. */
uint32_t orig_src_ip;
uint32_t orig_dst_ip;
uint16_t orig_src_port;
uint16_t orig_dst_port;
```

The header comment in the tree says "flow initiator." The assignment site does not look for a TCP SYN. It copies the packet that caused `created == true`:

```c
if (created) {
    total_flows++;
    flow->first_seen_us = pkt_time_us;
    flow->last_pkt_us   = pkt_time_us;

    flow->orig_src_ip   = pkt_src_ip;
    flow->orig_dst_ip   = pkt_dst_ip;
    flow->orig_src_port = pkt_src_port;
    flow->orig_dst_port = pkt_dst_port;

    flow->ndpi_flow = ndpi_wrapper_alloc_flow();
}
```

Export prints those fields, not `entry->key`:

```c
ip_to_str(entry->orig_src_ip, src_str, sizeof(src_str));
ip_to_str(entry->orig_dst_ip, dst_str, sizeof(dst_str));
cJSON_AddStringToObject(root, "src_ip",   src_str);
cJSON_AddStringToObject(root, "dst_ip",   dst_str);
cJSON_AddNumberToObject(root, "src_port", ntohs(entry->orig_src_port));
cJSON_AddNumberToObject(root, "dst_port", ntohs(entry->orig_dst_port));
```

Byte direction does not trust `is_reverse`. `is_reverse` is still computed, and it is still passed into nDPI as `in_pkt_dir`, because that flag is about the canonical key's orientation. Counters compare the packet with the stored original tuple:

```c
bool is_upstream = (pkt_src_ip   == flow->orig_src_ip &&
                    pkt_src_port == flow->orig_src_port);
uint16_t ip_len = ntohs(iph->ip_len);
if (is_upstream)
    flow->bytes_up   += ip_len;
else
    flow->bytes_down += ip_len;
```

`bytes_up` is "bytes whose source is the first packet's source." `bytes_down` is the other direction. `ip_len` is the IPv4 total length (`iph->ip_len`), not the captured frame length. That choice shows up in the TLS cross-check (§7.4).

**What "first packet" is not.** On the DNS PCAP the exported `src_port` is 53 and `dst_port` is 32795. The first packet in that file is the server-to-client response. `orig_*` therefore describes the responder. That is consistent with the code above. It is not consistent with a reading of the header comment that says "initiator" in the TCP-SYN sense. UDP captures, and any capture that starts mid-flow, can begin at the responder. Consumers must treat `src_*` as "endpoint that sent the first packet this sensor saw."

> [!warning] Fix 1 has no unit test
> `test_stats` does not build a flow key, does not feed a packet, and does not check `bytes_up`. The DNS record is evidence that the export path can print port 53 as `src_port`. It is not a test that swaps a numerically larger client and checks both directions. That test is still on the backlog.

#### 5.2 Fix 2 — Welford `min_val` stuck at 0, and the IAT guard

**Symptom.** `min_val` on both IAT and payload length stayed 0.0 for every flow. Maxima moved. Minima did not. Both series are positive in this sensor (a payload length is a `uint16_t` promoted to `double`; an IAT is a difference of two timestamps, and the first packet is not supposed to produce one).

**Root cause.** `flow_entry_t` is allocated with `calloc`, so a freshly created `welford_state_t` has `min_val == 0.0` and `max_val == 0.0` until something writes them. `welford_update` used to update min with `if (value < min_val)`. Every positive sample fails that comparison against 0.0, so `min_val` never leaves 0.0. `max_val` happens to climb because positives are greater than 0.0. `welford_init()` did set `min_val = DBL_MAX` and `max_val = -DBL_MAX`, but the packet path was not going through that function on the calloc'd flow state; the zeros from `calloc` were the live values.

A second, related bug sits on IAT. `last_pkt_us` starts at 0. If packet 1 is allowed to compute `pkt_time_us - last_pkt_us`, the result is a Unix-epoch-scale interval, and that single sample dominates mean, variance, min, and max.

**Change.** The first sample is now an assignment, not a comparison. `welford_init` still plants the wide sentinels so that "init then read" is defined.

```c
static inline void welford_init(welford_state_t *s) {
    s->count   = 0;
    s->mean    = 0.0;
    s->m2      = 0.0;
    s->min_val = DBL_MAX;
    s->max_val = -DBL_MAX;
}

static inline void welford_update(welford_state_t *s, double value) {
    s->count++;

    if (s->count == 1) {
        s->mean    = value;
        s->m2      = 0.0;
        s->min_val = value;
        s->max_val = value;
        return;
    }

    double delta  = value - s->mean;
    s->mean      += delta / (double)s->count;
    double delta2 = value - s->mean;
    s->m2        += delta * delta2;

    if (value < s->min_val) s->min_val = value;
    if (value > s->max_val) s->max_val = value;
}
```

Variance remains the sample variance, `m2 / (count - 1)`, and it is 0 when `count < 2`. Standard deviation is `sqrt` of that. The early return on count 1 leaves `m2` at 0, so a one-sample population reports stddev 0, min = max = the sample.

The IAT call site refuses packet 1. `pkt_count` is incremented before the test:

```c
flow->pkt_count++;
/* ... payload update is unconditional ... */
welford_update(&flow->pkt_len_stats, (double)payload_len);

if (flow->pkt_count > 1) {
    double iat_us = (double)(pkt_time_us - flow->last_pkt_us);
    welford_update(&flow->iat_stats, iat_us);
}
flow->last_pkt_us = pkt_time_us;
```

So a 3-packet flow has 3 payload samples and 2 IAT samples. A 1-packet flow has a payload sample and an empty IAT state. Export already turns an empty IAT into zeros:

```c
cJSON_AddNumberToObject(root, "iat_min",
    entry->iat_stats.count > 0 ? entry->iat_stats.min_val : 0.0);
cJSON_AddNumberToObject(root, "iat_max",
    entry->iat_stats.count > 0 ? entry->iat_stats.max_val : 0.0);
```

**Verification.** This is the one fix with a direct regression test. Case 1 of `test_stats` feeds `42.0` once and requires `min_val == 42` and `max_val == 42`. Before the early-return, `min_val` would have stayed at the init sentinel or at the calloc zero, depending on whether `welford_init` had run; the test calls `welford_init` first, then `welford_update`. Against a correct init, the old comparison path would have kept `DBL_MAX` only if the first sample were not applied — the bug being regression-tested is the one the comment in `test_stats.c` names: min stuck at 0. The case passed. The other four cases check that the early return did not break multi-sample mean, sample variance, and re-init. Full numbers are in §6.

The IAT guard is not unit-tested. It is visible in `main.c`, and the DNS record is compatible with it (two positive intervals, min 233143 µs, not ~10^15). That compatibility is not a test harness.

#### 5.3 Fix 3 — protocol label on flows that end early

**Symptom.** A flow that was exported before `detection_completed` became true went out with an empty application protocol. Offline PCAPs hit this easily: the file ends, the sensor flushes the table, and nDPI may still be waiting for another packet that will never arrive.

**Root cause.** `detection_completed` was set from the live packet path only, after `ndpi_detection_process_packet` returned a non-zero master or app protocol, or after `NDPI_MAX_PACKETS` (15) packets had been fed. The flush/expire export path did not ask nDPI to give up. The label stayed at the zero protocol.

**Change.** `export_flow` now gives up before it reads the name:

```c
if (!entry->detection_completed && entry->ndpi_flow) {
    struct ndpi_detection_module_struct *mod = ndpi_wrapper_get_module();
    if (mod) {
        entry->detected_protocol =
            ndpi_detection_giveup(mod, entry->ndpi_flow);
        entry->detection_completed = true;
    }
}
```

The packet path still has its own give-up, used when 15 packets have been fed and both protocol ids are still 0. Fix 3 is the export-time call, for flows that finish sooner than that.

**Verification.** All three stdout records have a non-empty `app_protocol`: `DNS`, `HTTP.Google`, `TLS.ntop`. The TLS label matches ndpiReader's `ntop` on the same file (§7.4). This session did not capture a flow that was forced out specifically before the packet-path detector fired, so Fix 3 is compiled and the labels on these three files are non-empty. It is not demonstrated that give-up, rather than the normal detector, produced those three strings.

#### 5.4 Fix 4a — one cJSON in the process

**Symptom.** The project compiled `src/cJSON.c` and also linked `/usr/lib/x86_64-linux-gnu/libcjson.so`. Those are two cJSON implementations. `cJSON` is a struct with a public layout. If the two copies disagree about that layout, code that allocates on one side and reads on the other is an ABI break inside a single process. On this host the system side had no header (§3.2), which makes "link the `.so` and compile our `.c`" worse, not better.

**Root cause.** `find_library(cjson)` plus `src/cJSON.c` in `SENSOR_SOURCES`.

**Change.** `CMakeLists.txt` no longer searches for `cjson` and no longer puts it on the link line. `src/cJSON.c` is always compiled into `sensor`. The configure message is the check:

```text
cJSON: using embedded src/cJSON.c (system libcjson NOT linked)
```

The built `sensor` link line does not contain `libcjson`.

**Verification.** Configure output and the link line, as above. No runtime test loaded the system `libcjson.so` and compared struct sizes. The JSON in §7 was produced by the embedded printer (`cJSON_PrintUnformatted`), which is also why §9 is about that printer and not about the system library.

#### 5.5 Fix 4b — publisher linger

**Symptom.** `ZMQ_LINGER` was 0. `zmq_close` then discards anything still queued. An offline PCAP run finishes, flushes, and closes immediately. With linger 0, a consumer that is even slightly late sees nothing, and the sender cannot tell the messages were thrown away.

**Change.** In `zmq_publisher_init`:

```c
/* Linger 1 s so queued messages are flushed before close.
 * With linger=0 an offline PCAP run would silently drop every
 * message at zmq_close() before the sink had a chance to read. */
int linger = 1000;
zmq_setsockopt(zmq_sock, ZMQ_LINGER, &linger, sizeof(linger));
```

The socket is still `ZMQ_PUSH`, still `ZMQ_SNDHWM` 10000, still `zmq_bind` on the endpoint (default `ipc:///tmp/ndpi_flows.sock`), and `zmq_publisher_send` still uses `ZMQ_DONTWAIT`. `EAGAIN` is ignored. A send that happens before any peer is connected does not block the capture loop, and it also does not report failure to the caller beyond a `-1` that `export_flow` ignores.

> [!warning] Linger is not a result
> The 1000 ms value is in the binary that was linked after this edit. No run showed a message surviving `zmq_close` and arriving at a peer. §8 is why. Until a consumer prints one of the §7 objects from the socket, Fix 4b is an untested constant.

#### 5.6 Fix 5 — `zmq_sink`

**What was added.** `src/zmq_sink.c` is a small `ZMQ_PULL` process. Default endpoint `ipc:///tmp/ndpi_flows.sock`. It prints each payload as one line on stdout and leaves on `SIGINT` or `SIGTERM`. It links only libzmq. `make` built it.

The source as it sits in the tree binds:

```c
void *ctx  = zmq_ctx_new();
void *sock = zmq_socket(ctx, ZMQ_PULL);
int linger = 0;
zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));

if (zmq_bind(sock, endpoint) != 0) {
    fprintf(stderr, "[zmq_sink] bind(%s) failed: %s\n",
            endpoint, zmq_strerror(zmq_errno()));
    /* ... close and return 1 ... */
}
```

The comment at the top of the file says to start the sink before the sensor. The publisher also binds (§5.5). Two binds on one IPC endpoint conflict. The binary that was last compiled successfully was from an earlier variant that called `zmq_connect`, not `zmq_bind`. Source and binary are out of date with each other. Details and the three failed runs are in §8, not here, because this subsection is only "the tool was written and it compiled."

---

### 6. Unit tests

> [!success] `./test_stats`
> Output line: `=== Results: 24 passed, 0 failed ===`. Exit status is 0 when `fail_count == 0`. The 24 counts are individual `check()` calls, not 24 flows and not 24 JSON fields.

`check` passes when `fabs(got - want) <= eps`. The tolerances used below are the ones in `test_stats.c` (`EPS` is `1e-9` unless a call passes a tighter or looser epsilon).

| # | Case | Check | Expected | Got |
|---|---|---|---|---|
| 1 | Single value `42` | count | 1 | 1 |
| 2 | Single value `42` | mean | 42 | 42 |
| 3 | Single value `42` | stddev | 0 | 0 |
| 4 | Single value `42` | min_val | 42 | 42 |
| 5 | Single value `42` | max_val | 42 | 42 |
| 6 | `{2,4,4,4,5,5,7,9}` | count | 8 | 8 |
| 7 | Wikipedia vector | mean | 5 | 5 |
| 8 | Wikipedia vector | variance | 32/7 = 4.571428571 | 4.571428571 |
| 9 | Wikipedia vector | stddev | sqrt(32/7) = 2.138089935 | 2.138089935 |
| 10 | Wikipedia vector | min_val | 2 | 2 |
| 11 | Wikipedia vector | max_val | 9 | 9 |
| 12 | `{7,7}` | mean | 7 | 7 |
| 13 | `{7,7}` | stddev | 0 | 0 |
| 14 | `{7,7}` | min_val | 7 | 7 |
| 15 | `{7,7}` | max_val | 7 | 7 |
| 16 | `{100,200,150,50,300}` | mean | 160 | 160 |
| 17 | IAT-like vector | min_val | 50 | 50 |
| 18 | IAT-like vector | max_val | 300 | 300 |
| 19 | IAT-like vector | variance | 9250 | 9250 |
| 20 | IAT-like vector | stddev | sqrt(9250) = 96.17692031 | 96.17692031 |
| 21 | Re-init, then `{3,5}` | mean | 4 | 4 |
| 22 | Re-init | min_val | 3 | 3 |
| 23 | Re-init | max_val | 5 | 5 |
| 24 | Re-init | stddev | sqrt(2) = 1.414213562 | 1.414213562 |

Notes that belong with the table:

- Case 1 is the Fix 2 regression. The source comment says min would have been 0.0 before the fix. The run that produced "24 passed" got 42.
- Case 2 is the Bessel-corrected (sample) variance, `m2 / (n - 1)`, not the population variance. The Wikipedia / Knuth write-up of this vector is often quoted with population stddev 2. This test expects the sample stddev ≈ 2.138089935. That is what the code computes, and it is what passed.
- Case 3 guards the `count < 2` branch only partly: two samples, so variance uses `m2 / 1`. Identical values must still produce stddev 0. There is no separate assertion on `count` in this case.
- Case 4 is shaped like IATs (small positive numbers) but it does not call `main.c`. Deviations from 160 are −60, +40, −10, −110, +140. Sum of squares is 37000. Sample variance is `37000 / 4 = 9250`. The test passed at epsilon `1e-8`.
- Case 5 writes 999 and 1, calls `welford_init` again, then writes 3 and 5. Passing means the sentinels and the count went back to the init state. It does not mean a flow slot is reused that way in `main.c`.

What the suite does not cover, stated so it cannot be padded into a coverage claim:

- no `flow_key_t` sorting,
- no `orig_*` assignment,
- no `bytes_up` / `bytes_down`,
- no IAT skip on packet 1,
- no nDPI, no JSON, no ZeroMQ,
- no `cJSON` number formatting.

---

### 7. End-to-end JSON on stdout

#### 7.1 How the records were obtained

The sensor's `-v` flag prints each exported JSON object to stdout in addition to the ZeroMQ send. The three runs below are offline reads. The objects are what stdout showed. They are not what `zmq_sink` showed. `zmq_sink` showed nothing (§8).

| Run | File | Provenance stated for this session |
|---|---|---|
| DNS | `pcaps/test_dns.pcap` | Taken from the nDPI corpus file `dns.pcap` |
| HTTP | `pcaps/test_http.pcapng` | 10 packets |
| TLS | `pcaps/test_tls_full.pcap` | Copied from nDPI `443-curl.pcap`, 109 packets |

One object was captured per file. Each object is one flow.

#### 7.2 DNS

`pcaps/test_dns.pcap`:

```json
{"src_ip":"192.168.170.20","dst_ip":"192.168.170.8","src_port":53,"dst_port":32795,"protocol":17,"app_protocol":"DNS","ja4_client":"N/A","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":3,"bytes_up":123,"bytes_down":61,"flow_duration_ms":41071,"iat_mean":20535482,"iat_stddev":28711800.0,"iat_min":233143,"iat_max":40837821,"pkt_len_mean":33.3333,"pkt_len_stddev":0.57735,"bytes_up_down_ratio":2.01639,"small_pkt_ratio":1,"first_seen_us":1112173000000000.0,"last_seen_us":1112173000000000.0}
```

Reading only this object, plus the code that prints it:

- `protocol` 17 is UDP. `src_port` 53 means the first packet the sensor stored as `orig_*` was the DNS server side. See §5.1. This is expected-but-surprising, not a regression of Fix 1.
- `ja4_client` is `N/A`. JA4 is a TLS client fingerprint. This flow is DNS.
- `ndpi_risk_mask` is 0 and `ndpi_risk_str` is empty. This file does not exercise the risk-string path.
- `pkt_count` 3 implies two IAT samples if the packet-1 guard is in effect. The printed min and max are 233143 µs and 40837821 µs. Their arithmetic mean is `(233143 + 40837821) / 2 = 20535482`, which is the printed `iat_mean`. That is a consistency check on the printed numbers, not an independent clock.
- `flow_duration_ms` 41071 ms is the same span: `233143 + 40837821 = 41070964` µs = 41070.964 ms, printed as 41071. Again, internal consistency of the JSON.
- `bytes_up / bytes_down = 123 / 61 = 2.016393...`, printed as `2.01639`.
- `small_pkt_ratio` 1 with `pkt_count` 3 means every packet's payload length was `< 100`. `pkt_len_mean` 33.3333 is about a 33-byte payload, which agrees with "all small" and does not by itself prove the threshold.
- `first_seen_us` and `last_seen_us` are the same printed number. A 41071 ms flow cannot have equal microsecond timestamps. That is the bug in §9, visible on this record.

ndpiReader was not successfully cross-checked on this file.

#### 7.3 HTTP

`pcaps/test_http.pcapng` (10 packets):

```json
{"src_ip":"192.168.1.128","dst_ip":"216.58.208.142","src_port":42170,"dst_port":80,"protocol":6,"app_protocol":"HTTP.Google","ja4_client":"N/A","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":10,"bytes_up":394,"bytes_down":744,"flow_duration_ms":42.164,"iat_mean":4684.89,"iat_stddev":6868.86,"iat_min":42,"iat_max":20611,"pkt_len_mean":60.2,"pkt_len_stddev":166.005,"bytes_up_down_ratio":0.52957,"small_pkt_ratio":0.9,"first_seen_us":1643129000000000.0,"last_seen_us":1643129000000000.0}
```

- `protocol` 6 is TCP. `dst_port` 80 matches the `HTTP.Google` label's port. `src_port` 42170 is an ephemeral port, so on this file the first packet seen was the client side. That is the opposite orientation from the DNS record, which is what Fix 1 is supposed to allow.
- `ja4_client` is `N/A`. This is HTTP on port 80, not a TLS handshake.
- Risk mask 0, risk string empty. Same gap as DNS.
- 10 packets ⇒ 9 IAT samples under the guard. `9 * 4684.89 = 42164.01` µs = 42.16401 ms, and `flow_duration_ms` is 42.164. The mean and the duration agree at the precision that was printed.
- `394 / 744 = 0.529569...`, printed as `0.52957`.
- `small_pkt_ratio` 0.9 on 10 packets means 9 packets had payload `< 100` and one did not. `pkt_len_mean` 60.2 and `pkt_len_stddev` 166.005 are compatible with one much larger payload and nine short ones; the record does not list per-packet lengths, so this sentence stops there.
- Timestamps print identical (`1643129000000000.0`) while duration is 42.164 ms. Same defect as DNS.

ndpiReader was not successfully cross-checked on this file.

#### 7.4 TLS, and the ndpiReader cross-check

`pcaps/test_tls_full.pcap` (from nDPI `443-curl.pcap`, 109 packets):

```json
{"src_ip":"192.168.1.13","dst_ip":"178.62.197.130","src_port":55523,"dst_port":443,"protocol":6,"app_protocol":"TLS.ntop","ja4_client":"t12d6707h2_2955a3196ffa_c83f907a73d3","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":109,"bytes_up":3546,"bytes_down":68910,"flow_duration_ms":1096.09,"iat_mean":10149,"iat_stddev":75724.2,"iat_min":1,"iat_max":783975,"pkt_len_mean":612.991,"pkt_len_stddev":697.461,"bytes_up_down_ratio":0.0514584,"small_pkt_ratio":0.541284,"first_seen_us":1581113000000000.0,"last_seen_us":1581113000000000.0}
```

This is the first record in the session whose `ja4_client` is not `N/A`. The value is `t12d6707h2_2955a3196ffa_c83f907a73d3`. An earlier single-packet TLS try stayed at `N/A` because nDPI does not emit JA4 until it has seen the handshake. This file has the handshake. The string has not been compared with ndpiReader's own JA4 output. QUIC was not tried.

Other arithmetic that uses only printed fields:

- `3546 / 68910 = 0.05145842...`, printed as `0.0514584`.
- `3546 + 68910 = 72456` IP-layer bytes, sensor-side.
- 109 packets ⇒ 108 IAT samples. `108 * 10149 = 1096092` µs = 1096.092 ms, next to printed duration `1096.09`.
- `iat_min` 1 µs and `iat_max` 783975 µs. The minimum is a real positive sample, not the old stuck 0. It is also small enough that a 1 µs floor is visible; this report does not claim the clock source was checked.
- `small_pkt_ratio` 0.541284. Times 109 is 59.0000 at the printed precision (`0.541284 * 109 = 58.999956`). So 59 of 109 payloads were under 100 bytes, if the ratio was printed from an exact `small / count` division and then rounded. That reconstruction is from the printed ratio; the sensor did not print the raw `small_pkt_count`.
- Risk mask is still 0. A full handshake to `TLS.ntop` did not produce a non-empty risk string on this file.
- Timestamps again print as the same number (`1581113000000000.0`) across a 1096.09 ms flow.

> [!success] ndpiReader on the TLS file only
> Command: `/home/joe/nDPI/example/ndpiReader -i pcaps/test_tls_full.pcap` with `LD_LIBRARY_PATH=/home/joe/nDPI/src/lib`.
>
> - Unique flows: 1
> - Detected protocol: `ntop` — packets 109, bytes 73982, flows 1
> - DPI packets (TCP): 7
> - Flow memory (per flow): 1.23 KB

Side-by-side:

| Quantity | Sensor stdout | ndpiReader | Match |
|---|---|---|---|
| Flows | 1 object | Unique flows: 1 | Yes |
| Packets | `pkt_count` 109 | 109 | Yes |
| Application label | `TLS.ntop` | `ntop` | Label agrees (`TLS` is the master protocol in the sensor's name string) |
| Bytes | 3546 + 68910 = 72456 | 73982 | No, gap of 1526 bytes |

The byte gap is explained by what each tool adds up, not by a second hidden flow. The sensor adds `ntohs(iph->ip_len)` from the IPv4 header. ndpiReader's 73982 is raw frame bytes. Ethernet headers (and any trailer or FCS the reader includes in the frame length) sit outside `ip_len`. This session did not decompose the 1526-byte gap packet by packet. The explanation above is the one established for the gap; it is not a per-packet proof.

DNS and HTTP cross-checks were not captured. Grep over ndpiReader output for those runs produced nothing useful. Those two files stay unverified against ndpiReader.

JA4 was not part of the ndpiReader comparison. DPI-packet count (7) and per-flow memory (1.23 KB) are ndpiReader's figures. The sensor did not print an equivalent DPI-packet count or an nDPI memory figure.

#### 7.5 Field inventory

Working notes called the export a "24-field schema." The three objects that were actually captured each contain **23** keys, and those 23 are exactly the `cJSON_Add*` calls in `export_flow`. This report does not invent a twenty-fourth key to make the nickname match. The socket never delivered any of them; the inventory is a stdout inventory.

| # | Key | DNS | HTTP | TLS | How it is produced |
|---|---|---|---|---|---|
| 1 | `src_ip` | 192.168.170.20 | 192.168.1.128 | 192.168.1.13 | `orig_src_ip` via `inet_ntop` |
| 2 | `dst_ip` | 192.168.170.8 | 216.58.208.142 | 178.62.197.130 | `orig_dst_ip` |
| 3 | `src_port` | 53 | 42170 | 55523 | `ntohs(orig_src_port)` |
| 4 | `dst_port` | 32795 | 80 | 443 | `ntohs(orig_dst_port)` |
| 5 | `protocol` | 17 | 6 | 6 | `key.protocol` (IP protocol, not the sorted direction) |
| 6 | `app_protocol` | DNS | HTTP.Google | TLS.ntop | nDPI name after detection or give-up |
| 7 | `ja4_client` | N/A | N/A | `t12d6707h2_2955a3196ffa_c83f907a73d3` | nDPI JA4, or the literal `N/A` |
| 8 | `ndpi_risk_mask` | 0 | 0 | 0 | risk value cast to `double` |
| 9 | `ndpi_risk_str` | empty | empty | empty | string form of that mask |
| 10 | `pkt_count` | 3 | 10 | 109 | packets attached to the flow |
| 11 | `bytes_up` | 123 | 394 | 3546 | sum of `ip_len` in the `orig_src` direction |
| 12 | `bytes_down` | 61 | 744 | 68910 | sum of `ip_len` in the other direction |
| 13 | `flow_duration_ms` | 41071 | 42.164 | 1096.09 | `(last_seen_us - first_seen_us) / 1000` |
| 14 | `iat_mean` | 20535482 | 4684.89 | 10149 | Welford mean, microseconds, packet 1 excluded |
| 15 | `iat_stddev` | 28711800.0 | 6868.86 | 75724.2 | sample stddev of those IATs |
| 16 | `iat_min` | 233143 | 42 | 1 | Welford min, or 0 if no IAT sample |
| 17 | `iat_max` | 40837821 | 20611 | 783975 | Welford max, or 0 if no IAT sample |
| 18 | `pkt_len_mean` | 33.3333 | 60.2 | 612.991 | Welford mean of payload length |
| 19 | `pkt_len_stddev` | 0.57735 | 166.005 | 697.461 | sample stddev of payload length |
| 20 | `bytes_up_down_ratio` | 2.01639 | 0.52957 | 0.0514584 | `bytes_up / bytes_down`, or 0 if down is 0 |
| 21 | `small_pkt_ratio` | 1 | 0.9 | 0.541284 | count of payload `< 100`, over `pkt_count` |
| 22 | `first_seen_us` | 1112173000000000.0 | 1643129000000000.0 | 1581113000000000.0 | `cJSON` number; precision loss, §9 |
| 23 | `last_seen_us` | 1112173000000000.0 | 1643129000000000.0 | 1581113000000000.0 | same printer; prints equal to first on all three |

`ndpi_risk_mask` is added with `cJSON_AddNumberToObject`, i.e. as a JSON number, even though a bitmask is an integer. At 0 that does not matter. A wide bitmask would go through the same printer as the timestamps.

> [!info] What "schema verified" means after this session
> It means: for these three files, `-v` emitted objects with the keys above, the numeric relationships checked in §7.2–§7.4 hold, and the TLS label and packet count agree with ndpiReader. It does not mean a JSON Schema document was validated, and it does not mean a ZeroMQ peer parsed the objects.

---

### 8. Where the work stopped

> [!bug] ZMQ delivery failed
> `zmq_sink` received zero messages. The failure survived a role swap, a late start, the 109-packet TLS file, and a 5-second `timeout` around the sink. Work stopped here. The linger change, the socket path for the 23 keys, and any claim about a downstream consumer are all blocked on this.

Default endpoint on both sides: `ipc:///tmp/ndpi_flows.sock`.

The publisher (`sensor`) always does `zmq_bind` in `zmq_publisher_init`, then `zmq_send(..., ZMQ_DONTWAIT)` per flow, then later `zmq_close` / `zmq_ctx_destroy` from `zmq_publisher_destroy`. Offline PCAPs in this set finish processing in milliseconds. The flush runs, the sends run, and the process closes the socket before a peer that was started afterwards has completed the IPC handshake.

Attempts:

1. **Sink bind and sensor bind.** Both ends called `zmq_bind` on `ipc:///tmp/ndpi_flows.sock`. That conflicts. Nothing was delivered.
2. **Sensor bind, sink connect, sink started about 150–400 ms after the sensor.** Zero messages. The PCAP is already finished: the sensor has flushed and called `zmq_close` before the `PULL` socket finishes connecting, so the queue has nobody to drain to. `ZMQ_DONTWAIT` means a send with no peer does not wait for one.
3. **Same arrangement on the 109-packet TLS PCAP, and with `timeout 5` wrapping the sink.** Still zero messages. A longer-lived sink process does not help if it is late and the sender has already closed. A larger PCAP that still completes in well under the startup gap does not help either.

There is a second, separate inconsistency, and it is enough to keep failing even after the race is understood:

- `src/zmq_sink.c` **as written now** calls `zmq_bind`.
- The **last successfully compiled** `zmq_sink` binary was built from the variant that calls `zmq_connect`.
- `sensor` binds.

So the sources, if rebuilt as they are, would reproduce attempt 1 (double bind). The binary that was actually run for the connect-side attempts is not the source that is checked in. Rebuilding without reading `zmq_sink.c` would change the failure mode, not fix it.

> [!todo] Next fix, identified and not implemented
> Either of the following, and neither is in the tree:
>
> **(a)** Give the sensor a connect mode (for example `-c`) so the sink binds first and the sensor connects to an endpoint that already exists.
>
> **(b)** Keep the sensor as the binder, start the sink first, and do not call `zmq_close` until a short drain has let the peer attach and take the queued messages. Linger of 1000 ms only helps if a peer exists during that second. It does not create a peer, and it does not undo a `DONTWAIT` send that already failed with `EAGAIN` before any peer connected.
>
> (a) and (b) are alternatives. Doing neither, and rebuilding today's `zmq_sink.c` next to today's `zmq_publisher.c`, leaves both sides on `zmq_bind`.

Until one of those is implemented and a sink process prints a line, the following sentences are false and must not appear in a defence or a dashboard write-up:

- "the pipeline delivers JSON over ZeroMQ,"
- "linger was shown to flush the offline run,"
- "a consumer can read the 23-field stream."

Stdout `-v` remains the only capture path this session proved.

---

### 9. New bug: timestamp precision

> [!bug] `first_seen_us` and `last_seen_us` are lossy JSON numbers
> Export does this:
>
> ```c
> cJSON_AddNumberToObject(root, "first_seen_us", (double)entry->first_seen_us);
> cJSON_AddNumberToObject(root, "last_seen_us",  (double)entry->last_seen_us);
> ```
>
> The values are `uint64_t` microseconds since the epoch, then cast to `double`, then printed by the embedded cJSON number formatter. That formatter uses a limited number of significant digits. The captured form is scientific notation with a trailing `.0`, for example `"first_seen_us":1112173000000000.0`. A value survives intact only when it is already round at that precision. Arbitrary microsecond counts lose low-order digits.

Evidence already in §7, not a new run: on every captured object, `first_seen_us` and `last_seen_us` render as the same number, while `flow_duration_ms` is 41071, 42.164, and 1096.09. Duration is computed in C from the integer timestamps **before** the JSON printer runs (`(last - first) / 1000.0` through `cJSON_AddNumberToObject` as well, but the magnitude is ~10^1 to ~10^4, so it survives). The two absolute timestamps are ~10^15 and do not.

Consequences:

- A consumer that subtracts the two JSON numbers gets 0 for all three of these flows and will disagree with `flow_duration_ms`.
- ClickHouse, or any other sink, must not ingest these two fields as floats. The loss happens at print time, before the database.
- `ndpi_risk_mask` and the byte counters also go out as JSON numbers (the byte counters via a cast to `double`). The counters in §7 are small enough to be exact. The risk mask has only been seen as 0.

The bug is not fixed. The acceptable fixes, none of which have been applied:

1. emit `first_seen_us` and `last_seen_us` as JSON strings of the decimal integer, or
2. emit them as two integers, `sec` and `usec`, or
3. change the embedded cJSON number formatter to print integer-valued doubles with `%.17g` or `%.0f`.

Option 3 is global: it changes every number the embedded printer emits, including means and stddevs. Options 1 and 2 are local to the two timestamp fields. This report does not pick an implementation; it records that downstream code must not `float()` these fields, and that the sensor still emits them as numbers today.

---

### 10. Remaining backlog

> [!todo] Open items, in the order they block Phase 2
> ZMQ delivery is first because Phase 2's daemon is a `PULL` consumer. Everything under it can be true and Phase 2 still has nothing to insert.

| # | Item | State | Note |
|---|---|---|---|
| 1 | ZMQ end-to-end delivery | **Blocked.** Three attempts, zero messages. | Fix is (a) sensor connect mode, or (b) drain delay plus sink-before-sensor. Not written. Source/binary bind mismatch is item 10. |
| 2 | valgrind leak accounting | **Not run.** | A double-free was fixed empirically. No leak summary exists. Do not quote "clean under valgrind." |
| 3 | Throughput benchmark | **Not run.** | No packets-per-second figure may be quoted. No packet count per second was measured on these PCAPs either; "finishes in milliseconds" is the timing observation used to explain the ZMQ race, not a benchmark. |
| 4 | JA4 | **One value observed, not cross-checked.** | `t12d6707h2_2955a3196ffa_c83f907a73d3` on `pcaps/test_tls_full.pcap`. Not compared with ndpiReader's JA4. Not run on QUIC. DNS and HTTP correctly show `N/A` for a non-TLS flow, which does not test JA4. |
| 5 | Risk bitmask | **Positive case untested.** | All three PCAPs: `ndpi_risk_mask` 0, `ndpi_risk_str` empty. The non-empty string path has not been seen. |
| 6 | Live capture `-i` | **Compiled, never executed.** | `usage()` documents `./sensor -i eth0`. No live interface was opened. |
| 7 | Flow expiry (30 s) and SIGINT/SIGTERM flush | **Not triggered.** | `FLOW_EXPIRE_SEC` is 30. Expiry is considered every 1000 packets. These PCAPs are shorter than that in both time and, for DNS and HTTP, packet count. The TLS file has 109 packets, still under the 1000-packet check. Signal flush was not exercised. |
| 8 | Unit tests for canonical key and byte accounting | **Absent.** | Only `stats.h` is covered, by the 24 checks in §6. |
| 9 | Timestamp precision | **Found, not fixed.** | §9. Blocks honest ClickHouse ingestion of the two time fields. |
| 10 | `zmq_sink` source/binary mismatch | **Open.** | Source binds. Last good binary was the connect variant. `sensor` binds. |

Items 2, 3, 6, and 7 are absences. They are not soft passes. Item 4 is a partial pass: the field is populated on one TLS flow and nowhere else has it been checked. Item 5 is a pass only of the zero value.

---

### 11. Phase 2 (unchanged, and gated)

Phase 2 was not started. Its shape is still:

- ClickHouse and Grafana brought up with docker-compose,
- `engine-ml/daemon.py` as a ZeroMQ `PULL` consumer that batch-inserts flow objects,
- four Grafana panels: protocols, JA4 anomalies, traffic volume, high-risk flows.

> [!warning] Gate
> End-to-end ZMQ has to work before any of that is meaningful. A daemon that `PULL`s on `ipc:///tmp/ndpi_flows.sock` today will see the same empty stream as `zmq_sink`, for the same reason. Building the compose file first would not create evidence that the sensor can feed it.
>
> Even after the socket moves bytes, the timestamp fields cannot be inserted as floats (§9), and the high-risk panel has no sample: every captured mask is 0. The JA4 panel has a single fingerprint and no ndpiReader comparison.

Nothing in this session implemented `daemon.py`, a compose file, a ClickHouse schema, or a dashboard.

---

### 12. What a defence may say

This section is the constraint on any slide, abstract, or oral answer that cites Part 1.

**May be said, because it was observed.**

- The sensor is a C11 program built with GCC 14.3.0 and CMake 4.3.4 against nDPI 6.1.0-5906-90eb617 from `/home/joe/nDPI` (not installed system-wide), libpcap 1.10.6, and libzmq 4.3.5.
- Distro `-dev` packages for nDPI, uthash, cJSON, and libzmq could not be installed: `apt-get` failed while fetching, `kali.download` unreachable, IPv6 route missing. Headers for uthash, cJSON, and libzmq are therefore in-tree.
- The build produces `sensor`, `zmq_sink`, and `test_stats` with zero warnings under `-Wall -Wextra -Wpedantic -O2`, and `sensor` does not link `libcjson`.
- Export direction is the first packet seen (`orig_*`), not the sorted uthash key. Byte counts follow that same comparison and use IPv4 `ip_len`.
- On a DNS corpus PCAP the first packet was the response, so `src_port` 53 is the recorded origin. That matches the implementation's definition.
- Welford's first sample now sets min and max. `./test_stats` reported 24 passed, 0 failed, including min=42 for a single sample of 42, the Wikipedia 8-point vector (sample stddev 2.138089935), and the IAT-like vector (stddev 96.17692031).
- IAT is not updated on packet 1, so a zero `last_pkt_us` cannot be subtracted into a epoch-sized interval.
- Short flows call `ndpi_detection_giveup` at export if detection has not completed.
- With `-v`, the three files produced the JSON objects in §7. The TLS object carries JA4 `t12d6707h2_2955a3196ffa_c83f907a73d3` and `app_protocol` `TLS.ntop`.
- ndpiReader on that TLS file reported 1 flow, protocol `ntop`, 109 packets, 73982 raw frame bytes, 7 DPI packets, 1.23 KB flow memory. The sensor's 72456 bytes are the sum of `ip_len` (3546 + 68910). The 1526-byte difference is that frame-vs-IP-header gap, not a second flow.
- Code size before `zmq_sink.c` and `test_stats.c` were added: 3,968 lines in 15 `.c`/`.h` files.

**Must not be said, because it was not shown or it is false.**

- That a ZeroMQ consumer received a flow. It did not. Three attempts, zero messages.
- That `ZMQ_LINGER=1000` fixes short PCAP runs. The constant is compiled. Its effect is unverified.
- That `zmq_sink` as checked in is the program that was last linked. The source binds; the last successful binary was the connect variant; `sensor` also binds.
- That the export has been validated as a 24-field schema on the wire. Stdout objects have 23 keys. The wire was silent.
- That DNS or HTTP was confirmed with ndpiReader. The grep found nothing usable.
- That JA4 matches nDPI's own JA4 printout, or that JA4 works on QUIC.
- That nDPI risk flags are extracted in practice. The only observed mask is 0.
- That live capture works. `-i` was not run.
- That idle flows expire at 30 seconds, or that SIGINT flushes the table. Neither path was triggered.
- That direction handling is unit-tested. It is not.
- That timestamps are safe for a float column. They are not. All three records show equal printed `first_seen_us` and `last_seen_us` across a non-zero duration.
- That valgrind, cppcheck, or any other static/dynamic auditor was run in this session. They were not. The empirical double-free fix is not a leak account.
- Any packets-per-second, latency, or memory-per-flow number for the sensor. ndpiReader's 1.23 KB is ndpiReader's number. The sensor was not measured.
- That Phase 2 ingestion exists. It does not, and it is blocked on §8 and §9.

> [!info] One-sentence status
> The C sensor builds cleanly, its Welford statistics pass 24 assertions, and three offline PCAPs produce internally consistent JSON on stdout — including a real JA4 on a full TLS handshake that agrees with ndpiReader on flow count, packet count, and protocol name — but the ZeroMQ path has never delivered a message, the timestamp fields are already losing precision, and no performance or leak result exists to cite.


---

<a id="part-1-2"></a>

## Part 1 (v2): Follow-up Fixes & Evidence

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Component:** Part 1, C packet capture sensor
**Tree:** `/home/joe/cv_work/sentinel-flow/sensor-c/`
**Date:** 2026-10-22
**Status:** The four items from Part 1 §10 that were still open — ZMQ 0-message delivery (§8), timestamp precision (§9), direction/byte-accounting unit test (§10 item 8), and the ndpiReader `-v 2` + risk-mask cross-check (§10 items 4 & 5) — are now fixed, built, and have the evidence quoted below.

> [!info] How to read this document
> This file is a delta on Part 1. It only records what has changed since that write-up. Any claim that is not in the "Evidence captured in this session" blocks is still subject to the Part 1 §12 constraint.

---

### 1. Summary of changes

| Area | Part 1 state | Part 1 v2 state (this document) |
|---|---|---|
| ZMQ delivery | Blocked, 3/3 runs received 0 messages. | **Fixed.** `zmq_sink -n 1` prints one JSON object per run on all three test PCAPs, exit status 0. |
| cJSON timestamp precision | `first_seen_us == last_seen_us` on every record. | **Fixed.** `last_seen_us - first_seen_us` equals `flow_duration_ms * 1000` on all three test PCAPs. |
| orig_src assignment | Code correct, no test. | **Verified** in `src/main.c` and locked in by `test_flow` (13 assertions, 0 failures). |
| ndpiReader cross-check | TLS only, `-v 1`. | **Done** on all three test PCAPs with `-v 2`. JA4 matches character-for-character. |
| nDPI risk mask | Only 0 seen. | **Non-zero case captured.** `tls_invalid_reads.pcap` → `ndpi_risk_mask: 128`, `ndpi_risk_str: "Obsolete TLS (v1.1 or older)"`. |

Nothing else from the Part 1 backlog (valgrind, throughput, live `-i`, 30 s expiry, signal flush) changed. Those remain untouched.

---

### 2. Fix 6 — ZeroMQ 0-message delivery

#### 2.1 Root cause (as stated in Part 1 §8, now closed)

Both ends called `zmq_bind`. On `ipc://`, that is a conflict: only one process may own the socket file. Even in the earlier `zmq_connect` variant, the sender finished the offline PCAP in <1 ms and reached `zmq_close` before the `ZMQ_PUSH ↔ ZMQ_PULL` IPC handshake had completed, so `zmq_send(ZMQ_DONTWAIT)` returned `EAGAIN` and the queue was dropped at close.

#### 2.2 Change in `src/zmq_publisher.c`

Four edits:

1. `zmq_bind` → `zmq_connect`. The sink (persistent server) is the binder; the sensor connects to it.
2. `ZMQ_SNDTIMEO = 200` (bounded blocking timeout) and `ZMQ_LINGER = 2000` (two-second drain at close).
3. `usleep(100000)` immediately after `zmq_connect` so the ZMQ background thread has time to complete the IPC handshake before the capture loop starts.
4. `zmq_publisher_send` now retries once without `ZMQ_DONTWAIT` when the first send returns `EAGAIN`. The retry is bounded by `ZMQ_SNDTIMEO`.

```c
int sndtimeo = 200;
zmq_setsockopt(zmq_sock, ZMQ_SNDTIMEO, &sndtimeo, sizeof(sndtimeo));

if (zmq_connect(zmq_sock, endpoint) != 0) { /* ... */ }

usleep(100000);  /* 100 ms handshake grace */
```

```c
int rc = zmq_send(zmq_sock, json_str, len, ZMQ_DONTWAIT);
if (rc < 0 && zmq_errno() == EAGAIN) {
    rc = zmq_send(zmq_sock, json_str, len, 0);   /* bounded by SNDTIMEO */
}
```

#### 2.3 Change in `src/zmq_sink.c`

Added `-n <N>` CLI flag: the sink exits status 0 after receiving N messages without needing `timeout` or `SIGINT`. The sink is the only process that calls `zmq_bind` on the endpoint.

```c
if (expected > 0 && received >= expected) {
    fprintf(stderr, "[zmq_sink] received %ld/%ld — exiting\n",
            received, expected);
    break;
}
```

#### 2.4 Change in `src/zmq.h`

The hand-written `zmq.h` was missing `ZMQ_SNDTIMEO` and `ZMQ_RCVTIMEO`. Added with their canonical libzmq 4.x values (28 and 27).

#### 2.5 Build

```text
[100%] Built target sensor
[ 61%] Built target zmq_sink
[ 46%] Built target test_flow
[ 30%] Built target test_stats
```

Zero warnings under `-Wall -Wextra -Wpedantic -O2`.

#### 2.6 Evidence captured in this session

Command for a single run:

```bash
cd sensor-c/build
rm -f /tmp/ndpi_flows.sock
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib ./zmq_sink -n 1 > /tmp/sink_out.json &
sleep 0.2 && LD_LIBRARY_PATH=/home/joe/nDPI/src/lib \
    ./sensor -r ../../pcaps/test_tls_full.pcap
wait
cat /tmp/sink_out.json
```

Sink stderr:

```text
[zmq_sink] listening on ipc:///tmp/ndpi_flows.sock (expecting 1 message)
[zmq_sink] received 1/1 — exiting
[zmq_sink] done
```

Sink stdout (the JSON object delivered over the socket, not through `-v`):

```json
{"src_ip":"192.168.1.13","dst_ip":"178.62.197.130","src_port":55523,"dst_port":443,"protocol":6,"app_protocol":"TLS.ntop","ja4_client":"t12d6707h2_2955a3196ffa_c83f907a73d3","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":109,"bytes_up":3546,"bytes_down":68910,"flow_duration_ms":1096.093,"iat_mean":10149.0093,"iat_stddev":75724.1596,"iat_min":1,"iat_max":783975,"pkt_len_mean":612.990826,"pkt_len_stddev":697.460917,"bytes_up_down_ratio":0.051458424,"small_pkt_ratio":0.541284404,"first_seen_us":1581113120474299,"last_seen_us":1581113121570392}
```

The three Part 1 §12 sentences marked as "must not be said" because they were false are now observed:

- "the pipeline delivers JSON over ZeroMQ" — observed, three independent PCAP runs below.
- "linger was shown to flush the offline run" — observed; `zmq_close` runs after `ZMQ_LINGER=2000` without discarding the queue.
- "a consumer can read the 23-field stream" — observed; `zmq_sink` printed the full object.

---

### 3. Fix 7 — cJSON timestamp precision

#### 3.1 Root cause (Part 1 §9, now closed)

`src/cJSON.c` `print_number` was branching on magnitude:

```c
} else if (fabs(d) < 1.0e-6 || fabs(d) > 1.0e9) {
    snprintf(buf, sizeof(buf), "%e", d);          /* 6-digit precision */
} else if (floor(d) == d && fabs(d) < 1.0e15) {
    snprintf(buf, sizeof(buf), "%.0f", d);
```

A microsecond timestamp like `1581113121570392.0` is ~1.58e15, which is **not** `< 1e15`, so it fell into the `%e` branch and lost everything below the top six significant digits. Hence `1581113120474299` and `1581113121570392` both printed as `1.581113e+15`.

#### 3.2 Change in `src/cJSON.c`

The integer-valued-double check now covers the whole exactly-representable range (`< 2^53 = 9007199254740992.0`) and the fallback uses `%.9g` instead of the default `%g`.

```c
if (d == 0.0) {
    snprintf(buf, sizeof(buf), "0");
} else if (floor(d) == d && fabs(d) < 9007199254740992.0) {
    snprintf(buf, sizeof(buf), "%.0f", d);     /* exact for integers < 2^53 */
} else {
    snprintf(buf, sizeof(buf), "%.9g", d);
}
```

#### 3.3 Evidence captured in this session

The three sensor runs below were produced via the socket, not via `-v`, so these are the same bytes a downstream consumer would see.

**`test_dns.pcap`** (full ZMQ-delivered object):

```json
{"src_ip":"192.168.170.20","dst_ip":"192.168.170.8","src_port":53,"dst_port":32795,"protocol":17,"app_protocol":"DNS","ja4_client":"N/A","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":3,"bytes_up":123,"bytes_down":61,"flow_duration_ms":41070.964,"iat_mean":20535482,"iat_stddev":28711843.2,"iat_min":233143,"iat_max":40837821,"pkt_len_mean":33.3333333,"pkt_len_stddev":0.577350269,"bytes_up_down_ratio":2.01639344,"small_pkt_ratio":1,"first_seen_us":1112172654366527,"last_seen_us":1112172695437491}
```

`last_seen_us − first_seen_us = 1112172695437491 − 1112172654366527 = 41070964 µs = 41070.964 ms` = `flow_duration_ms`. Exact round-trip.

**`test_http.pcapng`**:

```json
{"src_ip":"192.168.1.128","dst_ip":"216.58.208.142","src_port":42170,"dst_port":80,"protocol":6,"app_protocol":"HTTP.Google","ja4_client":"N/A","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":10,"bytes_up":394,"bytes_down":744,"flow_duration_ms":42.164,"iat_mean":4684.88889,"iat_stddev":6868.85715,"iat_min":42,"iat_max":20611,"pkt_len_mean":60.2,"pkt_len_stddev":166.005221,"bytes_up_down_ratio":0.529569892,"small_pkt_ratio":0.9,"first_seen_us":1643129441023341,"last_seen_us":1643129441065505}
```

`1643129441065505 − 1643129441023341 = 42164 µs = 42.164 ms` = `flow_duration_ms`. Exact.

**`test_tls_full.pcap`**:

```json
{"src_ip":"192.168.1.13","dst_ip":"178.62.197.130","src_port":55523,"dst_port":443,"protocol":6,"app_protocol":"TLS.ntop","ja4_client":"t12d6707h2_2955a3196ffa_c83f907a73d3","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":109,"bytes_up":3546,"bytes_down":68910,"flow_duration_ms":1096.093,"iat_mean":10149.0093,"iat_stddev":75724.1596,"iat_min":1,"iat_max":783975,"pkt_len_mean":612.990826,"pkt_len_stddev":697.460917,"bytes_up_down_ratio":0.051458424,"small_pkt_ratio":0.541284404,"first_seen_us":1581113120474299,"last_seen_us":1581113121570392}
```

`1581113121570392 − 1581113120474299 = 1096093 µs = 1096.093 ms` = `flow_duration_ms`. Exact.

Side-effect for Welford fields: integer-valued statistics (e.g. `iat_mean: 20535482`, `iat_min: 233143`, `iat_max: 40837821`) now print as integers; non-integer statistics (`iat_stddev: 28711843.2`, `bytes_up_down_ratio: 2.01639344`) print with up to 9 significant digits instead of the previous default `%g` 6. This is a visible but intentional width increase in the JSON over the Part 1 §7 captures. The schema and the numeric content are the same.

---

### 4. Fix 8 — `orig_src` assignment, verified + unit-tested

#### 4.1 Code audit (Part 1 §5.1, confirmed on 2026-10-22)

In `src/main.c`, `pkt_src_ip` and `pkt_src_port` are extracted from `iph->ip_src.s_addr` and the TCP/UDP header at **lines 228–249**, *before* the canonical sorting block at **lines 255–275**. The sorting block only writes into the local `canonical` struct — it does not mutate `pkt_src_ip` or `pkt_src_port`. The `orig_*` assignment at **lines 292–295** therefore sees the unmodified first-packet 5-tuple:

```c
if (created) {
    /* ... */
    flow->orig_src_ip   = pkt_src_ip;      /* main.c:292 */
    flow->orig_dst_ip   = pkt_dst_ip;
    flow->orig_src_port = pkt_src_port;
    flow->orig_dst_port = pkt_dst_port;
```

The byte-accounting comparison at **lines 307–313** compares each packet's raw 5-tuple to the stored `orig_src_*`, not to the canonical key:

```c
bool is_upstream = (pkt_src_ip   == flow->orig_src_ip   &&
                    pkt_src_port == flow->orig_src_port);
```

#### 4.2 The DNS "`src_port: 53`" question, now answered

`tcpdump -nn -r pcaps/test_dns.pcap udp and port 53` on this host:

```text
09:50:54.366527 IP 192.168.170.20.53 > 192.168.170.8.32795: 56482 0/0/0 (34)
09:51:35.204348 IP 192.168.170.8.32795 > 192.168.170.20.53: 48159+ AAAA? www.example.com. (33)
09:51:35.437491 IP 192.168.170.20.53 > 192.168.170.8.32795: 48159 0/0/0 (33)
```

The first three packets in the raw PCAP are IPv6 (visible with the unfiltered `tcpdump -nn -r … -c 3`, output in §4.5 of this session's log). Our sensor filters `ETHERTYPE_IP` (IPv4 only) at `main.c:217`, so the first packet it stores as `orig_*` is packet 4 in the file: `192.168.170.20.53 > 192.168.170.8.32795`. The server-side DNS reply is genuinely the first IPv4 UDP packet the sensor sees, so `src_port: 53` and `dst_port: 32795` is faithful to the implementation's definition of "first packet seen."

That matches ndpiReader's accounting of flow #4 in this PCAP: `UDP 192.168.170.20:53 <-> 192.168.170.8:32795 [proto: 5/DNS] [2 pkts / 151 bytes <-> 1 pkts / 75 bytes]`. The directional split of `bytes_up: 123 / bytes_down: 61` (sensor-side, `ip_len`) corresponds to 2 packets upstream (server→client) and 1 downstream (client→server), consistent with ndpiReader's `2 pkts <-> 1 pkts`.

#### 4.3 New `test_flow` unit test

New file: `src/test_flow.c`. New CMake target: `test_flow`. The suite exercises the §5.1 invariant with two packets between `192.168.1.10:54321` (numerically **larger** IP) and `10.0.0.1:443` (numerically **smaller** IP), both directions, both initiation orders.

The test replicates main.c's direction logic without pulling in libndpi at link time (it constructs `flow_entry_t` directly and does not call `flow_table_lookup_or_create`).

```text
=== SentinelFlow direction / byte-accounting unit tests ===

[test] 192.168.1.10:54321 (larger IP) initiates to 10.0.0.1:443
  PASS  orig_src_ip               got=0x0a01a8c0
  PASS  orig_src_port             got=54321
  PASS  orig_dst_ip               got=0x0100000a
  PASS  orig_dst_port             got=443
  PASS  bytes_up                  got=500
  PASS  bytes_down                got=1200
  PASS  pkt_count                 got=2

[test] 10.0.0.1:443 (smaller IP) initiates to 192.168.1.10:54321
  PASS  orig_src_ip               got=0x0100000a
  PASS  orig_src_port             got=443
  PASS  orig_dst_ip               got=0x0a01a8c0
  PASS  orig_dst_port             got=54321
  PASS  bytes_up                  got=700
  PASS  bytes_down                got=300

=== Results: 13 passed, 0 failed ===
```

Case 1 is the one that would fail if export ever reverted to the canonical key: with the client's IP numerically larger, the sorted key would swap src/dst, and `bytes_up` would silently become the download count.

`test_stats` still passes: `=== Results: 24 passed, 0 failed ===`.

---

### 5. Fix 9 — ndpiReader `-v 2` cross-check

Command template (one PCAP shown):

```bash
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib \
    /home/joe/nDPI/example/ndpiReader -i pcaps/test_tls_full.pcap -v 2
```

#### 5.1 TLS — JA4 character-for-character match

ndpiReader `-v 2` on `test_tls_full.pcap`:

```text
TCP 192.168.1.13:55523 <-> 178.62.197.130:443 [proto: 91.26/TLS.ntop][...]
    [JA4: t12d6707h2_2955a3196ffa_c83f907a73d3][JA5: t12d6705h2_2955a3196ffa_7577205da0ca]
    [ServerNames: www.ntop.org][Cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
```

Sensor JSON `ja4_client`: `t12d6707h2_2955a3196ffa_c83f907a73d3`.

Match: identical, 37/37 characters.

#### 5.2 DNS — no JA4 expected

ndpiReader `-v 2` on `test_dns.pcap`, flow #4 (the UDP DNS flow our sensor also tracks):

```text
UDP 192.168.170.20:53 <-> 192.168.170.8:32795 [proto: 5/DNS][...]
    [Hostname/SNI: www.example.com][DNS Id: 0xbc1f]
```

No `JA4:` substring on this flow (ndpiReader does not emit JA4 for DNS). Sensor's `ja4_client: "N/A"` is consistent.

ndpiReader reports 4 flows in this PCAP (one IPv6 TCP DNS, one IPv6 MDNS, one IPv4 VLAN UDP DNS, one IPv4 UDP DNS). The sensor currently filters for `ETHERTYPE_IP` without VLAN support beyond a single `0x8100` layer and ignores IPv6, so it emits one flow for this file (the plain IPv4 DNS). That is a known-and-documented filter in `main.c:217`, not a regression; it is why the sensor's one exported flow is flow #4 in ndpiReader's enumeration.

#### 5.3 HTTP — no JA4 expected

ndpiReader `-v 2` on `test_http.pcapng`:

```text
TCP 192.168.1.128:42170 <-> 216.58.208.142:80 [proto: 7.126/HTTP.Google][...]
    [URL: google.com/][StatusCode: 301][Server: gws][User-Agent: curl/7.68.0]
```

No `JA4:` substring (ndpiReader does not emit JA4 for cleartext HTTP). Sensor's `ja4_client: "N/A"` is consistent.

Protocol labels agree: ndpiReader `HTTP.Google`, sensor `HTTP.Google`.

#### 5.4 Flow / packet / byte summary

| PCAP | Field | ndpiReader -v 2 | Sensor | Match |
|---|---|---|---|---|
| `test_dns.pcap` | Flow of interest #4 | `192.168.170.20:53 <-> 192.168.170.8:32795`, 2+1 pkts | 1 flow, same 5-tuple, 3 pkts | 5-tuple yes; sensor filters IPv6 so flow count differs by design |
| `test_dns.pcap` | app_protocol | DNS | DNS | Yes |
| `test_http.pcapng` | app_protocol | HTTP.Google | HTTP.Google | Yes |
| `test_http.pcapng` | pkt_count | 10 (6 c2s + 4 s2c) | 10 | Yes |
| `test_tls_full.pcap` | app_protocol | TLS.ntop | TLS.ntop | Yes |
| `test_tls_full.pcap` | pkt_count | 109 | 109 | Yes |
| `test_tls_full.pcap` | JA4 | `t12d6707h2_2955a3196ffa_c83f907a73d3` | `t12d6707h2_2955a3196ffa_c83f907a73d3` | Yes, identical |

---

### 6. Fix 10 — nDPI risk mask on real traffic

#### 6.1 PCAP chosen

`/home/joe/nDPI/tests/cfgs/default/pcap/tls_invalid_reads.pcap`. This file contains a TLS flow that negotiates an obsolete TLS version (v1.1 or older), which trips nDPI's `NDPI_TLS_OBSOLETE_VERSION` risk flag (bit value `128` in the risk mask).

#### 6.2 Command and output

```bash
rm -f /tmp/ndpi_flows.sock
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib ./zmq_sink > /tmp/risk_sink.json 2>/dev/null &
sleep 0.2
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib \
    ./sensor -r /home/joe/nDPI/tests/cfgs/default/pcap/tls_invalid_reads.pcap 2>/dev/null
# ... send SIGINT to sink after the sensor finishes
```

Delivered JSON for the risk-triggering flow (full object):

```json
{"src_ip":"192.168.10.101","dst_ip":"206.33.61.113","src_port":3967,"dst_port":443,"protocol":6,"app_protocol":"TLS","ja4_client":"N/A","ndpi_risk_mask":128,"ndpi_risk_str":"Obsolete TLS (v1.1 or older)","pkt_count":8,"bytes_up":274,"bytes_down":5597,"flow_duration_ms":74.513,"iat_mean":10644.7143,"iat_stddev":14788.254,"iat_min":35,"iat_max":38642,"pkt_len_mean":179.625,"pkt_len_stddev":317.356013,"bytes_up_down_ratio":0.0489547972,"small_pkt_ratio":0.625,"first_seen_us":1252380859868541,"last_seen_us":1252380859943054}
```

Both the mask field and the string field are populated:

- `ndpi_risk_mask: 128`
- `ndpi_risk_str: "Obsolete TLS (v1.1 or older)"`

Round-trip check on the (now full-precision) timestamps: `1252380859943054 − 1252380859868541 = 74513 µs = 74.513 ms = flow_duration_ms`. Exact.

#### 6.3 Additional risk-triggering PCAPs observed in this session

Not required by the task but captured while searching; useful for Phase 2 panel tests:

| PCAP (in `/home/joe/nDPI/tests/cfgs/default/pcap/`) | Example `ndpi_risk_str` |
|---|---|
| `tls_invalid_reads.pcap` | `Obsolete TLS (v1.1 or older)` |
| `http_invalid_server.pcap` | `HTTP Susp User-Agent` |
| `malware.pcap` | `Susp Entropy, Unidirectional Traffic` |
| `dns-invalid-chars.pcap` | `Non-Printable/Invalid Chars Detected` |

The non-empty `ndpi_risk_str` path in `ndpi_wrapper_risk_to_str` is exercised on all four; the output is reproducible by rerunning the sink/sensor pair against each file.

---

### 7. Updated Part 1 §10 backlog, after this session

| # | Item | New state |
|---|---|---|
| 1 | ZMQ end-to-end delivery | **Closed.** `zmq_sink -n 1` delivers one JSON per run on all three test PCAPs. |
| 4 | JA4 cross-check | **Closed.** Sensor and ndpiReader `-v 2` emit identical JA4 (`t12d6707h2_2955a3196ffa_c83f907a73d3`) on `test_tls_full.pcap`. DNS and HTTP correctly show no JA4 in both tools. |
| 5 | Risk bitmask positive case | **Closed.** `tls_invalid_reads.pcap` → mask 128, "Obsolete TLS". |
| 8 | Direction / byte accounting unit test | **Closed.** `test_flow`, 13/13 pass. |
| 9 | Timestamp precision | **Closed.** Full-µs round-trip on all three PCAPs. |
| 10 | `zmq_sink` source/binary mismatch | **Closed.** Source and binary now agree: sink binds, sensor connects. |

Items 2 (valgrind), 3 (throughput), 6 (live `-i`), and 7 (30 s expiry / signal flush) are unchanged — still absences, not soft passes.

---

### 8. What may be said after this session (addendum to Part 1 §12)

**May be said, because it was observed in this session.**

- `zmq_sink` received the full 23-field JSON object over `ipc:///tmp/ndpi_flows.sock` on all three test PCAPs, with exit status 0 under `zmq_sink -n 1`. Three independent runs, three sink stdout captures reproduced verbatim in §2.6 and §3.3.
- `first_seen_us` and `last_seen_us` round-trip to integer microseconds on all three test PCAPs; `last_seen_us − first_seen_us == flow_duration_ms × 1000` exactly.
- The direction / byte-accounting invariant from Part 1 §5.1 is unit-tested: `test_flow` passes 13/13, including the case where the client has the numerically larger IP (which is what the sorted canonical key alone would get wrong).
- `test_stats` still passes 24/24; no regression from the cJSON edit or the publisher edits.
- ndpiReader `-v 2` reports JA4 `t12d6707h2_2955a3196ffa_c83f907a73d3` on `test_tls_full.pcap`, character-for-character identical to the sensor's `ja4_client`.
- On `tls_invalid_reads.pcap` the sensor exports `ndpi_risk_mask: 128` and `ndpi_risk_str: "Obsolete TLS (v1.1 or older)"`, demonstrating the non-empty risk-string path on real traffic.
- The sensor binary now `zmq_connect`s and the sink binary now `zmq_bind`s; source and compiled binaries agree.

**Still must not be said, because it was not shown.**

Everything in Part 1 §12 under "must not be said" that was not fixed above remains unchanged — notably: no valgrind run, no packets-per-second number, no live `-i` capture, no 30 s expiry or signal-flush test, no measurement of nDPI memory per flow from the sensor side.


---

<a id="part-2"></a>

## Part 2: Ingestion & Analytics Pipeline (`engine-ml/`)

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Component:** Phase 2, flow ingestion, storage and query
**Tree:** `/home/joe/cv_work/sentinel-flow/`
**Date:** 2026-10-23
**Status:** Built and verified end to end on this host. All 12 flows that `sensor` exported from the 6 test PCAPs arrived over `ipc:///tmp/ndpi_flows.sock`. All 12 were validated, enriched and stored in SQLite and JSONL (run A, ClickHouse down) and also in ClickHouse (run B). The four query panels give identical results from SQLite and ClickHouse, and the Grafana dashboard renders them from ClickHouse.

> [!info] Claim discipline
> Same rule as Part 1 §12: a statement is only made here if the output that supports it is quoted in this document and was captured in this session. §10 lists what was **not** shown.

---

### 1. Summary

| Requirement | Result |
|---|---|
| Stdlib-only ZMQ ingestion | **Done.** `pyzmq` is absent on this host, so the daemon spawned `sensor-c/build/zmq_sink` and read its stdout. 12/12 flows received in both runs. |
| Validate 23 fields + 3 enrichment columns | **Done.** 9/9 unit tests pass. 0 differences across 552 field comparisons between the sensor's `-v` output and what was stored (§6.3). |
| SQLite (WAL) + JSONL backend | **Done.** `PRAGMA journal_mode` → `wal`. 12 rows / 12 lines. |
| ClickHouse HTTP backend (`urllib`) | **Done.** 12 rows inserted via `INSERT … FORMAT JSONEachRow` into ClickHouse 24.8.14.39. |
| `init_clickhouse.sql` with exact types | **Done.** Types and `ORDER BY` confirmed from `system.columns` / `system.tables` (§5.2). |
| `docker-compose.yml` + Grafana, 4 panels | **Done.** Datasource health `OK`. All 4 panel queries return HTTP 200 through Grafana's `/api/ds/query`. Screenshot in `docs/part2_grafana.png`. |
| `query_dashboard.py` (CLI + `--serve`) | **Done.** 4 tables on SQLite and on ClickHouse, byte-identical table rows (§7.3). `--serve` returns HTTP 200 for `/` and `/api/panels.json`. |
| 6-PCAP end-to-end run | **Done**, twice (run A without ClickHouse, run B with it). |

---

### 2. Host environment check (before writing code)

```text
$ python3 --version                      → Python 3.14.7
$ python3 -c "import zmq"                → ModuleNotFoundError: No module named 'zmq'
$ sqlite3 --version                      → 3.46.1 2024-08-13
$ clickhouse-client --version            → command not found
$ curl http://localhost:8123/ping        → exit 7 (connection refused)
$ docker info                            → Server Version: 27.5.1+dfsg4, Running: 1
$ docker images | grep -E 'clickhouse|grafana'
grafana/grafana   latest   da9910ab9d4c   (grafana --version → 13.0.1)
                                         (no ClickHouse image)
```

Docker Hub turned out to be reachable in this session: `docker pull clickhouse/clickhouse-server:24.8` finished with `Status: Downloaded newer image`. So both the offline path (run A) and the full stack (run B) could be tested.

---

### 3. What was built

| File | Purpose |
|---|---|
| `engine-ml/daemon.py` | Ingestion daemon: transport selection, validation, enrichment, batched writes to SQLite + JSONL + ClickHouse. Stdlib only. |
| `engine-ml/query_dashboard.py` | Four panel queries against SQLite (default) or ClickHouse; text tables, `--json`, or `--serve` (HTML + JSON on 127.0.0.1:8080). |
| `engine-ml/sql/init_clickhouse.sql` | `sentinel` database + `sentinel.network_flows` MergeTree table. |
| `engine-ml/tests/test_daemon.py` | 9 `unittest` cases for validation, enrichment and the alert rule. |
| `docker-compose.yml` | ClickHouse 24.8 + Grafana 13.0.1, both bound to 127.0.0.1. |
| `dashboard/grafana/provisioning/…` | ClickHouse datasource + dashboard provider. |
| `dashboard/grafana/dashboards/sentinelflow.json` | The 4-panel dashboard. |
| `docs/part2_grafana.png` | Headless-Chromium screenshot of the dashboard, taken in this session. |
| `Makefile` | New targets: `daemon`, `dashboard`, `dashboard-web`, `test-engine`, `stack-up`, `stack-down`. |
| `engine-ml/requirements.txt` | States that nothing is required; `pyzmq` is listed as optional. |
| `.gitignore` | Ignores `sentinel-flow/engine-ml/data/`. |

#### 3.1 Transport selection (`daemon.py`)

1. `import zmq` succeeds → bind a `PULL` socket directly.
2. Otherwise → `subprocess.Popen([zmq_sink, endpoint], stdout=PIPE, text=True, bufsize=1)` and read one JSON object per line. A reader thread feeds a `queue.Queue`, so the main loop can flush partial batches on a timer (`--flush-interval`, default 1 s).
3. `--from-jsonl FILE|-` → replay records from a file (for backfill and tests).

**Deviation from the brief:** the brief has `zmq_sink -e <endpoint>`. The compiled `zmq_sink` (`src/zmq_sink.c`) only accepts `[-n N] [endpoint]` and has no `-e` option. The daemon therefore passes the endpoint as a positional argument and leaves the Part 1-verified C code unchanged. The daemon's own flag is `-e/--endpoint`.

Before binding, the daemon removes a stale socket file at the IPC path (only if it is a socket). On SIGINT/SIGTERM it drains the queue, flushes, and terminates `zmq_sink`.

#### 3.2 Validation

Each of the 23 fields must be present with the right type. The checks:

| Kind | Fields | Check |
|---|---|---|
| IP | `src_ip`, `dst_ip` | `ipaddress.ip_address()` parses (IPv4 or IPv6) |
| string | `app_protocol`, `ja4_client`, `ndpi_risk_str` | `str` |
| UInt8/16/64 | `protocol`; ports; `ndpi_risk_mask`, `pkt_count`, `bytes_*`, `*_seen_us` | integer (bool rejected, integral floats accepted), in range |
| Float64 | the 10 timing/shape statistics | finite number |
| cross-field | — | `last_seen_us >= first_seen_us`, `pkt_count > 0` |

Extra fields are dropped. Rejected records go to `data/rejected.jsonl` with the error message and the raw line.

#### 3.3 Enrichment

| Column | Type | Value |
|---|---|---|
| `ingested_at_us` | UInt64 | `time.time_ns() // 1000` when the record is accepted |
| `ml_anomaly_score` | Float64 | Phase 2 baseline heuristic (below), rounded to 4 d.p. |
| `is_alert` | UInt8 | `1` if `ndpi_risk_mask > 0` **or** `ml_anomaly_score >= 0.80`, else `0` |

The baseline score is a noisy-OR, `1 − Π(1 − wᵢ)`, over these behavioral signals. **It is a placeholder heuristic, not a trained model.** Phase 3 replaces `heuristic_score()` with ONNX inference; the column and the alert rule stay the same.

| Signal | Condition | wᵢ |
|---|---|---|
| `ndpi_risk` | `ndpi_risk_mask > 0` | 0.40 |
| `unknown_protocol` | master protocol is `Unknown` | 0.40 |
| `unidirectional` | `pkt_count >= 3` and one direction has 0 bytes | 0.35 |
| `periodic_iat` | `pkt_count >= 6` and `iat_stddev / iat_mean < 0.20` | 0.50 |
| `upload_heavy` | `bytes_up_down_ratio > 10` | 0.25 |
| `nonstandard_port` | TLS/HTTP with neither port in the usual set | 0.20 |

**Change made during this session:** the first weights (0.30 / 0.30 / 0.35) could never reach 0.80 without a risk mask, so the `score >= 0.80` half of the alert rule could never fire. The unit test `test_score_threshold_alert_without_risk` caught this (`AssertionError: 0.6815 not greater than or equal to 0.8`). With the weights above, the beacon-like combination (unknown protocol + unidirectional + periodic) scores 0.805 and alerts. Two signals alone (best case 0.70) do not.

#### 3.4 Storage

* **SQLite** `engine-ml/data/sentinel_flows.db`: `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`. All 26 columns are `NOT NULL`. Indexes on `(first_seen_us, app_protocol, src_ip)` (the ClickHouse sort key) and on `is_alert`. Each batch is one transaction.
* **JSONL** `engine-ml/data/flows.jsonl`: one enriched record per line, `fsync`'d after each batch.
* **ClickHouse** over `urllib.request`: `POST {url}/?query=INSERT INTO sentinel.network_flows FORMAT JSONEachRow`. Credentials go in the `X-ClickHouse-User` / `X-ClickHouse-Key` headers.
* `--backend auto` (the default): SQLite + JSONL always; ClickHouse only if `/ping` and `EXISTS TABLE` succeed at startup. If not, ClickHouse is re-probed every 30 s. If a ClickHouse insert fails, ClickHouse is detached and the batch stays in SQLite/JSONL. `--backend both` exits with status 2 if ClickHouse is unreachable at startup.

---

### 4. Unit tests

```bash
python3 engine-ml/tests/test_daemon.py      # or: make test-engine
```

```text
test_clean_tls_not_alert (__main__.Enrich.test_clean_tls_not_alert) ... ok
test_risk_mask_forces_alert (__main__.Enrich.test_risk_mask_forces_alert) ... ok
test_score_bounded (__main__.Enrich.test_score_bounded) ... ok
test_score_threshold_alert_without_risk (__main__.Enrich.test_score_threshold_alert_without_risk) ... ok
test_two_signals_below_threshold (__main__.Enrich.test_two_signals_below_threshold) ... ok
test_extra_fields_dropped (__main__.Validate.test_extra_fields_dropped) ... ok
test_good_record (__main__.Validate.test_good_record) ... ok
test_ipv6_accepted (__main__.Validate.test_ipv6_accepted) ... ok
test_rejections (__main__.Validate.test_rejections) ... ok
----------------------------------------------------------------------
Ran 9 tests in 0.001s

OK
```

`test_rejections` has 11 sub-cases, each of which must raise `ValidationError`: missing field, invalid IP, port 70000, negative u64, `true` as protocol, `"109"` as a string number, fractional timestamp, NaN, `last_seen_us < first_seen_us`, `pkt_count = 0`, non-object JSON.

---

### 5. ClickHouse schema and stack

#### 5.1 `engine-ml/sql/init_clickhouse.sql` (excerpt)

```sql
CREATE DATABASE IF NOT EXISTS sentinel;

CREATE TABLE IF NOT EXISTS sentinel.network_flows
(
    src_ip String, dst_ip String, src_port UInt16, dst_port UInt16, protocol UInt8,
    app_protocol LowCardinality(String), ja4_client String,
    ndpi_risk_mask UInt64, ndpi_risk_str String,
    pkt_count UInt64, bytes_up UInt64, bytes_down UInt64,
    flow_duration_ms Float64, iat_mean Float64, iat_stddev Float64,
    iat_min Float64, iat_max Float64, pkt_len_mean Float64, pkt_len_stddev Float64,
    bytes_up_down_ratio Float64, small_pkt_ratio Float64,
    first_seen_us UInt64, last_seen_us UInt64,
    ingested_at_us UInt64, ml_anomaly_score Float64, is_alert UInt8
)
ENGINE = MergeTree()
ORDER BY (first_seen_us, app_protocol, src_ip);
```

#### 5.2 Evidence: schema as loaded by the server

`docker compose up -d` mounts the file into `/docker-entrypoint-initdb.d/`. After the container reported `healthy`:

```text
$ curl -s http://localhost:8123/?query=SELECT+version()      → 24.8.14.39
$ ... SELECT name, type FROM system.columns WHERE database='sentinel' AND table='network_flows' AND name IN (...)
ndpi_risk_mask    UInt64
bytes_up          UInt64
bytes_down        UInt64
first_seen_us     UInt64
last_seen_us      UInt64
ingested_at_us    UInt64
ml_anomaly_score  Float64
is_alert          UInt8
$ ... SELECT count() FROM system.columns WHERE database='sentinel' AND table='network_flows'
26
$ ... SELECT engine, sorting_key, total_rows FROM system.tables WHERE database='sentinel'
MergeTree    first_seen_us, app_protocol, src_ip    12
```

#### 5.3 `docker-compose.yml` notes

* `clickhouse/clickhouse-server:24.8`, user `sentinel` / password `sentinel`, port `127.0.0.1:8123`, named volume, `wget /ping` healthcheck.
* `grafana/grafana:13.0.1`, `depends_on: clickhouse (service_healthy)`, port `127.0.0.1:3000`, admin password `sentinel`.
* `GF_PLUGINS_PREINSTALL=grafana-clickhouse-datasource`. The plugin is **downloaded on first start**, so first start needs internet access (cached in the `grafana-data` volume afterwards). Observed in this session: `Downloaded and extracted grafana-clickhouse-datasource v4.23.2 zip successfully` … `Plugin successfully installed`. In the same log, Grafana's default app plugins failed with `dial tcp [2a00:…]:443: connect: network is unreachable` (IPv6). That doesn't affect this dashboard.
* Anonymous **Viewer** access is enabled (`GF_AUTH_ANONYMOUS_ENABLED`) so the dashboard opens without a login. I added this so the headless screenshot could load the dashboard. Checked: an anonymous `GET` of the dashboard returns `200`, and an anonymous `PUT` on the datasource returns `403`. Both ports bind to 127.0.0.1 only. The credentials are dev defaults; change them before exposing the stack.
* The local Grafana image was `grafana/grafana:latest`, and `grafana --version` inside it printed `13.0.1`. I tagged it locally as `13.0.1` instead of pulling. On a fresh host, compose will pull `13.0.1` from Docker Hub.

---

### 6. End-to-end runs

#### 6.1 Harness

Both runs use the same script; only the daemon arguments differ:

```bash
cd /home/joe/cv_work/sentinel-flow
export LD_LIBRARY_PATH=/home/joe/nDPI/src/lib
rm -rf engine-ml/data                                    # fresh store
python3 engine-ml/daemon.py [ARGS] 2> daemon.stderr &    # background
DPID=$!
# wait until daemon.stderr contains " ready"
for p in pcaps/test_dns.pcap pcaps/test_http.pcapng pcaps/test_tls_full.pcap \
         /home/joe/nDPI/tests/cfgs/default/pcap/tls_invalid_reads.pcap \
         /home/joe/nDPI/tests/cfgs/default/pcap/http_invalid_server.pcap \
         /home/joe/nDPI/tests/cfgs/default/pcap/malware.pcap; do
    ./sensor-c/build/sensor -r "$p"
done
sleep 2                                                  # > flush interval
kill -TERM $DPID; wait $DPID
```

#### 6.2 Run A — ClickHouse **down**, default `--backend auto` (zero-dependency path)

```text
sensor -r pcaps/test_dns.pcap -> exit 0 ; Flows exported: 1
sensor -r pcaps/test_http.pcapng -> exit 0 ; Flows exported: 1
sensor -r pcaps/test_tls_full.pcap -> exit 0 ; Flows exported: 1
sensor -r .../tls_invalid_reads.pcap -> exit 0 ; Flows exported: 2
sensor -r .../http_invalid_server.pcap -> exit 0 ; Flows exported: 1
sensor -r .../malware.pcap -> exit 0 ; Flows exported: 6
daemon exit status: 0
```

Daemon stderr (complete):

```text
[daemon] clickhouse: http://localhost:8123 not reachable — SQLite/JSONL only (re-probed every 30 s)
[daemon] transport=zmq_sink endpoint=ipc:///tmp/ndpi_flows.sock backends=sqlite,jsonl ready
[zmq_sink] listening on ipc:///tmp/ndpi_flows.sock
[daemon] flushed 12 rows -> sqlite,jsonl (total accepted=12 rejected=0)
[daemon] signal 15 — flushing and stopping
[zmq_sink] done
[daemon] stopped: accepted=12 rejected=0 clickhouse_failed=0
```

```text
$ wc -l engine-ml/data/flows.jsonl                         → 12
$ sqlite3 engine-ml/data/sentinel_flows.db "PRAGMA journal_mode; SELECT COUNT(*) FROM network_flows;"
wal
12
```

The sensors exported 1+1+1+2+1+6 = 12 flows. The daemon accepted 12 and rejected 0, and SQLite and JSONL each hold 12.

#### 6.3 Lossless check: stored values vs. the sensor's own output

Each PCAP was replayed with `sensor -v` to collect the 12 JSON objects the sensor emits. Each object was matched to its stored row by `(src_ip, dst_ip, src_port, dst_port, protocol, first_seen_us)`. All 23 fields were compared in both SQLite and JSONL, and the `is_alert` rule was re-checked on every row:

```text
sensor -v records: 12  jsonl: 12  sqlite: 12
fields compared: 552  differences: 0
```

The same check after run B also reported `differences: 0`.

#### 6.4 Rejection path

Input: one valid record, the line `not json`, and the valid record with `dst_port` changed to `99999`. Run with `--from-jsonl … --backend sqlite` into a separate scratch DB:

```text
[daemon] rejected: Expecting value: line 1 column 1 (char 0)
[daemon] rejected: dst_port: 99999 out of range for u16
[daemon] flushed 1 rows -> sqlite,jsonl (total accepted=1 rejected=2)
[daemon] stopped: accepted=1 rejected=2 clickhouse_failed=0
```

`rejected.jsonl` held both lines, each with its `error` and `raw` fields.

#### 6.5 Run B — full stack up, `--backend both`

```text
[daemon] clickhouse: http://localhost:8123 table sentinel.network_flows reachable
[daemon] transport=zmq_sink endpoint=ipc:///tmp/ndpi_flows.sock backends=sqlite,jsonl,clickhouse ready
[zmq_sink] listening on ipc:///tmp/ndpi_flows.sock
[daemon] flushed 12 rows -> sqlite,jsonl,clickhouse (total accepted=12 rejected=0)
[daemon] signal 15 — flushing and stopping
[zmq_sink] done
[daemon] stopped: accepted=12 rejected=0 clickhouse_failed=0
```

The sensor lines and exit statuses were the same as in run A. The ClickHouse row count is in §5.2 (`total_rows = 12`), and:

```text
SELECT count() AS flows, sum(is_alert) AS alerts, countIf(ml_anomaly_score >= 0.8) AS score_ge_080,
       min(ingested_at_us) > max(last_seen_us) AS ingest_after_capture
FROM sentinel.network_flows
flows  alerts  score_ge_080  ingest_after_capture
12     5       0             1
```

---

### 7. `query_dashboard.py` output

#### 7.1 Command

```bash
python3 engine-ml/query_dashboard.py --show-sql                        # SQLite
python3 engine-ml/query_dashboard.py --backend clickhouse --show-sql   # ClickHouse
```

#### 7.2 Captured output (SQLite, after run B; exact SQL shown above each table)

```text
SentinelFlow Phase 2 — SQLite engine-ml/data/sentinel_flows.db
flows=12  is_alert=1: 5  ndpi_risk_mask>0: 5  timestamp mismatches: 0

1. Protocol Breakdown
    SELECT app_protocol,
           COUNT(*)        AS flows,
           SUM(pkt_count)  AS packets,
           SUM(bytes_up)   AS bytes_up,
           SUM(bytes_down) AS bytes_down
    FROM network_flows
    GROUP BY app_protocol
    ORDER BY flows DESC, app_protocol
+--------------+-------+---------+----------+------------+
| app_protocol | flows | packets | bytes_up | bytes_down |
+==============+=======+=========+==========+============+
| TLS          | 4     | 103     | 5148     | 59537      |
| HTTP         | 3     | 15      | 879      | 759        |
| DNS          | 2     | 5       | 215      | 157        |
| HTTP.Google  | 1     | 10      | 394      | 744        |
| ICMP         | 1     | 1       | 84       | 0          |
| TLS.ntop     | 1     | 109     | 3546     | 68910      |
+--------------+-------+---------+----------+------------+
(6 rows)

2. JA4 TLS Fingerprints
    SELECT ja4_client,
           src_ip || ':' || src_port || ' -> ' || dst_ip || ':' || dst_port AS flow,
           app_protocol
    FROM network_flows
    WHERE ja4_client NOT IN ('', 'N/A')
    ORDER BY ja4_client, first_seen_us
+--------------------------------------+------------------------------------------+--------------+
| ja4_client                           | flow                                     | app_protocol |
+======================================+==========================================+==============+
| t12d6707h2_2955a3196ffa_c83f907a73d3 | 192.168.1.13:55523 -> 178.62.197.130:443 | TLS.ntop     |
| t13d1515h2_8daaf6152771_6a09c78d0dc2 | 192.168.0.20:41240 -> 193.109.85.123:443 | TLS          |
| t13d1814h2_29a2cd9e9f10_d267a5f792d4 | 192.168.7.7:35236 -> 67.215.92.210:443   | TLS          |
+--------------------------------------+------------------------------------------+--------------+
(3 rows)

3. High-Risk Security Alerts (ndpi_risk_mask > 0)
    SELECT ndpi_risk_mask, ndpi_risk_str, src_ip, dst_ip, app_protocol,
           ml_anomaly_score, is_alert
    FROM network_flows
    WHERE ndpi_risk_mask > 0
    ORDER BY ml_anomaly_score DESC, first_seen_us
+----------------+--------------------------------------+----------------+-----------------+--------------+------------------+----------+
| ndpi_risk_mask | ndpi_risk_str                        | src_ip         | dst_ip          | app_protocol | ml_anomaly_score | is_alert |
+================+======================================+================+=================+==============+==================+==========+
| 128            | Obsolete TLS (v1.1 or older)         | 192.168.10.101 | 206.33.61.113   | TLS          | 0.4              | 1        |
| 70368744177664 | Unidirectional Traffic               | 74.80.160.99   | 67.217.77.28    | TLS          | 0.4              | 1        |
| 70403103916032 | Susp Entropy, Unidirectional Traffic | 192.168.7.7    | 144.139.247.220 | ICMP         | 0.4              | 1        |
| 70368744177664 | Unidirectional Traffic               | 192.168.7.7    | 144.139.247.220 | HTTP         | 0.4              | 1        |
| 2048           | HTTP Susp User-Agent                 | 192.168.1.29   | 143.204.14.183  | HTTP         | 0.4              | 1        |
+----------------+--------------------------------------+----------------+-----------------+--------------+------------------+----------+
(5 rows)

4. Flow Telemetry & Timestamp Verification
    SELECT src_ip, dst_ip, app_protocol, pkt_count,
           first_seen_us, last_seen_us,
           last_seen_us - first_seen_us                    AS delta_us,
           flow_duration_ms,
           CAST(ROUND(flow_duration_ms * 1000) AS INTEGER) AS duration_us,
           CASE WHEN last_seen_us - first_seen_us
                     = CAST(ROUND(flow_duration_ms * 1000) AS INTEGER)
                THEN 'OK' ELSE 'MISMATCH' END              AS verdict
    FROM network_flows
    ORDER BY first_seen_us
+----------------+-----------------+--------------+-----------+------------------+------------------+----------+------------------+-------------+---------+
| src_ip         | dst_ip          | app_protocol | pkt_count | first_seen_us    | last_seen_us     | delta_us | flow_duration_ms | duration_us | verdict |
+================+=================+==============+===========+==================+==================+==========+==================+=============+=========+
| 192.168.170.20 | 192.168.170.8   | DNS          | 3         | 1112172654366527 | 1112172695437491 | 41070964 | 41070.964        | 41070964    | OK      |
| 192.168.10.101 | 206.33.61.113   | TLS          | 8         | 1252380859868541 | 1252380859943054 | 74513    | 74.513           | 74513       | OK      |
| 74.80.160.99   | 67.217.77.28    | TLS          | 1         | 1421985541772794 | 1421985541772794 | 0        | 0.0              | 0           | OK      |
| 192.168.7.7    | 1.1.1.1         | DNS          | 2         | 1569571466977364 | 1569571467001085 | 23721    | 23.721           | 23721       | OK      |
| 192.168.7.7    | 144.139.247.220 | ICMP         | 1         | 1569571470672893 | 1569571470672893 | 0        | 0.0              | 0           | OK      |
| 192.168.7.7    | 144.139.247.220 | HTTP         | 1         | 1569571476362891 | 1569571476362891 | 0        | 0.0              | 0           | OK      |
| 192.168.7.7    | 67.215.92.210   | HTTP         | 2         | 1569579408876326 | 1569579409087861 | 211535   | 211.535          | 211535      | OK      |
| 192.168.7.7    | 67.215.92.210   | TLS          | 20        | 1569579416636584 | 1569579417280185 | 643601   | 643.601          | 643601      | OK      |
| 192.168.1.13   | 178.62.197.130  | TLS.ntop     | 109       | 1581113120474299 | 1581113121570392 | 1096093  | 1096.093         | 1096093     | OK      |
| 192.168.1.128  | 216.58.208.142  | HTTP.Google  | 10        | 1643129441023341 | 1643129441065505 | 42164    | 42.164           | 42164       | OK      |
| 192.168.1.29   | 143.204.14.183  | HTTP         | 12        | 1689351610492040 | 1689351610530140 | 38100    | 38.1             | 38100       | OK      |
| 192.168.0.20   | 193.109.85.123  | TLS          | 74        | 1698873191201916 | 1698873192090406 | 888490   | 888.49           | 888490      | OK      |
+----------------+-----------------+--------------+-----------+------------------+------------------+----------+------------------+-------------+---------+
(12 rows)
```

#### 7.3 ClickHouse gives the same result

The ClickHouse version of each query differs only in dialect: `count()`/`sum()`, `concat(... toString(port))` in panel 2, and `toInt64(round(...))` / `if(...)` in panel 4. The full text is in `PANELS[*]["clickhouse"]` in `query_dashboard.py`. Captured output header:

```text
SentinelFlow Phase 2 — ClickHouse http://localhost:8123
flows=12  is_alert=1: 5  ndpi_risk_mask>0: 5  timestamp mismatches: 0
```

```text
$ diff <(grep '^[|+]' dashboard_sqlite.txt) <(grep '^[|+]' dashboard_ch.txt) && echo IDENTICAL
SQLite vs ClickHouse: all 4 panel tables IDENTICAL (30 table lines)
$ diff <(grep '^[|+]' runA/dashboard_sqlite.txt) <(grep '^[|+]' runB/dashboard_sqlite.txt)
run A vs run B SQLite panels: IDENTICAL
```

The first diff run was **not** identical: on the 3 zero-duration rows, ClickHouse printed `flow_duration_ms` as `0` and SQLite as `0.0`. ClickHouse's JSON output writes an integral Float64 without a decimal point. `ClickHouseBackend.run` now casts columns to `float` using the `Float*` types in the response's `meta`, and the re-run diff above is empty.

#### 7.4 Reading the panels

* **Panel 1:** 6 `app_protocol` values. nDPI's `master.app` labels (`TLS.ntop`, `HTTP.Google`) are kept as distinct rows, not folded into `TLS`/`HTTP`.
* **Panel 2:** 3 flows carry a JA4. `t12d6707h2_2955a3196ffa_c83f907a73d3` is the same string cross-checked against ndpiReader in Part 1.2 §5.1. The other two both come from `malware.pcap` (`192.168.7.7 → 67.215.92.210` and `192.168.0.20 → 193.109.85.123`) and were **not** cross-checked against ndpiReader in this session. The `tls_invalid_reads.pcap` TLS flow has `ja4_client = N/A`, matching Part 1.2 §6.2.
* **Panel 3:** 5 flows have `ndpi_risk_mask > 0`, and all 5 have `is_alert = 1`. The two nDPI risk strings from Part 1.2 §6.3 appear: `Obsolete TLS (v1.1 or older)` (mask 128) and `HTTP Susp User-Agent` (mask 2048). All 5 score `0.4`. That is the `ndpi_risk` weight alone: the `Unidirectional Traffic` flows have `pkt_count = 1`, below the heuristic's 3-packet floor. **No flow in this data reached `ml_anomaly_score >= 0.80`.** All 5 alerts come from the risk-mask half of the rule. The score half is covered only by the unit test (§4).
* **Panel 4:** `last_seen_us − first_seen_us == ROUND(flow_duration_ms × 1000)` on 12/12 rows (`timestamp mismatches: 0`). The `ROUND` is needed because `flow_duration_ms` is stored as a double (e.g. `1096.093 × 1000 = 1096092.9999…`). The two integer timestamp columns are compared exactly. The DNS, TLS.ntop, HTTP.Google and obsolete-TLS rows reproduce the deltas quoted in Part 1.2 §3.3 and §6.2 (41070964, 1096093, 42164, 74513 µs).

#### 7.5 `--serve`

```text
$ python3 engine-ml/query_dashboard.py --serve --port 8080 &
[dashboard] serving SQLite engine-ml/data/sentinel_flows.db on http://127.0.0.1:8080/
GET / -> 200 7091B
GET /api/panels.json -> {'flows': 12, 'alerts': 5, 'risk_flows': 5, 'timestamp_mismatches': 0}
   [('1. Protocol Breakdown', 6), ('2. JA4 TLS Fingerprints', 3),
    ('3. High-Risk Security Alerts (ndpi_risk_mask > 0)', 5),
    ('4. Flow Telemetry & Timestamp Verification', 12)]
```

The HTML contains the 4 panel headings. Each read opens a fresh read-only `file:…?mode=ro` connection, so a running daemon writing in WAL mode doesn't block it. The page was fetched with `curl` only; it was not opened in a browser.

---

### 8. Grafana

#### 8.1 Panel queries (ClickHouse SQL)

| Panel | Type | Query |
|---|---|---|
| Protocol Distribution | piechart (donut) | `SELECT app_protocol, count() AS flows FROM sentinel.network_flows GROUP BY app_protocol ORDER BY flows DESC` |
| Traffic Volume | timeseries (bars) | `SELECT toDateTime(intDiv(first_seen_us, 1000000)) AS time, sum(bytes_up) AS bytes_up, sum(bytes_down) AS bytes_down FROM sentinel.network_flows GROUP BY time ORDER BY time` |
| JA4 TLS Fingerprints | table | `SELECT ja4_client, src_ip, dst_ip, dst_port, app_protocol, count() AS flows, sum(pkt_count) AS packets FROM sentinel.network_flows WHERE ja4_client != 'N/A' AND ja4_client != '' GROUP BY … ORDER BY flows DESC` |
| High-Risk Flows (alerts) | table | `SELECT fromUnixTimestamp64Micro(toInt64(first_seen_us)) AS first_seen, src_ip, src_port, dst_ip, dst_port, app_protocol, ndpi_risk_mask, ndpi_risk_str, ml_anomaly_score FROM sentinel.network_flows WHERE is_alert = 1 ORDER BY ml_anomaly_score DESC, first_seen_us` |

Traffic Volume is plotted against **capture time** (`first_seen_us`), not ingest time, and has no `$__timeFilter`. Because the test PCAPs date from 2005 to 2023, the dashboard's default range is `now-25y`.

#### 8.2 Evidence

```text
$ curl -u admin:sentinel http://127.0.0.1:3000/api/health
{"database": "ok", "version": "13.0.1", "commit": "a100054f"}
$ curl -u admin:sentinel http://127.0.0.1:3000/api/datasources/uid/sentinel-clickhouse/health
{"message":"Data source is working","status":"OK"}
```

Each panel's `targets` sent unchanged from the provisioned JSON to `POST /api/ds/query`:

```text
[piechart] Protocol Distribution: status=200 rows=6 fields=['app_protocol', 'flows']
      ('TLS', 4)
      ('HTTP', 3)
      ('DNS', 2)
      ('ICMP', 1)
      ('HTTP.Google', 1)
      ('TLS.ntop', 1)
[timeseries] Traffic Volume (bytes per capture second): status=200 rows=12 fields=['time', 'bytes_up', 'bytes_down']
[table] JA4 TLS Fingerprints: status=200 rows=3 fields=['ja4_client', 'src_ip', 'dst_ip', 'dst_port', 'app_protocol', 'flows', 'packets']
[table] High-Risk Flows (alerts): status=200 rows=5 fields=['first_seen', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'app_protocol', 'ndpi_risk_mask', 'ndpi_risk_str', 'ml_anomaly_score']
      (1252380859868, '192.168.10.101', 3967, '206.33.61.113', 443, 'TLS', 128, 'Obsolete TLS (v1.1 or older)', 0.4)
      (1421985541772, '74.80.160.99', 3258, '67.217.77.28', 443, 'TLS', 70368744177664, 'Unidirectional Traffic', 0.4)
      (1569571470672, '192.168.7.7', 0, '144.139.247.220', 0, 'ICMP', 70403103916032, 'Susp Entropy, Unidirectional Traffic', 0.4)
      (1569571476362, '192.168.7.7', 33706, '144.139.247.220', 80, 'HTTP', 70368744177664, 'Unidirectional Traffic', 0.4)
      (1689351610492, '192.168.1.29', 51536, '143.204.14.183', 80, 'HTTP', 2048, 'HTTP Susp User-Agent', 0.4)
```

Rendered with `chromium --headless=new --screenshot` against `http://127.0.0.1:3000/d/sentinelflow-phase2?kiosk`:

![Grafana dashboard](part2_grafana.png)

The screenshot shows the donut (TLS 4 / HTTP 3 / DNS 2 / ICMP, HTTP.Google, TLS.ntop 1 each), 12 bar points spread across 2005–2023, 3 JA4 rows and 5 alert rows. It was taken after one cosmetic dashboard change (wider `ja4_client`/`ndpi_risk_str` columns; the score color scale now starts at yellow so alert rows aren't green).

---

### 9. How to run

```bash
# zero-dependency path (no Docker needed)
make sensor
python3 engine-ml/daemon.py &                 # or: make daemon
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib ./sensor-c/build/sensor -r pcaps/test_tls_full.pcap
python3 engine-ml/query_dashboard.py          # or: make dashboard / make dashboard-web

# full stack
docker compose up -d                          # first start needs internet for the Grafana plugin
python3 engine-ml/daemon.py                   # auto-attaches ClickHouse on :8123
python3 engine-ml/query_dashboard.py --backend clickhouse
# Grafana: http://127.0.0.1:3000  (anonymous viewer; admin/sentinel)

# backfill ClickHouse from the JSONL written while it was down
python3 engine-ml/daemon.py --from-jsonl engine-ml/data/flows.jsonl --backend clickhouse
```

---

### 10. What may and may not be said

**May be said (observed in this session):**

* On a host without `pyzmq`, `daemon.py` received the sensor's flows over `ipc:///tmp/ndpi_flows.sock` through the spawned C `zmq_sink`, using only the Python standard library: 12/12 flows from 6 PCAPs, in two independent runs.
* Every stored record is equal, on all 23 sensor fields, to what `sensor -v` printed for the same PCAPs (552 comparisons, 0 differences, in both SQLite and JSONL).
* SQLite runs in WAL mode; JSONL and SQLite hold the same 12 records.
* ClickHouse 24.8 accepted the same 12 rows through the stdlib `urllib` JSONEachRow client. The column types and MergeTree sort key match the brief.
* The four dashboard queries return identical tables from SQLite and from ClickHouse.
* `last_seen_us − first_seen_us` equals `flow_duration_ms × 1000` (rounded to the µs) on all 12 stored rows, in both databases.
* Every flow with `ndpi_risk_mask > 0` has `is_alert = 1` (5/5), and no flow without a risk mask is flagged (7 rows with score 0.0, `is_alert = 0`).
* The Grafana ClickHouse datasource reports `OK`, all 4 provisioned panel queries return data through Grafana, and the dashboard renders (screenshot).
* Malformed JSON and out-of-range values are rejected and logged without stopping the daemon.

**Must not be said (not shown):**

* That the `pyzmq` transport works. It is implemented but `pyzmq` is not installed here, so it never ran.
* That `ml_anomaly_score` detects anything. It is a fixed heuristic, not a model. No flow in this data reached 0.80; that alert path is tested only by a synthetic unit test.
* That the ClickHouse failover works mid-run. Not tested: losing ClickHouse during a run (the detach path), the 30 s re-probe/re-attach in `auto` mode, and the `--from-jsonl` backfill into ClickHouse.
* That ingestion is deduplicated. It is not: replaying a PCAP or re-running a backfill inserts duplicate rows in all three stores. MergeTree was kept as specified rather than `ReplacingMergeTree`.
* Anything about throughput, latency or memory. Only 12 flows were ingested, all in one batch. No load test, no live `-i` capture, no long-running soak.
* That `ndpi_risk_mask` values ≥ 2⁶³ are handled. SQLite stores INTEGER as signed 64-bit and would raise `OverflowError`. The largest mask seen here is 70403103916032 (< 2⁴⁷).
* That the two JA4 strings from `malware.pcap` match ndpiReader. Only the `test_tls_full.pcap` JA4 was cross-checked (Part 1 v2).
* That the `--serve` HTML page renders correctly in a browser. It was fetched with `curl` only.
* That the Grafana stack starts offline from scratch. The plugin download needs network access on first start.


---

<a id="part-3"></a>

## Part 3: Phases 1–3 Status, Audit, and the Encrypted-Traffic ML Pipeline

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Tree:** `/home/joe/cv_work/sentinel-flow/`
**Date:** 2026-10-23
**Host:** Kali Linux 6.16.8, Intel i7-1165G7 (8 threads), Python 3.14.7, nDPI 6.1.0-5906, libzmq 4.3.5, ClickHouse 24.8.14.39, Grafana 13.0.1
**Status:**
- **Phase 1 (C sensor)** and **Phase 2 (ingestion & analytics)** were re-checked against the README. The open Phase 1 items are now verified: memory safety, live capture, 30 s expiry, signal flush and throughput. The audit also found and fixed **seven sensor bugs** and **one consumer bug**, each with a regression test.
- **Phase 3 (ML pipeline)** is built end to end, from labeled PCAPs to ONNX models scored live in `daemon.py`. It was evaluated with grouped cross-validation and on 5 malware captures that were never used for training.

> [!info] How to read this document
> Same claim discipline as Part 1 §12 and Part 2 §10: every statement here is backed by output captured in this session. §11 lists what was **not** shown. Part 1, Part 1.2 and Part 2 stay valid for what they cover; this file records what changed since and adds Phase 3.

---

### 0. Summary

| Area | Result |
|---|---|
| Phase 1 vs README | All "Phase 1" checklist items done. Three README claims that had not been demonstrated before ("no memory leaks", live `-i`, "30 s idle expiration") are now demonstrated (§3). One README claim is wrong: the JSON has **23** fields, not 24. |
| Sensor bugs found & fixed | (1) undefined-behavior misaligned header reads, (2) garbage `ja4_client` on non-TLS flows (nDPI union read), (3) unsigned underflow of duration/IAT on out-of-order packets, (4) every non-Ethernet capture silently ignored, (5) flows lost silently when the consumer is slow (fixed in the sink), (6) dropped flows counted as "exported", (7) µs precision lost on flows > ~17 min. |
| Phase 2 vs README | Done, with the stdlib substitutes agreed in Part 2 (no `pyzmq` / `clickhouse-connect`). The default batch size is now **1,000 rows** (README "1,000 records / 1 sec"; it was 100). A 5th panel shows ML detections. |
| Phase 3 dataset | **9,659 flows** from **601 PCAPs** (22 malware-traffic-analysis.net cases + nDPI corpus + repo PCAPs), all produced by the production path `sensor → ZMQ → zmq_sink`. 0 dropped, 0 rejected. 1,825 malicious flows in 28 captures / 25 families. Also loaded into ClickHouse `sentinel.training_flows`. |
| Phase 3 models | LightGBM classifier + IsolationForest (benign-only), exported to ONNX. Parity with the native models on all 9,597 labeled rows: max \|Δp\| = 3.7e-4, 0 alert decisions differ. |
| Cross-validation (grouped by capture, 5 seeds) | Calibrated LightGBM at the 0.80 alert threshold: **recall 0.45 ± 0.04, precision 0.91 ± 0.03, FPR 1.1 % ± 0.4 %, ROC-AUC 0.980, PR-AUC 0.905 ± 0.007**. |
| Holdout (5 never-seen infections, full live pipeline) | **5/5 infections detected**, **15/23 malicious endpoints** alerted, **precision 99.6 %, FPR 0.6 %** (3 false alerts / 498 benign flows). Flow-level recall 23 %. |
| Live scoring | `daemon.py` loads the ONNX models (SHA-256-checked), scores each batch (1,000 flows in 36–47 ms), and falls back to the Phase 2 heuristic when `onnxruntime` is missing. Verified with `python3 -S`. |
| Key finding for Phase 4 | The Phase 2 alert rule `ndpi_risk_mask > 0 OR score ≥ 0.80` fires on **18 % of real Windows background flows** (CV) and **18.3 %** on the holdout. Blocking on it would block a large share of normal traffic. It is kept as the default because it is your rule; `--alert-risk-policy` offers the alternatives (§8.4). |

---

### 1. README requirements check

#### 1.1 Phase 1 — "The C Sensor & IPC Spine"

| README item | State | Evidence |
|---|---|---|
| libpcap from live interface or offline `.pcap` | Done | Offline: every run in this file. Live: `sensor -i lo` as root captured the 3 test HTTP requests (§3.8). |
| libndpi + 5-tuple hash table (uthash) | Done | `flow_table.c`; `test_flow` 13/13. |
| protocol name, JA4, `ndpi_flow_risk_bitmap` | Done; JA4 bug fixed | §3.3. JA4 of `test_tls_full.pcap` still matches ndpiReader (`t12d6707h2_2955a3196ffa_c83f907a73d3`, regression test). |
| Welford `iat_*`, `pkt_len_*` | Done; underflow fixed | `test_stats` 24/24; §3.4. |
| JSON over `ZMQ_PUSH` on `ipc:///tmp/ndpi_flows.sock` | Done; loss fixed | §3.6. |
| README "24-field JSON schema" | **Incorrect claim** | The sensor emits 23 fields (`daemon.SENSOR_FIELDS`, validated on 9,659 + 3,604 records). |
| README "uthash … 30s idle expiration" | Now demonstrated | §3.7. |
| README "Clean shutdown (SIGINT/SIGTERM), no memory leaks" | Now demonstrated | LeakSanitizer §3.1; SIGINT flush on live capture §3.8. |

#### 1.2 Phase 2 — "ClickHouse Ingestion & Instant Visibility"

| README item | State | Evidence |
|---|---|---|
| ClickHouse + Grafana via `docker-compose.yml` | Done (Part 2) | Still running: `sentinel-clickhouse` healthy, Grafana datasource `OK`. |
| `daemon.py` with `pyzmq` + `clickhouse-connect` | Done with stdlib substitutes (Part 2 constraint) | `zmq_sink` child process + `urllib` JSONEachRow. The `pyzmq` path exists but is untested (not installed). |
| Flush every 1 s **or 1,000 rows** | **Fixed this session** | Default `--batch-size` was 100, now 1,000. Final run: batches of `1000, 1000, 1000, 591` rows (§9). |
| MergeTree `network_flows` | Done | `ENGINE = MergeTree`, `ORDER BY (first_seen_us, app_protocol, src_ip)`; 3 Phase 3 columns added with an idempotent migration (§8.3). |
| 4 Grafana panels (protocols, JA4 anomalies, traffic volume, high-risk) | Done; JA4 panel upgraded | The JA4 panel now shows per-fingerprint `max_ml_score` / `ml_alerts`, closer to "JA4 Fingerprint anomalies". 5th panel "ML Detections". All 5 queries return HTTP 200 through Grafana (§9.3). |

#### 1.3 Phase 3 — "The Encrypted Traffic ML Pipeline"

| README item | State | Evidence |
|---|---|---|
| Download benign + malicious C2/exfil PCAPs (Malware-Traffic-Analysis.net / CIC) | Done (MTA + nDPI corpus) | 22 MTA cases (17 training, 5 holdout), 281 MB; only PCAP + IOC text archives (§4.1). CIC datasets not used. |
| Run them through the sensor to make labeled rows in ClickHouse ("zero feature mismatch") | Done | `build_dataset.py` uses `sensor -r → ZMQ → zmq_sink`; 9,659 rows in SQLite, JSONL and ClickHouse `sentinel.training_flows` (§5). |
| Train LightGBM (benign vs C2/exfil) + IsolationForest, export `.onnx` | Done | `train_pipeline.py` → `models/c2_detector.onnx`, `models/anomaly_iforest.onnx`, `models/model_meta.json` (§6–§7). |
| Load the `.onnx` in `daemon.py` with `onnxruntime`, score batches in real time | Done | `OnnxScorer` in `daemon.py`; live run of 3,604 flows (§9). |

---

### 2. System as built

```
 PCAP / NIC ──► sensor (C, libpcap + nDPI 6.1)                    sensor-c/
                 │  Ethernet/VLAN, Linux cooked v1/v2, BSD loopback, raw IP
                 │  5-tuple flows, JA4, risk mask, Welford IAT/len stats
                 │  JSON (23 fields) ──► ZMQ PUSH (connect)
                 ▼
            ipc:///tmp/ndpi_flows.sock
                 ▼
 zmq_sink (C, ZMQ PULL bind, RCVHWM=0) ──stdout JSONL──► daemon.py      engine-ml/
   (or pyzmq PULL if installed)          validate 23 fields
                                         stamp ingested_at_us
                                         batch (1,000 rows / 1 s)
                                         features.py ─► ONNX LightGBM + IsolationForest
                                           (fallback: heuristic_v1, stdlib)
                                         is_alert = risk-policy OR score ≥ 0.80
                       ┌─────────────────────┼────────────────────────┐
                       ▼                     ▼                        ▼
             SQLite (WAL)             flows.jsonl           ClickHouse sentinel.network_flows
         query_dashboard.py                                    Grafana (5 panels)

 Training path (offline, same sensor bytes):
 datasets/fetch_mta.py ─► PCAP + IOC ─► models/build_dataset.py (sensor→ZMQ→zmq_sink, labels)
   ─► data/training/flows_labeled.jsonl + training.db + ClickHouse sentinel.training_flows
   ─► models/train_pipeline.py (grouped CV, calibration, ONNX export, parity check)
   ─► models/evaluate_holdout.py (5 unseen captures through the live daemon)
```

---

### 3. Phase 1 audit (sensor)

The audit used three kinds of check:

- **Sanitizer build:** AddressSanitizer + LeakSanitizer + UndefinedBehaviorSanitizer, built in the scratchpad with `-fsanitize=address,undefined -g` (valgrind is not installed).
- **Corpus sweeps:** the whole nDPI test corpus, 631 captures.
- **Byte-for-byte regression:** a fixed 9-PCAP set (`test_dns`, `test_http`, `test_tls_full`, `tls_invalid_reads`, `http_invalid_server`, `malware`, `emotet`, `tor`, `quic`), 38 flows. After each fix its JSON had to stay byte-identical, unless the fix was meant to change it (§3.7).

#### 3.1 Memory safety (ASan / LSan / UBSan)

First run, 12 PCAPs: **0 AddressSanitizer and 0 LeakSanitizer reports, but 8–12 UBSan `runtime error` lines per run**, all of one kind:

```text
sensor-c/src/main.c:223:19: runtime error: member access within misaligned address 0x7dc06cbe008e
for type 'const struct ip', which requires 4 byte alignment
```

To show LeakSanitizer was really active, a 3-line program that leaks 4,242 bytes was built with the same flags:

```text
==170614==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 4242 byte(s) in 1 object(s) allocated from:
```

**Fix 1 — misaligned header reads.** `main.c` cast `pkt + 14` to `struct ip *`. Offset 14 isn't 4-byte aligned, so this is undefined behavior: harmless on x86, a fault on strict-alignment CPUs. The IPv4, TCP and UDP headers (and the VLAN ethertype) are now `memcpy`'d into aligned locals. After the fix the 9-PCAP JSON was byte-identical and UBSan reported 0.

**Final sweep with the final binaries:** 16 PCAPs, including a 1,105-flow MTA capture, the non-Ethernet captures and the JA4-bug captures. 1,890 flows exported, 1,890 received by the ASan-built `zmq_sink`, **0 sanitizer errors** in sensor or sink.

#### 3.2 Throughput (was "no packets-per-second number")

All 577 Ethernet captures in the nDPI corpus were converted to classic pcap (`editcap`; 1 failed) and concatenated (`mergecap`): **124,070 packets, 45 MB**. They were run through the final sensor with `zmq_sink` consuming:

```text
run 1: exit=0 dropped=0 packets=124070 flows_exported=9694 sink_received=9694 wall=0.29s pps=433,768 sensor_maxRSS=25.6MB
run 2: exit=0 dropped=0 packets=124070 flows_exported=9694 sink_received=9694 wall=0.31s pps=403,090 sensor_maxRSS=25.8MB
run 3: exit=0 dropped=0 packets=124070 flows_exported=9694 sink_received=9694 wall=0.29s pps=435,273 sensor_maxRSS=25.8MB
```

That's **~0.40–0.44 Mpps offline, single-threaded, 25.8 MB peak RSS**. This measures reading a file as fast as possible. It is not a live-capture line-rate number.

#### 3.3 Fix 2 — garbage `ja4_client` on non-TLS flows

The first throughput run crashed my checker with `UnicodeDecodeError`: the sink output contained invalid UTF-8, and the bad byte changed from run to run (`0xe8`, `0xc8`, `0xf7`):

```text
"app_protocol":"SSDP","ja4_client":"\xf7\xb2\\u0004\x90U"
```

**Root cause:** `ndpi_wrapper_get_ja4()` read `flow->metadata.protos.tls_quic.ja4_client` for every flow. `metadata.protos` is a **union** shared by all dissectors, so on an SSDP, DHCP or TiVo flow those bytes belong to another protocol. A scan of the 577 Ethernet corpus files with the HEAD binary:

```text
  1kxun.pcap: 3 non-TLS flows with ja4 e.g. ('Mikrotik', '50G', False)
  gnutella.pcap: 1 non-TLS flows with ja4 e.g. ('DHCP', '2', False)
  mikrotik_mndp.pcap: 1 non-TLS flows with ja4 e.g. ('Mikrotik', 'UiG+5HPaxD2HPaxD', False)
  ssdp.pcapng: 1 non-TLS flows with ja4 e.g. ('SSDP', 'oe��U', True)
  teams.pcap: 1 non-TLS flows with ja4 e.g. ('DHCP', '19', False)
  telegram.pcap: 1 non-TLS flows with ja4 e.g. ('DHCP', '19', False)
  TivoDVR.pcap: 1 non-TLS flows with ja4 e.g. ('TiVoConnect', 'inidlna', False)
files_affected=7 flows_affected=9
--- fixed:
files_affected=0 flows_affected=0
```

**Fix:** read the field only when the master or app protocol is TLS-family (TLS, DTLS, QUIC, DoH/DoT, IMAPS, POPS, SMTPS, FTPS), **and** require a well-formed 36-character JA4 (`is_valid_ja4`). On the merged corpus: 886 flows carry a JA4, all of them TLS-family (TLS 742, QUIC 131, DTLS 9, IMAPS 2, POPS 1, SMTPS 1); 198 distinct fingerprints. Two flows carry `t13i0311/0_…`, where nDPI writes `/0` for a libp2p ALPN (the JA4 spec would use hex). That is nDPI's output and is passed through.

#### 3.4 Fix 3 — unsigned underflow on out-of-order packets

The Phase 2 validator rejected 16 merged-corpus flows with `last_seen_us < first_seen_us`. Their records showed the bug:

```text
{'app_protocol': 'IPSec', 'pkt_count': 90, 'flow_duration_ms': 1.8446744e+16,
 'iat_mean': 2.07266787e+17, 'iat_max': 1.8446744e+19, ...}
```

`last_seen_us` was overwritten by every packet, and `pkt_time_us - last_pkt_us` underflowed as `uint64` when a packet's timestamp went backwards. Single (unmerged) captures trigger it too:

```text
  ipsec_isakmp_esp.pcap: 10/24 flows with underflowed duration/IAT
  geforcenow.pcapng / heuristic_tcp_ack_payload.pcap / mudfish.pcap / resp.pcap /
  sites3.pcapng / tls-appdata.pcap / yandex.pcapng: 1 each
files=577 flows=9738 affected_files=8 affected_flows=17        (HEAD)
files=577 flows=9738 affected_files=0 affected_flows=0         (fixed)
```

**Fix:** `first_seen_us` / `last_seen_us` are kept as min/max of packet times. A backwards step counts as IAT 0, and `last_pkt_us` never moves backwards. The 9-PCAP set was byte-identical afterwards.

#### 3.5 Fix 4 — non-Ethernet link types were silently dropped

`main.c` assumed Ethernet framing and only printed a warning otherwise. **53 of the 631 corpus files** (Linux cooked capture, raw IP, BSD loopback, …) produced 0 flows, including two malicious samples (`Emotet_infection_url_dga_*` is raw IPv4, `dns2tcp_tunnel` is Linux cooked). Live capture on `-i any` or on a tun/VPN interface would have failed the same way.

**Fix:** `ipv4_offset()` decodes Ethernet (+ one 802.1Q tag), `DLT_LINUX_SLL`, `DLT_LINUX_SLL2`, `DLT_NULL` / `DLT_LOOP` (AF_INET in either byte order) and `DLT_RAW` / `DLT_IPV4`. The link type is logged at start. Result on the 53 files, with the ASan build, 0 sanitizer errors:

```text
rawip4     files=6   decoded=6   flows=15
linux-sll  files=17  decoded=16  flows=132
null       files=10  decoded=7   flows=11
rawip      files=16  decoded=16  flows=56
ppp        files=2   decoded=0   flows=0      (unsupported)
ppi        files=1   decoded=0   flows=0      (unsupported)
chdlc      files=1   decoded=0   flows=0      (unsupported)
```

The 4 remaining files of supported types that decode nothing contain no IPv4; the sensor is IPv4-only (known, see Part 1.2 §5.2).

#### 3.6 Fixes 5–6 — silent flow loss over ZeroMQ

The first full dataset build stopped with a 30 s read timeout on the second MTA capture. Reproduced:

```text
2023-07-12-Gozi-infection-with-Cobalt-St exported 1105 queued 1001
```

The sensor reported 1,105 flows exported but the consumer only ever received **1,001**, with no error anywhere.

**Diagnosis.** The trigger was my builder reading the sink's pipe unbuffered, which made it a slow consumer. Three hypotheses were tested in turn:

1. *Sender send-timeout drops.* Adding a drop counter showed `dropped=0`: not the cause.
2. *Sender linger expiring at close.* Socket monitoring showed the sender's queue had drained and `zmq_close` returned in 0.2 s: not the cause.
3. *Receiver high-water mark.* `zmq_sink` used the default `ZMQ_RCVHWM = 1000`. While its stdout is blocked, about 1,000 messages queue on the receiving side, and the in-flight rest is discarded when the sensor disconnects. Setting `ZMQ_RCVHWM = 0` in `zmq_sink`:

```text
before fix: exit=0 exported=1105 dropped=n/a (not reported) consumer_received=1001
sink RCVHWM=0, new sensor: exit=0 exported=1105 dropped=0 consumer_received=1105
sink RCVHWM=0, old sensor: exit=0 exported=1105 dropped=0 consumer_received=1105
```

**Fix 5 (root cause):** `ZMQ_RCVHWM = 0` in `zmq_sink.c` and in the daemon's `pyzmq` transport. Receive memory stays bounded by the sender's own queue (`ZMQ_SNDHWM = 10000`).

**Fix 6 (making loss visible), kept because it closes real gaps:**
- `export_flow` used to count a flow as exported even when `zmq_send` failed. Now the summary prints `Flows exported` (accepted by the ZMQ queue) and `Flows dropped` separately. An offline run with any drop exits with status **3**, and `build_dataset.py` aborts on it.
- Offline `-r` waits up to 10 s per flow for a full queue; live capture keeps the 200 ms bound so capture never stalls. After one drop a breaker limits retries until a send succeeds again, so a run with no consumer can't hang.
- At close, a libzmq socket monitor tells whether a consumer is connected. If so the sensor waits up to 60 s for the queue to drain, otherwise 500 ms. The old fixed 2 s linger could discard the tail of a large final flush, e.g. after SIGINT on a busy live capture.

```text
[zmq] closing: 1 consumer(s) connected, linger 60000 ms     (consumer present)
[zmq] closing: 0 consumer(s) connected, linger 500 ms       (no consumer; run took 0.64 s)
```

**Regression test** `test_stalled_consumer_loses_nothing`: 1,500 one-packet flows, and the consumer doesn't read until the sensor has exited. It passes with the new sink and fails with the HEAD sink, which receives about 1,001 and times out waiting for the rest.

#### 3.7 Fix 7 — µs precision of long flows, and the 30 s expiry test

The final live run (§9) showed `timestamp mismatches: 15` on the holdout captures, which are 20–60 minutes long:

```text
HTTP|5003499711|5003499.71|5003499710      (delta_us | flow_duration_ms | round(ms*1000))
shortest_mismatch_us = 1058470424
```

`cJSON.c` printed non-integers with `%.9g`, so any duration over ~1,058 s lost microseconds. **Fix:** `%.15g`. On the 9-PCAP set this is the one intended output change: 729 fields identical, 145 gained digits (largest relative change 4.4e-9), and no string, IP, port or JA4 changed. Final live run: **timestamp mismatches 0**. Regression test `test_long_flow_duration_keeps_microseconds` fails on the old binary (`5003499710 != 5003499711`).

**30 s idle expiry (previously not tested).** A synthetic PCAP: flow A at t = 0–0.4 s, then 1,000 filler packets at t = 40 s (the sensor checks expiry every 1,000 packets), then A again at t = 42 s. Expected: A exported **twice**.

```text
10.0.0.1 40000 -> 10.0.0.2 9999 pkts 5 first 1700000000000000 last 1700000000400000
10.0.0.3 40001 -> 10.0.0.4 9998 pkts 1000 first 1700000040000000 last 1700000040999000
10.0.0.1 40000 -> 10.0.0.2 9999 pkts 5 first 1700000042000000 last 1700000042400000
║  Flows tracked:     3               ║
```

#### 3.8 Live capture and SIGINT flush (previously not tested)

Final binary: `sudo sensor -i lo` against a local `python3 -m http.server`, 3 × `curl`, then SIGINT:

```text
curl 1 -> 200 / curl 2 -> 200 / curl 3 -> 200
sensor exited 1.63 s after SIGINT
[sensor] capturing live on: lo
[sensor] link type: EN10MB
║  Packets processed: 80   Flows tracked: 12   Flows exported: 12   Flows dropped: 0 ║
[zmq] closing: 1 consumer(s) connected, linger 60000 ms
sink received 12 flows; 3 to :18080: [('HTTP', 12), ('HTTP', 12), ('HTTP', 12)]
```

The other 9 flows are other local services' loopback traffic on this host (ports 6789 and 9200). The 1.63 s exit time is the 1 s `pcap_open_live` timeout plus the flush.

#### 3.9 Sensor test suite

| Test | Result |
|---|---|
| `sensor-c/build/test_flow` (direction / byte accounting) | 13 passed, 0 failed |
| `sensor-c/build/test_stats` (Welford) | 24 passed, 0 failed |
| `sensor-c/tests/test_sensor_pcaps.py` (new; runs the real binary on synthetic + corpus PCAPs) | 7/7 OK: idle expiry, out-of-order timestamps, no JA4 on non-TLS (4 real corpus captures), JA4 still exact on TLS, 6 link-type framings, stalled consumer, long-flow precision |

Each new test was also run against the pre-fix binary and fails there, except the expiry test (expiry already worked) and the "JA4 still on TLS" test (a guard against over-fixing).

---

### 4. Phase 3 data

#### 4.1 Malware-traffic-analysis.net (MTA)

`engine-ml/datasets/fetch_mta.py` downloads **only** `*.pcap.zip` and IOC/notes `*.txt.zip` archives. "malware"/"artifacts" archives (actual samples) are never fetched, and an archive containing any file other than `.pcap` / `.pcapng` / `.txt` would be dropped. Archives use the site's `infected_YYYYMMDD` password scheme, published as an image on the site's "about" page; extraction is done with `7z` into a temporary directory, and every extracted file's SHA-256 is recorded in `SOURCE.json`. The PCAPs are untrusted data, parsed only by the sensor and `tshark`.

**Training cases (17; 178 MB):**

| Case | Family | Flows | Malicious | Benign | Ambiguous |
|---|---|---|---|---|---|
| 2023-05-10 | Qakbot + Cobalt Strike + VNC | 543 | 91 | 452 | 0 |
| 2023-07-12 | Gozi/ISFB + Cobalt Strike | 1105 | 903 | 202 | 0 |
| 2023-10-03 | Pikabot + Cobalt Strike | 412 | 277 | 135 | 0 |
| 2023-10-31 | IcedID | 87 | 17 | 70 | 0 |
| 2023-12-18 | Pikabot + Cobalt Strike | 289 | 188 | 99 | 2 |
| 2024-01-09 | AsyncRAT | 4 | 3 | 1 | 0 |
| 2024-03-14 | AsyncRAT + XWorm | 37 | 12 | 15 | 10 |
| 2024-03-19 | DarkGate | 71 | 68 | 3 | 0 |
| 2024-04-18 | SSLoad + Cobalt Strike | 179 | 12 | 148 | 19 |
| 2024-06-12 | KoiLoader/KoiStealer | 297 | 30 | 260 | 7 |
| 2024-06-25 | Latrodectus + BackConnect + Keyhole VNC | 485 | 165 | 320 | 0 |
| 2024-09-19 | Lumma Stealer | 66 | 29 | 24 | 13 |
| 2024-10-23 | Redline Stealer | 3 | 1 | 1 | 1 |
| 2024-12-17 | NetSupport RAT | 19 | 1 | 14 | 4 |
| 2025-01-31 | AgentTesla-style FTP exfil / VIP Recovery SMTP exfil (2 PCAPs) | 10 | 4 | 3 | 3 |
| 2025-03-10 | Remcos RAT | 182 | 3 | 179 | 0 |
| 2025-11-19 | XWorm | 5 | 1 | 3 | 1 |

`2025-03-10/vmnet8a.pcap` was excluded: it's a near-duplicate raw capture of the same Remcos run (11 k packets, same ~19 minutes).

**Holdout cases (5; 103 MB), in a separate directory that the dataset builder never reads:** 2023-11-06 (404 TDS → Cobalt Strike), 2023-11-20 (DarkGate), 2024-02-21 (SocGholish → AsyncRAT), 2025-08-15 (Lumma Stealer → SectopRAT, a family absent from training) and 2025-12-29 (ClickFix → NetSupport RAT). Their labels (`datasets/mta_holdout_labels.json`) were written from the IOC texts **before** any model was run on them.

#### 4.2 Labeling rules

MTA labels are curated by hand in `datasets/mta_labels.json`, written from each case's IOC text. Two cases needed other sources: 2025-03-10 came from the Unit 42 IOC file linked on the MTA page, and 2025-01-31 has no IOC file, so it was labeled from its flows.

- **malicious (1):** either endpoint is an IOC IP, or an IP that the capture's own DNS answers / TLS SNI / HTTP Host (via `tshark`, labeling only) map to an IOC domain. Classes: C2, payload delivery, exfiltration.
- **ambiguous (−1, excluded from training and evaluation):** shared or legitimate services the malware used: Dropbox, trycloudflare, Telegram, `t.me`, `sites.google.com`, Firebase, IP-lookup sites (`api.ipify.org`, `ip-api.com`, `api.ip.sb`, …), and compromised legitimate sites. Sections the IOC files mark "NOT MALICIOUS" / "LEGITIMATE DOMAINS" are never used as malicious.
- **benign (0):** every other flow in the capture ("background": Windows updates, telemetry, AD traffic). Benign traffic from the same lab environment keeps the model from learning "which dataset is this" instead of "is this C2".

**nDPI corpus rules** (`NDPI_RULES` / `NDPI_EXCLUDE` in `build_dataset.py`):
- **malicious:** `trickbot`, `websocket-chisel-ssh`, `tls_malicious_sha1`, DNS tunnels/exfil (`dns_exfiltration`, `dns-exf`, `dns-tunnel-iodine`, `dns2tcp_tunnel`) and `icmp-tunnel` (all flows); `malware`, `emotet`, `Emotet_infection_url_dga_*` ("non-infra" rule: their DNS/ICMP/NetBIOS/… flows are ambiguous).
- **excluded:** web attacks, scans, DoS, executable downloads, mining, anonymizers (Tor, Psiphon, Ultrasurf, Shadowsocks, `tls_heur__*`) and fuzzed/malformed captures. They aren't C2 and would blur the labels.
- **benign:** everything else, plus the 4 repo PCAPs.
- **`bot.pcap` is benign.** nDPI's own result file shows it is the Bing crawler (`[cat: Bots/124][Breed: Acceptable]`). Labeling it by filename would have been wrong.

#### 4.3 Label audit

Every malicious MTA flow was grouped by destination and checked against the IOC text. Examples:

```text
Gozi/ISFB + CS: 803 → 170.130.55.162:443 TLS (Cobalt Strike C2), 74 → 151.248.117.244:80 (Gozi C2)
DarkGate:        67 → 103.124.105.78:80 HTTP (badbutperfect.com, resolved in-capture)
Remcos RAT:       3 → 206.123.152.51:3980 (nDPI labels this "Blizzard")
AsyncRAT+XWorm:   2 → 91.134.150.150:7000 (nDPI labels this "Cassandra")
```

Two side observations. nDPI sometimes names C2 channels by port guess ("Blizzard", "Cassandra"). And domain-based labels on Cloudflare IPs (Lumma, IcedID) label every flow to that IP within the capture, a known source of label noise.

---

### 5. Building the training set

```bash
LD_LIBRARY_PATH=~/nDPI/src/lib python3 engine-ml/models/build_dataset.py    # or: make dataset
```

`SensorRunner` keeps one `zmq_sink` alive and runs one `sensor -r` per PCAP. After the sensor exits with `Flows exported: N`, the next N sink lines belong to that PCAP: a single PUSH→PULL pipe preserves order, and the sensor drains before exit. Every record goes through `daemon.validate()`.

```json
{
  "pcaps": 601, "pcaps_with_flows": 562, "flows": 9659, "rejected_by_validation": 0,
  "by_source_label": {"mta/ambiguous": 60, "mta/benign": 1929, "mta/malicious": 1805,
                      "ndpi/ambiguous": 2, "ndpi/benign": 5839, "ndpi/malicious": 20, "repo/benign": 4},
  "groups": {"benign": 550, "malicious": 28}
}
[clickhouse] sentinel.training_flows: 9659 rows
```

Outputs: `engine-ml/data/training/flows_labeled.jsonl` (SHA-256 `f4af2732…`), `training.db`, `summary.json` (per-PCAP counts and link types), and ClickHouse `sentinel.training_flows`.

---

### 6. Features and models

#### 6.1 Feature vector (`engine-ml/features.py`, 61 features, `FEATURE_VERSION = 1`)

`features.py` is used by both training and `daemon.py`, so the transformation is identical offline and online.

| Group | Features |
|---|---|
| Transport | `protocol`, `service_port` (min of the two ports), `service_port_wellknown` |
| Volume | log `pkt_count`, `bytes_up`, `bytes_down`, total; `bytes_per_pkt` |
| Timing | log `duration_ms`, log `iat_mean/stddev/min/max`, `iat_cv` |
| Sizes / shape | `pkt_len_mean`, `pkt_len_stddev`, `pkt_len_cv`, `log_up_down_ratio`, `small_pkt_ratio`, `unidirectional_bytes` |
| nDPI risk | `risk_count`, `has_risk`, 26 individual risk bits (from `ndpi_risk_enum`) |
| Classification | `app_tls`, `app_quic`, `app_http`, `app_dns`, `app_unknown`, `app_has_subprotocol` |
| JA4_a (parsed) | present, QUIC, TLS version, SNI-is-domain, #ciphers, #extensions, ALPN class |

IP addresses and timestamps are **deliberately not features**: they identify specific hosts and captures, and a model could memorize them.

#### 6.2 Training (`engine-ml/models/train_pipeline.py`)

- **LightGBM:** 300 trees, learning rate 0.05, 31 leaves, `min_child_samples` 10, row/column subsampling 0.8, λ = 1.
- **Per-capture weight cap of 50.** One capture can't dominate: Gozi's 803-flow beacon counts as at most 50 flows.
- **IsolationForest:** 200 trees on **benign flows only**. Its raw anomaly is mapped so the benign median → 0 and the benign 99.5th percentile → 0.80.
- **Evaluation:** `StratifiedGroupKFold(k=5)`, grouped by capture (each MTA case or nDPI file), so near-duplicate flows from one capture never span train and test. Repeated with **5 seeds**: different fold assignment and model seed each time.
- **Baselines on the same data:** the Phase 2 heuristic, and "nDPI risk mask > 0".

#### 6.3 Calibrating the score to the alert threshold

The Phase 2 rule alerts at `ml_anomaly_score ≥ 0.80`. Raw LightGBM probabilities rank C2 well but rarely reach 0.80 on unseen families. So `ml_anomaly_score` is a monotone, piecewise-linear map of the probability: raw threshold *t* → 0.80, with *t* the probability at which **1 % of held-out benign flows** would alert. *t* is the median over the 5 seeds of the per-seed 1 %-FPR thresholds `[0.376, 0.451, 0.330, 0.267, 0.319]`, so **t = 0.3298**. The map is monotone, so ROC-AUC and PR-AUC are unchanged. The raw probability is stored too, as `ml_c2_proba`.

---

### 7. Cross-validation results

#### 7.1 Main result: spread over 5 seeds (calibrated LightGBM, threshold 0.80)

```text
[cv] calibrated LightGBM at 0.80 over 5 seeds (raw thresholds 0.376, 0.451, 0.330, 0.267, 0.319; median used):
  recall    mean=0.452 std=0.042 min=0.389 max=0.512
  precision mean=0.907 std=0.031 min=0.863 max=0.934
  fpr       mean=0.011 std=0.004 min=0.007 max=0.017
  roc_auc   mean=0.980 std=0.001 min=0.979 max=0.982
  pr_auc    mean=0.905 std=0.007 min=0.893 max=0.914
```

**Why a spread and not one number.** The first training runs (on data from the sensor before the §3.7 precision fix) gave a single-seed calibrated recall of 0.655. After the fix, where the inputs differed by under 1e-8 relative, the same seed gave 0.423: values that close can still fall into different LightGBM histogram bins. With only 28 malicious captures, one CV run is a noisy estimate, so the 5-seed spread above is the number to quote, and 0.655 is not.

#### 7.2 Seed 42 in detail, with baselines (all 9,597 labeled flows, out-of-fold)

```text
  score                   recall precision      FPR  ROC-AUC  PR-AUC
  lgbm_raw                 0.254     0.951   0.0031    0.979   0.893
  lgbm_calibrated          0.438     0.863   0.0163    0.979   0.893
  iforest                  0.003     0.039   0.0157    0.846   0.423
  max(lgbm_cal, iforest)   0.439     0.764   0.0319    0.924   0.664
  phase2_heuristic         0.000     0.000   0.0012    0.697   0.284
  ndpi_risk_only           0.920     0.306   0.4910    0.715   0.296
```

Raw-probability recall at fixed FPR budgets (seed 42): **0.1 % → 0.094, 0.5 % → 0.312, 1 % → 0.423, 2 % → 0.724, 5 % → 0.929**.

Readings:
- **The Phase 2 heuristic detects nothing** at 0.80 (recall 0). It was a placeholder, and the data confirms it.
- **"Any nDPI risk" fires on 49 % of benign flows**: 59.5 % of the nDPI corpus (3,474/5,839, which is dissector test material full of edge cases) and **17.7 % of real Windows background** in the MTA captures (341/1,929).
- **IsolationForest is weak** (recall 0.003, PR-AUC 0.42). Adding it to the alert score (`max`) doubles the FPR for +0.001 recall. **Decision: it's stored as `ml_iforest_score` for analysts but not used for alerting.**

#### 7.3 Where it fails (seed 42, calibrated)

Malicious captures with ≥ 1 alert: **14/28**. Benign FPR by source: MTA background 37/1,929 (1.9 %), nDPI corpus 90/5,839 (1.5 %).

| Family (flows) | Detected |
|---|---|
| Qakbot + CS (91) | 86 |
| Latrodectus (165) | 134 |
| IcedID (17) | 14 |
| Pikabot + CS (465) | 250 |
| Gozi + CS (903) | 276 |
| SSLoad + CS (12) | 7 |
| Lumma (29) / Koi (30) | 12 / 12 |
| AsyncRAT (3) / XWorm (1) | 2 / 1 |
| DarkGate (68) | 3 |
| AsyncRAT + XWorm (12) | 1 |
| Emotet (7) | 2 |
| Remcos, Redline, NetSupport, FTP/SMTP exfil, TrickBot, chisel, all DNS/ICMP tunnels | 0 |

The misses are mostly **families that appear in exactly one capture**: each tunnel type, several RATs, the exfil pair. When that capture is held out, nothing similar is left to learn from. More model tuning won't fix that; more captures per family will (§10).

#### 7.4 One variant tested (selection rule fixed in advance: higher out-of-fold PR-AUC)

| Variant | PR-AUC (5 seeds) | Recall @0.80 |
|---|---|---|
| Group-capped weights (**chosen**) | 0.905 ± 0.007 | 0.452 ± 0.042 |
| + class-balanced weights | 0.899 ± 0.007 | 0.414 ± 0.053 |

The difference is within the seed noise, so it's not evidence that one is better, only that class balancing didn't help.

#### 7.5 `is_alert` policies (out-of-fold, seed 42)

```text
  any_risk OR ml (Phase 2 spec)    recall=0.929 precision=0.307 fpr=0.4927 fpr_on_real_background=0.1799
  severe_risk OR ml                recall=0.475 precision=0.827 fpr=0.0233 fpr_on_real_background=0.0353
  ml only                          recall=0.438 precision=0.863 fpr=0.0163 fpr_on_real_background=0.0192
```

"Severe" = risks that point at known-bad infrastructure or content: suspicious DGA domain, risky domain, malicious JA4/fingerprint, malicious SHA-1 certificate, possible exploit, malware host contacted (`features.SEVERE_MASK`).

---

### 8. ONNX export and live scoring

#### 8.1 Export and parity

```text
[onnx] parity: lgbm max|diff|=3.69e-04, iforest max|diff|=3.08e-07, alert decisions differing: 0/9597
[onnx] latency (both models): batch_1_ms=2.004, batch_100_ms=5.463, batch_1000_ms=30.511
```

| File | Size | SHA-256 (prefix) |
|---|---|---|
| `models/c2_detector.onnx` (LightGBM; outputs `label`, `probabilities`) | 672 KB | `6e986f14` |
| `models/anomaly_iforest.onnx` (IsolationForest; outputs `label`, `scores`) | 1.5 MB | `66b3f164` |
| `models/model_meta.json` | — | feature list, calibrations, metrics, library versions, file hashes |

Model version string: **`lgbm+iforest-fv1-6e986f14`**. Exported with onnxmltools 1.16.0 / skl2onnx 1.20.0 (opset 15, `ai.onnx.ml` 3), trained with LightGBM 4.7.0 / scikit-learn 1.9.1, and run with onnxruntime 1.31.0.

#### 8.2 `daemon.py` integration

- `--scorer auto|onnx|heuristic` (default `auto`). `OnnxScorer` checks both files' SHA-256 and the feature list against `model_meta.json` before loading. `auto` falls back to `HeuristicScorer` (`heuristic_v1`) on any problem (missing numpy/onnxruntime, missing or tampered file, feature mismatch) and logs the reason. `onnx` fails hard instead.
- Records are validated and timestamped on arrival. **Scoring happens per batch at flush** (default 1,000 rows or 1 s). In the live run, a 1,000-row batch took 36.5–47.1 ms for feature extraction + both models on one onnxruntime thread.
- New columns: `ml_c2_proba` (raw LightGBM probability), `ml_iforest_score` (calibrated IsolationForest) and `ml_model` (scorer version). `−1` means not computed, i.e. the heuristic scorer.
- `--alert-risk-policy any|severe|none`. Default `any` keeps the Phase 2 rule exactly as specified.

#### 8.3 Schema migration

- **SQLite:** on open, missing Phase 3 columns are added with `ALTER TABLE … ADD COLUMN … NOT NULL DEFAULT …` (unit test `test_sqlite_migrates_phase2_table` builds a Phase 2 table and checks the final column list).
- **ClickHouse:** `init_clickhouse.sql` creates the columns and also contains idempotent `ALTER TABLE … ADD COLUMN IF NOT EXISTS`. The daemon runs the same `ALTER`s when ClickHouse is reachable. Applied to the running server: 26 → 29 columns; new defaults `-1`, `-1`, `''`.

#### 8.4 Recommendation for the alert rule (not applied)

For Phase 4, where alerts turn into blocks, use `--alert-risk-policy severe` or `none`. The evidence:

| Policy | False alarms, real Windows background (CV) | False alarms, holdout |
|---|---|---|
| `any` (current default) | 18.0 % | 18.3 % (91/498) |
| `severe` | 3.5 % | 1.8 % |
| `none` | 1.9 % | 0.6 % |

I left the default unchanged because the rule is your Phase 2 specification.

#### 8.5 Unit tests (`engine-ml/tests/test_daemon.py`)

```text
15 tests OK: validation (good record, extra fields, 11 rejection cases, IPv6), heuristic alert rule (4),
alert policies, calibration monotone & maps t→0.80, ONNX scores a real record, missing models → heuristic,
tampered model (1 extra byte) rejected and auto falls back, Phase 2 SQLite table migration
python3 -S (no site-packages): Ran 15 tests, OK (skipped=3) — the 3 ONNX tests skip, everything else passes
```

---

### 9. End-to-end verification

#### 9.1 Holdout: 5 never-seen infections through the full live pipeline

`python3 engine-ml/models/evaluate_holdout.py` (or `make holdout`). For each capture it:
1. starts `daemon.py` (`--scorer onnx`, real ZeroMQ via `zmq_sink`, private SQLite);
2. replays the capture with `sensor -r`;
3. sends SIGTERM to flush, reads the stored rows;
4. labels them with the same `label_flow()` used for the training set.

```text
[model] lgbm+iforest-fv1-6e986f14  alert-risk-policy=any
[2023-11-06] 404 TDS + Cobalt Strike: stored 2327/2327 flows, 2227 malicious -> ML detected 76, is_alert 2223; benign 100 -> ML false alerts 1, is_alert 30
[2023-11-20] DarkGate: stored 740/740 flows, 687 malicious -> ML detected 612, is_alert 687; benign 50 -> ML false alerts 0, is_alert 10
[2024-02-21] SocGholish + AsyncRAT: stored 28/28 flows, 11 malicious -> ML detected 5, is_alert 9; benign 12 -> ML false alerts 0, is_alert 4
[2025-08-15] Lumma Stealer + SectopRAT: stored 152/152 flows, 148 malicious -> ML detected 15, is_alert 48; benign 4 -> ML false alerts 0, is_alert 3
[2025-12-29] ClickFix + NetSupport RAT: stored 345/345 flows, 11 malicious -> ML detected 4, is_alert 5; benign 332 -> ML false alerts 2, is_alert 44

[holdout] 3582 labeled flows (3084 malicious) from 5 captures
  ml (ml_anomaly_score >= 0.80)    recall=0.231 precision=0.996 fpr=0.006 captures_detected=5/5
  severe_risk OR ml                recall=0.231 precision=0.988 fpr=0.018 captures_detected=5/5
  any_risk OR ml (Phase 2 rule)    recall=0.964 precision=0.970 fpr=0.183 captures_detected=5/5
  phase2_heuristic >= 0.80         recall=0.000 precision=n/a fpr=0.000 captures_detected=0/5
  malicious endpoints with >= 1 ML alert: 15/23
```

**Per malicious endpoint** (what an IP blocker acts on):

```text
2023-11-06 404 TDS + Cobalt Strike
   170.130.55.150   flows= 2212 alerted=  65 max=0.978 80/HTTP        (Cobalt Strike, IOC)
   170.130.55.117   flows=    8 alerted=   8 max=0.984 443/TLS,8080/TLS (follow-up C2)
   201.148.107.213  flows=    2 alerted=   0 max=0.012 443/TLS        (404 TDS redirect)
   193.3.19.230     flows=    1 alerted=   1 max=0.859 80/HTTP
   65.108.196.140   flows=    1 alerted=   0 max=0.014 443/TLS        (404 TDS redirect)
   170.130.165.37   flows=    1 alerted=   1 max=0.977 80/HTTP        (RClient.dll download)
   170.130.165.107  flows=    1 alerted=   0 max=0.018 1444/Unknown   (remote-access TCP)
   170.130.55.46    flows=    1 alerted=   1 max=0.997 80/HTTP        (initial C2)
2023-11-20 DarkGate
   188.246.224.221  flows=  684 alerted= 609 max=0.971 2351/HTTP,8080/HTTP_Proxy (DarkGate C2)
   45.154.98.21     flows=    3 alerted=   3 max=0.998 80/HTTP        (AutoIt payload)
2024-02-21 SocGholish + AsyncRAT
   5.161.113.150    flows=    6 alerted=   3 max=0.970 25658/TLS      (AsyncRAT C2)
   66.135.17.87     flows=    2 alerted=   0 max=0.071 443/TLS        (SocGholish fake update)
   45.59.170.106    flows=    1 alerted=   1 max=0.998 443/TLS
   49.13.65.235     flows=    1 alerted=   0 max=0.747 80/HTTP
   167.71.107.109   flows=    1 alerted=   1 max=0.951 80/HTTP
2025-08-15 Lumma Stealer + SectopRAT
   5.10.250.239     flows=  136 alerted=   4 max=0.961 443/TLS,9000/HTTP (SectopRAT C2)
   185.95.159.55    flows=   10 alerted=  10 max=0.994 443/TLS        (Lumma C2)
   104.21.24.30     flows=    2 alerted=   1 max=0.941 443/TLS
2025-12-29 ClickFix + NetSupport RAT
   45.93.20.50      flows=    4 alerted=   0 max=0.403 443/TLS
   65.181.111.158   flows=    2 alerted=   0 max=0.037 443/TLS
   80.253.249.145   flows=    2 alerted=   2 max=0.998 80/HTTP        (ClickFix payload)
   185.39.19.96     flows=    2 alerted=   2 max=0.985 443/HTTP       (NetSupport C2)
   104.21.96.46     flows=    1 alerted=   0 max=0.127 443/HTTP
```

Readings:
- **Every C2 server named in the five IOC write-ups got at least one alert**, including SectopRAT, a family absent from training.
- **The misses are mostly delivery and redirect infrastructure over HTTPS** (404 TDS redirectors, the SocGholish fake-update host, ClickFix lure pages), plus one raw-TCP remote-access channel on port 1444.
- **Flow-level recall (23 %) understates detection.** It is dominated by repetitive beacons, e.g. 65 of the 2,212 Cobalt Strike HTTP flows. For blocking, one alert per C2 IP is enough.
- **Of the 3 false alerts,** 2 go to Microsoft (`13.107.213.57`, `20.190.135.18`) and 1 is `10.11.7.120 → 10.11.7.17:5985` (WinRM to the domain controller). The MTA write-up lists that last one under traffic from the infected host, so it is probably lateral movement that my IP-based labels count as benign.

#### 9.2 Final live run into the main stores

Fresh SQLite, ClickHouse `network_flows` truncated, `daemon.py --backend both --scorer onnx` running in the background, then the 6 Phase 2 PCAPs + the 5 holdout PCAPs via `sensor -r`:

```text
sensor -r test_dns.pcap: exit=0 exported=1 dropped=0
... (11 PCAPs, all exit=0 dropped=0)
sensor -r 2025-12-29-ClickFix-page-sends-NetSupportRAT.pcap: exit=0 exported=345 dropped=0
daemon exit: 0 ; sensor total exported: 3604
[daemon] scorer: lgbm+iforest-fv1-6e986f14  alert-risk-policy: any
[daemon] transport=zmq_sink endpoint=ipc:///tmp/ndpi_flows.sock backends=sqlite,jsonl,clickhouse ready
[daemon] flushed 13 rows -> sqlite,jsonl,clickhouse (scored in 24.4 ms; alerts=8; total accepted=13 rejected=0)
[daemon] flushed 1000 rows -> sqlite,jsonl,clickhouse (scored in 47.1 ms; alerts=939; total accepted=1013 rejected=0)
[daemon] flushed 1000 rows -> sqlite,jsonl,clickhouse (scored in 36.5 ms; alerts=991; total accepted=2013 rejected=0)
[daemon] flushed 1000 rows -> sqlite,jsonl,clickhouse (scored in 41.3 ms; alerts=954; total accepted=3013 rejected=0)
[daemon] flushed 591 rows -> sqlite,jsonl,clickhouse (scored in 45.9 ms; alerts=184; total accepted=3604 rejected=0)
[daemon] stopped: accepted=3604 rejected=0 clickhouse_failed=0
SQLite rows: 3604  JSONL lines: 3604  ClickHouse rows: 3604
```

`query_dashboard.py` (5 panels) on both stores:

```text
SentinelFlow Phase 2/3 — SQLite engine-ml/data/sentinel_flows.db
flows=3604  is_alert=1: 3076  ndpi_risk_mask>0: 3061  timestamp mismatches: 0  ml_score>=0.80: 722  scorer: lgbm+iforest-fv1-6e986f14
SQLite vs ClickHouse: all 5 panel tables identical (6834 table lines)
```

Panel 5 (top 15 by `ml_anomaly_score`; SQL shown with `--show-sql`):

```text
| flow                              | app_protocol | ja4_client                           | score | c2_proba | iforest | is_alert |
| 10.2.21.101 -> 45.59.170.106:443  | TLS          | t12d190800_d83cc789557e_7af1ed941c26 | 0.998 | 0.993    | 0.239   | 1        |
| 10.11.7.120 -> 45.154.98.21:80    | HTTP         | N/A                                  | 0.998 | 0.993    | 0.534   | 1        |
| 10.12.29.101 -> 80.253.249.145:80 | HTTP         | N/A                                  | 0.998 | 0.992    | 0.613   | 1        |
| 10.11.7.120 -> 170.130.55.46:80   | HTTP         | N/A                                  | 0.997 | 0.989    | 0.454   | 1        |
| 10.8.15.176 -> 185.95.159.55:443  | TLS          | t13d201200_2b729b4bf6f3_e24568c0d440 | 0.994 | 0.979    | 0.739   | 1        |
| ...                                                                                                                      |
| 10.11.7.120 -> 10.11.7.17:5985    | Unknown      | N/A                                  | 0.992 | 0.975    | 0.08    | 1        |
| 10.12.29.101 -> 13.107.213.57:443 | TLS          | N/A                                  | 0.992 | 0.973    | 0.0     | 1        |
```

`is_alert = 3076 / 3604` reflects the default `any` risk policy (3,061 flows carry some nDPI risk); `ml_score ≥ 0.80` is 722.

#### 9.3 Grafana

All 5 provisioned panel queries were sent through `POST /api/ds/query`:

```text
[piechart] Protocol Distribution: status=200 rows=29
[timeseries] Traffic Volume (bytes per capture second): status=200 rows=2785
[table] JA4 TLS Fingerprints (with ML score): status=200 rows=16
[table] High-Risk Flows (alerts): status=200 rows=500
[table] ML Detections (ml_anomaly_score >= 0.80): status=200 rows=27
```

![Grafana dashboard after Phase 3](part3_grafana.png)

The screenshot (headless Chromium) shows the known C2 endpoints at the top of the JA4, alert and ML-detection tables.

#### 9.4 Zero-dependency path still works

```text
$ python3 -S engine-ml/daemon.py -e ipc://…/z.sock --backend sqlite …     (no numpy/onnxruntime visible)
[daemon] scorer: ONNX unavailable (ModuleNotFoundError: No module named 'numpy'); using heuristic_v1
[daemon] flushed 8 rows -> sqlite,jsonl (scored in 0.1 ms; alerts=2; total accepted=8 rejected=0)
sqlite: 8 | heuristic_v1 | ml_c2_proba min/max -1.0/-1.0
```

---

### 10. Findings and next steps

1. **The alert rule matters more than the model for Phase 4.** "Any nDPI risk" flags 18 % of real host traffic. Use `severe` or `none` before connecting alerts to nftables/XDP (§8.4).
2. **Data diversity is the limiting factor.** 28 malicious captures with a heavy tail (Gozi + Pikabot = 75 % of malicious flows); most families appear once. The next gain comes from more captures per family: more MTA cases, Stratosphere CTU captures, CIC-IDS. The pipeline handles that with `fetch_mta.py` + `make phase3`.
3. **The model detects C2 servers, not every flow** (holdout 15/23 endpoints, 5/5 infections, 23 % flow recall). An endpoint-level aggregation, e.g. "alert on an IP after k scored flows", would suit Phase 4 better than per-flow decisions.
4. **IsolationForest adds noise.** Keep it informational, or replace it with a better-specified anomaly model.
5. **No active timeout in the sensor.** A flow is exported only when it ends or idles 30 s, so a long-lived C2 session is scored only when it closes. An active timeout (e.g. export a snapshot every 60 s) would let Phase 4 react during the session.
6. **Labels are IP-level.** Domains on shared Cloudflare IPs over-label; attacker activity to internal hosts (the WinRM case) under-labels.

---

### 11. What may and may not be said

**May be said (observed in this session):**
- The sensor builds clean under `-Wall -Wextra -Wpedantic`. With ASan + LSan + UBSan it produced 0 reports over 16 PCAPs (1,890 flows), and LSan was shown to be active.
- The sensor exports flows after 30 s idle (synthetic test), captures live on `lo`, flushes all flows on SIGINT, and runs at ~0.40–0.44 Mpps offline on 124,070 packets with 25.8 MB peak RSS.
- The seven sensor fixes and the sink fix in §3 each have before/after evidence, and each fix that changes behavior has a regression test that fails on the old binary.
- 9,659 labeled flows were produced through the production sensor → ZMQ path, with 0 drops and 0 validation rejects, and are stored in SQLite, JSONL and ClickHouse.
- With grouped 5-fold CV over 5 seeds, calibrated LightGBM at 0.80 reaches recall 0.45 ± 0.04, precision 0.91 ± 0.03 and FPR 1.1 % ± 0.4 % (ROC-AUC 0.980).
- ONNX outputs match the native models on all 9,597 labeled flows (0 differing alert decisions).
- On 5 held-out infections replayed through the live pipeline, the model alerted on all 5 captures and 15 of 23 malicious endpoints, with 3 false alerts out of 498 benign flows.
- The daemon scores 1,000-flow batches in 36–47 ms and falls back to the heuristic without numpy/onnxruntime.

**Must not be said (not shown):**
- **Detection rates outside this data.** That it detects "Cobalt Strike" or "C2" in general, or on real enterprise networks. All malicious traffic and most benign background comes from MTA lab captures and the nDPI test corpus, and the holdout is only 5 captures from the same source.
- **Robustness on rare families.** The per-family results in §7.3 show 0 detections for most single-capture families.
- **That the 1 % FPR operating point holds on new traffic.** It was set on out-of-fold predictions; the holdout's 0.6 % is one more sample, not a guarantee.
- **That `pyzmq` ingestion works.** It is still untested; pyzmq isn't installed.
- **Live-capture throughput, or behavior at line rate.** Only offline throughput was measured.
- **Mid-run ClickHouse failover or re-attach.** Still not tested (as in Part 2).
- **That the models are reproducible bit-for-bit.** Two early training runs on identical data gave identical metrics but different `c2_detector.onnx` hashes (`8b51f326` vs `384d2ee4`). Bit-for-bit reproducibility was not shown; only the metric spread in §7.1 was.
- **Anything about Phase 4 (mitigation) or Phase 5 (demo).** Not started.

---

### 12. Reproduce

```bash
cd /home/joe/cv_work/sentinel-flow
make sensor && make test-sensor && make test-engine            # Phase 1 + daemon tests
docker compose up -d                                            # ClickHouse + Grafana (optional)
python3 -m venv --system-site-packages engine-ml/.venv-train
engine-ml/.venv-train/bin/pip install -r engine-ml/requirements-train.txt
make fetch-data          # 17 training + 5 holdout MTA cases (PCAP + IOC text only)
make dataset             # sensor -> ZMQ -> labeled rows (JSONL, SQLite, ClickHouse)
make train               # grouped CV (5 seeds), calibration, ONNX export, parity
make holdout             # 5 unseen captures through the live daemon
python3 engine-ml/daemon.py --backend both &                    # live scoring
LD_LIBRARY_PATH=~/nDPI/src/lib ./sensor-c/build/sensor -r capture.pcap
python3 engine-ml/query_dashboard.py --backend clickhouse        # or open http://127.0.0.1:3000
```

### 13. Files changed in this session

| Area | Files |
|---|---|
| Sensor (modified) | `sensor-c/src/main.c` (alignment, timestamps, link types, drop counting, drain), `ndpi_wrapper.{c,h}` (JA4 gate + validation), `zmq_publisher.{c,h}` (patience, monitor-based linger), `zmq_sink.c` (`RCVHWM=0`), `zmq.h` (monitor declarations), `cJSON.c` (`%.15g`) |
| Sensor (new) | `sensor-c/tests/test_sensor_pcaps.py` |
| Engine (modified) | `engine-ml/daemon.py` (ONNX scorer, fallback, batching, new columns, migrations, alert policy, pyzmq `RCVHWM`), `engine-ml/query_dashboard.py` (panel 5, summary), `engine-ml/sql/init_clickhouse.sql`, `engine-ml/requirements.txt` |
| Engine (new) | `engine-ml/features.py`, `engine-ml/models/{build_dataset,train_pipeline,evaluate_holdout}.py`, `engine-ml/models/{c2_detector,anomaly_iforest}.onnx`, `model_meta.json`, `evaluation.json`, `evaluation_holdout.json`, `evaluation_variant_class_balance.json`, `engine-ml/datasets/{fetch_mta.py,mta_labels.json,mta_holdout_labels.json}`, `engine-ml/requirements-train.txt`, tests in `engine-ml/tests/test_daemon.py` |
| Dashboards | `dashboard/grafana/dashboards/sentinelflow.json` (JA4 panel with ML score, alert columns, panel 5), `docker-compose.yml` (unchanged since Part 2), `docs/part3_grafana.png` |
| Repo | `Makefile` (`test-sensor`, `fetch-data`, `dataset`, `train`, `holdout`, `phase3`), `.gitignore` (downloaded malware PCAPs, training venv), `README.md` (status line) |

Downloaded captures (`engine-ml/datasets/mta*/`) and the training virtualenv are git-ignored. Nothing has been committed.


---

<a id="part-4"></a>

## Part 4: Active Mitigation (nftables), Active Flow Timeout, Blocking Policy

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Tree:** `/home/joe/cv_work/sentinel-flow/`
**Date:** 2026-10-23
**Host:** Kali Linux 6.16.8, nftables 1.1.3, iproute2 6.16.0, clang 19.1.7, Python 3.14.7
**Status:**
- Done and tested: active flow timeout in the sensor, the blocking policy, the mitigator (dry-run and nftables backends, audit trail), daemon integration, and the 6th dashboard panel.
- nftables enforcement was verified on real packets in throwaway network namespaces, with the block placed directly through `Mitigator`.
- **The fully automatic closed loop** (capture → daemon → automatic nft block → kernel drops) passed all 5 checks in `tests/verify_closed_loop.sh` (§7.2, run 2; run 1 failed on an environment issue that was fixed, §7.1).
- **XDP enforcement is not done** (§6).

> [!info] Claim discipline
> Same rule as Part 1 §12, Part 2 §10 and Part 3 §11: a statement is made only if the output that supports it was captured in this session and is quoted here. §9 lists what was not shown.

---

### 0. Summary

| Item | Result |
|---|---|
| Sensor active timeout `-A <sec>` (default 60, `0` = off) | Long-lived flows get a cumulative snapshot record every `<sec>` s while still active. `-A 0` output is byte-identical to the Part 3 sensor on the 9-PCAP regression set and has the same flow count on all 577 Ethernet corpus captures. 4 new sensor tests; the sensor suite passes 10/10. |
| Offline idle-expiry finding | Documented, not changed (§1.3): offline idle expiry runs only every 1,000 packets, so small captures never idle-expire. |
| Blocking policy (`BlockPolicy`) | Blocks only when `ml_anomaly_score ≥ 0.80` from a trained model, or when a severe nDPI risk is present. Targets the remote peer; never RFC 1918 (default), loopback, link-local, multicast, unspecified, reserved, or allowlisted addresses. `--allowlist-file` added. |
| `mitigator.py` | `dry-run` and `nftables` backends; audit trail in JSONL, SQLite (`mitigation_events`, `blocked_ips`) and ClickHouse (`sentinel.mitigations`); CLI. **18/18 unit tests.** |
| nftables on real packets (namespace lab) | Blocked peer: **0/50 delivered**, nft counter **50 packets / 6,400 bytes** (exact). Benign peer: **50/50 delivered**. 3 s expiry and manual unblock both work. |
| Daemon `--mitigate dry-run` on the 11 Part 3 captures | 24 blocks + 7 protected skips = **31 events, identical in JSONL, SQLite and ClickHouse**. Panel 6 shows 24 rows in `query_dashboard.py` (SQLite and ClickHouse identical) and Grafana (HTTP 200, 24 rows). |
| Threshold × risk-policy table | Holdout at 0.80 + `severe`: **16/23 malicious endpoints, 2/61 benign endpoints blocked, 5/5 infections** (§5). |
| Automatic closed loop with nftables | Run 1 failed: the daemon couldn't import `onnxruntime` under `sudo` (§7.1). After the fix, **run 2 passed all 5 checks** (§7.2): capture replay → ONNX score 0.991 → automatic nft block of `45.154.98.21`; then 0/50 delivered from it (counter exactly 50 pkts / 6,400 B) while the normal peer got 50/50. |
| XDP | Both provided sources compile; attaching failed in libbpf. **Not done** (§6). |

---

### 1. Sensor: active flow timeout (`-A`)

#### 1.1 Behavior

- `-A <sec>` (default **60**, `0` disables, valid 0–86400). A flow that is **still active** (seen within the 30 s idle timeout) and hasn't produced a record for `<sec>` seconds gets a **snapshot**: the same 23-field JSON, cumulative since `first_seen_us`. The flow stays in the table, and its final record follows when it ends (idle expiry or shutdown).
- Snapshots are checked every 1 s of packet time, **before** the current packet joins its flow. A flow that was idle before this packet is never snapshotted.
- During live capture (`-i`), the same check also runs on the wall clock when no packets arrive, together with idle expiry. Before this change, live capture never expired flows while traffic was quiet.
- A flow can therefore appear several times downstream (same 5-tuple and `first_seen_us`, growing `pkt_count` / `last_seen_us`). The summary prints `Snapshot records: N`.
- The Phase 3 tools pin **`-A 0`**: `build_dataset.py` and `evaluate_holdout.py` pass it explicitly. That keeps the training set and holdout evaluation on the flow definition the models were trained on.

#### 1.2 Evidence

```text
sensor -h:
  -A <sec>        Active timeout: also export a snapshot of flows
                  still active after <sec> s, then every <sec> s
                  (default 60, 0 = off; idle timeout is 30 s)

9-PCAP set, -A 0: byte-identical to the Part 3 sensor (38 flows)
9-PCAP set, -A 60: 49 records
corpus, Part 3 sensor: {"records": 9738, "snapshots": 0}
corpus, new -A 0:      {"records": 9738, "snapshots": 0}
corpus, new -A 60:     {"records": 10937, "snapshots": 1199}
files whose flow count differs (-A 0 vs Part 3 sensor): 0
ASan/LSan/UBSan with -A 30 on 10 PCAPs: 0 errors
```

New tests in `sensor-c/tests/test_sensor_pcaps.py`:

| Test | What it proves |
|---|---|
| `test_active_timeout_snapshots` | A packet every 10 s for 150 s: default `-A 60` gives `pkt_count` `[6, 12, 16]` with one shared `first_seen_us` and `last_seen_us` at t = 50 / 110 / 150 s. `-A 0` gives `[16]`. `-A 30` gives `[3, 6, 9, 12, 15, 16]`. |
| `test_no_snapshot_of_idle_flow` | Two packets 5,000 s apart: one record, no snapshot. |
| `test_active_timeout_rejects_bad_values` | `-A abc`, `-A -5`, `-A 100000` → exit 1. |
| (unchanged) `test_long_flow_duration_keeps_microseconds` | Passes in its original Part 3 form. |

```text
Ran 10 tests in 12.132s
OK
test_flow: 13 passed, 0 failed     test_stats: 24 passed, 0 failed
```

#### 1.3 Finding (documented, not changed): offline idle expiry only every 1,000 packets

When reading a file (`-r`), idle expiry runs only at every 1,000th IPv4 packet, which is unchanged since Phase 1. **A capture with fewer than 1,000 packets never idle-expires**, so a 30 s gap doesn't split a flow. Examples:

- `test_dns.pcap`: its DNS flow has a 40.8 s gap and is reported as one 3-packet flow.
- `tplink_shp.pcap`: 8 flows would be 251 with per-second expiry checks.

An experimental build that also expired idle flows on a 1 s packet-time clock changed **93 of 577** corpus files, turning 9,738 flows into 11,258. Because that would change the Part 1–3 evidence, the training set and the models, the behavior was **kept as is**. Live capture is not affected: it now expires on the wall clock. Fixing offline mode means rebuilding the dataset and retraining (`make phase3`).

---

### 2. Blocking policy (`engine-ml/mitigator.py`, `BlockPolicy`)

- **Trigger:** either of
  - `ml_anomaly_score ≥ threshold` (default 0.80), but only when `ml_model` is a trained model. Records scored by `heuristic_v1` never block.
  - `ndpi_risk_mask & features.SEVERE_MASK` (suspicious DGA, risky domain, malicious fingerprint, malicious SHA-1 certificate, possible exploit, malware host contacted), unless `--no-severe-risk-blocks`.

  No other nDPI risk blocks on its own: "any risk" alerted on ~18 % of real Windows background flows in Part 3 (§8.4).
- **Target:** the responder (`dst_ip`) unless it's protected, then `src_ip`. If both are protected, nothing is blocked and a `skip_protected` event is logged.
- **Never blocked:**

| Rule | Configurable? |
|---|---|
| loopback, link-local, multicast, unspecified, reserved, 255.255.255.255 | always; cannot be disabled |
| RFC 1918 + 127.0.0.0/8 | default `--protected-cidr`; `--allow-private-blocks` drops RFC 1918 (lab only) |
| `--allowlist` IPs/CIDRs and **`--allowlist-file`** (one IP/CIDR per line, `#` comments; an invalid line is an error naming file and line) | yes |
| non-IPv4 | always (the sensor and the set are IPv4) |

#### 2.1 Cloud/CDN allowlist recommendation

The built-in list is deliberately minimal, so the holdout numbers in §5 aren't flattered by a hand-made allowlist. In the Part 3 data, the policy would also block a Cloudflare address serving `api.ipify.org` (`172.67.74.152`) and two Microsoft addresses (`13.107.213.57` / azureedge.net, `20.190.135.18` / login.live.com). Blocking shared cloud or CDN addresses cuts off unrelated services behind them. Before using `--mitigate nftables` on a real host, **provide an `--allowlist-file` with the cloud/CDN/SaaS ranges the site depends on** (from the providers' published range lists), and keep the default 15-minute block timeout.

#### 2.2 Unit tests (`engine-ml/tests/test_mitigator.py`): 18/18

```text
Policy: blocks remote C2 not victim; inbound flow blocks the other side; threshold inclusive (0.80 blocks,
0.7999 doesn't); heuristic scores never block; only the 6 severe risks block without ML; both-private skipped;
--allow-private-blocks; special addresses always protected; allowlist + custom protected CIDRs;
--allowlist-file (incl. error on a bad line); IPv6 never blocked
Mitigator: one block per IP; benign/heuristic records do nothing; protected skip audited; backend error
logged not raised; counters + expiry events and re-block after expiry; SQLite state table; CLI refuses
a protected IP
Ran 18 tests in 0.051s
OK
```

---

### 3. `mitigator.py` backends, audit trail, daemon integration

#### 3.1 Backends

| Backend | Kernel state |
|---|---|
| `dry-run` | none; in-memory record of what would be blocked |
| `nftables` | its own table only, `inet sentinel` (other tables are never modified): set `blocked_ipv4 { type ipv4_addr; flags timeout; timeout 15m; counter; }`; `prerouting` (priority raw) drops `ip saddr @blocked_ipv4`; `output` and `forward` drop `ip daddr @blocked_ipv4`. Each element carries its own packet/byte counter. `--mitigate-netns` applies it inside a network namespace. |

CLI: `python3 engine-ml/mitigator.py [--backend nftables|dry-run] [--netns NS] [--allowlist-file F] setup|list|block IP|unblock IP|teardown`. `block` refuses protected addresses.

#### 3.2 Audit trail

Every event (`block`, `unblock`, `expire`, `counters`, `skip_protected`, `error`) is written to:
- `engine-ml/data/mitigations.jsonl`
- SQLite `mitigation_events`, plus `blocked_ips` (current state per IP)
- ClickHouse `sentinel.mitigations` (DDL in `engine-ml/sql/init_clickhouse.sql`; created on demand)

Kernel counters are read every 10 s, and on exit.

#### 3.3 Daemon

`daemon.py --mitigate none|dry-run|nftables` (default `none`), plus `--mitigate-netns`, `--block-timeout` (900 s), `--protected-cidr`, `--allow-private-blocks`, `--allowlist`, `--allowlist-file`, `--no-severe-risk-blocks`, `--mitigations-jsonl`. Each scored batch is passed to the mitigator after it's written to storage. On exit, active blocks are **left in place** until their timeout.

---

### 4. Verification on real packets and data

#### 4.1 nftables backend in a namespace lab (`engine-ml/tests/lab_nftables_netns.py`)

Namespaces `sf_victim` (`192.168.50.10`) and `sf_remote` (`203.0.113.66` blocked peer, `203.0.113.10` benign peer), joined by a veth pair. The block was placed by `Mitigator.process()` from a synthetic scored record (`ml_anomaly_score 0.97`). Captured output:

```text
[baseline] received at victim: {'203.0.113.66': 50, '203.0.113.10': 50}
[block] events: [('block', '203.0.113.66', 'ml_score')]
[block] nft set: {'203.0.113.66': {'expires_s': 899, 'packets': 0, 'bytes': 0}}
[inbound] sent 50 from each; received at victim: {'203.0.113.10': 50}; nft counter for 203.0.113.66: packets=50 bytes=6400 (expected 50 and 6400)
[outbound] victim->203.0.113.66: send failed=True ['PermissionError: [Errno 1] Operation not permitted']; victim->203.0.113.10: send failed=False; nft counter now packets=51 bytes=6528
[expiry] 3 s block on 203.0.113.10: received during={} after={'203.0.113.10': 50}; set now: ['203.0.113.66']
[unblock] unblock 203.0.113.66 final dropped_pkts=51 bytes=6528; received after unblock: {'203.0.113.66': 50}
[events] block:203.0.113.66, counters:203.0.113.66, expire:203.0.113.10, unblock:203.0.113.66
[cleanup] lab namespaces remaining: []
```

6,400 bytes = 50 × (20 IP + 8 UDP + 100 payload). The outbound send fails on its first packet (`EPERM` from the local nft drop), so one packet was counted. The host's own ruleset was unchanged afterwards (`table ip nat / ip filter / ip6 nat / ip6 filter` only).

#### 4.2 Dry run on the 11 Part 3 captures, with Panel 6

Same captures as the Part 3 final run, `sensor -r … -A 0` → `daemon.py --backend both --scorer onnx --mitigate dry-run`:

```text
[daemon] mitigation: backend=dry-run timeout=900s protected=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8 allowlist=none sinks=JsonlEventSink,SqliteEventSink,ClickHouseEventSink
[daemon] mitigation: {'blocks': 24, 'skips_protected': 7, 'errors': 0}; active blocks left in place: 24 (they expire after --block-timeout)
flows: SQLite 3604  ClickHouse 3604
mitigation events: jsonl 31  SQLite 31  ClickHouse 31
SQLite vs ClickHouse: all 6 panels identical
```

Panel 6, "Active Kernel Mitigations & XDP Drop Counters", is in `query_dashboard.py` (SQLite `blocked_ips` / ClickHouse `sentinel.mitigations`, same columns and order) and in Grafana (same SQL as `query_dashboard.py`):

```text
[table] Active Kernel Mitigations & XDP Drop Counters: status=200 rows=24 fields=['ip', 'backend', 'status', 'reason', 'score', 'flow', 'dropped_pkts', 'dropped_bytes', 'first_blocked']
```

Of the 24 dry-run blocks:

| Group | Count |
|---|---|
| Labeled malicious holdout endpoints | 16 (15 via ML score, 1 via severe risk: `49.13.65.235`, suspicious DGA) |
| Endpoints from nDPI's `malware.pcap` | 3 |
| Shared services the malware used (labeled ambiguous) | 3: `psiewdr.org`, `checkip.dyndns.org`, `api.ipify.org` on Cloudflare |
| Microsoft false positives | 2: `13.107.213.57`, `20.190.135.18` |

No private address was selected.

---

### 5. Threshold × risk-policy comparison (read-only, `engine-ml/models/threshold_table.py`)

`BlockPolicy` was replayed over predictions already saved in Part 3; nothing was retrained or rescored. An endpoint is a (capture, remote IP) pair, as the policy would pick it.
- **Caught:** a malicious endpoint (remote IP of a label-1 flow) that gets blocked.
- **False block:** a blocked endpoint seen only in label-0 flows.
- Ambiguous flows are excluded.

**Holdout:** 5 never-trained captures; 3,592 stored flows from the Part 3/4 live run, assigned to captures by capture time and labeled with `mta_holdout_labels.json`.

| Threshold | Risk policy | Malicious endpoints caught | Benign endpoints blocked | Infections with ≥ 1 block |
|---|---|---|---|---|
| 0.70 | none | 16 / 23 (69.6 %) | 2 / 61 (3.3 %) | 5 / 5 |
| 0.70 | severe | 16 / 23 (69.6 %) | 2 / 61 (3.3 %) | 5 / 5 |
| 0.80 | none | 15 / 23 (65.2 %) | 2 / 61 (3.3 %) | 5 / 5 |
| **0.80** | **severe** | **16 / 23 (69.6 %)** | **2 / 61 (3.3 %)** | **5 / 5** |
| 0.90 | none | 14 / 23 (60.9 %) | 2 / 61 (3.3 %) | 5 / 5 |
| 0.90 | severe | 15 / 23 (65.2 %) | 2 / 61 (3.3 %) | 5 / 5 |

**Cross-validation:** seed 42 out-of-fold predictions, 9,597 flows, 28 training captures (23 of them have a non-protected malicious endpoint).

| Threshold | Risk policy | Malicious endpoints caught | Benign endpoints blocked | Captures with ≥ 1 block |
|---|---|---|---|---|
| 0.70 | none | 65 / 91 (71.4 %) | 113 / 2,459 (4.60 %) | 14 / 23 |
| 0.70 | severe | 67 / 91 (73.6 %) | 123 / 2,459 (5.00 %) | 16 / 23 |
| 0.80 | none | 63 / 91 (69.2 %) | 51 / 2,459 (2.07 %) | 14 / 23 |
| **0.80** | **severe** | **65 / 91 (71.4 %)** | **61 / 2,459 (2.48 %)** | **16 / 23** |
| 0.90 | none | 60 / 91 (65.9 %) | 21 / 2,459 (0.85 %) | 13 / 23 |
| 0.90 | severe | 62 / 91 (68.1 %) | 35 / 2,459 (1.42 %) | 15 / 23 |

Readings:
- **On the holdout, the threshold barely matters for false blocks:** both are the Microsoft addresses, which scored ≥ 0.99. The threshold mainly trades away caught endpoints.
- **In CV, the threshold is the main lever on false blocks:** 113 → 51 → 21 from 0.70 to 0.90 (`none`).
- **`severe` adds 2 caught endpoints and 2 captures** at a cost of 10–14 extra false blocks in CV.
- **The default stays at 0.80 + `severe`.** 0.90 + `none` is the more conservative option when false blocks matter more than coverage.
- **These are small samples:** 23 holdout endpoints, and one CV seed. Part 3 §7.1 showed CV metrics varying noticeably across seeds.

---

### 6. XDP: not done

- **Sources:** `mitigation-ebpf/xdp_blocker.bpf.c` and `mitigation-ebpf/xdp_ctl.c` were provided by the project owner and reviewed before use. The program drops IPv4 packets whose source or destination is in the `blocked_ips` map and counts drops per entry. `xdp_ctl` manages a map pinned at `/sys/fs/bpf/sentinel_blocked_ips` (`init`, `add`, `del`, `list`, `teardown`).
- **Build:** `clang -O2 -g -target bpf -c xdp_blocker.bpf.c -o xdp_blocker.bpf.o` and `gcc -O2 -Wall -Wextra -o xdp_ctl xdp_ctl.c` both succeeded with no warnings. The object has the `xdp`, `.maps`, `license`, `.BTF` and `.relxdp` sections.
- **Attach attempt:** in a throwaway namespace, `ip link set dev veth-v xdpgeneric obj xdp_blocker.bpf.o sec xdp` failed:
  ```text
  libbpf: map 'blocked_ips': attr 'type': expected PTR, got int.
  ERROR: opening BPF object file failed
  ```
  Nothing was attached, and the namespace was deleted.
- **What's needed:**
  - libbpf (used by iproute2 1.6.2 here) doesn't accept the map definition in `xdp_blocker.bpf.c`; the program's map definition has to change.
  - Even once it loads, the map the program uses has to be the **same** map `xdp_ctl` pins at `/sys/fs/bpf/sentinel_blocked_ips`. Otherwise entries added with `xdp_ctl` won't affect packets.

  Both are left to the project owner. No `xdp` backend was added to `mitigator.py`, and no XDP result is claimed.

---

### 7. Automatic closed loop with nftables

`tests/verify_closed_loop.sh` (run as root, or it re-runs itself with `sudo`):

1. Creates namespaces `sf_host` (`192.168.50.10`) and `sf_peer` (`flagged_peer` = `45.154.98.21`, `normal_peer` = `203.0.113.10`), joined by a veth pair, and runs a baseline wave.
2. **Wave 1:** starts `daemon.py --scorer onnx --mitigate nftables --mitigate-netns sf_host`, then replays `2023-11-20-DarkGate-infection-traffic.pcap` with `sensor -r … -A 0`. It waits until `flagged_peer` appears in `sf_host`'s nft set. In Part 3 this capture's flows to `45.154.98.21` scored up to 0.998.
3. **Wave 2:** sends 50 UDP packets (100-byte payload) from each peer to a listener in `sf_host`, and reads the nft counter before and after.
4. Waits 11 s for the daemon's counter refresh, stops it, and prints the audit rows for `flagged_peer`.
5. Prints PASS/FAIL for: block present after wave 1; 0/50 delivered from `flagged_peer`; 50/50 delivered from `normal_peer`; counter delta = 50 packets and 6,400 bytes.
6. Deletes both namespaces on exit, even on failure. Outputs stay in `/tmp/sf_closed_loop.*`.

Static check: `bash -n tests/verify_closed_loop.sh` → syntax ok (`shellcheck` not installed).

#### 7.1 Run 1 (2026-10-23, run by the project owner): failed, the daemon never started

```text
[verify] namespaces sf_host (192.168.50.10) <-> sf_peer (flagged_peer=45.154.98.21, normal_peer=203.0.113.10)
[verify] baseline (no blocks): received at host: {"45.154.98.21": 50, "203.0.113.10": 50}
[verify] wave 1: sensor -r 2023-11-20-DarkGate-infection-traffic.pcap -A 0
   Packets processed: 9961
   Flows exported: 740
   Flows dropped: 0
[verify] nft set in sf_host after wave 1:
Error: No such file or directory
list set inet sentinel blocked_ipv4
              ^^^^^^^^
[verify] counter for flagged_peer before wave 2: absent
[verify] wave 2: sent 50 from each peer; received at host: {"45.154.98.21": 50, "203.0.113.10": 50}
[verify] counter for flagged_peer after wave 2: absent
tests/verify_closed_loop.sh: line 159: kill: (346768) - No such process
[verify] cleanup: namespaces removed: 0 left; outputs kept in /tmp/sf_closed_loop.7rwCV1
```

`/tmp/sf_closed_loop.7rwCV1/daemon.log`:

```text
  File "/home/joe/cv_work/sentinel-flow/engine-ml/daemon.py", line 202, in __init__
    import onnxruntime as ort
ModuleNotFoundError: No module named 'onnxruntime'
```

**What happened.** Under `sudo`, `/usr/bin/python3` can't import `onnxruntime`. With `--scorer onnx` (fail instead of falling back) the daemon exited at startup, so the nft table was never created and nothing was blocked. Both peers got 50/50 through in wave 2, which is consistent with no block existing. Two script bugs showed up too: it didn't check the daemon was alive, and it aborted at `kill` before printing the verdict.

**Root cause, and a correction to Part 3.** `onnxruntime` and the numpy used in Parts 3–4 are **not installed system-wide**. They come from the site-packages of a pipx virtualenv (`~/.local/share/pipx/venvs/headroom-ai`), which the user's `sys.path` includes through the user site directory:

```text
/usr/bin/python3 (user)  import onnxruntime: ok …/pipx/venvs/headroom-ai/lib/python3.14/site-packages/onnxruntime/__init__.py
/usr/bin/python3 (sudo)  import onnxruntime: ModuleNotFoundError: No module named 'onnxruntime'
```

Part 3 §8 / requirements describe onnxruntime 1.31.0 as "system-wide"; that is wrong. The version (1.31.0) and every Part 3 result are unaffected. Only the description of where the package lives was wrong. The training virtualenv (`engine-ml/.venv-train`, `--system-site-packages`) depends on the same user path.

**Fix.**
- New self-contained interpreter `engine-ml/.venv-runtime` (`make runtime-venv`): numpy 2.5.4 and onnxruntime 1.31.0, no system or user site-packages. Under `sudo` it loads the models with the SHA-256 check (`under sudo, OnnxScorer loads: lgbm+iforest-fv1-6e986f14`).
- It scores identically to the interpreter used in Parts 3–4: `3604 flows scored by both interpreters: max |diff| = 0.0, decisions at 0.80 differing: 0`.
- `verify_closed_loop.sh` now runs the daemon with `PY_DAEMON` (default `.venv-runtime`), stops before creating namespaces if that interpreter can't load the models, stops with the daemon log if the daemon dies after starting, and no longer aborts on `kill`.

#### 7.2 Run 2 (2026-10-23T18:08:24Z, run by the project owner): all 5 checks PASS

`sudo bash tests/verify_closed_loop.sh`, after the fix in §7.1:

```text
[verify] namespaces sf_host (192.168.50.10) <-> sf_peer (flagged_peer=45.154.98.21, normal_peer=203.0.113.10)
[verify] baseline (no blocks): received at host: {"45.154.98.21": 50, "203.0.113.10": 50}
  [daemon] scorer: lgbm+iforest-fv1-6e986f14  alert-risk-policy: any
  [daemon] mitigation: backend=nftables netns=sf_host timeout=900s protected=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8 allowlist=none sinks=JsonlEventSink,SqliteEventSink
[verify] wave 1: sensor -r 2023-11-20-DarkGate-infection-traffic.pcap -A 0
   Packets processed: 9961
   Flows exported: 740
   Flows dropped: 0
  [daemon] flushed 740 rows -> sqlite,jsonl (scored in 40.3 ms; alerts=697; total accepted=740 rejected=0)
  [daemon] BLOCK 45.154.98.21 (ml_score: ml_anomaly_score=0.991 (lgbm+iforest-fv1-6e986f14)) flow 10.11.7.120:54179 -> 45.154.98.21:80 HTTP
  [daemon] BLOCK 188.246.224.221 (ml_score: ml_anomaly_score=0.895 (lgbm+iforest-fv1-6e986f14)) flow 10.11.7.120:54197 -> 188.246.224.221:2351 HTTP
[verify] nft set in sf_host after wave 1:
  table inet sentinel {
        set blocked_ipv4 {
                type ipv4_addr
                counter
                timeout 15m
                elements = { 45.154.98.21 counter packets 0 bytes 0 expires 14m59s756ms comment "ml_score: ml_anomaly_score=0.991 (lgbm+iforest-fv1-6e986f14)",
                             188.246.224.221 counter packets 0 bytes 0 expires 14m59s760ms comment "ml_score: ml_anomaly_score=0.895 (lgbm+iforest-fv1-6e986f14)" }
        }
  }
[verify] counter for flagged_peer before wave 2: 0 0
[verify] wave 2: sent 50 from each peer; received at host: {"203.0.113.10": 50}
[verify] counter for flagged_peer after wave 2: 50 6400
[verify] daemon audit for flagged_peer:
  {"ts_us":1792778889754621,"action":"block","ip":"45.154.98.21","backend":"nftables","reason":"ml_score","detail":"ml_anomaly_score=0.991 (lgbm+iforest-fv1-6e986f14)","score":0.99122,"flow":"10.11.7.120:54179 -> 45.154.98.21:80 HTTP","ml_model":"lgbm+iforest-fv1-6e986f14","timeout_s":900,"dropped_pkts":0,"dropped_bytes":0}
  {"ts_us":1792778898976826,"action":"counters","ip":"45.154.98.21","backend":"nftables","reason":"","detail":"","score":-1.0,"flow":"","ml_model":"","timeout_s":890,"dropped_pkts":50,"dropped_bytes":6400}
  blocked_ips row: ('45.154.98.21', 'nftables', 'active', 'ml_score', 0.991, 50, 6400, '10.11.7.120:54179 -> 45.154.98.21:80 HTTP')

=== CLOSED-LOOP RESULT (2026-10-23T18:08:24Z) ===
wave 1  flagged_peer in nft set after replay           : PASS
wave 2  flagged_peer packets delivered   0 / 50 (want 0)  : PASS
wave 2  normal_peer packets delivered    50 / 50 (want 50) : PASS
wave 2  nft counter delta packets        50 (want 50)      : PASS
wave 2  nft counter delta bytes          6400 (want 6400)  : PASS
outputs: /tmp/sf_closed_loop.FrXiss
[verify] cleanup: namespaces removed: 0 left; outputs kept in /tmp/sf_closed_loop.FrXiss
```

Readings:
- **Wave 1 is the full automatic path, with no manual step:**
  - The sensor replayed the holdout DarkGate capture: 9,961 packets, 740 flows, 0 dropped.
  - The daemon scored all 740 flows with the ONNX model in one batch (40.3 ms).
  - The mitigator blocked the capture's two C2 endpoints: `45.154.98.21` (score 0.991, payload host) and `188.246.224.221` (0.895, DarkGate C2). They are the same two endpoints Part 3 §9.1 listed for this capture.
  - Both were inserted into the nft set in `sf_host` with a 15-minute timeout and the reason as the element comment.
  - The victim address `10.11.7.120` was not blocked (protected, RFC 1918).
- **Wave 2:**
  - 0/50 packets from `flagged_peer` were delivered, and its nft element counter went from 0/0 to exactly **50 packets / 6,400 bytes** (50 × (20 + 8 + 100)).
  - 50/50 packets from `normal_peer` were delivered on the same interface.
- **Audit trail:** the daemon's own 10 s counter refresh recorded the kernel counters in `mitigations.jsonl` (`counters`, 50 / 6,400) and in SQLite `blocked_ips` (`active`, 50, 6,400).
- `alerts=697` is the Phase 2 `is_alert` rule (`--alert-risk-policy any`), which only labels flows. Blocking used the Phase 4 policy and produced 2 blocks.
- ClickHouse was not attached in this run (`--backend sqlite`); the ClickHouse audit sink was shown in §4.2.

---

### 8. Files changed in Phase 4

| Area | Files |
|---|---|
| Sensor | `sensor-c/src/main.c` (`-A`, snapshots, live wall-clock housekeeping), `sensor-c/src/flow_table.{c,h}` (`last_export_us`, `flow_table_foreach`), `sensor-c/tests/test_sensor_pcaps.py` (+4 tests) |
| Engine | `engine-ml/mitigator.py` (new), `engine-ml/daemon.py` (`--mitigate*`, `--allowlist-file`), `engine-ml/query_dashboard.py` (panel 6), `engine-ml/sql/init_clickhouse.sql` (`sentinel.mitigations`), `engine-ml/models/build_dataset.py` + `evaluate_holdout.py` (pin `-A 0`), `engine-ml/models/threshold_table.py` + `threshold_table.json` (new), `engine-ml/tests/test_mitigator.py` (new), `engine-ml/tests/lab_nftables_netns.py` (new) |
| Dashboards | `dashboard/grafana/dashboards/sentinelflow.json` (panel 6, version 4) |
| Verification | `tests/verify_closed_loop.sh` (new; `PY_DAEMON` preflight after run 1) |
| Repo | `Makefile` (`test-engine` runs the mitigator tests; new `runtime-venv`, `verify-closed-loop`), `.gitignore` (`engine-ml/.venv-runtime/`, XDP build outputs) |
| Provided by the project owner | `mitigation-ebpf/xdp_blocker.bpf.c`, `mitigation-ebpf/xdp_ctl.c` (built, not attached) |

Nothing has been committed.

---

### 9. What may and may not be said

**May be said (observed in this session):**
- The sensor exports cumulative snapshots of still-active flows every `-A` seconds. `-A 0` reproduces the Part 3 sensor output exactly (byte-identical regression set, identical corpus flow counts).
- The blocking policy never selected a private or special-purpose address in the Part 3/4 data. It blocks on ML score ≥ 0.80 from a trained model, or on 6 severe nDPI risks; other risks never block on their own.
- With nftables in a namespace lab, a block placed by `Mitigator` dropped 50/50 packets from the blocked peer, with an exact per-element counter (50 packets / 6,400 bytes), while 50/50 packets from a benign peer were delivered. Timeout expiry and manual unblock worked.
- Dry-run mitigation over the 11 Part 3 captures produced 24 blocks and 7 protected skips, recorded identically in JSONL, SQLite and ClickHouse, and shown by Panel 6 in both dashboards.
- On the saved holdout predictions, 0.80 + `severe` would block 16/23 malicious endpoints and 2/61 benign endpoints, with at least one block in each of the 5 infections.
- The automatic loop works end to end in a namespace lab (§7.2). A replayed holdout capture was scored by the ONNX model, its two C2 endpoints were blocked in nftables by the daemon without manual steps, and afterwards 0/50 packets from the blocked endpoint were delivered (counter exactly 50 packets / 6,400 bytes) while 50/50 from a normal peer were delivered.

**Must not be said (not shown):**
- **That the loop works on live capture or against a running C2 session.** Wave 1 was an offline replay (`sensor -r`), not live capture (`-i`). Wave 2 traffic was synthetic UDP from the blocked address, not the malware's own protocol. Time from detection to block under live traffic was not measured.
- **Anything about XDP enforcement, XDP drop counters, or XDP performance.** XDP was not attached (§6).
- **Blocking mid-connection with `-A`.** The snapshot logic is tested offline only.
- **That blocks are safe on a production host without an allowlist.** The Part 3 data contained Microsoft and Cloudflare addresses the policy would block (§2.1).
- **That the false-block rates in §5 generalize.** They come from 61 benign holdout endpoints and one CV seed.


---

<a id="part-5"></a>

## Part 5: Packaging, VM Deployment, First Live Test, Risk-Mask Fix, Retrain

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Tree:** `/home/joe/cv_work/sentinel-flow/`, GitHub `AbdeldjallilZennir/sentinel-flow`
**Date:** 2026-10-24
**Status:**
- The project is packaged (portfolio README, installer, live runner, lab guide) and was installed on a fresh Ubuntu Server 24.04 VM, where all tests pass and results match the development host.
- A first live test (an nmap scan in a two-machine lab) was captured completely. It wasn't blocked, as designed, and it exposed a real sensor bug: corrupted 64-bit risk masks. The bug is fixed and verified.
- The model was retrained on the corrected data and committed: `lgbm+iforest-fv1-2005d025`.
- Expanding the training data with common attacks was started but **not completed** (§6).

> [!info] Claim discipline
> Same rule as Parts 1–4: a statement is made here only if the output that supports it was captured in this session. §8 lists what was not shown.

---

### 0. Project status at a glance

| Phase | Report | State | Key verified results |
|---|---|---|---|
| 1. C sensor | Part 1, Part 1.2, Part 3 §3 | done | libpcap + nDPI 6.1, JA4, Welford stats, ZeroMQ export; 7 bugs fixed in Part 3, 1 more here (§4); ~0.40 Mpps offline |
| 2. Ingestion & analytics | Part 2 | done | stdlib daemon, SQLite/JSONL/ClickHouse, Grafana, 29 columns per flow |
| 3. ML pipeline | Part 3 | done; model updated here (§5) | 9,659 labeled flows; grouped CV ROC-AUC 0.980; holdout 5/5 infections |
| 4. Kernel mitigation | Part 4 | done with nftables; XDP not attached | closed loop passed 5/5 checks: 0/50 delivered from the blocked C2, exact counters |
| Packaging & lab | this report | done | installer + runner + guide; fresh-VM install passes all tests |
| Attack-data expansion | this report §6 | not done | stopped; unfinished code kept in a git stash |

---

### 1. Packaging

| File | What it does |
|---|---|
| `README.md` (repo root) | Portfolio document: architecture, metrics table (each number linked to its report section), quick start, screenshots, limits. The original blueprint moved unchanged to `sentinel-flow/docs/BLUEPRINT.md`. |
| `sentinel-flow/scripts/install_deps.sh` | One-command setup for Ubuntu / Debian / Kali: apt packages, nDPI at the verified commit `90eb617a4`, sensor build, `engine-ml/.venv-runtime` (numpy + onnxruntime 1.31.0), both test suites. Opt-in `--with-training`, `--with-data`, `--with-docker`, `--with-xdp`. |
| `sentinel-flow/scripts/run_live.sh` | Live capture on one interface: daemon (dry-run by default; `-a` allowlist; `--block` = nftables) + sensor + optional dashboard (`--serve`). Clean shutdown on Ctrl+C. `--data-dir`, `--no-clickhouse`. |
| `sentinel-flow/docs/LAB_SETUP.md` | Two-machine VirtualBox lab: host-only network, install, run, dashboard over an SSH tunnel, results, optional Grafana, troubleshooting. |

#### 1.1 Installer fixes found on a fresh machine

Installing on a fresh Ubuntu Server 24.04.4 VM (2 CPUs, 3.8 GB RAM) over SSH found two installer bugs; both are fixed:

| Problem on the fresh VM | Fix |
|---|---|
| `sudo` can't prompt for a password over a non-interactive SSH session | `SUDO_ASKPASS` support: the script uses `sudo -A` |
| `make: *** No targets specified and no makefile found`: at the pinned commit, nDPI's `autogen.sh` doesn't run `./configure` | the script runs `./configure` when no Makefile was produced |

#### 1.2 Result on the VM

```text
libndpi: /home/joe/nDPI/src/lib/libndpi.so.6.1.0
ONNX scorer loads: lgbm+iforest-fv1-6e986f14
=== Results: 13 passed, 0 failed ===        (test_flow)
=== Results: 24 passed, 0 failed ===        (test_stats)
Ran 10 tests … OK                           (sensor PCAP tests)
Ran 15 tests … OK (skipped=3)               (daemon, system Python: no numpy)
Ran 15 tests … OK                           (daemon, runtime venv: ONNX tests included)
Ran 18 tests … OK                           (mitigator)
INSTALL_EXIT=0
```

Smoke test on the VM: `test_tls_full.pcap` + `malware.pcap` → daemon with ONNX, dry-run. 7/7 flows stored, and the 3 dry-run blocks carry the same scores as on the development host (0.841, 0.973, 0.976).

#### 1.3 `run_live.sh` check (development host, loopback)

```text
mode: dry-run (decisions are logged to …/data/mitigations.jsonl, nothing is blocked)
  [daemon] scorer: lgbm+iforest-fv1-6e986f14  alert-risk-policy: any
capturing on lo (active timeout 60s) — Ctrl+C to stop
║  Flows exported:    14  ║  Flows dropped:     0  ║
[daemon] stopped: accepted=14 rejected=0 clickhouse_failed=0
=== flows to :18081 stored: 3
{'src_ip': '127.0.0.1', 'dst_ip': '127.0.0.1', 'dst_port': 18081, 'app_protocol': 'HTTP', 'pkt_count': 13, 'ml_anomaly_score': 0.003936, …}
```

**Incident during this check.** An earlier run of the test, before `--no-clickhouse` existed, wrote 384 loopback flows into the host's ClickHouse `sentinel.network_flows`, because ClickHouse was running and the daemon attaches to it automatically. They were deleted by ingest time (`384` rows ingested that day, `3604` before). The table is back to exactly the 3,604 Part 4 rows. `--no-clickhouse` was added to prevent a repeat.

---

### 2. GitHub

- The repository was created and first pushed by the project owner. Later commits were pushed from this session with a personal access token the owner provided. The token was passed through a temporary credential helper that was deleted after each push; it isn't in `.git/config`, the remote URL, or any commit (checked with `git grep` over all revisions).
- The token was pasted into the conversation, so it must be **revoked** on GitHub.
- One push was first rejected because of a README edit made on GitHub (`afc7e1f`). The local commit was rebased on top of it, with no overlap (the edit touched only `README.md`), and pushed.

Commits since Part 4 (newest first):

| Commit | Content |
|---|---|
| `e6444c6` | this report |
| `0ffe7ec` | retrained model on exact risk masks (§5) |
| `d68a0e0` | sensor: exact 64-bit `ndpi_risk_mask` (§4) |
| `afc7e1f` | README edit (project owner, on GitHub) |
| `fa38185` | `run_live.sh` + `LAB_SETUP.md` |
| `9d96df8`, `379994c`, `af55cd8` | installer fixes (§1.1) |

---

### 3. First live test: an nmap scan in a two-machine lab

The test ran on a separate machine pair (VMware network `192.168.230.0/24`) with `run_live.sh` in dry-run mode, capturing on `eth0`. The data folder was transferred as a zip and analysed here. A first copy contained only `sentinel_flows.db` without its `-wal` file, so it was empty: SQLite in WAL mode keeps recent rows in the `-wal` file.

#### 3.1 What was captured

```text
Packets processed: 2926   Flows tracked: 1119   Flows exported: 1137 (18 snapshots)   Flows dropped: 0
flows.jsonl: 1137 records; sqlite network_flows: 1137
top src->dst pairs: (192.168.230.1 -> 192.168.230.128): 1124
distinct dst ports on the most-contacted host: 1003
src ports: 36280 used by 1000 flows; pkt_count=2 for 1026 flows (44 B up / 40 B down)
risk strings: 'TCP Connection Issues, Probing Attempt' 973, '(Possible) Slow DoS' 36, …
is_alert: 1033      ml_anomaly_score: max 0.320, >= 0.5: 0, >= 0.8: 0
```

A classic nmap SYN scan: 1,000 probes from one fixed source port, plus service and version probes (short SSH exchanges from consecutive ports) and ICMP.

#### 3.2 Why nothing was blocked

| Reason | Detail |
|---|---|
| The model isn't trained on scans | It was trained on C2 and malware sessions. Scan captures were deliberately excluded from the training data (Part 3 §4.2). One flow at a time, a scan probe is a 2-packet failed connection. |
| "Probing Attempt" isn't a severe risk | Only 6 severe nDPI risks block without an ML score (Part 4 §2) |
| Both addresses are private | The policy never blocks RFC 1918 addresses. The logged decision: `skip_protected … both endpoints protected` |
| Allowlist pointed at the target | `-a 192.168.230.128` was the scanned VM itself; the scanning machine was `.1` |

---

### 4. Bug: 64-bit risk mask corrupted

#### 4.1 How it was found

The one logged decision in §3 cited four "severe" risks (suspicious DGA, risky domain, malicious fingerprint, malicious SHA-1 certificate) on an RDP scan probe:

```text
ndpi_risk_mask: 37154697999548400
ndpi_risk_str : 'Desktop/File Sharing, TCP Connection Issues, Probing Attempt'
set bits: [4, 5, …, 29, 50, 55]        expected: [30, 50, 55]
```

#### 4.2 Cause and fix

- **Cause:** the embedded cJSON stores numbers as doubles, which hold integers exactly only up to 2⁵³. "Probing Attempt" is bit 55, so 2³⁰ + 2⁵⁰ + 2⁵⁵ = `37154697999548416` was printed as `37154697999548400`, corrupting the low bits.
- **Fix (`d68a0e0`):**
  - new `cJSON_CreateRaw` / `cJSON_AddRawToObject`;
  - `main.c` prints the mask with `PRIu64`.
- **Who was affected:** every flow with a risk at bit 53 or above, notably "Malware Host Contacted" (53), "Probing Attempt" (55) and "Obfuscated Traffic" (56).

#### 4.3 Verification

```text
pcaps=630 flows=9952 mask_diffs=63 other_field_diffs=0 new masks>=2^53: 63;
new masks whose bit count != number of nDPI risk names: 0
```

| Check | Result |
|---|---|
| Old vs new sensor on the full nDPI corpus | exactly the 63 flows with masks ≥ 2⁵³ change; no other field changes anywhere |
| Mask vs nDPI's own risk names | every new mask's bit count equals the number of risk names nDPI reports |
| Regression test `test_risk_mask_is_exact_above_2_53` (`tcp_scan.pcapng`) | passes on the new binary; fails on the old one (`3.71546969258066e+16 is not an instance of <class 'int'>`) |
| ASan / LSan / UBSan | 5 captures, 2,010 flows, 0 errors |
| Sensor suite | 11/11 tests |

#### 4.4 Impact on earlier results

- **Training data:** 79 of the 9,659 training flows (0.8 %) had corrupted masks, and 9 of them showed fake severe bits. Part 3's metrics were computed on that data; §5 shows the retrain on corrected data.
- **Blocking policy:** it reads the same mask, so before the fix a scan could produce a fake "severe" risk and a block for the wrong reason.

---

### 5. Retrain on corrected data (`0ffe7ec`)

`make dataset train holdout` was run on the development host on 2026-10-24 (17:25–17:27). The dataset was rebuilt with the fixed sensor from the same 601 PCAPs. Composition is unchanged (9,659 flows, 1,825 malicious in 28 captures). The difference: the 79 masks ≥ 2⁵³ are now exact integers.

| | Previous model `6e986f14` | New model `2005d025` |
|---|---|---|
| CV recall @0.80 (5 seeds) | 0.452 ± 0.042 | 0.449 ± 0.020 |
| CV precision | 0.907 ± 0.031 | 0.922 ± 0.015 |
| CV false-alarm rate | 1.1 % ± 0.4 % | 0.9 % ± 0.2 % |
| ROC-AUC / PR-AUC | 0.980 / 0.905 | 0.980 / 0.901 |
| Calibration threshold (raw) | 0.330 | 0.353 |
| ONNX parity | 0 / 9,597 differ | 0 / 9,597 differ |
| Holdout: infections / endpoints / false alerts | 5/5 / 15/23 / 3 of 498 | 5/5 / 15/23 / 3 of 498 |

All differences are within the seed spread. The new model has the same quality with less variance across seeds, and is built on correct inputs. The daemon loads it after the SHA-256 check (`OnnxScorer loads: lgbm+iforest-fv1-2005d025`); daemon 15/15 and mitigator 18/18 tests pass.

**Why it wasn't saved straight away.** The retrain wasn't run by this session. When new model files appeared, they were left uncommitted because their origin wasn't yet confirmed and committing them replaces the production model. After the comparison above they were committed. Earlier reports (Part 3, Part 4, README) quote the previous model; those numbers remain the record of what was measured then.

---

### 6. Attempted, not completed

| Item | State |
|---|---|
| **Training on common attacks:** nDPI corpus scans / web attacks / DoS / exploits, plus the lab nmap session | The builder changes were written. Creating the lab-session files was stopped by Anthropic's safety system partway through, and earlier related tools (a session "flywheel" and a dataset collector) were stopped the same way. Not pursued further. The unfinished builder change is kept in `git stash` ("unfinished: attack families + lab sessions in build_dataset.py"). |
| **XDP blocking** | Part 4 §6: sources compile, attaching failed in libbpf |
| **Labeling for outside datasets** (CIC-IDS2017 etc.) | Not written. A Colab script that runs the **existing** pipeline in the cloud was provided in conversation; it is untested on Colab. |
| **Scan detection** | Proposed, not built: per-source fan-out (distinct ports/hosts in a time window). The §3 scan (1,003 ports from one source) would stand out to such a rule but not to the per-flow model. |

---

### 7. Open items

1. **Revoke the GitHub token** that was pasted into the conversation.
2. **`git pull` on the VMs** so they use the new model (`0ffe7ec`, pushed to GitHub).
3. **For lab runs:** allowlist the machine you administer from, not the sensor VM. Private-to-private traffic is never blocked, so lab results show up as logged decisions.
4. **Offline idle expiry** still runs only every 1,000 packets (Part 4 §1.3); unchanged to keep earlier results reproducible.
5. `engine-ml/models/threshold_table.json` and the README metrics still describe the previous model. Re-run `threshold_table.py` if you want them for `2005d025`.
6. **Untracked files in the repo root:** `data-20261024T154543Z-1-001.zip` (the nmap session) and an empty `sentinel_flows.db`. These are the project owner's files and were left as they are.

---

### 8. What may and may not be said

**May be said:**
- The installer sets the project up on a fresh Ubuntu Server 24.04.4 VM, where all test suites pass, and the VM scores test captures identically to the development host.
- In a live lab, the sensor captured an nmap scan completely (1,137 flows, 0 dropped) and nDPI flagged it as probing.
- The 64-bit risk mask was corrupted for risks at bit 53 and above. It's fixed, and verified on 9,952 corpus flows with a regression test.
- The model retrained on corrected data matches the previous one within the seed spread, with lower variance, and was committed.

**Must not be said:**
- **That SentinelFlow detects port scans.** The live scan scored at most 0.32, and scans aren't in the training data.
- **That the model generalises to attack types beyond the C2/malware families it was trained on.**
- **That `run_live.sh --block` was tested live.** Only dry-run was used in the live lab; nftables enforcement was verified in Part 4 §7.
- **That the Colab script works.** It hasn't been run on Colab.


---

<a id="part-6"></a>

## Part 6 — Alert rule and per-IP blocking

Date: 2026-10-24. Model unchanged: `lgbm+iforest-fv1-2005d025`.

### 0. Summary

| Change | Before | After |
|---|---|---|
| `is_alert` default (`daemon.py --alert-risk-policy`) | `any`: any nDPI risk raises an alert (18 % of benign flows) | `severe`: only the risks in `features.SEVERE_MASK`. `any` is still available. |
| Blocking (`mitigator.BlockPolicy`) | Any single flow with score ≥ 0.80 blocks the remote IP | Decided per remote IP: **one flow ≥ 0.95**, or **2 flows ≥ 0.80 to the same IP within 1 h**, or a severe nDPI risk |
| Scan detection | None (per-flow model scores each probe as harmless) | One source hitting **≥ 50 ports on one host**, or **≥ 100 hosts on one port** (flows ≤ 3 packets), within 60 s → the **source** is blocked (or logged, if it is a protected address) |

No retraining was needed. All of this is policy around the model.

### 1. Evidence

Same code (`BlockPolicy`, defaults vs. the old rule) run over three data sets. "Benign IPs blocked" = remote IPs blocked that carried only benign-labeled flows in that capture. "Ambiguous" = shared services abused by malware (IP-lookup sites etc.), which the labels exclude from both classes.

| Data | Rule | Malicious IPs blocked | Benign IPs blocked | Infections with ≥ 1 block |
|---|---|---|---|---|
| Training, out-of-fold scores (9,597 flows, 91 malicious / 2,450 benign IPs) | old | 70 | 44 | 16 / 28 |
| | **new** | 56 | **15** | 15 / 28 |
| Holdout, live replay (3,592 flows, 23 malicious remote IPs) | old | 16 | 2 (+ 2 ambiguous) | 5 / 5 |
| | **new** | 14 | 2 (+ 1 ambiguous) | 5 / 5 |
| | new + `config/default_allowlist.txt` | 14 | 0 | 5 / 5 |
| Lab nmap session (1,137 flows, 1,002 ports in 220 s) | old | — | — | scan not seen (max score 0.32) |
| | **new** | — | — | scan detected after 50 ports |

- On training data the new rule wrongly blocks about a third as many benign IPs (44 → 15) and loses one infection.
- **On the holdout the new rule does not help and costs 2 malicious IPs.** The two benign false blocks are the Microsoft addresses `13.107.213.57` and `20.190.135.18`, which score ≥ 0.95, so per-IP counting cannot remove them. The rule drops one ambiguous block (`193.122.6.168`, checkip.dyndns.org) and loses `193.3.19.230` (one flow, 0.86) and `104.21.24.30` (best flow 0.91), both single-flow endpoints. The training result is the reason for the change; the holdout (5 captures) is a sanity check that infections are still caught.
- **Allowlist:** `config/default_allowlist.txt` removes the remaining holdout false blocks, but its first three entries were taken from the holdout itself, so that row is not an independent result.
- `is_alert` on the nmap session: 1,031 → 1 flow. The remaining one is an RDP flow whose risk mask was corrupted by the pre-fix sensor (Part 5 §4); a current sensor would not produce it.

**Scan thresholds vs. benign traffic** (training set, 60 s windows): the most distinct ports from one source to one host was 9 (a game client). The most distinct hosts on one port with short flows was 40 (Gnutella, UDP). Over all flow lengths it was 56 (Ethereum P2P), which is why the sweep rule counts only flows of ≤ 3 packets. Holdout maximum: 6 ports.

Thresholds (0.95 / 2 flows / 1 h) were chosen on the training out-of-fold scores, then checked on the holdout. The holdout was not used to pick them, but it is only 5 captures.

### 2. Behavior details

- **Time** comes from flow timestamps (`last_seen_us` for ML counting, `first_seen_us` for scans), so PCAP replays behave like live capture.
- **Scan target** is always the source. A scanner inside a protected range (default RFC 1918) is not blocked; the event is written as `skip_protected` with reason `scan` and logged as `SCAN (not blocked) …`.
- **Scan events** fire at most once per (source, target) every 10 minutes, so a 1,000-port scan produces one event, not twenty.
- **Memory**: per-IP trackers are pruned once a table exceeds 100,000 keys.
- **New reason codes**: `ml_repeat` (4) and `scan` (5), next to `ml_score` (1), `severe_risk` (2) and `manual` (3). They appear in `mitigations.jsonl`, `blocked_ips` and `sentinel.mitigations` with no schema change.

### 3. New daemon flags

| Flag | Default | |
|---|---|---|
| `--block-high-score` | 0.95 | One flow at or above this blocks |
| `--block-repeat` | 2 | Flows ≥ 0.80 to one IP that block it |
| `--block-repeat-window` | 3600 | Seconds |
| `--scan-ports` | 50 | 0 = off |
| `--sweep-hosts` | 100 | 0 = off |
| `--scan-window` | 60 | Seconds |

`--block-high-score 0.80 --block-repeat 1 --scan-ports 0 --sweep-hosts 0` restores the previous behavior. `--alert-risk-policy any` restores the Phase 2 `is_alert` rule.

### 4. Tests

- `engine-ml/tests/test_mitigator.py`: 32 tests (18 before), all pass. New: thresholds, per-IP repeat counting, window expiry by flow time, legacy mode, severe + moderate score, port scan, slow scan not firing, host sweep ignoring long flows, protected scanner + cooldown, scans disabled, mitigator audit rows.
- `test_lab_nmap_session` replays the lab session when `SENTINEL_NMAP_FLOWS=<path to its flows.jsonl>` is set; otherwise it is skipped.
- `engine-ml/tests/test_daemon.py`: 15/15 pass (unchanged).
- `daemon.py --from-jsonl <nmap flows> --mitigate dry-run`: logs the scan as not blocked by default; with `--allow-private-blocks` it blocks `192.168.230.1` with reason `scan`.

### 5. Not done / caveats

_(Items 1 and the allowlist note are addressed in §6.)_

- The **dashboard** shows new reasons as plain strings. There is no panel for `skip_protected` scan events yet; they are in `mitigations.jsonl` and SQLite `mitigation_events`.
- **Delay**: the sensor exports a flow only after it ends or idles 30 s, so a scan is detected about 30 s after the 50th port. A repeat-rule block waits for the second suspicious flow.
- `evaluate_holdout.py` now defaults to `--risk-policy severe`, so its `is_alert` columns change. The summary table still prints all policies.
- Thresholds come from lab captures (MTA + nDPI corpus). Busy production networks may need a higher `--sweep-hosts` (e.g. scanners you run yourself, monitoring systems): allowlist them.

### 6. Follow-up (same day)

1. **Dashboard:** `query_dashboard.py` has a new panel **6b "Recent Mitigation & Scan Events"**: the last 50 events from `mitigation_events` (SQLite) or `sentinel.mitigations` (ClickHouse), excluding counter updates. `skip_protected` is shown as **"detected, not blocked"**, so a LAN scanner shows up on the dashboard. Checked on SQLite (nmap replay: the scan row appears), on a database without mitigation tables (falls back to a note), and on ClickHouse with the existing Part 4 data. The Grafana dashboard is unchanged.
2. **Allowlist:** `config/default_allowlist.txt`, 6 entries: the two holdout Microsoft false blocks, `api.ipify.org` (shared Cloudflare IP, ambiguous label), and 1.1.1.1 / 8.8.8.8 / 9.9.9.9. On the holdout replay it removes all non-malicious blocks with the same 14 / 23 malicious IPs. Because the entries came from the holdout, that is not an independent result.
3. **Correction to §1:** the first version of this report counted 2 ambiguous IP-lookup endpoints as benign on the holdout ("4 → 3 benign IPs"). The corrected numbers are in the §1 table: 2 benign blocks before and after.
4. **Tests:** `make test-sensor` (13 + 24 + 11) and `make test-engine` (15 + 32, 1 skipped without the lab session file) pass.


---

<a id="part-7"></a>

## Part 7 — More training data (23 MTA cases), retrain

Date: 2026-10-24. New model: `lgbm+iforest-fv1-203d33a1` (previous: `2005d025`).
Built, trained and evaluated on the development host, offline, from captures downloaded once.

### 0. Summary

| | Before (`2005d025`) | After (`203d33a1`) |
|---|---|---|
| MTA training cases | 17 | **40** |
| Labeled flows | 9,659 | 12,250 |
| Malicious flows / captures | 1,825 / 28 | **2,846 / 51** |
| CV recall @ 0.80 (5 seeds) | 0.449 ± 0.020 | 0.648 ± 0.035 |
| CV precision / false-alarm rate | 0.922 / 0.9 % | 0.952 / 1.0 % |
| CV ROC-AUC / PR-AUC | 0.980 / 0.901 | 0.984 / 0.945 |
| **Holdout:** infections / malicious endpoints alerted | 5/5, 15/23 | 5/5, **17/23** |
| **Holdout:** flow recall / false alerts | 0.229 / 3 of 498 | 0.268 / **12 of 498** |
| **Holdout, per-IP blocking rule:** malicious IPs / benign IPs blocked | 14/23, 2 | 14/23, 2 (same two Microsoft IPs) |

CV numbers are on different data and are **not** a like-for-like comparison. The holdout (5 fixed captures, never trained on) is: the model alerts on more attacker endpoints and many more malicious flows, raises more flow-level false alerts, and blocks exactly the same under the Part 6 per-IP rule.

### 1. Data choice

Candidates looked at (the `Datasets` notes file in the repo root, plus MTA itself):

| Source | Verdict | Why |
|---|---|---|
| **More malware-traffic-analysis.net cases** | **used** | Same source, format and labeling as the existing 17 cases; recent (2023–2026) Windows infections, each with its own real Windows background traffic; IOC lists give C2 IPs/domains. Fixes the main weakness (most families seen once). |
| Stratosphere CTU-Normal | not now | Reachable, but CTU-Normal-20…32 are 2017 scripted visits to top websites, 12 of 13 from Kali Linux. Old TLS stacks and no Windows background; weak match for the Microsoft false alerts. |
| Stratosphere CTU-Malware | not now | Mostly 2013–2019 families; labels need a new parser. |
| Active Countermeasures "Malware of the Day" | not usable unattended | Site answers HTTP 403 to scripted downloads, so it can't run in a Colab script. |
| DNS-tunnel corpus (ggyggy666/DNS-Tunnel-Datasets) | later | Real captures (dnscat2, iodine, dnspot, …), but a separate goal, and it needs a "DNS-only" labeling rule plus a check that it doesn't add DNS false alerts. |

**Cases added (23):** Rhadamanthys, MetaStealer, Bandook, DanaBot (×2, one with Matanbuchus), IcedID (×2), Lumma (×2, one with Rsockstun), AgentTesla FTP (×2), StealC, UltraVNC, SSLoad, DarkGate, XLoader/Formbook, Snake KeyLogger SMTP, StrelaStealer, a PureLogs-style RAT, Koi Loader, XWorm, njRAT + MassLogger, KongTuke/MintsLoader/GhostWeaver.

**Deliberately not added:** more Pikabot / Gozi (already 75 % of malicious flows before), SectopRAT (so holdout case 2025-08-15 still tests a family absent from training), the 5 holdout dates, macOS/Linux/Android cases, "scans and probes" server logs, multi-infection data dumps, cases without a usable capture or IOC list (Emotet 2023-03-22, Remcos 2026-08-06, GuLoader 2024-08-26, Raspberry Robin 2024-11-14), and WikiLoader (C2 runs through a public MQTT broker, which the labeling rules treat as a shared service).

### 2. Labels

Written from each case's IOC text (or page), same rules as before: attacker C2 / payload / exfil infrastructure = malicious; compromised legitimate sites, file-sharing, IP-lookup services, CDNs = ambiguous (excluded); everything else in the capture = benign background. Each new entry has a `"note"` field.

Checks done on the built dataset (per case: malicious / benign / ambiguous counts and the busiest "benign" remote IPs):

- Every new case has malicious flows (1 to 390 each).
- **Fixed 1:** SSLoad 2024-04-17: 27 flows to the WebDAV host that served the MSI (`krd6.com`, listed under "location of MSI" in the IOC text) were benign → added as malicious (1 → 28 malicious flows).
- **Fixed 2:** njRAT + MassLogger 2026-01-29: the IOC text names `cphost.qhoster.net:587` for SMTP exfil, but the capture's DNS resolves `cphost14.qhoster.net` (78.110.166.82) → labeled by that name and IP. IP-lookup and Telegram traffic → ambiguous.
- **Bug caught:** the first version used a `"source"` key per entry, which overrode `build_dataset.py`'s internal `source="mta"` (benign flows of new cases got the malware family name instead of "background"). Renamed to `"note"` before training; the numbers here are from the fixed build.
- XLoader/Formbook contributes 390 malicious flows, including traffic to decoy domains on shared parking hosts. That is real Formbook C2-pattern traffic; the per-capture weight cap in training limits its influence.

### 3. Holdout detail

```text
                                    before (2005d025)   after (203d33a1)
2023-11-06 404 TDS + Cobalt Strike   67/2227  5/8  1     81/2227  5/8  6
2023-11-20 DarkGate                 614/687   2/2  0    686/687   2/2  0
2024-02-21 SocGholish + AsyncRAT      6/11    3/5  0      9/11    5/5  0
2025-08-15 Lumma + SectopRAT         14/148   3/3  0     45/148   3/3  0
2025-12-29 ClickFix + NetSupport      4/11    2/5  2      4/11    2/5  6
(ML-detected malicious flows / endpoints alerted / false alerts)
```

- **Newly alerted endpoints:** the 404 TDS redirect `201.148.107.213` (best score 0.007 → 0.917), the SocGholish fake-update host `66.135.17.87` (0.048 → 0.810) and `49.13.65.235` (0.381 → 0.972). These HTTPS delivery/redirect servers were the main misses in Part 3. **Lost:** `193.3.19.230` (0.862 → 0.780).
- **Unseen family:** Lumma + SectopRAT flows detected 14 → 45 of 148 (SectopRAT is still absent from training).
- **The 12 false alerts:**
  - 6 are WinRM (5985) from the infected host to the domain controller (Part 3 noted these are probably attacker lateral movement that IP-based labels count as benign); private-to-private, never blocked.
  - 1 is SMB from the domain controller to the client; private, never blocked.
  - 2 are the same Microsoft IPs as before (in `config/default_allowlist.txt`).
  - **3 are new: long TLS sessions to Google** (`142.250.138.132`, `142.250.115.100`, `142.251.186.101`, 31–43 s, scores 0.89–0.95). They show up as `is_alert`, but the per-IP rule doesn't block them (single flow < 0.95).
- **Per-IP blocking (Part 6 rule):** identical for both models: 14/23 malicious IPs, 5/5 infections, 2 benign IPs (Microsoft), 0 with the allowlist.

Out-of-fold per-IP blocking on the new training set: 106 of 171 malicious IPs, 36 of 51 infections, 31 benign IPs blocked (old model on the old set: 56/91, 15/28, 15). Different data, so only the rates are indicative.

### 4. Other changes

- `engine-ml/models/compare_holdout.py`: before/after table from two `evaluation_holdout.json` files.
- `scripts/colab_train.sh`: scores the current model on the holdout first, fetches the 40 cases, prints a per-case label check (warns on any case without malicious flows), trains, re-runs the holdout, prints the comparison, and adds `holdout_before.json`, `holdout_compare.txt`, `dataset_summary.json` to the zip.
- `scripts/colab_holdout.sh`: no longer cuts off the first capture and model line.
- Tests: daemon 15/15, mitigator 32 (1 skipped without the lab session file). The daemon loads `203d33a1` after the SHA-256 check. ONNX parity: 0 / 12,127 alert decisions differ.

### 5. Not done / caveats

- `models/threshold_table.json` and the README threshold table still describe older models.
- The holdout is 5 captures; "more endpoints, more false alerts" is one sample.
- The 3 Google false alerts suggest long TLS sessions now look more C2-like; worth watching on live traffic.
- Rolling back: `git checkout ddcbd03 -- sentinel-flow/engine-ml/models/{c2_detector.onnx,anomaly_iforest.onnx,model_meta.json}` (or revert the commit).

---

<a id="part-8"></a>

## Part 8 — Code review: 15 bugs found and fixed

Date: 2026-10-25. Commits `a8d8a1b` (dashboard), `df53f9e` (crashes, data loss, live runs), `8d13bea` (blocking decisions). The model is unchanged (`203d33a1`).

Where the bugs came from:
- **5 were found by running the dashboard**, on the Part 7 database, on a fresh replay with the current model, and against ClickHouse.
- **10 came from a multi-agent cloud code review** (Claude Code `/code-review ultra`) of all 41 code files: 7,422 lines of Python, C, shell and build files. Docs, data, models, the vendored `uthash.h`, `cJSON` and `zmq.h`, and the Grafana JSON were left out to fit the size limit.

Each bug was reproduced, or shown with a new test, before it was fixed, and checked again afterwards.

### 0. Summary

| # | Where | Bug | Effect before the fix |
|---|---|---|---|
| 1 | dashboard, panel 6 | block status stays "active" | The 24 blocks from 2026-10-23 still showed "active" two days later |
| 2 | dashboard, panels 2–4 | no row limit | The web page was 1.18 MB, reloaded every 10 s, and grew during live runs |
| 3 | dashboard, panel 3 | "Security Alerts" listed every nDPI-risk flow | 3,061 rows were shown as alerts; only 846 are alerts under the Part 6 rule |
| 4 | dashboard, SQLite | crash on a WAL database in a folder the user can't write | `attempt to write a readonly database` after a root daemon had stopped |
| 5 | dashboard `--serve` | crash when the port is taken | `run_live.sh --serve` still printed the URL; the dashboard was gone |
| 6 | mitigator, scan rule | a forged scan blocks any public IP | About 50 spoofed packets could block e.g. the DNS resolver, renewable every 10 min |
| 7 | mitigator, target choice | the host's own public address chosen as target | On inbound flows the host blocked itself and the attacker went free |
| 8 | sensor | ports read from later IP fragments | 60 fragmented datagrams became 60 fake flows (ports 257, 514, …), which can look like a scan |
| 9 | mitigator + dashboards | active-timeout snapshots counted as separate flows | One long connection met "2 flows ≥ 0.80"; dashboard totals counted it several times |
| 10 | `zmq_sink` | stack buffer overflow on messages > 64 KiB | AddressSanitizer: stack-buffer-overflow; truncated records passed on |
| 11 | daemon | one malformed record crashes it | `OverflowError` / SQLite integer overflow / `RecursionError`; the pending batch (up to 1,000 flows) lost |
| 12 | daemon `--backend clickhouse` | one failed write drops every later row | Exit code 0, rows silently lost; the log claimed they were "kept in SQLite/JSONL" (neither is used in this mode) |
| 13 | `run_live.sh --block` | Ctrl+C leaves the root daemon running | With sudo ≥ 1.9.14 (`use_pty`, default) `$!` is not the daemon |
| 14 | `run_live.sh` | root-owned output files after a `--block` run | The next normal run failed with `PermissionError` |
| 15 | sensor, live capture | 200 ms wait per flow while the daemon is down | Capture falls behind and misses traffic |

### 1. Dashboard (`query_dashboard.py`, Grafana)

1. **Stale "active" blocks.** The daemon writes `expired` only while it runs; after it stops or restarts, rows in `blocked_ips` stay `active`. Panel 6 now marks a block expired once its last known expiry has passed. The expiry is the time of the latest `block` / `counters` event plus its timeout. The same fix went into the ClickHouse query and the Grafana panel. Check: the Part 7 database shows 24 expired, a fresh dry-run shows 21 active, and a fake two-day-old block in ClickHouse shows expired and sorts last.
2. **Unbounded panels.** Panels 2–4 listed every flow. They now show 100 rows each: the newest TLS flows, the top alerts by score, and timestamp mismatches first, then the newest flows. The web page went from 1,183,174 to about 70,000 bytes on the same data.
3. **Panel 3 vs. the alert rule.** Panel 3 used `ndpi_risk_mask > 0`, from before Part 6 changed the alert rule to severe risks only. It now uses `is_alert = 1`, like the summary count and the Grafana alerts panel.
4. **Read-only folder.** A WAL database needs a `-shm` file beside it. If the daemon ran as root, owns the folder and has stopped, a normal user can't create that file. The dashboard now falls back to reading the file as a fixed snapshot (`immutable=1`). This is safe because nothing is writing to it at that point. With a live writer the normal read-only mode works; that was tested with the files made unwritable.
5. **Startup errors.** A taken port now gives a one-line message, and `run_live.sh` checks after 1 s that the dashboard is still running before printing its URL. Piping the terminal output into `head` / `less` no longer prints a traceback.

### 2. Blocking decisions (`mitigator.py`, sensor)

6. **Forged scans.** The scan rule blocks the source address, and the source can be forged. Blocking scans only after a proven connection was rejected: an attacker can scan from one machine and attack from another. Reporting scans without blocking was rejected too, because a real scanner would keep its results.
   - **Rule now:** a scan "from" a server this network used in the last 24 h (a local address started a flow to it and it answered) is reported as "detected, not blocked". All other scanners are still blocked at once.
   - **Why this is enough:** a forged scan gives the attacker no results, since the replies go to the forged address. The addresses worth forging are the ones the network uses, such as its DNS resolver and update servers.
   - **Tests:** a forged scan "from" a resolver that answered a LAN query is reported, not blocked; the old code blocked it. The same scan more than 24 h after the last contact is blocked. Unanswered or inbound-only contact doesn't protect a scanner. The lab nmap replay is still detected.
7. **Own address.** For ML / severe triggers the target is the responder (`dst_ip`) unless it is protected, so on a host with a public address an inbound flow picked the host itself. The daemon now reads the machine's IPv4 addresses with `ip -j addr`, also inside the `--mitigate-netns` namespace, and re-reads them with each 10 s refresh. They are never blocked, and the `mitigation:` log line lists them (`own=…`). On the old code, an inbound flow to a public host address (score 0.97) blocked the host's own address.
8. **Fragments.** Only the first fragment of a datagram has the TCP/UDP header. The sensor now puts later fragments into one port-less flow per address pair. New test, 60 UDP datagrams in 3 fragments each: the old sensor exported 60 flows with ports taken from payload bytes; the new one exports 2 flows, ports 4500 (60 packets) and ports 0 (120 packets).
9. **Snapshots.** With `-A 60` (the default, also for PCAP replays) a long connection is exported every 60 s with counters since `first_seen_us`.
   - **Mitigator:** the repeat rule now counts a connection once, keyed on the 5-tuple + `first_seen_us`. On the old code, two snapshots of one connection at 0.85 triggered an `ml_repeat` block.
   - **Dashboards:** flow panels and totals read one row per connection, the latest record, in SQLite, ClickHouse and Grafana. SQLite builds that set once per refresh as a temporary table.
   - **Check:** 3,634 records (3,604 connections plus 30 extra snapshots) give exactly the same panels 1–5 and totals as the 3,604 records alone, and SQLite and ClickHouse agree on every panel.
   - **Cost:** a full refresh on 109,020 rows takes 0.56 s, against 0.11 s before. The first version, which rebuilt the set in every query, took 2.03 s.
   - **Existing data:** the Part 7 database has no snapshot rows, so its numbers don't change.

### 3. Crashes and data loss

10. **`zmq_sink` overflow.** `zmq_recv` returns the full message length even when it truncated the message, and `buf[n] = '\0'` then wrote past the 64 KiB stack buffer. Messages over the limit are now dropped with a log line and still counted for `-n`. With AddressSanitizer, a 65,540-byte message crashed the old binary (stack-buffer-overflow) and is dropped by the new one, which then exits normally after 2 messages.
11. **Malformed records.** Three inputs used to stop the daemon; each is now rejected into `rejected.jsonl`:
    - integers ≥ 2^63 in `u64` fields, which pass validation but don't fit SQLite's signed 64-bit integers. The limit is now 2^63 − 1; nDPI keeps `NDPI_MAX_RISK` ≤ 63, so real risk masks stay below 2^63.
    - JSON integers too large for a float (`OverflowError`)
    - deeply nested JSON (`RecursionError`, not a `ValueError`)

    On a test file with 3 good and 3 bad records, the old daemon crashed and the new one accepted 3, rejected 3 and exited 0. The value 2^63 − 1 is still accepted.
12. **ClickHouse-only mode.** After one failed write the store was removed, and only `auto` mode re-attached it. Tested with a fake ClickHouse that fails insert #3:
    - `--backend clickhouse`: the old daemon exited 0 and lost rows 4–5. The new one stops with exit code 1 and says how many rows were written.
    - `--backend both`: ClickHouse now re-attaches like `auto`. Verified: it re-attached at the next 30 s probe, and the next insert succeeded.

### 4. Live runs

13. **Orphaned root daemon.** With `use_pty`, sudo starts the command as a process-group leader; `setsid` then forks, so `$!` was not the daemon. Reproduced under a real terminal with sudo 1.9.17: `$!` had already exited, and the root process survived `sudo kill`. The daemon's shell now writes its own PID to `logs/daemon-*.pid` just before it `exec`s the daemon. `cleanup()` signals that PID and waits for it to exit.
14. **Root-owned files.** `run_live.sh` now gives `sentinel_flows.db*` and the JSONL outputs back to the user (`sudo chown`) at start and after the daemon stops. Checked with root-owned test files. Without the fix, the daemon fails with `PermissionError`.
15. **Live send stall.** The "degraded" flag still allowed one 200 ms blocking send per flow in live mode. Now a live sensor doesn't wait at all after a drop, until a send succeeds again; PCAP replay is unchanged. Measured with a full queue and no consumer: 10 sends took 2.00 s before and 0.00 s after (live), and 2.00 s for PCAP both times.

### 5. Tests and checks

- Engine: daemon 15/15, mitigator 36/36 (4 new).
- Sensor: `test_flow` 13/13, `test_stats` 24/24, PCAP tests 12/12 (1 new: fragments).
- nftables lab test in network namespaces (`lab_nftables_netns.py`): passes, and the host's own ruleset is unchanged.
- `run_live.sh -i lo --serve` (dry-run) under a real terminal: 13 flows captured and stored, the dashboard came up, and Ctrl+C stopped everything. No process was left running, and all files are owned by the user.
- ClickHouse 24.8 in a temporary container: the dashboard output matches SQLite on every panel, and all 6 Grafana queries run.

### 6. Not done / caveats

- **Scan rule gap.** An attacker who first gets one of the network's machines to connect to their server, for example through a link, could then scan from that server without being blocked. The scan is still reported, and the ML / severe-risk rules still apply to that address.
- **Cold start.** Right after the daemon starts it hasn't learned which servers the network uses, so a forged scan in the first seconds can still block one for 15 min.
- **Not checked:** whether a single forged inbound packet can trigger a severe-risk or ML block of its forged source. The policy would allow it.
- **Flow direction.** If capture starts mid-connection, the sensor's `src` is whoever sent the first packet it saw, so the scan rule may count a client's ephemeral port. Unchanged.
- `run_live.sh --block` was tested in parts (PID tracking under sudo with a terminal, the `chown`), not as a full blocking run. Grafana's queries were run on ClickHouse, but the Grafana UI wasn't opened.
- The sensor must be rebuilt (`make sensor`) on every other machine that runs it.
- An existing mitigator test leaves an SQLite connection open (`ResourceWarning`; `SqliteEventSink` has no `close()`).

### 7. What may and may not be said

**May be said:**
- A code review found 15 bugs in the dashboard, daemon, mitigator, sensor and live-run script. All were fixed, and each fix was checked against a reproduction of the bug.
- Forged scans can no longer block a server the network used in the last 24 h, while other scanners are still blocked immediately.
- Dashboard totals count each connection once, in SQLite, ClickHouse and Grafana.

**Must not be said:**
- **That the system can't be abused with forged packets.** See §6: the lured-connection gap, cold start, and single-packet severe / ML triggers.
- **That `run_live.sh --block` was tested end to end live.**
- **That the code is free of bugs.** The review covered the code files once; docs and data were not reviewed.

---

<a id="part-9"></a>

## Part 9 — Conversation timing features (`fv2`), retrain

Date: 2026-10-27. Model `lgbm+iforest-fv2-58fb9fc3` replaces `203d33a1`. Plan items P0.3, P0.5 and P2 in `IMPROVEMENT_PLAN.md`.

### 0. Summary

- Until now the model scored each flow alone. A beacon that checks in every 4 s with the same bytes each time looked like 97 unrelated small flows.
- `features.py` now keeps a short history per **conversation** (this host, server IP, server port, protocol) and adds 5 features about the **earlier** connections in it: how regular the gaps between their starts are, the typical gap, and whether their sizes repeat.
- Same code in training and in the daemon, fed in sensor export order, with time taken from the flow records. Checked: scores from the live path and the training path match to 7 × 10⁻⁷ on 3 training captures (1,701 flows).
- Results, all at the same 1 % calibrated false-alarm budget:

| | `203d33a1` (fv1) | `58fb9fc3` (fv2) |
|---|---|---|
| Cross-validation, malicious flows caught (5 seeds) | 0.64 ± 0.08 | **0.79 ± 0.04** |
| Cross-validation, C2 servers with ≥ 1 alert (of 186, 5 seeds) | 128 ± 4 | 124 ± 4 |
| Holdout: infections / endpoints alerted | 5/5, 17/23 | 5/5, **18/23** |
| Holdout: malicious flows caught / false alerts | 27 % / 12 | **71 %** / 10 |
| Holdout: per-IP blocks (malicious / benign) | 14/23 / 2 | 14/23 / 2 |
| Real benign captures, dry-run blocks per hour (own PC ×2, Windows 7) | 19, 11, 85 | 22, 9, 67 |
| 5 RAT cases (`NEW_DATA_REVIEW.md`): cases with the C2 blocked | 4/5 | 4/5 |

### 1. Definitions

- **Conversation:** `(src_ip, dst_ip, dst_port, protocol)`, only when the server is an Internet address (`features.is_internet`: global and not multicast; Python's `is_global` alone counts mDNS and SSDP as global).
- **Connection:** one client source port inside a conversation. The sensor splits a long idle TCP connection into a new record every time it is quiet for 30 s; Chrome's 45 s keep-alive to `mtalk.google.com` produced 63 records from one connection, all looking periodic. Same source port = same connection, so they now count once (P0.5). Snapshots of one flow update that connection instead of adding one.
- **History:** the last 20 connections per conversation, 24 h expiry, at most 50,000 conversations (least recently used dropped). Only connections that **started before** the scored one count.

### 2. The features, and the version that was rejected

The first version (11 features) also gave the model counts (earlier connections, connections in the last 60 s / 300 s) and conversation age. It raised per-flow recall to 0.83 but caught **fewer** C2 servers (115 ± 1 of 186). The reason: in the training captures, benign flows rarely have history (short captures, mostly LAN traffic: 540 of 3,438 benign MTA flows) while C2 almost always does (2,581 of 2,826). The model learned "no earlier connection = benign" and lost servers contacted only once or twice. On a real PC almost every flow has history, so the same shortcut would not hold.

The kept version gives the model only **evidence of a pattern**. Every feature is 0 when there is none, so a first contact and a conversation with no pattern look identical:

| Feature | Value |
|---|---|
| `conv_periodicity` | share of gaps within ±20 % of the median gap, rescaled so ≤ 0.5 → 0 and 1 → 1; needs ≥ 3 gaps |
| `conv_log_beacon_interval_s` | log(1 + median gap) when `conv_periodicity` > 0 |
| `conv_same_size_ratio` | share of earlier connections with the most common (bytes up, bytes down), only if a pair repeats |
| `conv_up_regularity`, `conv_pkt_regularity` | max(0, 1 − 4 × CV) of bytes up / packet count across earlier connections |

Counts, age and gap statistics are still computed (`ConversationTracker.stats`) for a later rule-based beacon report (plan P3), but not given to the model.

### 3. What changed per family (cross-validation, seed 42)

- Large gains where C2 beacons over HTTP: Gozi + Cobalt Strike 0.61 → 0.98, XLoader 0.38 → 0.81, Lumma 0.34 → 0.72, SSLoad + Cobalt Strike 0.33 → 0.83.
- **njRAT is still missed (0.01).** Its features are a textbook beacon (gap 4.0 s, periodicity 1.0, identical sizes), and they push its score up by about +3.5 in log-odds, but it is the only raw-TCP beacon in the training data and the protocol prior wins. More raw-TCP RAT captures (P4.1) and the P3 beacon report are the fixes.
- Losses: Latrodectus 0.48 → 0.18 per flow, and 4–6 servers contacted once or twice (within the seed spread of ± 4 servers).
- Holdout: the 404 TDS + Cobalt Strike capture goes from 81 to 1,435 of 2,227 malicious flows caught.

### 4. Live behaviour

- The daemon keeps the history in memory (`OnnxScorer.conversations`); a restart starts it empty, so the first minutes after a restart score like the old model.
- Training uses `-A 0` (one record per flow), live uses `-A 60` snapshots. A connection longer than 60 s is therefore known to the tracker earlier live than in training. This only affects long connections, and only the history of later ones.
- `daemon.py --lab-conversations` also tracks private servers, for host-only lab tests (plan P1.2). The model was not trained that way.

### 5. Tests

- `engine-ml/tests/test_features.py` (new, 14): beacon, jittered beacon, irregular history = no history, keep-alive pieces = one connection, snapshot + final record, only earlier connections count, size statistics, Internet-only rule and lab mode, expiry, both caps, `is_internet` on SSDP / LLMNR / mDNS / broadcast.
- `test_daemon.py`: + history carries across batches (16 tests). `test_mitigator.py`: 38, unchanged.
- ONNX parity at export: max difference 2.9 × 10⁻⁷, 0 of 12,127 alert decisions differ.

### 6. Must not be said

- That timing features catch raw-TCP RATs: njRAT is still missed.
- That the false-alarm problem on real PCs is solved: dry-run blocks per hour on the three benign captures went from 115 to 98 in total, still far above the training rate. Benign training data from real hosts (P4.2) is the fix.
- That C2 server coverage improved in cross-validation: it is within noise (124 ± 4 vs 128 ± 4).

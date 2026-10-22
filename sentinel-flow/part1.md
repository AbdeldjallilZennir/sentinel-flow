# SentinelFlow — Part 1: C Packet Capture Sensor

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Component:** Part 1, C packet capture sensor
**Tree:** `/home/joe/cv_work/sentinel-flow/sensor-c/`
**Date:** October 21, 2026
**Status:** fixes applied, end-to-end delivery still blocked

> [!info] Scope
> This document replaces the previous Part 1 write-up. It covers only the C sensor: how it was built on this Kali host, the five fixes that were applied and compiled, the unit tests that actually ran, the three JSON records captured on stdout with `-v`, the partial ndpiReader cross-check, and the ZMQ path that is still broken. Nothing in this report is a throughput number, a valgrind result, or a claim that a downstream consumer received a message. Where a check was not run, it is listed as not run.

---

## 1. Executive summary

Part 1 is a userspace sensor. It reads packets with libpcap (offline PCAP or a live interface flag), keeps one `flow_entry_t` per bidirectional 5-tuple in a uthash table, asks nDPI 6.1 for an application label, a JA4 client string, and a risk mask, and emits one JSON object per finished flow. The object is handed to a ZeroMQ `PUSH` socket and, when `-v` is set, printed to stdout as well. Decryption is not part of the design. The features are metadata: addresses, ports, IP protocol, nDPI's label, JA4 when a TLS handshake was seen, byte and packet counts, inter-arrival and payload-length statistics, and two timestamps.

Five defects that were present in that pipeline have been changed in source and the tree has been rebuilt. The direction used for export is no longer the sorted hash key. Welford minima no longer stay at 0.0 after a `calloc`. Flows that end before nDPI sets `detection_completed` now pass through `ndpi_detection_giveup` at export. The process links one copy of cJSON, the copy compiled from `src/cJSON.c`, and does not also link `libcjson.so`. `ZMQ_LINGER` on the publisher is 1000 ms instead of 0. A small `zmq_sink` utility was added so a consumer could be pointed at `ipc:///tmp/ndpi_flows.sock`.

> [!success] What is actually shown to work
> `./test_stats` printed `=== Results: 24 passed, 0 failed ===`. `cmake .. -DCMAKE_BUILD_TYPE=Debug` followed by `make -j$(nproc)` produced `sensor`, `zmq_sink`, and `test_stats` with zero warnings under `-Wall -Wextra -Wpedantic -O2`. The sensor link line no longer contains `libcjson`. With `-v`, three offline captures produced one JSON object each: DNS (`app_protocol` `DNS`), HTTP (`HTTP.Google`), and a full TLS handshake (`TLS.ntop`) whose `ja4_client` is `t12d6707h2_2955a3196ffa_c83f907a73d3`. On the TLS file, ndpiReader also reported one flow, 109 packets, and protocol `ntop`.

> [!warning] What is not shown, and must not be claimed
> `zmq_sink` never received a message. Three wiring attempts all ended at zero messages, so `ZMQ_LINGER=1000` is compiled and unproven. The 23 keys present in the captured objects were checked on stdout, not on the socket. `src/zmq_sink.c` now calls `zmq_bind`, while the last binary that was successfully compiled was built from the `zmq_connect` variant, and `sensor` also binds. As the tree stands, both ends bind. Timestamps are emitted as JSON numbers and are already collapsing (`first_seen_us` and `last_seen_us` print identical while `flow_duration_ms` is not zero). valgrind was not run. No packets-per-second figure exists. Live `-i` capture was not executed. The 30-second expiry path and the signal flush path were not triggered. DNS and HTTP were not cross-checked with ndpiReader. No PCAP in this set produced a non-zero `ndpi_risk_mask`.

The previous status line that called the sensor "functional" with "quantitative validation pending" is withdrawn. The correct status is the one in the header: the fixes are in, the stdout export can be read, and end-to-end delivery is still blocked.

---

## 2. Where the work stands

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

## 3. Environment, and why headers are vendored

### 3.1 Host toolchain

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

### 3.2 Apt could not supply `-dev` packages

> [!warning] No archive access
> `apt-get install -y libndpi-dev uthash-dev libcjson-dev libzmq3-dev` failed at the fetch stage. `kali.download` was unreachable and the IPv6 route was missing. No `-dev` package from that command was installed. The tree is shaped around that failure. Replacing the vendored headers with distro packages was not possible in this session, and this report does not assume a later `apt-get` succeeded.

Consequences, one library at a time:

- **libzmq.** The runtime loader can open `libzmq.so.5`. There was no `zmq.h`, and there was no `libzmq.so` development symlink. A symlink was created by hand so `-lzmq` resolves, and `src/zmq.h` was written by hand so the sensor compiles. That header is a project file, not a copy installed by the package manager.
- **libcjson.** Only `libcjson.so.1` was present. There was no development header. A symlink was created, and both the header and the implementation were embedded: `src/cJSON.h` and `src/cJSON.c`. Fix 4a then stopped the build from linking the system `.so` at all, so the embedded `.c` is the only cJSON in the process.
- **uthash.** No `uthash-dev` package. `src/uthash.h` was copied from `/home/joe/nDPI/src/lib/third_party/include/uthash.h`.
- **nDPI.** There is no installed `libndpi-dev`. Includes come from `/home/joe/nDPI/src/include` and `/home/joe/nDPI/src/lib/third_party/include`. The shared object is the one in the nDPI build tree.

libpcap is the exception: the header and the library were already usable, and CMake uses `find_library(pcap REQUIRED)`.

### 3.3 What that means for the binary

The sensor is not a portable "link against distro nDPI" binary. It is tied to:

1. the nDPI 6.1 tree at `/home/joe/nDPI` (API and ABI of that build),
2. a hand-written `zmq.h` matched to libzmq 4.3.5 as present here,
3. the embedded cJSON, whose number printer is the one that emits the timestamps in §9,
4. a copied `uthash.h`.

> [!bug] Hand-written `zmq.h` is a standing risk
> The publisher and the sink both include `src/zmq.h`, not a system header. Socket-option constants and function prototypes in that file were not produced by the libzmq build. The delivery failure in §8 is explained by bind/connect timing, not by a proven header mismatch, but a hand-written header remains an unverified surface. This session did not diff `src/zmq.h` against upstream 4.3.5 headers, because those headers were not on the machine.

---

## 4. Source tree and build

### 4.1 Files

`sensor-c/CMakeLists.txt` builds three targets.

| Target | Sources | Libraries |
|---|---|---|
| `sensor` | `src/main.c`, `src/flow_table.c`, `src/ndpi_wrapper.c`, `src/zmq_publisher.c`, `src/stats.c`, `src/cJSON.c` | libndpi, libpcap, libzmq, `libm`, `pthread`. Not libcjson. |
| `zmq_sink` | `src/zmq_sink.c` | libzmq only |
| `test_stats` | `src/test_stats.c` | `libm` only |

Headers and the extra translation units sitting next to those sources: `src/flow_table.h`, `src/ndpi_wrapper.h`, `src/zmq_publisher.h`, `src/stats.h`, `src/cJSON.h`, `src/zmq.h`, `src/uthash.h`.

A line count taken before `zmq_sink.c` and `test_stats.c` existed was **3,968 lines across 15 `.c`/`.h` files**. Those two files were added after that count. This report does not replace 3,968 with a new total.

`stats.h` holds the Welford functions as `static inline`. `test_stats.c` includes that header and does not link `stats.c`. `sensor` still compiles `src/stats.c` as its own translation unit.

### 4.2 CMake facts that matter

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

### 4.3 Build result

> [!success] Build
> `cmake .. -DCMAKE_BUILD_TYPE=Debug` then `make -j$(nproc)` produced all three targets. The compiler reported zero warnings under `-Wall -Wextra -Wpedantic -O2`. The `sensor` link line does not contain `libcjson`.

That is the verification for "it compiles." It is not verification of ZMQ delivery, leak freedom, or packet rate.

---

## 5. The five fixes

Each subsection is symptom, root cause, the change as it stands in the tree, and what was actually used to check it.

### 5.1 Fix 1 — canonical key vs export direction

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

### 5.2 Fix 2 — Welford `min_val` stuck at 0, and the IAT guard

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

### 5.3 Fix 3 — protocol label on flows that end early

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

### 5.4 Fix 4a — one cJSON in the process

**Symptom.** The project compiled `src/cJSON.c` and also linked `/usr/lib/x86_64-linux-gnu/libcjson.so`. Those are two cJSON implementations. `cJSON` is a struct with a public layout. If the two copies disagree about that layout, code that allocates on one side and reads on the other is an ABI break inside a single process. On this host the system side had no header (§3.2), which makes "link the `.so` and compile our `.c`" worse, not better.

**Root cause.** `find_library(cjson)` plus `src/cJSON.c` in `SENSOR_SOURCES`.

**Change.** `CMakeLists.txt` no longer searches for `cjson` and no longer puts it on the link line. `src/cJSON.c` is always compiled into `sensor`. The configure message is the check:

```text
cJSON: using embedded src/cJSON.c (system libcjson NOT linked)
```

The built `sensor` link line does not contain `libcjson`.

**Verification.** Configure output and the link line, as above. No runtime test loaded the system `libcjson.so` and compared struct sizes. The JSON in §7 was produced by the embedded printer (`cJSON_PrintUnformatted`), which is also why §9 is about that printer and not about the system library.

### 5.5 Fix 4b — publisher linger

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

### 5.6 Fix 5 — `zmq_sink`

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

## 6. Unit tests

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

## 7. End-to-end JSON on stdout

### 7.1 How the records were obtained

The sensor's `-v` flag prints each exported JSON object to stdout in addition to the ZeroMQ send. The three runs below are offline reads. The objects are what stdout showed. They are not what `zmq_sink` showed. `zmq_sink` showed nothing (§8).

| Run | File | Provenance stated for this session |
|---|---|---|
| DNS | `pcaps/test_dns.pcap` | Taken from the nDPI corpus file `dns.pcap` |
| HTTP | `pcaps/test_http.pcapng` | 10 packets |
| TLS | `pcaps/test_tls_full.pcap` | Copied from nDPI `443-curl.pcap`, 109 packets |

One object was captured per file. Each object is one flow.

### 7.2 DNS

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

### 7.3 HTTP

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

### 7.4 TLS, and the ndpiReader cross-check

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

### 7.5 Field inventory

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

## 8. Where the work stopped

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

## 9. New bug: timestamp precision

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

## 10. Remaining backlog

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

## 11. Phase 2 (unchanged, and gated)

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

## 12. What a defence may say

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

/*
 * main.c — SentinelFlow C Sensor (Phase 1, v2)
 *
 * High-speed packet capture engine using libpcap + nDPI 6.x.
 * Reads from a live interface (-i eth0) or offline PCAP (-r file.pcap),
 * tracks bidirectional flows in a uthash hash table, extracts:
 *   - L7 protocol via nDPI
 *   - JA4 TLS fingerprint
 *   - nDPI risk bitmask
 *   - Running IAT & packet-length statistics (Welford's algorithm)
 *
 * Completed/expired flows are serialized to JSON and pushed over
 * ZeroMQ (IPC PUSH socket) for downstream ML inference & ingestion.
 * With -v each JSON record is also printed to stdout.
 *
 * Bug fixes (v2):
 *   1. orig_src/dst recorded on first packet; bytes_up/bytes_down
 *      keyed on orig_src_ip:orig_src_port, not canonical direction.
 *   2. IAT update guarded by pkt_count > 1 (was already correct).
 *   3. ndpi_detection_giveup() called at export time for flows that
 *      finished before detection_completed was set.
 *
 * Usage:
 *   ./sensor -r capture.pcap             # offline replay
 *   ./sensor -r capture.pcap -v          # + print JSON to stdout
 *   ./sensor -i eth0                     # live capture
 *   ./sensor -r capture.pcap -z tcp://0.0.0.0:5555
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>

#include "flow_table.h"
#include "ndpi_wrapper.h"
#include "zmq_publisher.h"
#include "cJSON.h"

/* ── Constants ───────────────────────────────────────────────────── */

#define DEFAULT_ZMQ_ENDPOINT  "ipc:///tmp/ndpi_flows.sock"
#define FLOW_EXPIRE_SEC       30
#define NDPI_MAX_PACKETS      15
#define EXPIRE_CHECK_INTERVAL 1000    /* housekeeping every N packets ... */
#define HOUSEKEEPING_US       1000000 /* ... or every 1 s of capture time */
#define FLOW_ACTIVE_TIMEOUT_SEC 60    /* default for -A; 0 disables       */
#define SNAP_LEN              65535
#define ZMQ_DRAIN_MS          60000   /* max wait at exit for a slow consumer */

/* ── Global State ────────────────────────────────────────────────── */

static flow_entry_t *flow_table    = NULL;
static volatile sig_atomic_t running = 1;
static uint64_t total_packets      = 0;
static uint64_t total_flows        = 0;
static uint64_t exported_flows     = 0;   /* delivered to the ZMQ queue */
static uint64_t dropped_flows      = 0;   /* ZMQ send failed */
static uint64_t snapshot_records   = 0;   /* active-timeout records sent */
static uint64_t repeats_skipped    = 0;   /* records identical to the last one sent */
static pcap_t  *capture_handle     = NULL; /* for pcap_breakloop() in the signal handler */
static uint64_t active_timeout_us  = (uint64_t)FLOW_ACTIVE_TIMEOUT_SEC * 1000000ULL;
static uint64_t last_housekeeping_us = 0;
static bool     live_capture       = false;
/* How long one flow may wait for a full ZMQ queue: offline replay has no
 * deadline so it waits (no data loss); live capture must not stall. */
static int      send_patience_ms   = 200;
static bool     verbose            = false;   /* -v flag */

/* ── Signal Handler ──────────────────────────────────────────────── */

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
    if (capture_handle)
        pcap_breakloop(capture_handle);   /* documented as safe in a signal handler */
}

/* FNV-1a over the serialized record; 0 is reserved for "nothing sent yet". */
static uint64_t record_hash(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

/* ── Helpers ─────────────────────────────────────────────────────── */

static inline uint64_t timeval_to_us(const struct timeval *tv)
{
    return (uint64_t)tv->tv_sec * 1000000ULL + (uint64_t)tv->tv_usec;
}

static void ip_to_str(uint32_t ip_net, char *buf, size_t len)
{
    struct in_addr addr = { .s_addr = ip_net };
    inet_ntop(AF_INET, &addr, buf, (socklen_t)len);
}

/* ── Flow Export (JSON over ZMQ, optionally stdout) ──────────────── */

/* Serialize the flow's current state and push it. Used both for the
 * final record (export_flow) and for active-timeout snapshots. */
static void emit_flow(flow_entry_t *entry)
{
    /* ── Addresses: use ORIGINAL first-packet 5-tuple ───────────── */
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    ip_to_str(entry->orig_src_ip, src_str, sizeof(src_str));
    ip_to_str(entry->orig_dst_ip, dst_str, sizeof(dst_str));

    char proto_name[128];
    ndpi_wrapper_protocol_name(entry->detected_protocol,
                               proto_name, sizeof(proto_name));

    const char *ja4 = "N/A";
    ndpi_risk risk   = 0;
    if (entry->ndpi_flow) {
        ja4  = ndpi_wrapper_get_ja4(entry->ndpi_flow, entry->detected_protocol);
        risk = ndpi_wrapper_get_risk(entry->ndpi_flow);
        if (!ja4) ja4 = "N/A";
    }

    char risk_str[512];
    ndpi_wrapper_risk_to_str(risk, risk_str, sizeof(risk_str));

    /* ── Derived features ────────────────────────────────────────── */
    double flow_duration_ms = (double)(entry->last_seen_us - entry->first_seen_us)
                              / 1000.0;
    double bytes_ratio = 0.0;
    if (entry->bytes_down > 0)
        bytes_ratio = (double)entry->bytes_up / (double)entry->bytes_down;
    double small_pkt_ratio = 0.0;
    if (entry->pkt_count > 0)
        small_pkt_ratio = (double)entry->small_pkt_count
                          / (double)entry->pkt_count;

    /* ── Build JSON ──────────────────────────────────────────────── */
    cJSON *root = cJSON_CreateObject();
    if (!root) return;

    /* Network identity — original direction */
    cJSON_AddStringToObject(root, "src_ip",   src_str);
    cJSON_AddStringToObject(root, "dst_ip",   dst_str);
    cJSON_AddNumberToObject(root, "src_port", ntohs(entry->orig_src_port));
    cJSON_AddNumberToObject(root, "dst_port", ntohs(entry->orig_dst_port));
    cJSON_AddNumberToObject(root, "protocol", entry->key.protocol);

    /* nDPI fields */
    cJSON_AddStringToObject(root, "app_protocol",   proto_name);
    cJSON_AddStringToObject(root, "ja4_client",     ja4);
    /* The risk mask uses all 64 bits (e.g. "Probing Attempt" is bit 55).
     * A double holds integers exactly only up to 2^53, so printing it as
     * a cJSON number corrupted the low bits; print the exact integer. */
    char risk_num[24];
    snprintf(risk_num, sizeof(risk_num), "%" PRIu64, (uint64_t)risk);
    cJSON_AddRawToObject(root, "ndpi_risk_mask", risk_num);
    cJSON_AddStringToObject(root, "ndpi_risk_str",  risk_str);

    /* Counters */
    cJSON_AddNumberToObject(root, "pkt_count",  entry->pkt_count);
    cJSON_AddNumberToObject(root, "bytes_up",   (double)entry->bytes_up);
    cJSON_AddNumberToObject(root, "bytes_down", (double)entry->bytes_down);
    cJSON_AddNumberToObject(root, "flow_duration_ms", flow_duration_ms);

    /* Welford IAT */
    cJSON_AddNumberToObject(root, "iat_mean",   entry->iat_stats.mean);
    cJSON_AddNumberToObject(root, "iat_stddev", welford_stddev(&entry->iat_stats));
    cJSON_AddNumberToObject(root, "iat_min",
        entry->iat_stats.count > 0 ? entry->iat_stats.min_val : 0.0);
    cJSON_AddNumberToObject(root, "iat_max",
        entry->iat_stats.count > 0 ? entry->iat_stats.max_val : 0.0);

    /* Welford packet length */
    cJSON_AddNumberToObject(root, "pkt_len_mean",
                            entry->pkt_len_stats.mean);
    cJSON_AddNumberToObject(root, "pkt_len_stddev",
                            welford_stddev(&entry->pkt_len_stats));

    /* Derived ratios */
    cJSON_AddNumberToObject(root, "bytes_up_down_ratio", bytes_ratio);
    cJSON_AddNumberToObject(root, "small_pkt_ratio",     small_pkt_ratio);

    /* Timestamps */
    cJSON_AddNumberToObject(root, "first_seen_us", (double)entry->first_seen_us);
    cJSON_AddNumberToObject(root, "last_seen_us",  (double)entry->last_seen_us);

    char *json_str = cJSON_PrintUnformatted(root);
    /* A final record right after an active-timeout snapshot, with no packet
     * in between, is byte-for-byte the snapshot again (2-6 % of records at the default
     * -A 60, 22 % at -A 15). Send each distinct record once. */
    uint64_t h = json_str ? record_hash(json_str) : 0;
    if (json_str && h == entry->last_emit_hash) {
        repeats_skipped++;
        cJSON_free(json_str);
        json_str = NULL;
    }
    if (json_str) {
        if (zmq_publisher_send(json_str, send_patience_ms) != 0) {
            dropped_flows++;
            if (dropped_flows == 1)
                fprintf(stderr, "[sensor] WARNING: ZMQ send failed (consumer too slow "
                        "or absent); flow dropped. Further drops are counted.\n");
        } else {
            exported_flows++;
            entry->last_emit_hash = h;   /* only a delivered record counts as sent */
        }
        if (verbose)
            printf("%s\n", json_str);
        cJSON_free(json_str);
    }

    cJSON_Delete(root);
}

/* Final record: the flow ended (idle expiry) or the sensor is stopping. */
static void export_flow(flow_entry_t *entry)
{
    if (entry->exported)
        return;
    entry->exported = true;

    /* ── Bug fix 3: giveup for flows that ended before detection ── */
    if (!entry->detection_completed && entry->ndpi_flow) {
        struct ndpi_detection_module_struct *mod = ndpi_wrapper_get_module();
        if (mod) {
            entry->detected_protocol =
                ndpi_detection_giveup(mod, entry->ndpi_flow);
            entry->detection_completed = true;
        }
    }
    emit_flow(entry);
}

/* Active timeout: a flow that keeps sending (never idle for 30 s) still
 * gets a record every active_timeout_us, so it can be scored and acted
 * on while the connection is open. The record is cumulative since
 * first_seen_us (same 23-field schema); the flow stays in the table and
 * its final record follows when it ends. Detection is not forced to
 * give up here, so app_protocol reflects nDPI's state at that moment. */
static void snapshot_if_due(flow_entry_t *entry, void *ctx)
{
    uint64_t now_us = *(const uint64_t *)ctx;
    uint64_t ref = entry->last_export_us ? entry->last_export_us
                                         : entry->first_seen_us;
    if (entry->exported || now_us < ref || now_us - ref < active_timeout_us)
        return;
    /* Only flows that are still active (seen within the idle timeout). */
    if (now_us < entry->last_seen_us ||
        now_us - entry->last_seen_us >= (uint64_t)FLOW_EXPIRE_SEC * 1000000ULL)
        return;
    entry->last_export_us = now_us;
    snapshot_records++;
    emit_flow(entry);
}

/* At time now_us: idle expiry and/or active-timeout snapshots. */
static void expire_idle(uint64_t now_us)
{
    if (now_us > (uint64_t)FLOW_EXPIRE_SEC * 1000000ULL)
        flow_table_expire(&flow_table,
                          now_us - (uint64_t)FLOW_EXPIRE_SEC * 1000000ULL,
                          export_flow);
}

static void take_snapshots(uint64_t now_us)
{
    last_housekeeping_us = now_us;
    if (active_timeout_us)
        flow_table_foreach(&flow_table, snapshot_if_due, &now_us);
}

/* ── Packet Processing Callback ──────────────────────────────────── */

/* ── Link-layer decoding ─────────────────────────────────────────── */

static int datalink = DLT_EN10MB;   /* set from pcap_datalink() in main */

static inline uint16_t rd16be(const u_char *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

/*
 * Find where the IPv4 header starts for the capture's link type.
 * Returns 1 and sets *off for IPv4 packets, 0 for anything else.
 * Supported: Ethernet (+ one 802.1Q tag), Linux cooked v1/v2 ("any"
 * device), BSD loopback (DLT_NULL / DLT_LOOP), and raw IP.
 */
static int ipv4_offset(const u_char *pkt, unsigned int caplen, unsigned int *off)
{
    switch (datalink) {
    case DLT_EN10MB: {
        if (caplen < 14) return 0;
        uint16_t type = rd16be(pkt + 12);
        unsigned int o = 14;
        if (type == 0x8100) {                       /* 802.1Q VLAN */
            if (caplen < 18) return 0;
            type = rd16be(pkt + 16);
            o = 18;
        }
        if (type != ETHERTYPE_IP) return 0;
        *off = o;
        return 1;
    }
    case DLT_LINUX_SLL:                             /* 16-byte header */
        if (caplen < 16 || rd16be(pkt + 14) != ETHERTYPE_IP) return 0;
        *off = 16;
        return 1;
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:                            /* 20-byte header */
        if (caplen < 20 || rd16be(pkt) != ETHERTYPE_IP) return 0;
        *off = 20;
        return 1;
#endif
    case DLT_NULL:
    case DLT_LOOP: {                                /* 4-byte AF_ family */
        if (caplen < 4) return 0;
        uint32_t fam;
        memcpy(&fam, pkt, sizeof(fam));
        /* DLT_NULL is host byte order of the *capturing* machine, so
         * accept AF_INET (2) in either byte order. */
        if (fam != 2 && fam != 0x02000000u) return 0;
        *off = 4;
        return 1;
    }
    case DLT_RAW:
#ifdef DLT_IPV4
    case DLT_IPV4:
#endif
        if (caplen < 1 || (pkt[0] >> 4) != 4) return 0;
        *off = 0;
        return 1;
    default:
        return 0;
    }
}

static void packet_callback(u_char *user __attribute__((unused)),
                             const struct pcap_pkthdr *hdr,
                             const u_char *pkt)
{
    total_packets++;

    /* ── Link layer → IPv4 offset ────────────────────────────────── */
    unsigned int ip_offset;
    if (!ipv4_offset(pkt, hdr->caplen, &ip_offset))
        return;
    if (hdr->caplen < ip_offset + sizeof(struct ip)) return;

    /* Active-timeout snapshots: every 1 s of packet time, checked BEFORE
     * this packet joins its flow, so "still active" means the flow was
     * seen within the idle timeout before this packet. Live capture also
     * expires idle flows here (and on the wall clock in the capture
     * loop). Time going backwards does not trigger anything. */
    {
        uint64_t t = timeval_to_us(&hdr->ts);
        if (last_housekeeping_us == 0)
            last_housekeeping_us = t;
        if (t > last_housekeeping_us && t - last_housekeeping_us >= HOUSEKEEPING_US) {
            if (live_capture)
                expire_idle(t);
            take_snapshots(t);
        }
    }


    /* Headers start at offset 14 (or 18), which is not 4-byte aligned.
     * Copy them into aligned locals instead of casting the packet
     * pointer: a direct cast is undefined behaviour (UBSan flagged it)
     * and faults on strict-alignment CPUs. */
    const u_char *ip_pkt = pkt + ip_offset;
    struct ip     ip_hdr;
    memcpy(&ip_hdr, ip_pkt, sizeof(ip_hdr));
    const struct ip *iph = &ip_hdr;

    if (iph->ip_v != 4) return;
    unsigned int ip_hdr_len = (unsigned int)iph->ip_hl * 4;
    if (ip_hdr_len < 20 || hdr->caplen < ip_offset + ip_hdr_len) return;

    /* ── Extract raw 5-tuple (as seen in this packet) ────────────── */
    uint32_t pkt_src_ip   = iph->ip_src.s_addr;
    uint32_t pkt_dst_ip   = iph->ip_dst.s_addr;
    uint16_t pkt_src_port = 0, pkt_dst_port = 0;
    uint16_t payload_len  = 0;

    const u_char   *l4_pkt      = ip_pkt + ip_hdr_len;
    unsigned int    l4_remaining = hdr->caplen - ip_offset - ip_hdr_len;

    /* Only the first fragment of a fragmented datagram has the TCP/UDP
     * header; later ones start with payload. Reading "ports" from them
     * made one fake flow per fragment, which looks like a port scan.
     * Later fragments go into one port-less flow per address pair. */
    bool later_fragment = (ntohs(iph->ip_off) & IP_OFFMASK) != 0;

    if (later_fragment) {
        payload_len = (uint16_t)l4_remaining;
    } else if (iph->ip_p == IPPROTO_TCP && l4_remaining >= sizeof(struct tcphdr)) {
        struct tcphdr tcp_hdr;
        memcpy(&tcp_hdr, l4_pkt, sizeof(tcp_hdr));
        const struct tcphdr *tcph = &tcp_hdr;
        pkt_src_port = tcph->th_sport;
        pkt_dst_port = tcph->th_dport;
        unsigned int tcp_hdr_len = (unsigned int)tcph->th_off * 4;
        if (tcp_hdr_len >= 20 && l4_remaining > tcp_hdr_len)
            payload_len = (uint16_t)(l4_remaining - tcp_hdr_len);
    } else if (iph->ip_p == IPPROTO_UDP && l4_remaining >= sizeof(struct udphdr)) {
        struct udphdr udp_hdr;
        memcpy(&udp_hdr, l4_pkt, sizeof(udp_hdr));
        const struct udphdr *udph = &udp_hdr;
        pkt_src_port = udph->uh_sport;
        pkt_dst_port = udph->uh_dport;
        if (l4_remaining > sizeof(struct udphdr))
            payload_len = (uint16_t)(l4_remaining - sizeof(struct udphdr));
    }

    /* ── Canonical (sorted) key for uthash ───────────────────────── *
     * Lower IP (host order) always in src slot.  When IPs are equal  *
     * the lower port wins.  This ensures both directions land on the  *
     * same hash-table bucket.                                         */
    flow_key_t canonical;
    memset(&canonical, 0, sizeof(canonical));
    canonical.protocol = iph->ip_p;

    bool is_reverse;   /* true when this packet is dst→src direction  */

    if (ntohl(pkt_src_ip) < ntohl(pkt_dst_ip) ||
        (pkt_src_ip == pkt_dst_ip && ntohs(pkt_src_port) <= ntohs(pkt_dst_port)))
    {
        canonical.src_ip   = pkt_src_ip;
        canonical.dst_ip   = pkt_dst_ip;
        canonical.src_port = pkt_src_port;
        canonical.dst_port = pkt_dst_port;
        is_reverse         = false;
    } else {
        canonical.src_ip   = pkt_dst_ip;
        canonical.dst_ip   = pkt_src_ip;
        canonical.src_port = pkt_dst_port;
        canonical.dst_port = pkt_src_port;
        is_reverse         = true;
    }

    /* ── Lookup / create flow ────────────────────────────────────── */
    bool created = false;
    flow_entry_t *flow = flow_table_lookup_or_create(&flow_table,
                                                      &canonical,
                                                      &created);
    if (!flow) return;

    uint64_t pkt_time_us = timeval_to_us(&hdr->ts);

    if (created) {
        total_flows++;
        flow->first_seen_us = pkt_time_us;
        flow->last_pkt_us   = pkt_time_us;

        /* ── Bug fix 1: record the ORIGINAL (first-packet) direction */
        flow->orig_src_ip   = pkt_src_ip;
        flow->orig_dst_ip   = pkt_dst_ip;
        flow->orig_src_port = pkt_src_port;
        flow->orig_dst_port = pkt_dst_port;

        /* Allocate nDPI flow struct */
        flow->ndpi_flow = ndpi_wrapper_alloc_flow();
    }

    /* Captures are not always time-ordered (8 of 577 nDPI test PCAPs
     * have packets that go backwards). Keep first/last as min/max so
     * last_seen_us - first_seen_us can never underflow. */
    if (pkt_time_us > flow->last_seen_us)  flow->last_seen_us  = pkt_time_us;
    if (pkt_time_us < flow->first_seen_us) flow->first_seen_us = pkt_time_us;
    flow->pkt_count++;

    /* ── Byte counters keyed on original direction ───────────────── *
     * Bug fix 1 (cont.): is_reverse is relative to the canonical key *
     * which may not match the original.  Instead compare directly.   */
    bool is_upstream = (pkt_src_ip   == flow->orig_src_ip   &&
                        pkt_src_port == flow->orig_src_port);
    uint16_t ip_len = ntohs(iph->ip_len);
    if (is_upstream)
        flow->bytes_up   += ip_len;
    else
        flow->bytes_down += ip_len;

    if (payload_len < 100)
        flow->small_pkt_count++;

    /* ── Welford: packet length ──────────────────────────────────── */
    welford_update(&flow->pkt_len_stats, (double)payload_len);

    /* ── Welford: IAT (skip first packet — no previous timestamp) ── *
     * Bug fix 2 guard: pkt_count is already incremented above.       */
    if (flow->pkt_count > 1) {
        /* A packet older than the previous one counts as IAT 0 instead
         * of an unsigned underflow (~1.8e19 us). */
        double iat_us = (pkt_time_us >= flow->last_pkt_us)
                        ? (double)(pkt_time_us - flow->last_pkt_us) : 0.0;
        welford_update(&flow->iat_stats, iat_us);
    }
    if (pkt_time_us > flow->last_pkt_us)
        flow->last_pkt_us = pkt_time_us;

    /* ── nDPI: feed packet for protocol detection ────────────────── */
    if (flow->ndpi_flow && !flow->detection_completed &&
        flow->ndpi_packets_processed < NDPI_MAX_PACKETS)
    {
        struct ndpi_detection_module_struct *mod = ndpi_wrapper_get_module();
        if (mod) {
            struct ndpi_flow_input_info input_info;
            memset(&input_info, 0, sizeof(input_info));
            input_info.in_pkt_dir         = is_reverse ? 1 : 0;
            input_info.seen_flow_beginning = (flow->pkt_count <= 1) ? 1 : 0;

            unsigned int ip_pkt_len = hdr->caplen - ip_offset;

            flow->detected_protocol =
                ndpi_detection_process_packet(mod,
                                              flow->ndpi_flow,
                                              ip_pkt,
                                              (unsigned short)ip_pkt_len,
                                              pkt_time_us / 1000,
                                              &input_info);

            flow->ndpi_packets_processed++;

            if (flow->detected_protocol.proto.master_protocol != 0 ||
                flow->detected_protocol.proto.app_protocol    != 0 ||
                flow->ndpi_packets_processed >= NDPI_MAX_PACKETS)
            {
                if (flow->detected_protocol.proto.master_protocol == 0 &&
                    flow->detected_protocol.proto.app_protocol    == 0)
                {
                    flow->detected_protocol =
                        ndpi_detection_giveup(mod, flow->ndpi_flow);
                }
                flow->detection_completed = true;
            }
        }
    }

    /* ── Idle expiry (after the packet joined its flow) ──────────────
     * Every EXPIRE_CHECK_INTERVAL packets, unchanged from Phases 1-3 so
     * offline output with -A 0 is byte-identical. Known limitation: a
     * capture with < 1000 IPv4 packets never idle-expires offline. */
    if (total_packets % EXPIRE_CHECK_INTERVAL == 0)
        expire_idle(pkt_time_us);
}

/* ── Usage ───────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "SentinelFlow C Sensor — Phase 1 v2\n"
        "\n"
        "Usage:\n"
        "  %s -r <pcap_file>              Read from offline PCAP\n"
        "  %s -i <interface>              Capture from live interface\n"
        "\n"
        "Options:\n"
        "  -r <file>       Offline PCAP file to read\n"
        "  -i <iface>      Live capture interface (e.g., eth0)\n"
        "  -z <endpoint>   ZeroMQ endpoint (default: %s)\n"
        "  -A <sec>        Active timeout: also export a snapshot of flows\n"
        "                  still active after <sec> s, then every <sec> s\n"
        "                  (default %d, 0 = off; idle timeout is %d s)\n"
        "  -v              Verbose: also print each flow JSON to stdout\n"
        "  -h              Show this help\n",
        prog, prog, DEFAULT_ZMQ_ENDPOINT, FLOW_ACTIVE_TIMEOUT_SEC, FLOW_EXPIRE_SEC);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    const char *pcap_file = NULL;
    const char *iface     = NULL;
    const char *zmq_ep    = DEFAULT_ZMQ_ENDPOINT;
    int opt;

    while ((opt = getopt(argc, argv, "r:i:z:A:vh")) != -1) {
        switch (opt) {
        case 'r': pcap_file = optarg;  break;
        case 'i': iface     = optarg;  break;
        case 'z': zmq_ep    = optarg;  break;
        case 'v': verbose   = true;    break;
        case 'A': {
            char *end = NULL;
            long sec = strtol(optarg, &end, 10);
            if (!end || *end != '\0' || sec < 0 || sec > 86400) {
                fprintf(stderr, "[sensor] -A must be 0..86400 seconds\n");
                return 1;
            }
            active_timeout_us = (uint64_t)sec * 1000000ULL;
            break;
        }
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (!pcap_file && !iface) {
        fprintf(stderr, "[sensor] error: specify -r <file> or -i <iface>\n");
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    if (ndpi_wrapper_init() != 0) {
        fprintf(stderr, "[sensor] fatal: nDPI initialization failed\n");
        return 1;
    }

    if (zmq_publisher_init(zmq_ep) != 0) {
        fprintf(stderr, "[sensor] fatal: ZeroMQ init failed\n");
        ndpi_wrapper_destroy();
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    if (pcap_file) {
        handle = pcap_open_offline(pcap_file, errbuf);
        if (!handle) {
            fprintf(stderr, "[sensor] pcap_open_offline(%s): %s\n",
                    pcap_file, errbuf);
            zmq_publisher_destroy(ZMQ_DRAIN_MS);
            ndpi_wrapper_destroy();
            return 1;
        }
        fprintf(stderr, "[sensor] reading from PCAP: %s\n", pcap_file);
        send_patience_ms = 10000;
    } else {
        handle = pcap_open_live(iface, SNAP_LEN, 1, 1000, errbuf);
        if (!handle) {
            fprintf(stderr, "[sensor] pcap_open_live(%s): %s\n",
                    iface, errbuf);
            zmq_publisher_destroy(ZMQ_DRAIN_MS);
            ndpi_wrapper_destroy();
            return 1;
        }
        fprintf(stderr, "[sensor] capturing live on: %s\n", iface);
        live_capture = true;
    }
    capture_handle = handle;

    /* Live: pcap_dispatch() can block indefinitely on a quiet interface,
     * which stopped idle expiry, snapshots and Ctrl+C until the next packet.
     * Use a non-blocking handle and wait in poll() with a 1 s timeout. */
    struct pollfd capture_fd = { .fd = -1, .events = POLLIN };
    if (!pcap_file) {
        capture_fd.fd = pcap_get_selectable_fd(handle);
        if (capture_fd.fd < 0) {
            fprintf(stderr, "[sensor] warning: capture has no selectable fd; "
                    "housekeeping waits for packets\n");
        } else if (pcap_setnonblock(handle, 1, errbuf) != 0) {
            fprintf(stderr, "[sensor] warning: pcap_setnonblock: %s; "
                    "housekeeping waits for packets\n", errbuf);
            capture_fd.fd = -1;
        }
    }

    datalink = pcap_datalink(handle);
    {
        switch (datalink) {
        case DLT_EN10MB: case DLT_LINUX_SLL: case DLT_NULL: case DLT_LOOP:
        case DLT_RAW:
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2:
#endif
#ifdef DLT_IPV4
        case DLT_IPV4:
#endif
            fprintf(stderr, "[sensor] link type: %s\n",
                    pcap_datalink_val_to_name(datalink));
            break;
        default:
            fprintf(stderr, "[sensor] warning: unsupported link type %s (%d); "
                    "no packets will be decoded\n",
                    pcap_datalink_val_to_name(datalink), datalink);
        }
    }

    fprintf(stderr, "[sensor] starting packet capture...\n");

    if (active_timeout_us) {
        fprintf(stderr, "[sensor] active timeout: %llu s (snapshots of long flows)\n",
                (unsigned long long)(active_timeout_us / 1000000ULL));
        if (active_timeout_us < (uint64_t)FLOW_EXPIRE_SEC * 1000000ULL)
            fprintf(stderr, "[sensor] warning: -A below the %d s idle timeout also "
                    "snapshots short flows that have already ended, so they get two "
                    "records; use 0 or >= %d\n", FLOW_EXPIRE_SEC, FLOW_EXPIRE_SEC);
    } else
        fprintf(stderr, "[sensor] active timeout: off\n");

    while (running) {
        if (capture_fd.fd >= 0) {
            int pr = poll(&capture_fd, 1, 1000);
            if (pr < 0 && errno != EINTR) {
                perror("[sensor] poll");
                break;
            }
            if (!running)
                break;
        }
        int ret = pcap_dispatch(handle, 64, packet_callback, NULL);
        if (ret == 0 && pcap_file) break;
        if (ret == PCAP_ERROR_BREAK) break;
        if (!pcap_file) {
            /* Live: also run housekeeping on the wall clock, so idle
             * expiry and snapshots happen when no packets arrive. */
            struct timeval now;
            gettimeofday(&now, NULL);
            uint64_t t = timeval_to_us(&now);
            if (last_housekeeping_us && t > last_housekeeping_us &&
                t - last_housekeeping_us >= HOUSEKEEPING_US)
            {
                expire_idle(t);
                take_snapshots(t);
            }
        }
        if (ret == PCAP_ERROR) {
            fprintf(stderr, "[sensor] pcap_dispatch error: %s\n",
                    pcap_geterr(handle));
            break;
        }
    }

    fprintf(stderr, "[sensor] flushing remaining flows...\n");
    flow_table_flush(&flow_table, export_flow);

    fprintf(stderr, "\n"
        "╔══════════════════════════════════════╗\n"
        "║       SentinelFlow Sensor Summary    ║\n"
        "╠══════════════════════════════════════╣\n"
        "║  Packets processed: %-15lu ║\n"
        "║  Flows tracked:     %-15lu ║\n"
        "║  Flows exported:    %-15lu ║\n"
        "║  Flows dropped:     %-15lu ║\n"
        "║  Snapshot records:  %-15lu ║\n"
        "║  Repeats skipped:   %-15lu ║\n"
        "╚══════════════════════════════════════╝\n",
        (unsigned long)total_packets,
        (unsigned long)total_flows,
        (unsigned long)exported_flows,
        (unsigned long)dropped_flows,
        (unsigned long)snapshot_records,
        (unsigned long)repeats_skipped);

    capture_handle = NULL;
    pcap_close(handle);
    zmq_publisher_destroy(ZMQ_DRAIN_MS);
    ndpi_wrapper_destroy();

    /* Offline replay is expected to be lossless: signal data loss. */
    return (pcap_file && dropped_flows > 0) ? 3 : 0;
}

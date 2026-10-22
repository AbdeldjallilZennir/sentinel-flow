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
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
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
#define EXPIRE_CHECK_INTERVAL 1000
#define SNAP_LEN              65535

/* ── Global State ────────────────────────────────────────────────── */

static flow_entry_t *flow_table    = NULL;
static volatile sig_atomic_t running = 1;
static uint64_t total_packets      = 0;
static uint64_t total_flows        = 0;
static uint64_t exported_flows     = 0;
static bool     verbose            = false;   /* -v flag */

/* ── Signal Handler ──────────────────────────────────────────────── */

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
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

static void export_flow(flow_entry_t *entry)
{
    if (entry->exported)
        return;
    entry->exported = true;
    exported_flows++;

    /* ── Bug fix 3: giveup for flows that ended before detection ── */
    if (!entry->detection_completed && entry->ndpi_flow) {
        struct ndpi_detection_module_struct *mod = ndpi_wrapper_get_module();
        if (mod) {
            entry->detected_protocol =
                ndpi_detection_giveup(mod, entry->ndpi_flow);
            entry->detection_completed = true;
        }
    }

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
        ja4  = ndpi_wrapper_get_ja4(entry->ndpi_flow);
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
    cJSON_AddNumberToObject(root, "ndpi_risk_mask", (double)risk);
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
    if (json_str) {
        zmq_publisher_send(json_str);
        if (verbose)
            printf("%s\n", json_str);
        cJSON_free(json_str);
    }

    cJSON_Delete(root);
}

/* ── Packet Processing Callback ──────────────────────────────────── */

static void packet_callback(u_char *user __attribute__((unused)),
                             const struct pcap_pkthdr *hdr,
                             const u_char *pkt)
{
    total_packets++;

    /* ── Parse Ethernet → IP ─────────────────────────────────────── */
    if (hdr->caplen < sizeof(struct ether_header))
        return;

    const struct ether_header *eth = (const struct ether_header *)pkt;
    uint16_t ether_type = ntohs(eth->ether_type);
    unsigned int ip_offset;

    if (ether_type == 0x8100) {   /* 802.1Q VLAN */
        if (hdr->caplen < sizeof(struct ether_header) + 4) return;
        ether_type = ntohs(*(uint16_t *)(pkt + sizeof(struct ether_header) + 2));
        ip_offset  = sizeof(struct ether_header) + 4;
    } else {
        ip_offset  = sizeof(struct ether_header);
    }

    if (ether_type != ETHERTYPE_IP) return;
    if (hdr->caplen < ip_offset + sizeof(struct ip)) return;

    const u_char     *ip_pkt = pkt + ip_offset;
    const struct ip  *iph    = (const struct ip *)ip_pkt;

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

    if (iph->ip_p == IPPROTO_TCP && l4_remaining >= sizeof(struct tcphdr)) {
        const struct tcphdr *tcph = (const struct tcphdr *)l4_pkt;
        pkt_src_port = tcph->th_sport;
        pkt_dst_port = tcph->th_dport;
        unsigned int tcp_hdr_len = (unsigned int)tcph->th_off * 4;
        if (tcp_hdr_len >= 20 && l4_remaining > tcp_hdr_len)
            payload_len = (uint16_t)(l4_remaining - tcp_hdr_len);
    } else if (iph->ip_p == IPPROTO_UDP && l4_remaining >= sizeof(struct udphdr)) {
        const struct udphdr *udph = (const struct udphdr *)l4_pkt;
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

    flow->last_seen_us = pkt_time_us;
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
        double iat_us = (double)(pkt_time_us - flow->last_pkt_us);
        welford_update(&flow->iat_stats, iat_us);
    }
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

    /* ── Periodic flow expiration ────────────────────────────────── */
    if (total_packets % EXPIRE_CHECK_INTERVAL == 0) {
        uint64_t cutoff = pkt_time_us - ((uint64_t)FLOW_EXPIRE_SEC * 1000000ULL);
        flow_table_expire(&flow_table, cutoff, export_flow);
    }
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
        "  -v              Verbose: also print each flow JSON to stdout\n"
        "  -h              Show this help\n",
        prog, prog, DEFAULT_ZMQ_ENDPOINT);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    const char *pcap_file = NULL;
    const char *iface     = NULL;
    const char *zmq_ep    = DEFAULT_ZMQ_ENDPOINT;
    int opt;

    while ((opt = getopt(argc, argv, "r:i:z:vh")) != -1) {
        switch (opt) {
        case 'r': pcap_file = optarg;  break;
        case 'i': iface     = optarg;  break;
        case 'z': zmq_ep    = optarg;  break;
        case 'v': verbose   = true;    break;
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
            zmq_publisher_destroy();
            ndpi_wrapper_destroy();
            return 1;
        }
        fprintf(stderr, "[sensor] reading from PCAP: %s\n", pcap_file);
    } else {
        handle = pcap_open_live(iface, SNAP_LEN, 1, 1000, errbuf);
        if (!handle) {
            fprintf(stderr, "[sensor] pcap_open_live(%s): %s\n",
                    iface, errbuf);
            zmq_publisher_destroy();
            ndpi_wrapper_destroy();
            return 1;
        }
        fprintf(stderr, "[sensor] capturing live on: %s\n", iface);
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
        fprintf(stderr, "[sensor] warning: non-Ethernet link layer (%d)\n",
                pcap_datalink(handle));

    fprintf(stderr, "[sensor] starting packet capture...\n");

    while (running) {
        int ret = pcap_dispatch(handle, 64, packet_callback, NULL);
        if (ret == 0 && pcap_file) break;
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
        "╚══════════════════════════════════════╝\n",
        (unsigned long)total_packets,
        (unsigned long)total_flows,
        (unsigned long)exported_flows);

    pcap_close(handle);
    zmq_publisher_destroy();
    ndpi_wrapper_destroy();

    return 0;
}

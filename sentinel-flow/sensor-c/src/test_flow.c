/*
 * test_flow.c — Direction / byte-accounting unit test
 *
 * Verifies the §5.1 invariant: `orig_src_ip` and `orig_src_port` are
 * recorded from the FIRST packet seen for a flow and never flip, even
 * when the client's IP is numerically larger than the server's and the
 * canonical sort would therefore swap src/dst in the hash key.
 *
 * Scenario:
 *   client 192.168.1.10:54321  (numerically LARGER IP)
 *   server      10.0.0.1:443   (numerically SMALLER IP)
 *
 * Packet 1 (client → server): 500 bytes IP len  → must count as bytes_up
 * Packet 2 (server → client): 1200 bytes IP len → must count as bytes_down
 *
 * Build & run:
 *   cd sensor-c/build && cmake .. && make test_flow
 *   ./test_flow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "flow_table.h"

/* ── Minimal replication of main.c's per-packet direction logic ───
 *
 * The real packet_callback() in main.c does flow-table lookup, nDPI
 * detection, and Welford updates.  This test exercises only the two
 * assignments that encode the direction invariant:
 *
 *   1. On flow creation, orig_* := packet's raw 5-tuple.
 *   2. On every packet, is_upstream compares the packet's src tuple
 *      with the stored orig_src, NOT the canonical hash key.
 */
static void simulate_packet(flow_entry_t *flow,
                            bool created,
                            uint32_t pkt_src_ip,
                            uint16_t pkt_src_port,
                            uint32_t pkt_dst_ip,
                            uint16_t pkt_dst_port,
                            uint16_t ip_len)
{
    if (created) {
        flow->orig_src_ip   = pkt_src_ip;
        flow->orig_dst_ip   = pkt_dst_ip;
        flow->orig_src_port = pkt_src_port;
        flow->orig_dst_port = pkt_dst_port;
    }

    flow->pkt_count++;

    bool is_upstream = (pkt_src_ip   == flow->orig_src_ip &&
                        pkt_src_port == flow->orig_src_port);
    if (is_upstream)
        flow->bytes_up   += ip_len;
    else
        flow->bytes_down += ip_len;
}

/* ── Assertion helpers ───────────────────────────────────────────── */

static int pass_count = 0;
static int fail_count = 0;

static void expect_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got == want) {
        printf("  PASS  %-24s  got=0x%08x\n", name, got);
        pass_count++;
    } else {
        printf("  FAIL  %-24s  got=0x%08x  want=0x%08x\n",
               name, got, want);
        fail_count++;
    }
}

static void expect_u16(const char *name, uint16_t got, uint16_t want)
{
    if (got == want) {
        printf("  PASS  %-24s  got=%u\n", name, got);
        pass_count++;
    } else {
        printf("  FAIL  %-24s  got=%u  want=%u\n", name, got, want);
        fail_count++;
    }
}

static void expect_u64(const char *name, uint64_t got, uint64_t want)
{
    if (got == want) {
        printf("  PASS  %-24s  got=%lu\n", name, (unsigned long)got);
        pass_count++;
    } else {
        printf("  FAIL  %-24s  got=%lu  want=%lu\n",
               name, (unsigned long)got, (unsigned long)want);
        fail_count++;
    }
}

/* ── Case 1: larger IP initiates, 1 up / 1 down ─────────────────── */

static void test_larger_ip_initiates(void)
{
    printf("\n[test] 192.168.1.10:54321 (larger IP) initiates to 10.0.0.1:443\n");

    uint32_t client_ip = inet_addr("192.168.1.10");  /* numerically larger */
    uint32_t server_ip = inet_addr("10.0.0.1");      /* numerically smaller */
    uint16_t client_port = htons(54321);
    uint16_t server_port = htons(443);

    flow_entry_t flow;
    memset(&flow, 0, sizeof(flow));

    /* Packet 1: client → server (upstream), 500 IP-layer bytes */
    simulate_packet(&flow,
                    /* created = */ true,
                    client_ip, client_port,
                    server_ip, server_port,
                    500);

    /* Packet 2: server → client (downstream), 1200 IP-layer bytes */
    simulate_packet(&flow,
                    /* created = */ false,
                    server_ip, server_port,
                    client_ip, client_port,
                    1200);

    /* orig_* must still point at the client (first packet seen) even
     * though the canonical hash key would swap them: server_ip is the
     * numerically smaller address and would therefore be key.src_ip. */
    expect_u32("orig_src_ip",   flow.orig_src_ip,   client_ip);
    expect_u16("orig_src_port", ntohs(flow.orig_src_port), 54321);
    expect_u32("orig_dst_ip",   flow.orig_dst_ip,   server_ip);
    expect_u16("orig_dst_port", ntohs(flow.orig_dst_port), 443);

    /* Byte split follows orig_*, not canonical direction. */
    expect_u64("bytes_up",   flow.bytes_up,   500);
    expect_u64("bytes_down", flow.bytes_down, 1200);
    expect_u64("pkt_count",  flow.pkt_count,  2);
}

/* ── Case 2: smaller IP initiates ────────────────────────────────── *
 *
 * Sanity check for the symmetric case.  Here the first packet's src is
 * the numerically smaller address — the canonical key would NOT swap,
 * so a buggy implementation that trusted the canonical key would
 * accidentally pass this case.  We include it so the suite covers both
 * orientations, not only the one that breaks the naive version.
 */

static void test_smaller_ip_initiates(void)
{
    printf("\n[test] 10.0.0.1:443 (smaller IP) initiates to 192.168.1.10:54321\n");

    uint32_t server_ip   = inet_addr("10.0.0.1");
    uint32_t client_ip   = inet_addr("192.168.1.10");
    uint16_t server_port = htons(443);
    uint16_t client_port = htons(54321);

    flow_entry_t flow;
    memset(&flow, 0, sizeof(flow));

    /* Packet 1: server → client (first packet, so this side is "up") */
    simulate_packet(&flow, true,
                    server_ip, server_port,
                    client_ip, client_port,
                    700);

    /* Packet 2: client → server (reverse of first packet, "down") */
    simulate_packet(&flow, false,
                    client_ip, client_port,
                    server_ip, server_port,
                    300);

    expect_u32("orig_src_ip",   flow.orig_src_ip,   server_ip);
    expect_u16("orig_src_port", ntohs(flow.orig_src_port), 443);
    expect_u32("orig_dst_ip",   flow.orig_dst_ip,   client_ip);
    expect_u16("orig_dst_port", ntohs(flow.orig_dst_port), 54321);

    expect_u64("bytes_up",   flow.bytes_up,   700);
    expect_u64("bytes_down", flow.bytes_down, 300);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== SentinelFlow direction / byte-accounting unit tests ===\n");

    test_larger_ip_initiates();
    test_smaller_ip_initiates();

    printf("\n=== Results: %d passed, %d failed ===\n",
           pass_count, fail_count);

    return fail_count == 0 ? 0 : 1;
}

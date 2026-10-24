/*
 * flow_table.h — 5-tuple flow hash table using uthash
 *
 * Each flow tracks bidirectional packet statistics using Welford's
 * online algorithm, nDPI detection state, and export readiness.
 *
 * The hash key is a *canonical* (direction-normalised) 5-tuple so
 * packets in both directions map to the same entry.  The ORIGINAL
 * first-packet 5-tuple is stored separately and used for export so
 * that src_ip/src_port always refer to the flow initiator.
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <ndpi_api.h>
#include "uthash.h"
#include "stats.h"

/* ── 5-Tuple Flow Key (canonical / sorted for uthash) ───────────── */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;        /* IPPROTO_TCP / IPPROTO_UDP          */
} __attribute__((packed)) flow_key_t;

/* ── Per-Flow State ──────────────────────────────────────────────── */
typedef struct flow_entry {
    flow_key_t key;           /* canonical hash key — MUST be first  */
    UT_hash_handle hh;        /* uthash bookkeeping                  */

    /* ── Original (initiator) 5-tuple ────────────────────────────── *
     * Recorded from the FIRST packet seen for this flow.             *
     * Used in JSON export so src_ip/src_port always = the sender     *
     * of packet #1, regardless of canonical key direction.           */
    uint32_t orig_src_ip;
    uint32_t orig_dst_ip;
    uint16_t orig_src_port;
    uint16_t orig_dst_port;

    /* ── Packet counters ─────────────────────────────────────────── */
    uint32_t pkt_count;
    uint64_t bytes_up;        /* orig_src → orig_dst                 */
    uint64_t bytes_down;      /* orig_dst → orig_src                 */
    uint32_t small_pkt_count; /* payload < 100 bytes                 */

    /* ── Timestamps (microseconds since epoch) ───────────────────── */
    uint64_t first_seen_us;
    uint64_t last_seen_us;
    uint64_t last_pkt_us;     /* for IAT computation                 */

    /* ── Welford running statistics ──────────────────────────────── */
    welford_state_t iat_stats;
    welford_state_t pkt_len_stats;

    /* ── nDPI state ──────────────────────────────────────────────── */
    struct ndpi_flow_struct  *ndpi_flow;
    ndpi_protocol             detected_protocol;
    bool                      detection_completed;
    uint16_t                  ndpi_packets_processed;

    /* ── Export control ──────────────────────────────────────────── */
    bool     exported;        /* final record sent (idle/flush)      */
    uint64_t last_export_us;  /* last active-timeout snapshot, 0=none */
} flow_entry_t;

/* ── Public API ──────────────────────────────────────────────────── */

/*
 * Lookup or create a flow entry.  Returns the entry (never NULL on
 * successful allocation).  *created is set to true when a new entry
 * was inserted.
 */
flow_entry_t *flow_table_lookup_or_create(flow_entry_t **table,
                                          const flow_key_t *key,
                                          bool *created);

/*
 * Expire (remove + free) all flows whose last_seen_us is older than
 * cutoff_us.  Calls export_fn on each expired flow before freeing.
 */
void flow_table_expire(flow_entry_t **table,
                       uint64_t cutoff_us,
                       void (*export_fn)(flow_entry_t *));

/*
 * Flush all flows: export + free regardless of age.
 */
void flow_table_flush(flow_entry_t **table,
                      void (*export_fn)(flow_entry_t *));

/*
 * Call fn(entry, ctx) for every flow (the table is not modified).
 */
void flow_table_foreach(flow_entry_t **table,
                        void (*fn)(flow_entry_t *, void *), void *ctx);

/*
 * Return number of active flows.
 */
uint32_t flow_table_count(flow_entry_t **table);

#endif /* FLOW_TABLE_H */

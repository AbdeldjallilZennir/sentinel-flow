/*
 * flow_table.c — 5-tuple flow hash table using uthash
 *
 * Provides lookup-or-create, expiration, and flush operations.
 * Each flow carries nDPI state and Welford running statistics.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "flow_table.h"
#include "ndpi_wrapper.h"

/* ── Lookup or Create ────────────────────────────────────────────── */

flow_entry_t *flow_table_lookup_or_create(flow_entry_t **table,
                                          const flow_key_t *key,
                                          bool *created)
{
    flow_entry_t *entry = NULL;

    HASH_FIND(hh, *table, key, sizeof(flow_key_t), entry);

    if (entry) {
        *created = false;
        return entry;
    }

    /* Allocate and zero-initialize a new entry */
    entry = (flow_entry_t *)calloc(1, sizeof(flow_entry_t));
    if (!entry) {
        fprintf(stderr, "[flow_table] calloc failed for new flow entry\n");
        *created = false;
        return NULL;
    }

    memcpy(&entry->key, key, sizeof(flow_key_t));
    welford_init(&entry->iat_stats);
    welford_init(&entry->pkt_len_stats);

    HASH_ADD(hh, *table, key, sizeof(flow_key_t), entry);

    *created = true;
    return entry;
}

/* ── Expire Stale Flows ──────────────────────────────────────────── */

void flow_table_expire(flow_entry_t **table,
                       uint64_t cutoff_us,
                       void (*export_fn)(flow_entry_t *))
{
    flow_entry_t *entry, *tmp;

    HASH_ITER(hh, *table, entry, tmp) {
        if (entry->last_seen_us < cutoff_us) {
            if (export_fn && !entry->exported) {
                export_fn(entry);
            }

            HASH_DEL(*table, entry);

            if (entry->ndpi_flow) {
                ndpi_wrapper_free_flow(entry->ndpi_flow);
                entry->ndpi_flow = NULL;
            }
            free(entry);
        }
    }
}

/* ── Flush All Flows ─────────────────────────────────────────────── */

void flow_table_flush(flow_entry_t **table,
                      void (*export_fn)(flow_entry_t *))
{
    flow_entry_t *entry, *tmp;

    HASH_ITER(hh, *table, entry, tmp) {
        if (export_fn && !entry->exported) {
            export_fn(entry);
        }

        HASH_DEL(*table, entry);

        if (entry->ndpi_flow) {
            ndpi_wrapper_free_flow(entry->ndpi_flow);
            entry->ndpi_flow = NULL;
        }
        free(entry);
    }
}

/* ── Iterate ─────────────────────────────────────────────────────── */

void flow_table_foreach(flow_entry_t **table,
                        void (*fn)(flow_entry_t *, void *), void *ctx)
{
    flow_entry_t *entry, *tmp;
    HASH_ITER(hh, *table, entry, tmp) {
        fn(entry, ctx);
    }
}

/* ── Count ───────────────────────────────────────────────────────── */

uint32_t flow_table_count(flow_entry_t **table)
{
    return HASH_COUNT(*table);
}

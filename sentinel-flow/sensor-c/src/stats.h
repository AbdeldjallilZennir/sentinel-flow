/*
 * stats.h — Welford's online algorithm for running mean & variance
 *
 * Tracks mean, variance, min, and max with O(1) memory per metric.
 * Reference: Welford (1962) — "Note on a Method for Calculating
 * Corrected Sums of Squares and Products"
 *
 * Bug fixed (v2): on the very first call (count==1 after increment)
 * min_val and max_val are both initialised to `value`.  Previously
 * the struct was zero-initialised by calloc, so min_val stayed 0.0
 * and the first value was only compared with DBL_MAX (max_val path)
 * giving a correct max but a wrong min on flows where all payloads
 * are > 0.  For IAT the first IAT is always > 0, so min stayed 0.
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <math.h>
#include <float.h>

typedef struct {
    uint64_t count;
    double   mean;
    double   m2;          /* sum of squares of differences from mean */
    double   min_val;
    double   max_val;
} welford_state_t;

/* ── Inline API ──────────────────────────────────────────────────── */

static inline void welford_init(welford_state_t *s) {
    s->count   = 0;
    s->mean    = 0.0;
    s->m2      = 0.0;
    s->min_val = DBL_MAX;
    s->max_val = -DBL_MAX;
}

static inline void welford_update(welford_state_t *s, double value) {
    s->count++;

    /* On the very first sample set min/max directly, then update the
     * running Welford accumulators.  Subsequent samples use the
     * comparison path.  This avoids the calloc-zero bug where
     * min_val would be stuck at 0.0 when all values are positive. */
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

static inline double welford_variance(const welford_state_t *s) {
    return (s->count < 2) ? 0.0 : s->m2 / (double)(s->count - 1);
}

static inline double welford_stddev(const welford_state_t *s) {
    return sqrt(welford_variance(s));
}

#endif /* STATS_H */

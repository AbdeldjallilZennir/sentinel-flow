/*
 * test_stats.c — Unit test for Welford's online algorithm (stats.h)
 *
 * Tests mean, stddev, min_val, and max_val against known fixed vectors
 * computed independently.  Exits 0 on pass, 1 on any failure.
 *
 * Build & run:
 *   cd sensor-c/build && cmake .. && make test_stats
 *   ./test_stats
 */

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include "stats.h"

/* ── Helpers ─────────────────────────────────────────────────────── */

static int pass_count = 0;
static int fail_count = 0;

#define EPS 1e-9

static void check(const char *name, double got, double want, double eps)
{
    double diff = fabs(got - want);
    if (diff <= eps) {
        printf("  PASS  %-30s  got=%.10g  want=%.10g\n", name, got, want);
        pass_count++;
    } else {
        printf("  FAIL  %-30s  got=%.10g  want=%.10g  diff=%.3g\n",
               name, got, want, diff);
        fail_count++;
    }
}

/* ── Test cases ──────────────────────────────────────────────────── */

/*
 * Case 1: single value.
 * Feed only one sample; count=1 so variance=0, stddev=0.
 * min_val and max_val must equal that single sample (bug-fix check).
 */
static void test_single_value(void)
{
    printf("\n[test] Single value: x = 42.0\n");
    welford_state_t s;
    welford_init(&s);
    welford_update(&s, 42.0);

    check("count",   (double)s.count, 1.0,  0.0);
    check("mean",    s.mean,          42.0, EPS);
    check("stddev",  welford_stddev(&s), 0.0, EPS);
    check("min_val", s.min_val,       42.0, EPS);  /* was stuck at 0 before fix */
    check("max_val", s.max_val,       42.0, EPS);
}

/*
 * Case 2: {2, 4, 4, 4, 5, 5, 7, 9}
 * Classic Welford example from Wikipedia / Knuth:
 *   mean   = 5.0
 *   stddev = 2.0 (population std; sample std ≈ 2.138)
 *
 * We use the sample (Bessel-corrected) formula:
 *   variance = m2 / (n-1) = 32 / 7 ≈ 4.571
 *   stddev   ≈ 2.138
 */
static void test_wikipedia_vector(void)
{
    printf("\n[test] Wikipedia vector: {2,4,4,4,5,5,7,9}\n");
    double vals[] = {2, 4, 4, 4, 5, 5, 7, 9};
    int n = (int)(sizeof(vals) / sizeof(vals[0]));

    welford_state_t s;
    welford_init(&s);
    for (int i = 0; i < n; i++) welford_update(&s, vals[i]);

    /* Mean = 40/8 = 5.0 */
    check("count",   (double)s.count, 8.0, 0.0);
    check("mean",    s.mean,          5.0, EPS);

    /* Sample variance = 32/7; sample stddev = sqrt(32/7) */
    double want_var    = 32.0 / 7.0;
    double want_stddev = sqrt(want_var);
    check("variance", welford_variance(&s), want_var,    1e-10);
    check("stddev",   welford_stddev(&s),   want_stddev, 1e-10);

    check("min_val", s.min_val, 2.0, EPS);
    check("max_val", s.max_val, 9.0, EPS);
}

/*
 * Case 3: two identical values — variance must be 0.
 */
static void test_identical_values(void)
{
    printf("\n[test] Two identical values: {7.0, 7.0}\n");
    welford_state_t s;
    welford_init(&s);
    welford_update(&s, 7.0);
    welford_update(&s, 7.0);

    check("mean",    s.mean,           7.0, EPS);
    check("stddev",  welford_stddev(&s), 0.0, EPS);
    check("min_val", s.min_val,        7.0, EPS);
    check("max_val", s.max_val,        7.0, EPS);
}

/*
 * Case 4: IAT-like sequence — small positive values.
 * Vector: {100, 200, 150, 50, 300}  (all in µs)
 *   mean   = 800/5 = 160
 *   m2     = (100-160)^2 + (200-160)^2 + ... (computed step by step)
 *          = 3600 + 1600 + 100 + 12100 + 19600 = 37000  [population]
 *   But Welford computes sample m2; let's compute independently:
 *   deviations from mean 160: -60, 40, -10, -110, 140
 *   sum of squares: 3600+1600+100+12100+19600 = 37000
 *   sample variance = 37000/4 = 9250; stddev = sqrt(9250)
 */
static void test_iat_vector(void)
{
    printf("\n[test] IAT-like vector: {100,200,150,50,300}\n");
    double vals[] = {100.0, 200.0, 150.0, 50.0, 300.0};
    int n = (int)(sizeof(vals) / sizeof(vals[0]));

    welford_state_t s;
    welford_init(&s);
    for (int i = 0; i < n; i++) welford_update(&s, vals[i]);

    check("mean",    s.mean,             160.0,         EPS);
    check("min_val", s.min_val,           50.0,         EPS);
    check("max_val", s.max_val,          300.0,         EPS);
    check("variance",welford_variance(&s),9250.0,       1e-8);
    check("stddev",  welford_stddev(&s), sqrt(9250.0),  1e-8);
}

/*
 * Case 5: welford_init reuse — re-initialising a used struct gives
 * correct results for a fresh sequence.
 */
static void test_reinit(void)
{
    printf("\n[test] Re-init reuse\n");
    welford_state_t s;
    welford_init(&s);
    welford_update(&s, 999.0);
    welford_update(&s, 1.0);

    /* Re-initialise and use with a different sequence */
    welford_init(&s);
    welford_update(&s, 3.0);
    welford_update(&s, 5.0);

    check("mean (after reinit)",    s.mean,           4.0, EPS);
    check("min_val (after reinit)", s.min_val,        3.0, EPS);
    check("max_val (after reinit)", s.max_val,        5.0, EPS);
    check("stddev (after reinit)",  welford_stddev(&s), sqrt(2.0), 1e-10);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== SentinelFlow stats.h unit tests ===\n");

    test_single_value();
    test_wikipedia_vector();
    test_identical_values();
    test_iat_vector();
    test_reinit();

    printf("\n=== Results: %d passed, %d failed ===\n",
           pass_count, fail_count);

    return fail_count == 0 ? 0 : 1;
}

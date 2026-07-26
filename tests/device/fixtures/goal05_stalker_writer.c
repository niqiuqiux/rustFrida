/*
 * Goal 05 fixture.
 *
 * `rf_goal05_compute` is the function the Stalker transform rewrites;
 * `rf_goal05_reference` runs the same arithmetic and is left alone. The batch
 * runner compares them on the calling thread, so a semantic change introduced
 * by hand-emitted code shows up without the test modelling ARM64 in JavaScript.
 *
 * Everything runs synchronously on the caller's thread: the QuickJS facade has
 * no timers yet, so a script that followed a worker thread would have to spin
 * and starve the very transform callbacks it is waiting for.
 */

#include <stdint.h>

static inline int compute_core(int x) {
    int y = x + 7;
    y ^= (y << 3);
    y += (y >> 2);
    y *= 5;
    y -= (x << 1);
    return y;
}

__attribute__((noinline)) int rf_goal05_compute(int x) {
    return compute_core(x);
}

__attribute__((noinline)) int rf_goal05_reference(int x) {
    return compute_core(x);
}

/* Returns the number of rounds where the rewritten function disagreed. */
int rf_goal05_run_batch(int rounds) {
    int mismatches = 0;
    for (int round = 0; round != rounds; round++) {
        int input = round & 0x3f;
        if (rf_goal05_compute(input) != rf_goal05_reference(input))
            mismatches++;
    }
    return mismatches;
}

/* Deliberately branch-heavy so a small event queue overflows quickly. */
int rf_goal05_churn(int rounds) {
    int total = 0;
    for (int round = 0; round != rounds; round++) {
        total += rf_goal05_compute(round & 0x1f);
        total ^= rf_goal05_reference(round & 0x0f);
    }
    return total;
}

uint64_t rf_goal05_compute_size(void) {
    /* Upper bound on the window the transform is allowed to rewrite. */
    return 0x100;
}

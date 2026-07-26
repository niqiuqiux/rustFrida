/*
 * Goal 06 fixture: targets for Memory.patchCode, Memory.scan, findPointers and
 * MemoryAccessMonitor.
 */

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Patched at runtime to return a different constant, which proves both the
 * write and the instruction-cache flush took effect. */
__attribute__((noinline)) int rf_goal06_patch_target(void) {
    return 0x1111;
}

/* A distinctive byte run for the pattern scanners. */
static volatile uint8_t g_haystack[8192];

/* Pointer-sized slots for findPointers. */
static void *g_pointer_slots[16];

/* Pages the access monitor watches. */
static uint8_t g_monitored[65536] __attribute__((aligned(65536)));

void rf_goal06_init(void) {
    memset((void *) g_haystack, 0, sizeof(g_haystack));
    /* Two non-overlapping needles, one deliberately near the end. */
    g_haystack[100] = 0x13;
    g_haystack[101] = 0x37;
    g_haystack[102] = 0x42;
    g_haystack[5000] = 0x13;
    g_haystack[5001] = 0x37;
    g_haystack[5002] = 0x42;

    memset(g_pointer_slots, 0, sizeof(g_pointer_slots));
    g_pointer_slots[3] = (void *) rf_goal06_patch_target;
    g_pointer_slots[9] = (void *) rf_goal06_patch_target;

    memset(g_monitored, 0, sizeof(g_monitored));
}

void *rf_goal06_haystack(void) {
    return (void *) g_haystack;
}

uint64_t rf_goal06_haystack_size(void) {
    return sizeof(g_haystack);
}

void *rf_goal06_pointer_slots(void) {
    return g_pointer_slots;
}

uint64_t rf_goal06_pointer_slots_size(void) {
    return sizeof(g_pointer_slots);
}

void *rf_goal06_monitored(void) {
    return g_monitored;
}

uint64_t rf_goal06_monitored_size(void) {
    return sizeof(g_monitored);
}

/* Touch the monitored region so the monitor has something to report. */
uint8_t rf_goal06_touch_monitored(uint64_t offset) {
    if (offset >= sizeof(g_monitored))
        return 0;
    g_monitored[offset] = (uint8_t) (offset & 0xff);
    return g_monitored[offset];
}

/*
 * A thread that touches the monitored pages on its own.
 *
 * The monitor reports faults taken by the target's own code; a touch driven
 * from a NativeFunction call would be caught by the agent's own fault handling
 * for that call instead, which is not what the monitor is for.
 */
static volatile int g_toucher_stop = 1;
static volatile uint64_t g_touch_rounds = 0;
static pthread_t g_toucher;
static volatile int g_toucher_started = 0;

static void *toucher_main(void *unused) {
    (void) unused;
    while (!g_toucher_stop) {
        for (size_t offset = 0; offset < sizeof(g_monitored); offset += 4096)
            g_monitored[offset] = (uint8_t) (offset & 0xff);
        g_touch_rounds++;
        usleep(2000);
    }
    return NULL;
}

int rf_goal06_start_toucher(void) {
    if (g_toucher_started)
        return 1;
    g_toucher_stop = 0;
    g_touch_rounds = 0;
    if (pthread_create(&g_toucher, NULL, toucher_main, NULL) != 0) {
        g_toucher_stop = 1;
        return 0;
    }
    g_toucher_started = 1;
    return 1;
}

/*
 * Signal only, never join.
 *
 * While a monitor is installed every fault the thread takes re-enters
 * JavaScript synchronously, so a round in progress can take far longer than the
 * script is willing to wait. The thread exits on its own once it finishes the
 * round it is in.
 */
void rf_goal06_stop_toucher(void) {
    if (!g_toucher_started)
        return;
    g_toucher_stop = 1;
    pthread_detach(g_toucher);
    g_toucher_started = 0;
}

uint64_t rf_goal06_touch_rounds(void) {
    return g_touch_rounds;
}

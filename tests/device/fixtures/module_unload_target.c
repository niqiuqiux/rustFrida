#include <stdint.h>

__attribute__((visibility("default"), noinline))
int rf_goal01_gum_target(int value) {
    return value + 1000;
}

__attribute__((visibility("default"), noinline))
int rf_goal01_native_target(int left, int right) {
    return left + right + 2000;
}

__attribute__((visibility("default"), noinline))
int rf_goal01_probe_target(int left, int right) {
    return left + right + 3000;
}

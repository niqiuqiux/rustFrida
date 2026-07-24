#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>

#define FIXTURE_PATH "/data/local/tmp/librf_goal01_unload.so"

static void *fixture_handle;

__attribute__((visibility("default"), noinline))
void rf_goal01_sleep_ms(unsigned int milliseconds) {
    usleep(milliseconds * 1000);
}

__attribute__((visibility("default"), noinline))
int rf_goal01_open(void) {
    if (fixture_handle != NULL)
        return 1;

    fixture_handle = dlopen(FIXTURE_PATH, RTLD_NOW | RTLD_LOCAL);
    return fixture_handle == NULL ? -1 : 0;
}

__attribute__((visibility("default"), noinline))
void *rf_goal01_symbol(int which) {
    const char *name;

    if (fixture_handle == NULL)
        return NULL;

    switch (which) {
    case 1:
        name = "rf_goal01_gum_target";
        break;
    case 2:
        name = "rf_goal01_native_target";
        break;
    case 3:
        name = "rf_goal01_probe_target";
        break;
    default:
        return NULL;
    }

    return dlsym(fixture_handle, name);
}

__attribute__((visibility("default"), noinline))
int rf_goal01_call(int which, int left, int right) {
    void *target = rf_goal01_symbol(which);

    if (target == NULL)
        return -7000 - which;
    if (which == 1)
        return ((int (*)(int)) target)(left);
    return ((int (*)(int, int)) target)(left, right);
}

__attribute__((visibility("default"), noinline))
int rf_goal01_close(void) {
    void *handle = fixture_handle;

    if (handle == NULL)
        return 1;
    fixture_handle = NULL;
    return dlclose(handle);
}

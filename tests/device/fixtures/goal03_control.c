#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>

#define MODULE_PATH "/data/local/tmp/librf_goal03_module.so"

static void *module_handle;
static pthread_t test_thread;
static atomic_int test_thread_running;
static atomic_int test_thread_stop;

static void *rf_goal03_thread_main(void *unused) {
    (void) unused;
    pthread_setname_np(pthread_self(), "goal03-control");
    atomic_store(&test_thread_running, 1);
    while (!atomic_load(&test_thread_stop))
        usleep(1000);
    return NULL;
}

__attribute__((visibility("default"), noinline))
void rf_goal03_sleep_ms(unsigned int milliseconds) {
    usleep(milliseconds * 1000);
}

__attribute__((visibility("default"), noinline))
int rf_goal03_open(void) {
    if (module_handle != NULL)
        return 1;
    module_handle = dlopen(MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    return module_handle == NULL ? -1 : 0;
}

__attribute__((visibility("default"), noinline))
void *rf_goal03_symbol(void) {
    return module_handle == NULL ? NULL : dlsym(module_handle, "rf_goal03_value");
}

__attribute__((visibility("default"), noinline))
int rf_goal03_close(void) {
    void *handle = module_handle;
    if (handle == NULL)
        return 1;
    module_handle = NULL;
    return dlclose(handle);
}

__attribute__((visibility("default"), noinline))
int rf_goal03_thread_start(void) {
    if (atomic_load(&test_thread_running))
        return 1;
    atomic_store(&test_thread_stop, 0);
    if (pthread_create(&test_thread, NULL, rf_goal03_thread_main, NULL) != 0)
        return -1;
    while (!atomic_load(&test_thread_running))
        usleep(1000);
    return 0;
}

__attribute__((visibility("default"), noinline))
int rf_goal03_thread_rename(void) {
    return atomic_load(&test_thread_running)
        ? pthread_setname_np(test_thread, "rf-g03-renamed")
        : -1;
}

__attribute__((visibility("default"), noinline))
int rf_goal03_thread_stop(void) {
    if (!atomic_load(&test_thread_running))
        return 1;
    atomic_store(&test_thread_stop, 1);
    if (pthread_join(test_thread, NULL) != 0)
        return -1;
    atomic_store(&test_thread_running, 0);
    return 0;
}

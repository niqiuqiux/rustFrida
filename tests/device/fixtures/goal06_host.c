#include <dlfcn.h>
#include <unistd.h>

#define FIXTURE_PATH "/data/local/tmp/librf_goal06_memory.so"

int main(void) {
    void *fixture = dlopen(FIXTURE_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (fixture == NULL)
        return 2;
    void (*init)(void) = dlsym(fixture, "rf_goal06_init");
    if (init != NULL)
        init();
    while (1)
        pause();
    return 0;
}

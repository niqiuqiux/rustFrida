#include <dlfcn.h>
#include <unistd.h>

#define FIXTURE_PATH "/data/local/tmp/librf_goal05_stalker_writer.so"

int main(void) {
    void *fixture = dlopen(FIXTURE_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (fixture == NULL)
        return 2;
    while (1)
        pause();
    return 0;
}

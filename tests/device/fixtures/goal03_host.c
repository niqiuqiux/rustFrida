#include <dlfcn.h>
#include <unistd.h>

#define CONTROL_PATH "/data/local/tmp/librf_goal03_control.so"

int main(void) {
    void *control = dlopen(CONTROL_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (control == NULL)
        return 2;
    while (1)
        pause();
    return 0;
}

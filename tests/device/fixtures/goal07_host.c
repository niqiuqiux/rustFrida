/* Goal 07 needs only a live process: the script under test is pure JavaScript. */

#include <unistd.h>

int main(void) {
    while (1)
        pause();
    return 0;
}

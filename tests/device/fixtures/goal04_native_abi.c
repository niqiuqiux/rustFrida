#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

typedef int (*binary_int_callback)(int, int);
typedef double (*mixed_callback)(int, double, float, int);
typedef float (*float_callback)(float);
typedef uint64_t (*gpr9_callback)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t);
typedef double (*fpr9_callback)(double, double, double, double, double,
                               double, double, double, double);
typedef int (*thread_callback)(int);
typedef void (*errno_callback)(void);

struct small_pair {
    int32_t left;
    int32_t right;
};

struct nested_payload {
    struct small_pair pair;
    double scale;
    uint64_t tag;
};

typedef struct small_pair (*small_pair_callback)(struct small_pair, int32_t);
typedef struct nested_payload (*nested_payload_callback)(struct nested_payload);

static thread_callback saved_callback;
static int saved_generation;

__attribute__((visibility("default"), noinline))
int rf_goal04_call_binary(binary_int_callback callback, int left, int right) {
    return callback(left, right);
}

__attribute__((visibility("default"), noinline))
double rf_goal04_call_mixed(mixed_callback callback) {
    return callback(7, 2.5, 1.25f, 9);
}

__attribute__((visibility("default"), noinline))
float rf_goal04_call_float(float_callback callback, float value) {
    return callback(value);
}

__attribute__((visibility("default"), noinline))
uint64_t rf_goal04_call_gpr9(gpr9_callback callback) {
    return callback(1, 2, 3, 4, 5, 6, 7, 8, 9);
}

__attribute__((visibility("default"), noinline))
double rf_goal04_call_fpr9(fpr9_callback callback) {
    return callback(1, 2, 3, 4, 5, 6, 7, 8, 9);
}

struct thread_call {
    thread_callback callback;
    int argument;
    int result;
};

static void *rf_goal04_thread_main(void *opaque) {
    struct thread_call *call = opaque;
    call->result = call->callback(call->argument);
    return NULL;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_call_thread(thread_callback callback, int argument) {
    struct thread_call call = { callback, argument, 0 };
    pthread_t thread;
    if (pthread_create(&thread, NULL, rf_goal04_thread_main, &call) != 0)
        return -1000;
    if (pthread_join(thread, NULL) != 0)
        return -1001;
    return call.result;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_call_errno(errno_callback callback, int value) {
    errno = value;
    callback();
    return errno;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_set_errno(int value) {
    errno = value;
    return value * 2;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_replace_target(int value) {
    return value + 1;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_probe_target(int value) {
    return value + 2;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_saved_generation(void) {
    return saved_generation;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_invoke_saved(int value) {
    return saved_callback == NULL ? -7777 : saved_callback(value);
}

__attribute__((visibility("default"), noinline))
void rf_goal04_save_callback(thread_callback callback) {
    saved_callback = callback;
    saved_generation++;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_variadic_ints(int count, ...) {
    va_list args;
    int result = 0;
    va_start(args, count);
    for (int index = 0; index != count; index++)
        result += va_arg(args, int);
    va_end(args);
    return result;
}

__attribute__((visibility("default"), noinline))
double rf_goal04_variadic_doubles(int count, ...) {
    va_list args;
    double result = 0;
    va_start(args, count);
    for (int index = 0; index != count; index++)
        result += va_arg(args, double);
    va_end(args);
    return result;
}

__attribute__((visibility("default"), noinline))
struct small_pair rf_goal04_small_pair(struct small_pair value, int32_t delta) {
    value.left += delta;
    value.right -= delta;
    return value;
}

__attribute__((visibility("default"), noinline))
struct nested_payload rf_goal04_nested_payload(struct nested_payload value) {
    value.pair.left += 1;
    value.pair.right += 2;
    value.scale *= 2;
    value.tag += 3;
    return value;
}

__attribute__((visibility("default"), noinline))
struct small_pair rf_goal04_call_small_pair(small_pair_callback callback) {
    struct small_pair value = { 20, 22 };
    return callback(value, 5);
}

__attribute__((visibility("default"), noinline))
struct nested_payload rf_goal04_call_nested_payload(nested_payload_callback callback) {
    struct nested_payload value = { { 4, 5 }, 1.5, 30 };
    return callback(value);
}

__attribute__((visibility("default"), noinline))
bool rf_goal04_bool_not(bool value) {
    return !value;
}

__attribute__((visibility("default"), noinline))
int rf_goal04_fault(void) {
    volatile int *address = (volatile int *) 0;
    return *address;
}

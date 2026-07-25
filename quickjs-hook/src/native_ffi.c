#include "../../frida-gum-sys/frida-gum.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

typedef struct _RfNativeFfiException RfNativeFfiException;

struct _RfNativeFfiException {
    uint32_t type;
    uint32_t memory_operation;
    uintptr_t address;
    uintptr_t memory_address;
};

extern void _frida_ffi_call(void *cif, void (*function)(void), void *result,
                            void **arguments);

int rf_native_ffi_call(void *cif, void *function, void *result,
                       void **arguments, int steal_exceptions,
                       int ignore_interceptor, int *system_error,
                       RfNativeFfiException *exception) {
    GumInterceptor *interceptor = gum_interceptor_obtain();
    GumExceptor *exceptor = NULL;
    GumExceptorScope scope;
    GumInvocationState invocation_state;
    int status = 0;

    memset(exception, 0, sizeof(*exception));
    if (ignore_interceptor)
        gum_interceptor_ignore_current_thread(interceptor);

    if (steal_exceptions) {
        exceptor = gum_exceptor_obtain();
        if (gum_exceptor_try(exceptor, &scope)) {
            gum_interceptor_save(&invocation_state);
            _frida_ffi_call(cif, (void (*)(void)) function, result, arguments);
            *system_error = errno;
        }
        if (gum_exceptor_catch(exceptor, &scope)) {
            gum_interceptor_restore(&invocation_state);
            exception->type = scope.exception.type;
            exception->memory_operation = scope.exception.memory.operation;
            exception->address = (uintptr_t) scope.exception.address;
            exception->memory_address = (uintptr_t) scope.exception.memory.address;
            status = -1;
        }
    } else {
        _frida_ffi_call(cif, (void (*)(void)) function, result, arguments);
        *system_error = errno;
    }

    if (ignore_interceptor)
        gum_interceptor_unignore_current_thread(interceptor);
    if (exceptor != NULL)
        g_object_unref(exceptor);
    g_object_unref(interceptor);

    return status;
}

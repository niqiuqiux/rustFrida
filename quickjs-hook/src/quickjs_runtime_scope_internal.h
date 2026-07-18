#ifndef RF_QUICKJS_RUNTIME_SCOPE_INTERNAL_H
#define RF_QUICKJS_RUNTIME_SCOPE_INTERNAL_H

typedef struct JSRuntimeInternalThreadState {
    uintptr_t stack_top;
    uintptr_t stack_limit;
    JSValue current_exception;
    BOOL current_exception_is_uncatchable;
    BOOL in_out_of_memory;
    struct JSStackFrame *current_stack_frame;
    struct list_head job_list;
} JSRuntimeInternalThreadState;

_Static_assert(sizeof(JSRuntimeInternalThreadState) <= sizeof(JSRuntimeThreadState),
               "JSRuntimeThreadState storage is too small");

#endif

#ifndef RF_QUICKJS_RUNTIME_SCOPE_H
#define RF_QUICKJS_RUNTIME_SCOPE_H

typedef struct JSRuntimeThreadState {
    char data[64];
} JSRuntimeThreadState;

void JS_Enter(JSRuntime *rt);
void JS_Suspend(JSRuntime *rt, JSRuntimeThreadState *state);
void JS_Resume(JSRuntime *rt, const JSRuntimeThreadState *state);
void JS_Leave(JSRuntime *rt);

#endif

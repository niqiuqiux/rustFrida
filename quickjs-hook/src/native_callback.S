/*
 * ARM64 scalar NativeCallback entry point.
 *
 * Per-callback thunks load their NativeCallbackData pointer into x16 and
 * branch here. We snapshot the AAPCS64 scalar argument registers and the
 * caller's stack pointer, let Rust dispatch into QuickJS, then restore the
 * integer or floating-point result selected by the callback signature.
 */

.text
.global native_callback_entry
.type native_callback_entry, @function
.align 4
native_callback_entry:
    sub     sp, sp, #160

    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]

    stp     d0, d1, [sp, #64]
    stp     d2, d3, [sp, #80]
    stp     d4, d5, [sp, #96]
    stp     d6, d7, [sp, #112]

    add     x9, sp, #160
    str     x9, [sp, #128]
    str     x30, [sp, #136]
    str     xzr, [sp, #144]
    str     xzr, [sp, #152]

    mov     x0, x16
    mov     x1, sp
    bl      native_callback_dispatch

    ldr     x0, [sp, #144]
    ldr     d0, [sp, #152]
    ldr     x30, [sp, #136]
    add     sp, sp, #160
    ret
.size native_callback_entry, .-native_callback_entry

#if defined(__linux__) || defined(__ANDROID__)
.section .note.GNU-stack,"",%progbits
#endif

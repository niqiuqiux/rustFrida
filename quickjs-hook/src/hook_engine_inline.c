/*
 * hook_engine_inline.c - Inline hook install/attach/replace/remove
 *
 * Contains: hook_install, generate_attach_thunk, hook_attach,
 * generate_replace_thunk, hook_replace, hook_invoke_trampoline,
 * hook_remove, hook_get_trampoline.
 */

#include "hook_engine_internal.h"
#include <stdbool.h>

/* --- Simple replacement hook (hook_install) --- */

void* hook_install(void* target, void* replacement, int stealth) {
    if (!g_engine.initialized || !target || !replacement) {
        return NULL;
    }

    hook_lock(&g_engine.lock);

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    entry->replacement = replacement;

    if (build_trampoline(entry, 0) < 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    if (patch_target(target, replacement, stealth, entry) != 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    finalize_hook(entry, NULL, 0);

    void* trampoline = entry->trampoline;
    hook_unlock(&g_engine.lock);
    return trampoline;
}

/* --- Shared thunk emit helpers --- */

void emit_save_hook_context(Arm64Writer* w, uint64_t target_pc, uint64_t trampoline_ptr) {
    /* Thunk-level 在途计数已废弃: 原来 emit_thunk_inflight_inc 在此 inc, epilogue dec,
     * 语义是"所有线程 PC 脱离 thunk"。问题: attach thunk 包裹原函数调用 (BLR),
     * 任何 Java 阻塞方法 (Looper.pollOnce / Object.wait / IO) 会把 DoCall 卡在
     * BLR trampoline 里, counter 永不归零 → drain 超时.
     *
     * 新语义: 只在 Rust java_hook_callback / native hook callback 进出点 inc/dec.
     * drain==0 等价于"无 JS callback 正在执行", 足以安全 free JS 资源 (callback JSValue
     * / replacement ArtMethod / JNI ref). 栈帧滞留于 attach thunk 的 BLR 之后不影响软清理
     * (不 munmap pool, 线程后续自然回落)。full cleanup 依赖时间衰减 + drain timeout leak 路径. */

    /* HookContext: x0-x30 (31*8=248) + sp (8) + pc (8) + nzcv (8) + trampoline (8) + d[8] (64) = 344 bytes
     * Round up to 16-byte alignment: 352 bytes */
    uint64_t stack_size = 352;
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Save x0-x30 to context on stack */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }
    /* Save x30 (LR) */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Save SP before we modified it (add back our allocation) */
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_SP, stack_size);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP, 248); /* sp offset */

    /* Save original PC (target address) to context */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, target_pc);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP, 256); /* pc offset */

    /* Save NZCV condition flags to context.nzcv ([SP+264]).
     * All instructions above (SUB/STP/STR/ADD/LDR) are non-flag-setting variants,
     * so NZCV is still intact at this point and reflects the hooked function's entry state. */
    arm64_writer_put_mrs_reg(w, ARM64_REG_X17, 0xDA10); /* MRS X17, NZCV */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 264); /* nzcv offset */

    /* Save trampoline address to context.trampoline ([SP+272]) if provided */
    if (trampoline_ptr != 0) {
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, trampoline_ptr);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP, 272); /* trampoline offset */
    }

    /* Save d0-d7 FP registers to context.d[] (offset 280) */
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(w, i, i + 1, ARM64_REG_SP, 280 + i * 8);
    }

    /* 初始化 intercept_leave = 1 (默认 wrap). on_enter 可写 0 切换 tail-jump.
     * offset 344 = sizeof(HookContext_reg/fp) 末尾, 仍在 352 字节栈框内. */
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X16, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP, 344);
}

void emit_callback_call(Arm64Writer* w, HookCallback callback, void* user_data) {
    /* Set up arguments: X0 = &HookContext (SP points to it), X1 = user_data */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_SP);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X1, (uint64_t)user_data);

    /* Call callback */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)callback);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
}

void emit_replace_epilogue(Arm64Writer* w) {
    /* Restore x0 (return value, possibly modified by callback or callOriginal) */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* Restore d0 for float/double returns. d1 is caller-saved and may be
     * restored as part of the pair load without changing observable ABI. */
    arm64_writer_put_fp_ldp_offset(w, 0, 1, ARM64_REG_SP, 280);

    /* Restore x18 (platform register) before returning to the original caller. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X18, ARM64_REG_SP, 144);

    /* Restore callee-saved registers x19-x29 from saved HookContext.
     * Replace-mode callback (BLR) 遵循 AAPCS64 调用约定，回调内部的 Rust/C 代码
     * 会自由使用 x19-x29 作为局部变量。如果不恢复，caller 的 callee-saved
     * 寄存器会被破坏 → 延迟 SIGSEGV (如 GetOatQuickMethodHeader 的 caller
     * 用 x25 做数据指针，回调破坏 x25 后 LDR [x25,#off] 崩溃)。 */
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X19, ARM64_REG_X20,
                                             ARM64_REG_SP, 152, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22,
                                             ARM64_REG_SP, 168, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24,
                                             ARM64_REG_SP, 184, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26,
                                             ARM64_REG_SP, 200, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28,
                                             ARM64_REG_SP, 216, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_SP, 232);

    /* Restore x30 (LR — return to the caller of the hooked function) */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Deallocate stack (352 bytes) */
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 352);

    /* thunk-level dec 已废弃 (见 emit_save_hook_context 注释) */
    arm64_writer_put_ret(w);
}

void emit_restore_caller_regs(Arm64Writer* w) {
    /* Restore x0-x15 from the saved HookContext.
     * x0-x7:  function arguments — the callback may have modified them.
     * x8:     indirect result register (XR) — must be preserved for struct-return fns.
     * x9-x15: caller-saved scratch — restore so the original function sees the same
     *          values it would have received had there been no thunk in the way.
     * x16:    NOT restored here — caller uses it as scratch to load addresses.
     * x17-x18: NOT restored here — caller restores them after loading x16. */
    for (int i = 0; i < 16; i += 2) {
        arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }

    /* Restore d0-d7 FP registers from context.d[] (offset 280) */
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP, 280 + i * 8);
    }
}

/* --- Generate attach thunk --- */

/* Generate thunk code for attach hook using arm64_writer */
void* generate_attach_thunk(HookEntry* entry, HookCallback on_enter,
                                    HookCallback on_leave, void* user_data,
                                    size_t* thunk_size_out) {
    void* thunk_mem;

    /* attach thunk 需要 near: target → thunk 通过 inline patch 跳转（ADRP/B 有距离限制） */
    if (entry->thunk && entry->thunk_alloc >= THUNK_ALLOC_SIZE) {
        thunk_mem = entry->thunk;
    } else {
        thunk_mem = hook_alloc_near(THUNK_ALLOC_SIZE, entry->target);
        if (!thunk_mem) return NULL;
        entry->thunk = thunk_mem;
        entry->thunk_alloc = THUNK_ALLOC_SIZE;
    }

    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    uint64_t stack_size = 352;

    /* Save HookContext (no trampoline for attach mode) */
    emit_save_hook_context(&w, (uint64_t)entry->target, 0);

    /* Call on_enter callback if set */
    if (on_enter) {
        emit_callback_call(&w, on_enter, user_data);
    }

    /* Restore x0-x15 from context (callback may have modified arguments) */
    emit_restore_caller_regs(&w);

    /* x16 = trampoline (scratch).
     *
     * 规则:
     *   on_leave == NULL → 必然 tail-jump.
     *   on_leave != NULL 且 intercept_leave == 0 → 本次调用 tail-jump.
     *   on_leave != NULL 且 intercept_leave != 0 → wrap 原函数并在返回后调用 on_leave.
     *
     * tail-jump 路径省掉 thunk 栈帧在 BLR 期间的驻留, 原函数阻塞时 PC 已脱离 thunk,
     * full cleanup munmap pool 安全 (对标 "miss 不留栈帧" 的性能+安全优化). */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)entry->trampoline);

    uint64_t lbl_tail = arm64_writer_new_label_id(&w);
    if (on_leave == NULL) {
        arm64_writer_put_b_label(&w, lbl_tail);
    } else {
        /* on_enter may disable leave interception for this invocation. This is
         * used by the address-level Interceptor dispatcher when no active JS
         * listener has an onLeave callback. */
        arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_SP, 344);
        arm64_writer_put_cbz_reg_label(&w, ARM64_REG_X17, lbl_tail);
    }

    /* --- wrap path (intercept leave) --- */
    /* 恢复真实 x17,x18 */
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_X18,
                                             ARM64_REG_SP, 136, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_blr_reg(&w, ARM64_REG_X16);

    /* Snapshot all caller-saved integer and FP return registers before invoking
     * on_leave. The callback is free to clobber these registers, and AAPCS64 may
     * return aggregates through x0-x7 or d0-d7 instead of x0 alone. */
    for (int i = 0; i < 16; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(&w, i, i + 1, ARM64_REG_SP, 280 + i * 8);
    }

    /* Call on_leave callback if set */
    if (on_leave) {
        emit_callback_call(&w, on_leave, user_data);
    }

    /* Restore return registers, including any changes made by on_leave. */
    emit_restore_caller_regs(&w);

    /* Restore x30 (LR) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Restore NZCV using x17 as scratch (x17 即将 RET 返回, 不需保留真值) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_SP, 264);
    arm64_writer_put_msr_reg(&w, 0xDA10, ARM64_REG_X17);

    /* Deallocate stack */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    arm64_writer_put_ret(&w);

    /* --- tail-jump path (no-intercept-leave) --- */
    arm64_writer_put_label(&w, lbl_tail);

    /* 恢复 caller's LR (x30), 让原函数 RET 直接回到 caller */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Restore NZCV using x17 as scratch (x17 稍后从 ctx 重载真值) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_SP, 264);
    arm64_writer_put_msr_reg(&w, 0xDA10, ARM64_REG_X17);

    /* 恢复真实 x17,x18 (覆盖 NZCV scratch) */
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_X18,
                                             ARM64_REG_SP, 136, ARM64_INDEX_SIGNED_OFFSET);

    /* Deallocate stack + tail-jump */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);
    arm64_writer_put_br_reg(&w, ARM64_REG_X16);

    /* Flush any pending labels */
    arm64_writer_flush(&w);

    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* --- Attach hook with enter/leave callbacks (hook_attach) --- */

int hook_attach(void* target, HookCallback on_enter, HookCallback on_leave, void* user_data, int stealth) {
    if (!g_engine.initialized) return HOOK_ERROR_NOT_INITIALIZED;
    if (!target) return HOOK_ERROR_INVALID_PARAM;
    if (!on_enter && !on_leave) return HOOK_ERROR_INVALID_PARAM;

    hook_lock(&g_engine.lock);

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    entry->on_enter = on_enter;
    entry->on_leave = on_leave;
    entry->user_data = user_data;

    if (build_trampoline(entry, 0) < 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    /* Generate thunk code */
    size_t thunk_size = 0;
    void* thunk_mem = generate_attach_thunk(entry, on_enter, on_leave, user_data, &thunk_size);
    if (!thunk_mem) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    int patch_result = patch_target(target, thunk_mem, stealth, entry);
    if (patch_result != 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return patch_result;
    }

    finalize_hook(entry, thunk_mem, thunk_size);

    hook_unlock(&g_engine.lock);
    return HOOK_OK;
}

/* --- Replace-mode thunk generation --- */

/* Generate a replace-mode thunk: save ctx → callback → restore x0 → RET.
 *
 * Unlike generate_attach_thunk, this thunk does NOT call the original function.
 * The callback receives a HookContext with the trampoline address at offset 272,
 * and can optionally invoke the original via hook_invoke_trampoline().
 *
 * Layout: SUB SP → STP x0-x30 → save SP/PC/NZCV/trampoline →
 *         BLR on_enter(ctx, user_data) → LDR x0 → LDR LR → ADD SP → RET
 */
static void* generate_replace_thunk(HookEntry* entry, HookCallback on_enter,
                                     void* user_data, size_t* thunk_size_out) {
    void* thunk_mem;

    /* replace thunk 需要 near: target → thunk 通过 inline patch 跳转（ADRP/B 有距离限制） */
    if (entry->thunk && entry->thunk_alloc >= THUNK_ALLOC_SIZE) {
        thunk_mem = entry->thunk;
    } else {
        thunk_mem = hook_alloc_near(THUNK_ALLOC_SIZE, entry->target);
        if (!thunk_mem) return NULL;
        entry->thunk = thunk_mem;
        entry->thunk_alloc = THUNK_ALLOC_SIZE;
    }

    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    uint64_t stack_size = 352;

    /* Save HookContext with trampoline address */
    emit_save_hook_context(&w, (uint64_t)entry->target, (uint64_t)entry->trampoline);

    /* Call on_enter callback */
    emit_callback_call(&w, on_enter, user_data);

    /* Restore x0 + LR, deallocate stack, RET */
    emit_replace_epilogue(&w);

    /* Flush any pending labels */
    arm64_writer_flush(&w);

    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* --- Replace-mode hook (hook_replace) --- */

void* hook_replace(void* target, HookCallback on_enter, void* user_data, int stealth) {
    if (!g_engine.initialized || !target || !on_enter) {
        return NULL;
    }

    hook_lock(&g_engine.lock);

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    entry->on_enter = on_enter;
    entry->user_data = user_data;

    if (build_trampoline(entry, 0) < 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    /* Generate replace thunk */
    size_t thunk_size = 0;
    void* thunk_mem = generate_replace_thunk(entry, on_enter, user_data, &thunk_size);
    if (!thunk_mem) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    if (patch_target(target, thunk_mem, stealth, entry) != 0) {
        free_entry(entry);
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    finalize_hook(entry, thunk_mem, thunk_size);

    void* trampoline = entry->trampoline;
    hook_unlock(&g_engine.lock);
    return trampoline;
}

/* --- Invoke trampoline (naked assembly) --- */

/*
 * hook_invoke_trampoline - Restore registers from HookContext and call trampoline.
 *
 * Signature: uint64_t hook_invoke_trampoline(HookContext* ctx, void* trampoline)
 *
 * On entry: X0 = ctx, X1 = trampoline
 * Restores x0-x15 from ctx (x0-x7 = args, x8 = XR, x9-x15 = scratch),
 * then calls trampoline via BLR, and returns the original function's x0.
 *
 * Implementation uses naked asm to avoid compiler frame setup interfering
 * with the careful register restoration sequence.
 */
__attribute__((naked))
uint64_t hook_invoke_trampoline(HookContext* ctx, void* trampoline) {
    __asm__ volatile(
        /* Save callee-saved frame state and scratch callee-saved regs. */
        "stp    x29, x30, [sp, #-16]!\n"
        "mov    x29, sp\n"
        "stp    x19, x20, [sp, #-16]!\n"

        /* X0 = ctx, X1 = trampoline. Keep both across the original call. */
        "mov    x19, x1\n"
        "mov    x20, x0\n"

        /* Restore FP argument registers before invoking the original. */
        "ldp    d0,  d1,  [x0, #280]\n"
        "ldp    d2,  d3,  [x0, #296]\n"
        "ldp    d4,  d5,  [x0, #312]\n"
        "ldp    d6,  d7,  [x0, #328]\n"

        /* Restore x2-x15 from ctx first (before we clobber x0/x1) */
        "ldp    x2,  x3,  [x0, #16]\n"
        "ldp    x4,  x5,  [x0, #32]\n"
        "ldp    x6,  x7,  [x0, #48]\n"
        "ldp    x8,  x9,  [x0, #64]\n"
        "ldp    x10, x11, [x0, #80]\n"
        "ldp    x12, x13, [x0, #96]\n"
        "ldp    x14, x15, [x0, #112]\n"
        /* Restore x17-x18 (x18 is Android's platform register). */
        "ldp    x17, x18, [x0, #136]\n"

        /* Restore x0-x1 from ctx (must be last since x0 = ctx pointer) */
        "ldp    x0,  x1,  [x0]\n"

        /* Move trampoline into x16. x19/x20 are restored after the original
         * returns so x20 remains available for storing x0/d0 return values. */
        "mov    x16, x19\n"

        /* Call the trampoline (original function) */
        "blr    x16\n"

        /* x0/d0 now contain the return value from the original function. Store
         * both back into HookContext so callers can consume integer and FP
         * returns through the same context object. */
        "str    x0, [x20, #0]\n"
        "str    d0, [x20, #280]\n"

        /* Restore frame and return */
        "ldp    x19, x20, [sp], #16\n"
        "ldp    x29, x30, [sp], #16\n"
        "ret\n"
    );
}

/* --- Remove hook --- */

int hook_remove(void* target) {
    if (!g_engine.initialized) {
        return HOOK_ERROR_NOT_INITIALIZED;
    }

    if (!target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    hook_lock(&g_engine.lock);

    HookEntry* prev = NULL;
    HookEntry* entry = g_engine.hooks;

    while (entry) {
        if (entry->target == target) {
            if (entry->stealth == 1) {
                /* Stealth 1: restore bytes through wxshadow_module prctl.
                 * 跨页 patch 有两个 tracked segment (first+second), 需分别 release. */
                int rc = wxshadow_release(target);
                if (rc != 0) {
                    hook_log("hook_remove: wxshadow_release FAILED for %p (stealth hook stays active)", target);
                    hook_unlock(&g_engine.lock);
                    return HOOK_ERROR_WXSHADOW_FAILED;
                }
                uintptr_t t = (uintptr_t)target;
                if ((t & 0xFFF) + (uintptr_t)entry->original_size > 0x1000) {
                    size_t first_len = 0x1000 - (t & 0xFFF);
                    void* second_addr = (void*)(t + first_len);
                    int rc2 = wxshadow_release(second_addr);
                    if (rc2 != 0) {
                        hook_log("hook_remove: stealth1 second-segment release failed at %p", second_addr);
                        /* target 首段已释放, 首指令已恢复原字节, CPU 执行回原流程.
                         * 第二段泄漏无害: 原指令已不会执行到 (首段直接 ret 原逻辑). */
                    }
                }
            } else if (entry->stealth == 2) {
                /* Stealth 2 (recomp): target is an anonymous slot. The route is
                 * restored by the recomp layer on live unhook, or fully disabled
                 * by PR_RECOMPILE_RELEASE during cleanup. Do not write the slot
                 * here; cleanup may have already made the mirror release-only. */
            } else {
                /* Normal hook (stealth==0): 优先走 rw-sibling 直写（JIT cache 走这条唯一路径）。
                 * 对装 hook 时走 rw-sibling 的目标, mprotect 本来就 EACCES, 不切这条会导致 unhook 失败,
                 * entry 无法 free_entry (还在链表), agent 卸载后 target 的 B 指令继续跳已释放 thunk → crash. */
                void* writable = find_rw_sibling(target, (size_t)entry->original_size);
                if (writable) {
                    memcpy(writable, entry->original_bytes, entry->original_size);
                    hook_flush_cache(target, entry->original_size);
                    hook_log("hook_remove: rw-sibling restore OK target=%p via writable=%p len=%zu",
                             target, writable, (size_t)entry->original_size);
                } else {
                    int saved_prot[8] = {0};
                    size_t saved_count = save_range_prot_pages(target, (size_t)entry->original_size,
                                                               saved_prot,
                                                               sizeof(saved_prot) / sizeof(saved_prot[0]));
                    if (saved_count == 0 ||
                            saved_count > sizeof(saved_prot) / sizeof(saved_prot[0]) ||
                            mprotect_range_pages(target, (size_t)entry->original_size,
                                                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                        hook_log("hook_remove: mprotect failed target=%p errno=%d, hook remains installed",
                                 target, errno);
                        hook_unlock(&g_engine.lock);
                        return HOOK_ERROR_MPROTECT_FAILED;
                    }
                    memcpy(target, entry->original_bytes, entry->original_size);
                    restore_range_prot_pages(target, (size_t)entry->original_size, saved_prot, saved_count);
                    hook_flush_cache(target, entry->original_size);
                }
            }

            /* Remove from hook list */
            if (prev) {
                prev->next = entry->next;
            } else {
                g_engine.hooks = entry->next;
            }

            /* Move to free list for reuse instead of discarding */
            free_entry(entry);

            hook_unlock(&g_engine.lock);
            return HOOK_OK;
        }
        prev = entry;
        entry = entry->next;
    }

    hook_unlock(&g_engine.lock);
    return HOOK_ERROR_NOT_FOUND;
}

int hook_discard(void* target) {
    if (!g_engine.initialized) {
        return HOOK_ERROR_NOT_INITIALIZED;
    }

    if (!target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    hook_lock(&g_engine.lock);

    HookEntry* prev = NULL;
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->target == target) {
            if (prev) {
                prev->next = entry->next;
            } else {
                g_engine.hooks = entry->next;
            }
            free_entry(entry);
            hook_log("hook_discard: forgot target=%p without restoring code", target);
            hook_unlock(&g_engine.lock);
            return HOOK_OK;
        }
        prev = entry;
        entry = entry->next;
    }

    hook_unlock(&g_engine.lock);
    return HOOK_ERROR_NOT_FOUND;
}

/* --- Get trampoline --- */

void* hook_get_trampoline(void* target) {
    hook_lock(&g_engine.lock);
    HookEntry* entry = find_hook(target);
    void* result = entry ? entry->trampoline : NULL;
    hook_unlock(&g_engine.lock);
    return result;
}

int hook_mark_recomp_hook(void* target) {
    if (!g_engine.initialized || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    hook_lock(&g_engine.lock);
    HookEntry* entry = find_hook(target);
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return HOOK_ERROR_NOT_FOUND;
    }

    entry->stealth = 2;
    hook_unlock(&g_engine.lock);
    return HOOK_OK;
}

int hook_mark_recomp_hook_by_trampoline(void* trampoline) {
    if (!g_engine.initialized || !trampoline) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    hook_lock(&g_engine.lock);
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->trampoline == trampoline) {
            entry->stealth = 2;
            hook_unlock(&g_engine.lock);
            return HOOK_OK;
        }
        entry = entry->next;
    }
    hook_unlock(&g_engine.lock);
    return HOOK_ERROR_NOT_FOUND;
}

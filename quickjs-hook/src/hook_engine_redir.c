/*
 * hook_engine_redir.c - Redirect thunks and native hook trampolines
 *
 * Contains: generate_redirect_thunk, hook_create_redirect,
 * hook_remove_redirect, generate_native_hook_thunk,
 * hook_create_native_trampoline.
 */

#include "hook_engine_internal.h"

#define NATIVE_FAKE_CODEINFO_BYTES 12
#define NATIVE_FAKE_OAT_PREFIX_SIZE (NATIVE_FAKE_CODEINFO_BYTES + 4)
#define NATIVE_HOOK_CONTEXT_FRAME_SIZE 352
#define NATIVE_STACK_METHOD_SLOT_SIZE 16
#define NATIVE_TOTAL_FRAME_SIZE (NATIVE_STACK_METHOD_SLOT_SIZE + NATIVE_HOOK_CONTEXT_FRAME_SIZE)
#define NATIVE_FAKE_PACKED_FRAME_SIZE (NATIVE_HOOK_CONTEXT_FRAME_SIZE / 16)

static void encode_native_fake_codeinfo(uint8_t buf[NATIVE_FAKE_CODEINFO_BYTES],
                                        uint32_t code_size, uint32_t frame_packed) {
    memset(buf, 0, NATIVE_FAKE_CODEINFO_BYTES);
    buf[0] = 0xF0;
    buf[1] = 0x0F;
    buf[2] = 0x00;
    buf[3] = (uint8_t)((code_size & 0x0F) << 4);
    buf[4] = (uint8_t)((code_size >> 4)  & 0xFF);
    buf[5] = (uint8_t)((code_size >> 12) & 0xFF);
    buf[6] = (uint8_t)((code_size >> 20) & 0xFF);
    buf[7] = (uint8_t)(((code_size >> 28) & 0x0F) | ((frame_packed & 0x0F) << 4));
    buf[8] = (uint8_t)((frame_packed >> 4)  & 0xFF);
    buf[9] = (uint8_t)((frame_packed >> 12) & 0xFF);
    buf[10]= (uint8_t)((frame_packed >> 20) & 0xFF);
    buf[11]= (uint8_t)((frame_packed >> 28) & 0x0F);
}

static void backfill_native_fake_oat_header(void* thunk_mem, uint32_t body_size) {
    uint8_t* p = (uint8_t*)thunk_mem;
    encode_native_fake_codeinfo(p, body_size, NATIVE_FAKE_PACKED_FRAME_SIZE);
    uint32_t code_info_offset = NATIVE_FAKE_OAT_PREFIX_SIZE;
    memcpy(p + NATIVE_FAKE_CODEINFO_BYTES, &code_info_offset, sizeof(uint32_t));
}

static void emit_save_native_hook_context(Arm64Writer* w, uint64_t target_pc) {
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, NATIVE_TOTAL_FRAME_SIZE);

    /* HookContext lives at SP+16. SP+0 is reserved for StackVisitor's ArtMethod*. */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, NATIVE_STACK_METHOD_SLOT_SIZE + i * 8,
                                                 ARM64_INDEX_SIGNED_OFFSET);
    }
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X30, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE + 240);

    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_SP, NATIVE_TOTAL_FRAME_SIZE);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE + 248);

    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, target_pc);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE + 256);

    arm64_writer_put_mrs_reg(w, ARM64_REG_X17, 0xDA10);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE + 264);

    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(w, i, i + 1, ARM64_REG_SP,
                                       NATIVE_STACK_METHOD_SLOT_SIZE + 280 + i * 8);
    }

    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X16, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE + 344);
}

static void emit_store_replacement_for_stackvisitor(Arm64Writer* w, uint64_t original_method) {
    uint64_t lbl_loop = arm64_writer_new_label_id(w);
    uint64_t lbl_found = arm64_writer_new_label_id(w);
    uint64_t lbl_done = arm64_writer_new_label_id(w);

    /* Default to 0; normal path below overwrites with replacement ArtMethod*. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_SP, 0);

    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)g_art_router_table);
    arm64_writer_put_label(w, lbl_loop);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_done);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X15, original_method);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X15);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_found);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, sizeof(ArtRouterEntry));
    arm64_writer_put_b_label(w, lbl_loop);

    arm64_writer_put_label(w, lbl_found);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_label(w, lbl_done);
}

static void emit_native_callback_call(Arm64Writer* w, HookCallback callback, void* user_data) {
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X0, ARM64_REG_SP, NATIVE_STACK_METHOD_SLOT_SIZE);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X1, (uint64_t)user_data);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)callback);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
}

/* Generate a redirect thunk (pointer-based hooking, no inline patching).
 *
 * Layout: save context → call on_enter(ctx, user_data) → restore registers →
 * BR x16 (tail-call to original_entry, preserving caller's LR).
 */
static void* generate_redirect_thunk(void* original_entry,
                                      HookCallback on_enter,
                                      void* user_data,
                                      void* thunk_mem,
                                      size_t* thunk_size_out) {
    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    uint64_t stack_size = 352;

    /* Save HookContext (no trampoline for redirect mode) */
    emit_save_hook_context(&w, (uint64_t)original_entry, 0);

    /* Call on_enter(ctx, user_data) */
    emit_callback_call(&w, on_enter, user_data);

    /* Restore x0-x15 from context (callback may have modified arguments) */
    emit_restore_caller_regs(&w);

    /* Load original_entry into x16 for tail-call */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)original_entry);

    /* Restore x17-x18 (saved earlier by STP) */
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_X18,
                                             ARM64_REG_SP, 136, ARM64_INDEX_SIGNED_OFFSET);

    /* Restore x30 (LR) — critical: tail-call via BR preserves caller's LR */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Restore NZCV */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X19, ARM64_REG_SP, 264);
    arm64_writer_put_msr_reg(&w, 0xDA10, ARM64_REG_X19);
    /* Restore x19 from context (we clobbered it for NZCV restore) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X19, ARM64_REG_SP, 152);

    /* Deallocate stack */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* thunk-level dec 废弃, 直接 br x16 tail-call 回原函数 */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)original_entry);
    arm64_writer_put_br_reg(&w, ARM64_REG_X16);

    if (arm64_writer_flush(&w) != 0) {
        hook_log("[hook] redirect thunk generation failed");
        arm64_writer_clear(&w);
        return NULL;
    }

    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* --- Shared redirect entry helpers --- */

/* Prepare a redirect entry: dup check + pool writable + alloc entry + alloc thunk_mem.
 * Caller must hold g_engine.lock. On failure: unlocks mutex and returns NULL.
 * On success: *out_entry is set and thunk_mem is returned (pool is writable). */
static void* prepare_redirect_entry(uint64_t key, HookRedirectEntry** out_entry) {
    /* Check for duplicate */
    HookRedirectEntry* cur = g_engine.redirects;
    while (cur) {
        if (cur->key == key) {
            hook_unlock(&g_engine.lock);
            return NULL;
        }
        cur = cur->next;
    }

    HookRedirectEntry* entry = (HookRedirectEntry*)hook_alloc(sizeof(HookRedirectEntry));
    if (!entry) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }
    memset(entry, 0, sizeof(HookRedirectEntry));

    /* redirect/native thunk 通过指针间接调用，不需要近距离分配 */
    void* thunk_mem = hook_alloc(THUNK_ALLOC_SIZE);
    if (!thunk_mem) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    *out_entry = entry;
    return thunk_mem;
}

/* Finalize a redirect entry: fill fields, flush cache, make executable, unlock.
 * Returns thunk address on success. */
static void* finalize_redirect_entry(HookRedirectEntry* entry, uint64_t key,
                                      void* original_entry, void* thunk, size_t thunk_size) {
    entry->key = key;
    entry->original_entry = original_entry;
    entry->thunk = thunk;
    entry->thunk_alloc = THUNK_ALLOC_SIZE;
    entry->next = g_engine.redirects;
    g_engine.redirects = entry;

    hook_flush_cache(thunk, thunk_size);

    hook_unlock(&g_engine.lock);
    return thunk;
}

/* Create a redirect hook — returns thunk address, caller writes it to the pointer slot */
void* hook_create_redirect(uint64_t key, void* original_entry,
                           HookCallback on_enter, void* user_data) {
    if (!g_engine.initialized || !original_entry || !on_enter)
        return NULL;

    hook_lock(&g_engine.lock);

    HookRedirectEntry* entry;
    void* thunk_mem = prepare_redirect_entry(key, &entry);
    if (!thunk_mem) return NULL;

    size_t thunk_size = 0;
    void* thunk = generate_redirect_thunk(original_entry, on_enter, user_data,
                                           thunk_mem, &thunk_size);
    if (!thunk) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    return finalize_redirect_entry(entry, key, original_entry, thunk, thunk_size);
}

/* Remove a redirect hook — returns original entry point (caller restores the pointer) */
void* hook_remove_redirect(uint64_t key) {
    if (!g_engine.initialized) return NULL;

    hook_lock(&g_engine.lock);

    HookRedirectEntry* prev = NULL;
    HookRedirectEntry* entry = g_engine.redirects;

    while (entry) {
        if (entry->key == key) {
            void* original = entry->original_entry;

            if (prev) {
                prev->next = entry->next;
            } else {
                g_engine.redirects = entry->next;
            }

            hook_unlock(&g_engine.lock);
            return original;
        }
        prev = entry;
        entry = entry->next;
    }

    hook_unlock(&g_engine.lock);
    return NULL;
}

/* Generate a native hook thunk (for replace-with-native approach).
 *
 * Similar to redirect thunk but ends with RET instead of BR to original.
 * Used when a Java method is converted to native and this thunk serves
 * as the native function implementation (stored in ArtMethod.data_).
 *
 * Layout: save context → call on_enter(ctx, user_data) → restore x0 → RET
 */
static void* generate_native_hook_thunk(HookCallback on_enter,
                                         void* user_data,
                                         uint64_t current_pc_hint,
                                         uint64_t original_method,
                                         void* thunk_mem,
                                         size_t* thunk_size_out) {
    Arm64Writer w;
    void* body_mem = (uint8_t*)thunk_mem + NATIVE_FAKE_OAT_PREFIX_SIZE;
    size_t body_alloc = THUNK_ALLOC_SIZE - NATIVE_FAKE_OAT_PREFIX_SIZE;
    arm64_writer_init(&w, body_mem, (uint64_t)body_mem, body_alloc);

    emit_save_native_hook_context(&w, current_pc_hint);
    emit_store_replacement_for_stackvisitor(&w, original_method);

    /* Call on_enter(ctx, user_data) */
    emit_native_callback_call(&w, on_enter, user_data);

    /* Restore x0 */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE);

    /* 统一从 saved LR 恢复 (= jni_trampoline 内的返回地址)。
     * 不再区分 compiled/shared_stub 路径。让 RET 回到 jni_trampoline epilogue，
     * 由 GenericJniMethodEnd 正常清理 JNI transition frame，避免 frame 泄漏。 */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE + 240); /* saved LR */

    /* Restore x18 (platform register) before returning */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X18, ARM64_REG_SP,
                                        NATIVE_STACK_METHOD_SLOT_SIZE + 144);

    /* Deallocate stack + ret (thunk-level dec 废弃) */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, NATIVE_TOTAL_FRAME_SIZE);
    arm64_writer_put_ret(&w);

    if (arm64_writer_flush(&w) != 0) {
        hook_log("[hook] native redirect thunk generation failed");
        arm64_writer_clear(&w);
        return NULL;
    }
    size_t body_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    backfill_native_fake_oat_header(thunk_mem, (uint32_t)body_size);
    *thunk_size_out = NATIVE_FAKE_OAT_PREFIX_SIZE + body_size;
    hook_flush_cache(thunk_mem, *thunk_size_out);

    return body_mem;
}

/* Create a native hook trampoline — called by ART's JNI trampoline as a native function.
 * Returns the thunk address to be stored in ArtMethod.data_ field.
 * Uses the redirect entry list for tracking (shares hook_remove_redirect for cleanup). */
void* hook_create_native_trampoline(uint64_t key, HookCallback on_enter, void* user_data,
                                    uint64_t current_pc_hint) {
    if (!g_engine.initialized || !on_enter)
        return NULL;

    hook_lock(&g_engine.lock);

    HookRedirectEntry* entry;
    /* native trampoline 通过 ArtMethod.data_ 间接调用，不需要 ADRP 近距离 */
    void* thunk_mem = prepare_redirect_entry(key, &entry);
    if (!thunk_mem) return NULL;

    size_t thunk_size = 0;
    void* thunk = generate_native_hook_thunk(on_enter, user_data, current_pc_hint, key, thunk_mem, &thunk_size);
    if (!thunk) {
        hook_unlock(&g_engine.lock);
        return NULL;
    }

    return finalize_redirect_entry(entry, key, NULL, thunk, thunk_size);
}

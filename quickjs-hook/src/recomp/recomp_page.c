/*
 * recompiler.c - ARM64 页级代码重编译器
 *
 * 基于现有 arm64_writer / arm64_relocator 基础设施实现。
 * 参考 Frida Gum Stalker 的重编译模型，但适配页级 1:1 偏移映射。
 */

#include "recomp_page.h"
#include "../arm64_writer.h"
#include "../arm64_relocator.h"
#include "../arm64_common.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>

extern void hook_log(const char* fmt, ...);

#ifndef RECOMP_DEBUG_LOG
#define RECOMP_DEBUG_LOG 0
#endif

/* ============================================================================
 * 内部辅助：判断指令是否为分支类
 * ============================================================================ */

static int is_branch_type(Arm64InsnType type) {
    switch (type) {
        case ARM64_INSN_B:
        case ARM64_INSN_BL:
        case ARM64_INSN_B_COND:
        case ARM64_INSN_CBZ:
        case ARM64_INSN_CBNZ:
        case ARM64_INSN_TBZ:
        case ARM64_INSN_TBNZ:
            return 1;
        default:
            return 0;
    }
}

/* 判断指令是否不可能 fall-through（无条件跳转/返回）。
 * BLR 是 call，callee RET 后必须继续执行下一条，不能当作 terminator。 */
static int is_unconditional_transfer(Arm64InsnType type) {
    return type == ARM64_INSN_B || type == ARM64_INSN_BR || type == ARM64_INSN_RET;
}

static int is_art_implicit_suspend_poll(uint32_t insn) {
    return insn == 0xf94002b5u; /* ldr x21, [x21] */
}

static int put_b_required(Arm64Writer* w, uint64_t target);
static int put_b_prefer_translated_or_orig(Arm64Writer* w, uint64_t translated_target, uint64_t orig_target);
static int emit_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint32_t insn,
    uint64_t return_addr,
    uint64_t orig_ret_addr
);

static int emit_suspend_poll_skip_null_trampoline(
    Arm64Writer* w,
    uint32_t insn,
    uint64_t orig_fallthrough,
    uint64_t suspend_entrypoint,
    uint64_t translated_fallthrough
) {
    uint64_t do_poll = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X21, do_poll);
    if (suspend_entrypoint != 0) {
        arm64_writer_put_ldr_reg_address(w, ARM64_REG_X30, orig_fallthrough);
        if (arm64_writer_put_b_imm(w, suspend_entrypoint) != 0) {
            arm64_writer_put_branch_address_reg(w, suspend_entrypoint, ARM64_REG_X16);
        }
    } else {
        if (put_b_prefer_translated_or_orig(w, translated_fallthrough, orig_fallthrough) != 0)
            return -1;
    }
    arm64_writer_put_label(w, do_poll);
    arm64_writer_put_insn(w, insn);
    return put_b_prefer_translated_or_orig(w, translated_fallthrough, orig_fallthrough);
}

/* ============================================================================
 * 编码 B / BL 指令（手动编码，不通过 writer）
 * ============================================================================ */

static int encode_b(uint64_t from_pc, uint64_t to_pc, uint32_t* out) {
    int64_t offset = (int64_t)to_pc - (int64_t)from_pc;
    if (offset & 3) return -1;
    int64_t imm26 = offset >> 2;
    if (!fits_signed(imm26, 26)) return -1;
    *out = 0x14000000 | ((uint32_t)imm26 & 0x03FFFFFF);
    return 0;
}

static int encode_bl(uint64_t from_pc, uint64_t to_pc, uint32_t* out) {
    int64_t offset = (int64_t)to_pc - (int64_t)from_pc;
    if (offset & 3) return -1;
    int64_t imm26 = offset >> 2;
    if (!fits_signed(imm26, 26)) return -1;
    *out = 0x94000000 | ((uint32_t)imm26 & 0x03FFFFFF);
    return 0;
}

/*
 * 安全 B 跳转：优先用 B（4 字节），失败时 fallback 到 MOVZ/MOVK + BR。
 * Fallback 仍需要一个 scratch；正常页外分支应先被重写到目标 recomp 页，
 * 避免走这个路径。这里作为最后 fallback。
 */
static void put_b_safe(Arm64Writer* w, uint64_t target) {
    if (arm64_writer_put_b_imm(w, target) != 0) {
        arm64_writer_put_branch_address_reg(w, target, ARM64_REG_X16);
    }
}

static int encode_branch_like(uint32_t insn, Arm64InsnType type, uint64_t from_pc, uint64_t to_pc, uint32_t* out) {
    int64_t offset = (int64_t)to_pc - (int64_t)from_pc;
    if (offset & 3) return -1;

    switch (type) {
    case ARM64_INSN_B:
        return encode_b(from_pc, to_pc, out);
    case ARM64_INSN_B_COND: {
        int64_t imm19 = offset >> 2;
        if (!fits_signed(imm19, 19)) return -1;
        *out = (insn & ~0x00ffffe0u) | (((uint32_t)imm19 & 0x7ffffu) << 5);
        return 0;
    }
    case ARM64_INSN_CBZ:
    case ARM64_INSN_CBNZ: {
        int64_t imm19 = offset >> 2;
        if (!fits_signed(imm19, 19)) return -1;
        *out = (insn & ~0x00ffffe0u) | (((uint32_t)imm19 & 0x7ffffu) << 5);
        return 0;
    }
    case ARM64_INSN_TBZ:
    case ARM64_INSN_TBNZ: {
        int64_t imm14 = offset >> 2;
        if (!fits_signed(imm14, 14)) return -1;
        *out = (insn & ~0x0007ffe0u) | (((uint32_t)imm14 & 0x3fffu) << 5);
        return 0;
    }
    default:
        return -1;
    }
}

static const char* branch_type_name(Arm64InsnType type) {
    switch (type) {
    case ARM64_INSN_B: return "B";
    case ARM64_INSN_B_COND: return "B.cond";
    case ARM64_INSN_CBZ: return "CBZ";
    case ARM64_INSN_CBNZ: return "CBNZ";
    case ARM64_INSN_TBZ: return "TBZ";
    case ARM64_INSN_TBNZ: return "TBNZ";
    default: return "?";
    }
}

static int put_b_required(Arm64Writer* w, uint64_t target) {
    if (target == 0)
        return -1;
    return arm64_writer_put_b_imm(w, target);
}

static int put_b_prefer_translated_or_orig(Arm64Writer* w, uint64_t translated_target, uint64_t orig_target) {
    uint64_t target = translated_target != 0 ? translated_target : orig_target;
    if (target == 0)
        return -1;
    return arm64_writer_put_b_imm(w, target);
}

static int emit_branch_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint64_t translated_target,
    uint64_t orig_target,
    uint64_t translated_fallthrough
) {
    switch (info->type) {
    case ARM64_INSN_B:
        return put_b_prefer_translated_or_orig(w, translated_target, orig_target);

    case ARM64_INSN_B_COND: {
        uint64_t skip = arm64_writer_new_label_id(w);
        Arm64Cond inv = (Arm64Cond)(info->cond ^ 1);
        arm64_writer_put_b_cond_label(w, inv, skip);
        if (put_b_prefer_translated_or_orig(w, translated_target, orig_target) != 0)
            return -1;
        arm64_writer_put_label(w, skip);
        return put_b_required(w, translated_fallthrough);
    }

    case ARM64_INSN_CBZ:
    case ARM64_INSN_CBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        if (info->type == ARM64_INSN_CBZ)
            arm64_writer_put_cbnz_reg_label(w, info->reg, skip);
        else
            arm64_writer_put_cbz_reg_label(w, info->reg, skip);
        if (put_b_prefer_translated_or_orig(w, translated_target, orig_target) != 0)
            return -1;
        arm64_writer_put_label(w, skip);
        return put_b_required(w, translated_fallthrough);
    }

    case ARM64_INSN_TBZ:
    case ARM64_INSN_TBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        if (info->type == ARM64_INSN_TBZ)
            arm64_writer_put_tbnz_reg_imm_label(w, info->reg, info->bit, skip);
        else
            arm64_writer_put_tbz_reg_imm_label(w, info->reg, info->bit, skip);
        if (put_b_prefer_translated_or_orig(w, translated_target, orig_target) != 0)
            return -1;
        arm64_writer_put_label(w, skip);
        return put_b_required(w, translated_fallthrough);
    }

    default:
        return -1;
    }
}

static int emit_branch_fallthrough_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint64_t translated_target,
    uint64_t orig_target,
    uint64_t translated_fallthrough,
    uint64_t orig_fallthrough
) {
    switch (info->type) {
    case ARM64_INSN_B:
        return put_b_prefer_translated_or_orig(w, translated_target, orig_target);

    case ARM64_INSN_B_COND: {
        uint64_t skip = arm64_writer_new_label_id(w);
        Arm64Cond inv = (Arm64Cond)(info->cond ^ 1);
        arm64_writer_put_b_cond_label(w, inv, skip);
        if (put_b_prefer_translated_or_orig(w, translated_target, orig_target) != 0)
            return -1;
        arm64_writer_put_label(w, skip);
        return put_b_prefer_translated_or_orig(w, translated_fallthrough, orig_fallthrough);
    }

    case ARM64_INSN_CBZ:
    case ARM64_INSN_CBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        if (info->type == ARM64_INSN_CBZ)
            arm64_writer_put_cbnz_reg_label(w, info->reg, skip);
        else
            arm64_writer_put_cbz_reg_label(w, info->reg, skip);
        if (put_b_prefer_translated_or_orig(w, translated_target, orig_target) != 0)
            return -1;
        arm64_writer_put_label(w, skip);
        return put_b_prefer_translated_or_orig(w, translated_fallthrough, orig_fallthrough);
    }

    case ARM64_INSN_TBZ:
    case ARM64_INSN_TBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        if (info->type == ARM64_INSN_TBZ)
            arm64_writer_put_tbnz_reg_imm_label(w, info->reg, info->bit, skip);
        else
            arm64_writer_put_tbz_reg_imm_label(w, info->reg, info->bit, skip);
        if (put_b_prefer_translated_or_orig(w, translated_target, orig_target) != 0)
            return -1;
        arm64_writer_put_label(w, skip);
        return put_b_prefer_translated_or_orig(w, translated_fallthrough, orig_fallthrough);
    }

    default:
        return -1;
    }
}

static int emit_fallthrough_noscratch_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint32_t insn,
    uint64_t orig_pc,
    uint64_t tramp_pc,
    uint64_t orig_next_page,
    uint64_t translated_next_page,
    uint64_t translated_branch_target
) {
    if (is_branch_type(info->type) &&
        info->type != ARM64_INSN_BL &&
        info->type != ARM64_INSN_BLR) {
        return emit_branch_fallthrough_trampoline(
            w, info, translated_branch_target, info->target,
            translated_next_page, orig_next_page);
    }

    if (info->type == ARM64_INSN_BL || info->type == ARM64_INSN_BLR) {
        return emit_trampoline(w, info, insn, orig_pc + 4, orig_pc + 4);
    }

    if (!info->is_pc_relative && info->type != ARM64_INSN_BLR) {
        arm64_writer_put_insn(w, insn);
        return put_b_prefer_translated_or_orig(w, translated_next_page, orig_next_page);
    }

    if (info->type == ARM64_INSN_PRFM_LITERAL) {
        arm64_writer_put_insn(w, 0xD503201F);
        return put_b_prefer_translated_or_orig(w, translated_next_page, orig_next_page);
    }

    if (info->type == ARM64_INSN_ADR || info->type == ARM64_INSN_ADRP) {
        arm64_writer_put_mov_reg_imm(w, info->dst_reg, info->target);
        return put_b_prefer_translated_or_orig(w, translated_next_page, orig_next_page);
    }

    if (info->type == ARM64_INSN_LDR_LITERAL) {
        Arm64Reg xd = info->dst_reg;
        arm64_writer_put_ldr_reg_address(w, xd, info->target);
        uint32_t opc = (insn >> 30) & 3;
        if (opc == 0) {
            Arm64Reg wd = (Arm64Reg)(xd + 32);
            arm64_writer_put_ldr_reg_reg_offset(w, wd, xd, 0);
        } else {
            arm64_writer_put_ldr_reg_reg_offset(w, xd, xd, 0);
        }
        return put_b_prefer_translated_or_orig(w, translated_next_page, orig_next_page);
    }

    if (info->type == ARM64_INSN_LDRSW_LITERAL) {
        Arm64Reg xd = info->dst_reg;
        arm64_writer_put_ldr_reg_address(w, xd, info->target);
        arm64_writer_put_ldrsw_reg_reg_offset(w, xd, xd, 0);
        return put_b_prefer_translated_or_orig(w, translated_next_page, orig_next_page);
    }

    if (info->type == ARM64_INSN_LDR_LITERAL_FP) {
        arm64_writer_put_push_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        arm64_writer_put_ldr_reg_address(w, ARM64_REG_X16, info->target);
        arm64_writer_put_ldr_fp_reg_reg(w, (uint32_t)info->dst_reg,
                                         ARM64_REG_X16, info->fp_size);
        arm64_writer_put_pop_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        return put_b_prefer_translated_or_orig(w, translated_next_page, orig_next_page);
    }

    uint32_t relocated = 0;
    if (arm64_relocator_relocate_insn(orig_pc, tramp_pc, insn, &relocated) == ARM64_RELOC_OK) {
        arm64_writer_put_insn(w, relocated);
        return put_b_prefer_translated_or_orig(w, translated_next_page, orig_next_page);
    }

    return -1;
}

/* ============================================================================
 * 跳板生成：为超出范围的 PC 相对指令生成跳板代码
 *
 * 设计要点：
 *   - B/BL：跳板做绝对跳转（MOVZ/MOVK + BR X17）
 *   - 条件分支：跳板先判断条件，taken 绝对跳转，not-taken 跳回下一条
 *   - ADR/ADRP：跳板用 MOVZ/MOVK 加载目标地址到目标寄存器，跳回下一条
 *   - LDR literal：跳板加载原始数据地址，从中读取数据，跳回下一条
 *   - 跳回路径使用 put_b_safe（B 优先，失败 fallback 到绝对跳转）
 * ============================================================================ */

/*
 * 页末 fall-through 跳板：执行原始指令后跳到下一原始页
 *
 * 非 PC 相对指令：直接复制原始指令 + 绝对跳转到 next_page
 * PC 相对指令：复用 emit_trampoline，但 return_addr = next_page
 * 页内条件分支：taken 跳回原始页内目标（内核重定向），not-taken 跳到 next_page
 */
static int emit_fallthrough_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint32_t insn,
    uint64_t next_page,       /* orig_base + PAGE_SIZE */
    uint64_t orig_base,       /* 用于计算页内目标 */
    size_t page_size
) {
    if (!info->is_pc_relative) {
        /* 非 PC 相对：复制原始指令 + 绝对跳转到下一页
         * 必须保护 X16/X17：put_branch_address 用 X16 做 scratch，
         * 但调用方可能把 X16 当通用寄存器（如 ART DoCall）。
         * 用 STP/BLR/LDP 模式：BLR 设 LR = LDP 指令地址，callee（= next_page
         * 的代码）最终 RET 回来，执行 LDP 恢复 X16/X17，然后完成。
         * 但 next_page 不是一个 callee（不会 RET），所以用 BR 但手动保护 X16。
         *
         * 简单方案: STP 保存, branch_address, LDP 恢复不可行（BR 之后无法 LDP）。
         * 实际方案: 原始指令可能修改 SP，不能用 STP。
         * 最终方案: 用 LDR X17, [PC+8] + BR X17 替代 MOVZ/MOVK X16 + BR X16，
         *           只 clobber X17（ARM64 PCS 允许 linker 用 X17，编译器极少用它做通用）。
         *           但 X17 也不安全。真正安全: 嵌入地址到代码流用 LDR literal。
         */
        arm64_writer_put_insn(w, insn);
        arm64_writer_put_branch_address_reg(w, next_page, ARM64_REG_X16);
        return 0;
    }

    /* 页内条件分支：taken 跳回原始目标（内核会重定向），not-taken 跳下一页 */
    if (is_branch_type(info->type) &&
        info->target >= orig_base &&
        info->target < orig_base + page_size) {

        switch (info->type) {
        case ARM64_INSN_B_COND: {
            uint64_t taken = arm64_writer_new_label_id(w);
            arm64_writer_put_b_cond_label(w, info->cond, taken);
            /* not-taken → 下一页 */
            arm64_writer_put_branch_address_reg(w, next_page, ARM64_REG_X16);
            arm64_writer_put_label(w, taken);
            /* taken → 原始页内目标（内核重定向到重编译页） */
            arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
            break;
        }
        case ARM64_INSN_CBZ:
        case ARM64_INSN_CBNZ: {
            uint64_t taken = arm64_writer_new_label_id(w);
            if (info->type == ARM64_INSN_CBZ)
                arm64_writer_put_cbz_reg_label(w, info->reg, taken);
            else
                arm64_writer_put_cbnz_reg_label(w, info->reg, taken);
            arm64_writer_put_branch_address_reg(w, next_page, ARM64_REG_X16);
            arm64_writer_put_label(w, taken);
            arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
            break;
        }
        case ARM64_INSN_TBZ:
        case ARM64_INSN_TBNZ: {
            uint64_t taken = arm64_writer_new_label_id(w);
            if (info->type == ARM64_INSN_TBZ)
                arm64_writer_put_tbz_reg_imm_label(w, info->reg, info->bit, taken);
            else
                arm64_writer_put_tbnz_reg_imm_label(w, info->reg, info->bit, taken);
            arm64_writer_put_branch_address_reg(w, next_page, ARM64_REG_X16);
            arm64_writer_put_label(w, taken);
            arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
            break;
        }
        case ARM64_INSN_BL:
            /* BL 到页内目标：不会 fall-through（BL 跳走了），但保险起见还是处理 */
            arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
            break;
        default:
            arm64_writer_put_insn(w, insn);
            arm64_writer_put_branch_address_reg(w, next_page, ARM64_REG_X16);
            break;
        }
        return 0;
    }

    /* 其余 PC 相对指令（ADR/ADRP/LDR literal/页外分支）：
     * 复用 emit_trampoline，return_addr 改为 next_page */
    return -1; /* 返回 -1 表示调用方应使用 emit_trampoline(return_addr=next_page) */
}

static int emit_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint32_t insn,
    uint64_t return_addr,  /* recomp_base + offset + 4 */
    uint64_t orig_ret_addr /* orig_base + offset + 4 (BL 用，其余传 0) */
) {
    switch (info->type) {

    /* ---- B ---- */
    case ARM64_INSN_B:
        arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
        break;

    /* ---- BL ---- */
    case ARM64_INSN_BL:
        /* LR = 原始返回地址，X16 = 跳转目标（进入新函数，clobber 无影响） */
        arm64_writer_put_mov_reg_imm(w, ARM64_REG_X30, orig_ret_addr);
        arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
        break;

    /* ---- BLR ---- */
    case ARM64_INSN_BLR:
        /* BLR 隐式写 LR = recomp_pc + 4，需手动设 LR = 原始返回地址 */
        if (info->reg == ARM64_REG_X30) {
            /* 目标寄存器就是 LR，先借 X16 保存原目标，再覆写 LR */
            arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X30);
            arm64_writer_put_mov_reg_imm(w, ARM64_REG_X30, orig_ret_addr);
            arm64_writer_put_br_reg(w, ARM64_REG_X16);
        } else {
            arm64_writer_put_mov_reg_imm(w, ARM64_REG_X30, orig_ret_addr);
            arm64_writer_put_br_reg(w, info->reg);
        }
        break;

    /* ---- B.cond ---- */
    case ARM64_INSN_B_COND: {
        /* B.!cond skip → 绝对跳转到 target → skip: B return_addr */
        uint64_t skip = arm64_writer_new_label_id(w);
        Arm64Cond inv = (Arm64Cond)(info->cond ^ 1);
        arm64_writer_put_b_cond_label(w, inv, skip);
        arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
        arm64_writer_put_label(w, skip);
        put_b_safe(w, return_addr);
        break;
    }

    /* ---- CBZ / CBNZ ---- */
    case ARM64_INSN_CBZ:
    case ARM64_INSN_CBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        /* 反转条件：CBZ → CBNZ skip，CBNZ → CBZ skip */
        if (info->type == ARM64_INSN_CBZ)
            arm64_writer_put_cbnz_reg_label(w, info->reg, skip);
        else
            arm64_writer_put_cbz_reg_label(w, info->reg, skip);
        arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
        arm64_writer_put_label(w, skip);
        put_b_safe(w, return_addr);
        break;
    }

    /* ---- TBZ / TBNZ ---- */
    case ARM64_INSN_TBZ:
    case ARM64_INSN_TBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        if (info->type == ARM64_INSN_TBZ)
            arm64_writer_put_tbnz_reg_imm_label(w, info->reg, info->bit, skip);
        else
            arm64_writer_put_tbz_reg_imm_label(w, info->reg, info->bit, skip);
        arm64_writer_put_branch_address_reg(w, info->target, ARM64_REG_X16);
        arm64_writer_put_label(w, skip);
        put_b_safe(w, return_addr);
        break;
    }

    /* ---- ADR / ADRP ---- */
    case ARM64_INSN_ADR:
    case ARM64_INSN_ADRP:
        /* 用 MOVZ/MOVK 序列加载目标地址到 Xd，然后跳回 */
        arm64_writer_put_mov_reg_imm(w, info->dst_reg, info->target);
        put_b_safe(w, return_addr);
        break;

    /* ---- LDR literal (GPR) ---- */
    case ARM64_INSN_LDR_LITERAL: {
        /* 自引用加载：
         *   LDR Xd, =data_addr    (加载原始数据地址)
         *   LDR Xd/Wd, [Xd]      (从原始地址读取数据)
         *   B return_addr
         */
        Arm64Reg xd = info->dst_reg;  /* 总是 Xn (0-30) */
        arm64_writer_put_ldr_reg_address(w, xd, info->target);

        uint32_t opc = (insn >> 30) & 3;
        if (opc == 0) {
            /* 32 位加载：LDR Wd, [Xd] */
            Arm64Reg wd = (Arm64Reg)(xd + 32);
            arm64_writer_put_ldr_reg_reg_offset(w, wd, xd, 0);
        } else {
            /* 64 位加载：LDR Xd, [Xd] */
            arm64_writer_put_ldr_reg_reg_offset(w, xd, xd, 0);
        }
        put_b_safe(w, return_addr);
        break;
    }

    /* ---- LDRSW literal ---- */
    case ARM64_INSN_LDRSW_LITERAL: {
        Arm64Reg xd = info->dst_reg;
        arm64_writer_put_ldr_reg_address(w, xd, info->target);
        arm64_writer_put_ldrsw_reg_reg_offset(w, xd, xd, 0);
        put_b_safe(w, return_addr);
        break;
    }

    /* ---- LDR literal (FP/SIMD) ---- */
    case ARM64_INSN_LDR_LITERAL_FP: {
        /* FP 寄存器不能做地址运算。保存/恢复 X16/X17，避免污染 ART
         * quick code 中后续仍会使用的临时寄存器。 */
        arm64_writer_put_push_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        arm64_writer_put_ldr_reg_address(w, ARM64_REG_X16, info->target);
        arm64_writer_put_ldr_fp_reg_reg(w, (uint32_t)info->dst_reg,
                                         ARM64_REG_X16, info->fp_size);
        arm64_writer_put_pop_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        put_b_safe(w, return_addr);
        break;
    }

    /* ---- PRFM literal ---- */
    case ARM64_INSN_PRFM_LITERAL:
        /* 预取指令丢弃即可，直接跳回 */
        put_b_safe(w, return_addr);
        break;

    default:
        /* 不应到达此处 */
        put_b_safe(w, return_addr);
        break;
    }

    return 0;
}

/* ============================================================================
 * 主入口：重编译一页代码
 * ============================================================================ */

int recompile_page(
    const void* orig_code,
    uint64_t orig_base,
    void* recomp_buf,
    uint64_t recomp_base,
    size_t page_size,
    void* tramp_buf,
    uint64_t tramp_base,
    size_t tramp_cap,
    size_t* tramp_used,
    uint64_t suspend_entrypoint,
    RecompTranslateExistingFn translate_existing,
    void* translate_user_data,
    RecompileStats* stats
) {
    RecompileStats local_stats;
    memset(&local_stats, 0, sizeof(local_stats));

    if (orig_code == NULL || recomp_buf == NULL || tramp_buf == NULL ||
        page_size == 0 || (page_size & 3) != 0 ||
        (page_size & (page_size - 1)) != 0 ||
        (orig_base & (page_size - 1)) != 0 ||
        (recomp_base & (page_size - 1)) != 0) {
        local_stats.error = -1;
        snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                 "invalid recomp page size or alignment (page_size=%zu)", page_size);
        if (stats)
            *stats = local_stats;
        return -1;
    }

    const uint32_t* orig_insns = (const uint32_t*)orig_code;
    uint32_t* recomp_insns = (uint32_t*)recomp_buf;
    size_t insn_count = page_size / sizeof(uint32_t);

    /* 初始化跳板区 writer */
    Arm64Writer tw;
    arm64_writer_init(&tw, tramp_buf, tramp_base, tramp_cap);

    /* 逐条处理 */
    for (size_t i = 0; i < insn_count; i++) {
        uint32_t insn = orig_insns[i];
        uint64_t orig_pc  = orig_base  + (uint64_t)(i * 4);
        uint64_t recomp_pc = recomp_base + (uint64_t)(i * 4);
        int is_last = (i == insn_count - 1);

        /* 分析指令 */
        Arm64InsnInfo info = arm64_relocator_analyze_insn(orig_pc, insn);

        if (is_branch_type(info.type) &&
            info.type != ARM64_INSN_BL &&
            info.type != ARM64_INSN_BLR &&
            !(is_last && !is_unconditional_transfer(info.type))) {
            if (info.target != 0) {
                uint32_t branch_insn = 0;
                uint64_t intra_target = 0;
                if (info.target >= orig_base && info.target < orig_base + page_size) {
                    intra_target = recomp_base + (info.target - orig_base);
                    if (encode_branch_like(insn, info.type, recomp_pc, intra_target, &branch_insn) == 0) {
                        recomp_insns[i] = branch_insn;
                        local_stats.num_intra_page++;
                        continue;
                    }
                }

                uint64_t translated_target = translate_existing
                    ? translate_existing(info.target, translate_user_data)
                    : 0;
                if (translated_target != 0 &&
                    encode_branch_like(insn, info.type, recomp_pc, translated_target, &branch_insn) == 0) {
                    recomp_insns[i] = branch_insn;
                    local_stats.num_direct_reloc++;
                    continue;
                }

                if (!arm64_writer_can_write(&tw, 32)) {
                    local_stats.error = -1;
                    snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                             "跳板区空间不足 (branch noscratch offset=0x%zx)", i * 4);
                    goto done;
                }

                uint64_t tramp_pc = arm64_writer_pc(&tw);
                uint64_t translated_fallthrough = recomp_pc + 4;
                if (emit_branch_trampoline(
                        &tw, &info, translated_target, info.target, translated_fallthrough) != 0) {
                    local_stats.error = -1;
                    snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                             "无 scratch 分支跳板超出 B 范围 (offset=0x%zx type=%s target=0x%llx branch_target=0x%llx)",
                             i * 4, branch_type_name(info.type),
                             (unsigned long long)info.target,
                             (unsigned long long)(translated_target != 0 ? translated_target : info.target));
                    goto done;
                }

                uint32_t tramp_branch_insn = 0;
                if (encode_b(recomp_pc, tramp_pc, &tramp_branch_insn) != 0) {
                    local_stats.error = -1;
                    snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                             "无法编码到无 scratch 分支跳板 (offset=0x%zx tramp=0x%llx)",
                             i * 4, (unsigned long long)tramp_pc);
                    goto done;
                }

                recomp_insns[i] = tramp_branch_insn;
                local_stats.num_trampolines++;
#if RECOMP_DEBUG_LOG
                hook_log("[recomp-BR-NOSCRATCH] page=%llx +0x%03x: %08x type=%s target=%llx translated=%llx tramp=%llx",
                         (unsigned long long)orig_base, i * 4, insn,
                         branch_type_name(info.type),
                         (unsigned long long)info.target,
                         (unsigned long long)(translated_target != 0 ? translated_target : info.target),
                         (unsigned long long)tramp_pc);
#endif
                continue;
            }

            if (info.target < orig_base || info.target >= orig_base + page_size) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "页外非调用分支缺少目标 recomp 页 (offset=0x%zx type=%s target=0x%llx)",
                         i * 4, branch_type_name(info.type),
                         (unsigned long long)info.target);
                goto done;
            }
        }

        /* ART arm64 quick implicit suspend checks are encoded as
         *   ldr x21, [x21]
         * on the original OAT/boot page. Executing the same instruction on an
         * anonymous recomp page with x21 == 0 raises SIGSEGV outside ART's
         * generated-code fault-manager range. When a quick suspend entrypoint
         * is known, dispatch to ART with LR set to the original next OAT PC;
         * otherwise skip the null fault as a temporary fallback. This must run
         * before the page-end fall-through fixup, so a poll at the last page
         * instruction is never copied into a generic fall-through trampoline. */
        if (is_art_implicit_suspend_poll(insn)) {
            if (!arm64_writer_can_write(&tw, suspend_entrypoint != 0 ? 56 : 24)) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "跳板区空间不足 (suspend-poll guard offset=0x%zx)", i * 4);
                goto done;
            }

            uint64_t tramp_pc = arm64_writer_pc(&tw);
            uint64_t translated_fallthrough = recomp_pc + 4;
            if (is_last) {
                uint64_t next_page = orig_base + page_size;
                translated_fallthrough = translate_existing
                    ? translate_existing(next_page, translate_user_data)
                    : 0;
            }
            uint64_t orig_fallthrough = orig_pc + 4;
            if (emit_suspend_poll_skip_null_trampoline(&tw, insn, orig_fallthrough,
                                                       suspend_entrypoint, translated_fallthrough) != 0) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "suspend-poll guard 跳板超出 B 范围 (offset=0x%zx)", i * 4);
                goto done;
            }

            uint32_t branch_insn;
            if (encode_b(recomp_pc, tramp_pc, &branch_insn) != 0) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "无法编码到 suspend-poll guard 跳板 (offset=0x%zx)", i * 4);
                goto done;
            }

            recomp_insns[i] = branch_insn;
            local_stats.num_trampolines++;
#if RECOMP_DEBUG_LOG
            hook_log("[recomp-SUSPEND] page=%llx +0x%03x: %08x -> guard tramp=%llx ret=%llx entry=%llx",
                     (unsigned long long)orig_base, i * 4, insn,
                     (unsigned long long)tramp_pc,
                     (unsigned long long)translated_fallthrough,
                     (unsigned long long)suspend_entrypoint);
#endif
            continue;
        }

        /* ================================================================
         * 页末 fall-through 修复：
         * 最后一条指令如果不是无条件跳转/返回，执行后 PC 会进入跳板区。
         * 必须强制走跳板，确保 fall-through 跳到原始下一页。
         * ================================================================ */
        if (is_last && !is_unconditional_transfer(info.type)) {
            if (!arm64_writer_can_write(&tw, 96)) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "跳板区空间不足 (fall-through fixup)");
                goto done;
            }

            uint64_t tramp_pc = arm64_writer_pc(&tw);
            uint64_t next_page = orig_base + page_size;
            uint64_t next_target = translate_existing
                ? translate_existing(next_page, translate_user_data)
                : 0;
            uint64_t translated_branch_target = 0;
            if (is_branch_type(info.type) &&
                info.type != ARM64_INSN_BL &&
                info.type != ARM64_INSN_BLR) {
                if (info.target >= orig_base && info.target < orig_base + page_size) {
                    translated_branch_target = recomp_base + (info.target - orig_base);
                } else if (translate_existing) {
                    translated_branch_target = translate_existing(info.target, translate_user_data);
                }
            }

            if (emit_fallthrough_noscratch_trampoline(
                    &tw, &info, insn, orig_pc, tramp_pc, next_page, next_target,
                    translated_branch_target) != 0) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "页末 fall-through 无 scratch 跳板失败 (offset=0x%zx type=%d next=0x%llx)",
                         i * 4, info.type,
                         (unsigned long long)next_page);
                goto done;
            }

            /* 替换为 B 到跳板（BL 也用 B，LR 由跳板设置） */
            uint32_t branch_insn;
            int enc_err = encode_b(recomp_pc, tramp_pc, &branch_insn);
            if (enc_err != 0) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "encode B failed (fall-through, offset=0x%zx)", i * 4);
                goto done;
            }
            recomp_insns[i] = branch_insn;
            local_stats.num_trampolines++;
            continue;
        }

        /* 1) 非 PC 相对指令：直接复制
         * 但 BLR 会隐式写 LR = recomp_pc + 4，绝不能直接复制。 */
        if (!info.is_pc_relative && info.type != ARM64_INSN_BLR) {
            recomp_insns[i] = insn;
            local_stats.num_copied++;
            continue;
        }

        /* 2) 页内分支：偏移不变，直接复制
         *    只对非调用型分支做此优化。BL/BLR 绝不能直接复制/直重定位，
         *    否则 LR 会落在 recomp 页而不是原始 OAT 页，ART 在
         *    dex_pc / CodeInfo / quick resolve 路径上会用错返回地址。 */
        if (is_branch_type(info.type) &&
            info.type != ARM64_INSN_BL &&
            info.type != ARM64_INSN_BLR &&
            !(is_last && !is_unconditional_transfer(info.type)) &&
            info.target >= orig_base &&
            info.target < orig_base + page_size) {
            recomp_insns[i] = insn;
            local_stats.num_intra_page++;
            continue;
        }

        /* 3) 尝试直接调整立即数 */
        uint32_t relocated = 0;
        Arm64RelocResult rr = (info.type == ARM64_INSN_BL || info.type == ARM64_INSN_BLR)
            ? ARM64_RELOC_OUT_OF_RANGE
            : arm64_relocator_relocate_insn(orig_pc, recomp_pc, insn, &relocated);

        if (rr == ARM64_RELOC_OK) {
            recomp_insns[i] = relocated;
            local_stats.num_direct_reloc++;
#if RECOMP_DEBUG_LOG
            if (info.type == ARM64_INSN_ADRP || info.type == ARM64_INSN_ADR) {
                hook_log("[recomp-RELOC] page=%llx +0x%03x: %08x → %08x  type=%s target=%llx dst_reg=%d",
                         (unsigned long long)orig_base, i * 4, insn, relocated,
                         info.type == ARM64_INSN_ADRP ? "ADRP" : "ADR",
                         (unsigned long long)info.target, (int)info.dst_reg);
            }
#endif
            continue;
        }

        /* 4) PRFM 特殊处理：直接替换为 NOP（无需跳板） */
        if (info.type == ARM64_INSN_PRFM_LITERAL) {
            recomp_insns[i] = 0xD503201F;  /* NOP */
            local_stats.num_direct_reloc++;
            continue;
        }

        /* 5) 超出范围：生成跳板 */
        if (!arm64_writer_can_write(&tw, 64)) {
            local_stats.error = -1;
            snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                     "跳板区空间不足 (offset=0x%zx)", i * 4);
            goto done;
        }

        uint64_t tramp_pc = arm64_writer_pc(&tw);
        uint64_t return_addr = recomp_pc + 4;
        uint64_t orig_ret_addr = orig_pc + 4;  /* BL 用：LR 指向原始地址 */

        /* 生成跳板代码 */
        size_t tramp_before = arm64_writer_offset(&tw);
        emit_trampoline(&tw, &info, insn, return_addr, orig_ret_addr);
        size_t tramp_after = arm64_writer_offset(&tw);

        /* 安全检查：跳板必须有内容 */
        if (tramp_after == tramp_before) {
            local_stats.error = -1;
            snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                     "空跳板 (offset=0x%zx, type=%d)", i * 4, info.type);
            goto done;
        }

        /* BL 也用 B（LR 由跳板手动设置为原始地址） */
        uint32_t branch_insn;
        int enc_err = encode_b(recomp_pc, tramp_pc, &branch_insn);

        if (enc_err != 0) {
            local_stats.error = -1;
            snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                     "无法编码到跳板的分支 (offset=0x%zx, tramp=0x%llx)",
                     i * 4, (unsigned long long)tramp_pc);
            goto done;
        }

        recomp_insns[i] = branch_insn;
        local_stats.num_trampolines++;

#if RECOMP_DEBUG_LOG
        /* DEBUG: 打印每条跳板化指令的详细信息 */
        {
            static const char* type_names[] = {
                [ARM64_INSN_B]="B", [ARM64_INSN_BL]="BL", [ARM64_INSN_B_COND]="B.cond",
                [ARM64_INSN_CBZ]="CBZ", [ARM64_INSN_CBNZ]="CBNZ",
                [ARM64_INSN_TBZ]="TBZ", [ARM64_INSN_TBNZ]="TBNZ",
                [ARM64_INSN_ADR]="ADR", [ARM64_INSN_ADRP]="ADRP",
                [ARM64_INSN_LDR_LITERAL]="LDR_LIT", [ARM64_INSN_LDRSW_LITERAL]="LDRSW_LIT",
                [ARM64_INSN_LDR_LITERAL_FP]="LDR_LIT_FP",
                [ARM64_INSN_PRFM_LITERAL]="PRFM_LIT",
                [ARM64_INSN_BR]="BR", [ARM64_INSN_BLR]="BLR", [ARM64_INSN_RET]="RET",
            };
            const char* tname = (info.type < sizeof(type_names)/sizeof(type_names[0]) && type_names[info.type])
                ? type_names[info.type] : "?";
            hook_log("[recomp-TRAMP] page=%llx +0x%03x: %08x → B tramp  type=%-10s target=%llx dst_reg=%d tramp_pc=%llx ret=%llx",
                     (unsigned long long)orig_base, i * 4, insn, tname,
                     (unsigned long long)info.target, (int)info.dst_reg,
                     (unsigned long long)tramp_pc, (unsigned long long)return_addr);
        }
#endif
    }

    /* flush writer 的 label 引用 */
    if (arm64_writer_flush(&tw) != 0) {
        local_stats.error = -1;
        snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                 "跳板区 label 解析失败");
    }

#if RECOMP_DEBUG_LOG
    /* DEBUG: dump 所有被修改的指令 + 未被修改但为 PC-relative 的（疑似遗漏） */
    if (local_stats.error == 0) {
        int miss_count = 0;
        for (size_t d = 0; d < insn_count; d++) {
            uint32_t orig = orig_insns[d];
            uint32_t recomp = recomp_insns[d];
            if (orig != recomp) {
                /* 已被 recomp 修改（trampoline 化），正常 */
            } else {
                /* 没改——检查是否漏掉了 PC-relative 指令 */
                uint64_t insn_pc = orig_base + (uint64_t)(d * 4);
                Arm64InsnInfo chk = arm64_relocator_analyze_insn(insn_pc, orig);
                if (chk.is_pc_relative) {
                    /* PC-relative 但没被改——如果是页内分支则正常，否则是 BUG */
                    if (is_branch_type(chk.type) &&
                        chk.target >= orig_base &&
                        chk.target < orig_base + page_size) {
                        /* 页内分支，正常保留 */
                    } else {
                        hook_log("[recomp-MISS] page=%llx offset=0x%03x: insn=%08x type=%d target=%llx NOT RELOCATED!",
                                 (unsigned long long)orig_base, d*4, orig, chk.type,
                                 (unsigned long long)chk.target);
                        miss_count++;
                    }
                }
            }
        }
        if (miss_count > 0) {
            hook_log("[recomp-MISS] page=%llx: %d PC-relative instructions NOT relocated!",
                     (unsigned long long)orig_base, miss_count);
        }
    }
#endif

    /* 在跳板区末尾填 BRK guard，防止 fall-through 到空白执行垃圾指令 */
    while (arm64_writer_can_write(&tw, 4)) {
        arm64_writer_put_brk_imm(&tw, 0xFEED);
    }

done:
    /* 记录实际跳板使用量：减去 BRK guard 填充。
     * BRK guard 从 actual end 到 capacity 全填满了，
     * 但 alloc_trampoline_slot 需要知道真实已用量才能分配后续 slot。
     * 计算方式：向后扫描 BRK，找到最后一个非 BRK 位置。 */
    {
        size_t used = arm64_writer_offset(&tw);
        uint32_t* base_u32 = (uint32_t*)tramp_buf;
        while (used >= 4) {
            uint32_t last = base_u32[(used / 4) - 1];
            if (last != (0xD4200000 | (0xFEED << 5)))  /* BRK #0xFEED */
                break;
            used -= 4;
        }
        if (tramp_used)
            *tramp_used = used;
    }

    if (stats)
        *stats = local_stats;

    arm64_writer_clear(&tw);

    return local_stats.error ? -1 : 0;
}

/* ============================================================================
 * arm64_install_user_patch — reloc a user patch body into a slot buffer and
 * append a fall-through B to the next original instruction.
 * ============================================================================ */

static void set_err(char* err_buf, size_t err_cap, const char* msg) {
    if (!err_buf || err_cap == 0) return;
    size_t n = strlen(msg);
    if (n >= err_cap) n = err_cap - 1;
    memcpy(err_buf, msg, n);
    err_buf[n] = '\0';
}

int arm64_install_user_patch(
    const uint8_t* user_bytes, size_t user_len,
    uint64_t user_src_pc,
    uint8_t* slot_buf, size_t slot_cap, uint64_t slot_pc,
    uint64_t fall_through_target,
    uint64_t orig_page_base,
    uint64_t recomp_page_base,
    size_t   redirect_page_size,
    char* err_buf, size_t err_cap
) {
    if (user_bytes == NULL || user_len == 0 || (user_len & 3) != 0) {
        set_err(err_buf, err_cap, "user_len must be non-zero and 4-byte multiple");
        return -1;
    }
    if (slot_buf == NULL || slot_cap < 16) {
        set_err(err_buf, err_cap, "slot_cap too small");
        return -1;
    }

    Arm64Writer w;
    Arm64Relocator r;
    arm64_writer_init(&w, slot_buf, slot_pc, slot_cap);
    arm64_relocator_init(&r, user_bytes, user_src_pc, &w);

    /* Page-redirect: branches whose target is inside the user_src_pc's page
     * get emitted as direct branches to recomp_page_base + offset instead of
     * 20-byte absolute-jump stubs back to the original (prctl-redirected) code. */
    if (redirect_page_size != 0) {
        r.page_redirect_orig_base = orig_page_base;
        r.page_redirect_new_base = recomp_page_base;
        r.page_redirect_size = redirect_page_size;
    }

    /* Within-region branch fixup: pre-create one writer label per source
     * instruction so patch-internal branches (B / CBZ / TBZ / B.cond with
     * target inside [user_src_pc, user_src_pc+user_len)) get re-emitted as
     * label-based branches pointing into the slot instead of back to the
     * original address. Capped at ARM64_RELOC_MAX_REGION (8) — larger patches
     * silently fall back to external-branch semantics. */
    int total_insns = (int)(user_len / 4);
    int region_n = (total_insns <= ARM64_RELOC_MAX_REGION) ? total_insns : 0;
    if (region_n > 0) {
        r.region_end = user_src_pc + user_len;
        r.region_label_count = region_n;
        for (int i = 0; i < region_n; i++) {
            r.region_labels[i].src_pc = user_src_pc + (uint64_t)(i * 4);
            r.region_labels[i].label_id = arm64_writer_new_label_id(&w);
        }
    }

    Arm64InsnType last_type = ARM64_INSN_UNKNOWN;
    int insn_idx = 0;

    /* Write every instruction in the user patch. We do NOT stop at the first
     * unconditional terminator — with internal branches a mid-stream RET/B is
     * just one exit path; subsequent instructions can be branch targets. */
    while (insn_idx < total_insns) {
        /* Place this instruction's label BEFORE emitting so back-refs resolve
         * immediately; forward-refs resolve during flush. */
        if (insn_idx < region_n) {
            arm64_writer_put_label(&w, r.region_labels[insn_idx].label_id);
        }

        /* User patch input has an explicit length. Keep relocating bytes after
         * B/BR/RET because a later instruction may be an internal branch
         * target; the public write_all() path still stops at EOI. */
        r.eoi = 0;
        int n = arm64_relocator_read_one(&r);
        if (n <= 0) break;

        Arm64RelocResult rr = arm64_relocator_write_one(&r);
        if (rr != ARM64_RELOC_OK) {
            set_err(err_buf, err_cap, "relocator_write_one failed (out of range or unsupported insn)");
            arm64_relocator_clear(&r);
            arm64_writer_clear(&w);
            return -1;
        }
        insn_idx++;
        last_type = r.current_info.type;
    }

    /* Place labels for any instructions not reached (e.g. early EOI) so forward
     * label references created before the loop exits are always resolvable. */
    for (int i = insn_idx; i < region_n; i++) {
        arm64_writer_put_label(&w, r.region_labels[i].label_id);
    }

    /* Append fall-through B only if the LAST instruction in the patch didn't
     * terminate flow itself (RET/B/BR). User patches ending with RET don't need
     * a fall-through; those ending with a conditional branch or plain MOV do. */
    if (!is_unconditional_transfer(last_type)) {
        put_b_safe(&w, fall_through_target);
    }

    if (arm64_writer_flush(&w) != 0) {
        set_err(err_buf, err_cap, "arm64_writer_flush failed (label out of range)");
        arm64_relocator_clear(&r);
        arm64_writer_clear(&w);
        return -1;
    }

    size_t written = arm64_writer_offset(&w);
    arm64_relocator_clear(&r);
    arm64_writer_clear(&w);

    if (written == 0) {
        set_err(err_buf, err_cap, "wrote zero bytes");
        return -1;
    }
    if (written > (size_t)INT_MAX) {
        set_err(err_buf, err_cap, "written size too large");
        return -1;
    }
    return (int)written;
}

#include "propagate.h"
#include <algorithm>

namespace hype {

bool Propagate::is_used(const Varnode& vn, const PcodeFunc& func, int skip_blk, int skip_idx) {
    for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
        auto& blk = func.blocks[bi];
        for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
            if (bi == skip_blk && oi == skip_idx) continue;
            auto& op = blk.ops[oi];
            if (op.op == PcodeOp::NOP) continue;
            for (auto& in : op.inputs)
                if (in.kind == vn.kind && in.id == vn.id && in.offset == vn.offset)
                    return true;
        }
    }
    return false;
}

void Propagate::replace_uses(PcodeFunc& func, const Varnode& old_vn, const Varnode& new_vn,
                             int def_blk, int def_idx) {
    for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
        auto& blk = func.blocks[bi];
        for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
            if (bi == def_blk && oi == def_idx) continue;
            for (auto& in : blk.ops[oi].inputs) {
                if (in.kind == old_vn.kind && in.id == old_vn.id && in.offset == old_vn.offset)
                    in = new_vn;
            }
        }
    }
}

void Propagate::copy_propagation(PcodeFunc& func) {
    for (int pass = 0; pass < 8; ++pass) {
        bool changed = false;
        for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
            auto& blk = func.blocks[bi];
            for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
                auto& op = blk.ops[oi];
                if (op.op != PcodeOp::COPY) continue;
                if (!op.output.valid()) continue;
                if (op.inputs.empty()) continue;
                if (op.seq == -1) continue;

                auto& src = op.inputs[0];
                if (!src.valid()) continue;
                if (src.is_const() && op.output.is_reg() && op.output.id == 4) continue;

                replace_uses(func, op.output, src, bi, oi);
                if (!is_used(op.output, func, bi, oi)) {
                    op.op = PcodeOp::NOP;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }
    for (auto& blk : func.blocks)
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
}

void Propagate::constant_fold(PcodeFunc& func) {
    for (auto& blk : func.blocks) {
        for (auto& op : blk.ops) {
            if (op.inputs.size() != 2) continue;
            if (!op.inputs[0].is_const() || !op.inputs[1].is_const()) continue;

            u64 l = op.inputs[0].offset;
            u64 r = op.inputs[1].offset;
            u64 result = 0;
            bool folded = true;

            switch (op.op) {
            case PcodeOp::ADD: result = l + r; break;
            case PcodeOp::SUB: result = l - r; break;
            case PcodeOp::AND: result = l & r; break;
            case PcodeOp::OR:  result = l | r; break;
            case PcodeOp::XOR: result = l ^ r; break;
            case PcodeOp::SHIFT_LEFT: result = (r < 64) ? (l << r) : 0; break;
            case PcodeOp::SHIFT_RIGHT: result = (r < 64) ? (l >> r) : 0; break;
            case PcodeOp::INT_MULT: result = l * r; break;
            case PcodeOp::INT_EQUAL: result = (l == r) ? 1 : 0; break;
            case PcodeOp::INT_LESS: result = (l < r) ? 1 : 0; break;
            case PcodeOp::INT_SLESS: result = ((i64)l < (i64)r) ? 1 : 0; break;
            default: folded = false; break;
            }

            if (folded) {
                op.op = PcodeOp::COPY;
                op.inputs = {vn_const(result, op.output.size)};
            }
        }
    }
}

void Propagate::dead_copy_elim(PcodeFunc& func) {
    for (int pass = 0; pass < 12; ++pass) {
        bool changed = false;
        for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
            auto& blk = func.blocks[bi];
            for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
                auto& op = blk.ops[oi];
                if (op.op == PcodeOp::NOP) continue;
                if (op.op == PcodeOp::CALL || op.op == PcodeOp::RETURN ||
                    op.op == PcodeOp::CBRANCH || op.op == PcodeOp::BRANCH ||
                    op.op == PcodeOp::STORE) continue;
                if (!op.output.valid()) continue;
                if (op.output.is_reg() && op.output.id == 0) continue;

                if (!is_used(op.output, func, bi, oi)) {
                    op.op = PcodeOp::NOP;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }
    for (auto& blk : func.blocks)
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
}

void Propagate::inline_single_use(PcodeFunc& func) {
    for (int pass = 0; pass < 8; ++pass) {
        bool changed = false;
        for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
            auto& blk = func.blocks[bi];
            for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
                auto& op = blk.ops[oi];
                if (op.op == PcodeOp::NOP || op.op == PcodeOp::CALL ||
                    op.op == PcodeOp::RETURN || op.op == PcodeOp::CBRANCH ||
                    op.op == PcodeOp::BRANCH || op.op == PcodeOp::STORE) continue;
                if (!op.output.valid() || !op.output.is_temp()) continue;
                if (op.inputs.empty()) continue;

                int use_count = 0;
                int ubi = -1, uoi = -1, uin = -1;
                for (int bi2 = 0; bi2 < (int)func.blocks.size() && use_count <= 1; ++bi2) {
                    auto& blk2 = func.blocks[bi2];
                    for (int oi2 = 0; oi2 < (int)blk2.ops.size() && use_count <= 1; ++oi2) {
                        if (bi2 == bi && oi2 == oi) continue;
                        if (blk2.ops[oi2].op == PcodeOp::NOP) continue;
                        for (int ii = 0; ii < (int)blk2.ops[oi2].inputs.size(); ++ii) {
                            auto& in = blk2.ops[oi2].inputs[ii];
                            if (in.kind == op.output.kind && in.id == op.output.id &&
                                in.offset == op.output.offset) {
                                ++use_count;
                                ubi = bi2; uoi = oi2; uin = ii;
                            }
                        }
                    }
                }

                if (use_count == 1 && ubi >= 0) {
                    auto& use_op = func.blocks[ubi].ops[uoi];
                    if (op.op == PcodeOp::COPY && op.inputs.size() == 1) {
                        use_op.inputs[uin] = op.inputs[0];
                    } else {
                        continue;
                    }
                    op.op = PcodeOp::NOP;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }
    for (auto& blk : func.blocks)
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
}

void Propagate::run(PcodeFunc& func) {
    eliminate_identity(func);
    fold_arg_setup(func);
    copy_propagation(func);
    constant_fold(func);
    copy_propagation(func);
    fold_flags(func);
    dead_copy_elim(func);
    copy_propagation(func);
    inline_single_use(func);
    constant_fold(func);
    dead_copy_elim(func);
}

void Propagate::eliminate_identity(PcodeFunc& func) {
    for (auto& blk : func.blocks) {
        for (auto& op : blk.ops) {
            if (op.op != PcodeOp::COPY) continue;
            if (op.inputs.empty()) continue;
            auto& src = op.inputs[0];
            if (op.output.kind == src.kind && op.output.id == src.id && op.output.offset == src.offset)
                op.op = PcodeOp::NOP;
            else if (op.output.is_reg() && src.is_reg() && op.output.id == src.id && op.output.offset == src.offset)
                op.op = PcodeOp::NOP;
        }
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
    }
}

void Propagate::fold_flags(PcodeFunc& func) {
    // pattern: t = AND(x, x); ZF = INT_EQUAL(t, 0); cond = BOOL_NOT(ZF); CBRANCH(target, cond)
    // collapse to: CBRANCH(target, INT_NOT_EQUAL(x, 0))
    // also: ZF = INT_EQUAL(x, y); cond = BOOL_NOT(ZF); CBRANCH → CBRANCH(target, INT_NOT_EQUAL(x, y))
    for (auto& blk : func.blocks) {
        for (int i = 0; i + 1 < (int)blk.ops.size(); ++i) {
            auto& op = blk.ops[i];
            // pattern: ZF = INT_EQUAL(a, b)
            if (op.op == PcodeOp::INT_EQUAL && op.output.valid() && op.output.id >= 100) {
                // look for BOOL_NOT of this flag, then CBRANCH
                for (int j = i + 1; j < (int)blk.ops.size(); ++j) {
                    auto& op2 = blk.ops[j];
                    if (op2.op == PcodeOp::BOOL_NOT && !op2.inputs.empty() &&
                        op2.inputs[0].id == op.output.id && op2.inputs[0].kind == op.output.kind) {
                        // found !ZF - now find CBRANCH using this
                        for (int k = j + 1; k < (int)blk.ops.size(); ++k) {
                            auto& op3 = blk.ops[k];
                            if (op3.op == PcodeOp::CBRANCH && op3.inputs.size() >= 2 &&
                                op3.inputs[1].id == op2.output.id && op3.inputs[1].kind == op2.output.kind) {
                                // collapse: CBRANCH uses INT_NOT_EQUAL(a, b) directly
                                PcodeInsn neq;
                                neq.op = PcodeOp::INT_NEQUAL;
                                neq.output = op2.output;
                                neq.inputs = op.inputs;
                                neq.addr = op.addr;
                                neq.seq = op.seq;
                                blk.ops[i] = neq;
                                op2.op = PcodeOp::NOP;
                                break;
                            }
                        }
                        break;
                    }
                    // direct use in CBRANCH (ZF directly)
                    if (op2.op == PcodeOp::CBRANCH && op2.inputs.size() >= 2 &&
                        op2.inputs[1].id == op.output.id && op2.inputs[1].kind == op.output.kind) {
                        // CBRANCH on ZF = INT_EQUAL(a, b) → branch if a == b
                        op2.inputs[1] = op.output; // keep as-is, emitter handles
                        break;
                    }
                }
            }

            // pattern: t = AND(x, x) → just use x (test reg, reg)
            if (op.op == PcodeOp::AND && op.inputs.size() == 2 &&
                op.inputs[0].kind == op.inputs[1].kind &&
                op.inputs[0].id == op.inputs[1].id &&
                op.inputs[0].offset == op.inputs[1].offset) {
                op.op = PcodeOp::COPY;
                op.inputs = {op.inputs[0]};
            }
        }
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
    }
}

void Propagate::fold_arg_setup(PcodeFunc& func) {
    // Fold argument-setup copies into the CALL instruction's inputs.
    // Pattern: COPY rcx, val; COPY rdx, val2; CALL target, rcx, rdx, r8, r9
    // Result: CALL target, val, val2, r8, r9 (and COPY ops become NOP)
    static constexpr int kArgRegs[] = {1, 2, 8, 9}; // RCX, RDX, R8, R9

    for (auto& blk : func.blocks) {
        for (int ci = 0; ci < (int)blk.ops.size(); ++ci) {
            auto& call_op = blk.ops[ci];
            if (call_op.op != PcodeOp::CALL) continue;

            for (int argi = 0; argi < 4; ++argi) {
                size_t input_idx = argi + 1; // inputs[0] is target
                if (input_idx >= call_op.inputs.size()) break;
                auto& arg_vn = call_op.inputs[input_idx];
                if (!arg_vn.is_reg() || arg_vn.id != kArgRegs[argi]) continue;

                // Scan backwards for COPY to this arg register
                for (int si = ci - 1; si >= 0; --si) {
                    auto& setup = blk.ops[si];
                    if (setup.op == PcodeOp::CALL) break;
                    if (setup.op == PcodeOp::NOP) continue;
                    if (setup.op == PcodeOp::COPY && setup.output.is_reg() &&
                        setup.output.id == kArgRegs[argi] && !setup.inputs.empty()) {
                        call_op.inputs[input_idx] = setup.inputs[0];
                        setup.op = PcodeOp::NOP;
                        break;
                    }
                    if (setup.output.is_reg() && setup.output.id == kArgRegs[argi])
                        break; // different op writes this reg
                }
            }
        }
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
    }

    // Kill stale writes to caller-saved regs (R10, R11) that are never read
    static constexpr int kCallerSaved[] = {10, 11};
    for (auto& blk : func.blocks) {
        for (int i = 0; i < (int)blk.ops.size(); ++i) {
            auto& op = blk.ops[i];
            if (op.op == PcodeOp::NOP || op.op == PcodeOp::CALL) continue;
            if (!op.output.valid() || !op.output.is_reg()) continue;
            bool is_clobbered = false;
            for (int r : kCallerSaved)
                if (op.output.id == r) { is_clobbered = true; break; }
            if (!is_clobbered) continue;

            // If next meaningful thing is a CALL, this write is dead
            for (int j = i + 1; j < (int)blk.ops.size(); ++j) {
                auto& next = blk.ops[j];
                if (next.op == PcodeOp::NOP) continue;
                if (next.op == PcodeOp::CALL) { op.op = PcodeOp::NOP; break; }
                // If something reads this reg before the call, keep it
                for (auto& in : next.inputs)
                    if (in.is_reg() && in.id == op.output.id) goto keep;
                if (next.output.is_reg() && next.output.id == op.output.id) break;
            }
            keep:;
        }
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
    }
}

}

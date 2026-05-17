#include "dce.h"
#include <unordered_set>
#include <algorithm>

namespace hype {

bool DCE::is_callee_saved(int id) const {
    return id == 3 || id == 5 ||
           id == 12 || id == 13 || id == 14 || id == 15;
}

bool DCE::is_used(const Varnode& vn, const PcodeFunc& func, int skip_blk, int skip_idx) {
    for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
        auto& blk = func.blocks[bi];
        for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
            if (bi == skip_blk && oi == skip_idx) continue;
            auto& op = blk.ops[oi];
            if (op.op == PcodeOp::NOP) continue;
            for (auto& in : op.inputs) {
                if (in.kind == vn.kind && in.id == vn.id && in.offset == vn.offset)
                    return true;
            }
        }
    }
    return false;
}

bool DCE::is_dead_flag(const PcodeInsn& op, const PcodeFunc& func) {
    if (!op.output.valid()) return false;
    if (!is_flag_reg(op.output.id)) return false;
    for (auto& blk : func.blocks)
        for (auto& o : blk.ops) {
            if (o.op == PcodeOp::NOP) continue;
            for (auto& in : o.inputs)
                if (in.kind == op.output.kind && in.id == op.output.id && in.offset == op.output.offset)
                    return false;
        }
    return true;
}

bool DCE::is_dead_stack_op(const PcodeInsn& op, const PcodeFunc&) {
    if (op.op == PcodeOp::STORE && !op.inputs.empty() && op.inputs[0].is_reg() && op.inputs[0].id == 4)
        return true;
    return false;
}

void DCE::run(PcodeFunc& func) {
    static constexpr int RSP_ID = 4;
    static constexpr int RBP_ID = 5;

    // Pass 1: eliminate ALL rsp/rbp arithmetic (prologue/epilogue)
    // Keep only: CALL, RETURN, CBRANCH, BRANCH, and ops that produce non-stack results
    for (auto& blk : func.blocks) {
        for (auto& op : blk.ops) {
            if (op.op == PcodeOp::NOP || op.op == PcodeOp::CALL ||
                op.op == PcodeOp::RETURN || op.op == PcodeOp::CBRANCH ||
                op.op == PcodeOp::BRANCH) continue;

            // kill RSP/RBP modifications (sub rsp, add rsp, mov rbp rsp, etc.)
            if (op.output.valid() && (op.output.id == RSP_ID || op.output.id == RBP_ID) && op.output.is_reg()) {
                op.op = PcodeOp::NOP;
                continue;
            }

            // kill stores to stack (push operations, spills)
            if (op.op == PcodeOp::STORE) {
                bool stack_store = false;
                if (!op.inputs.empty()) {
                    auto& addr = op.inputs[0];
                    if (addr.is_reg() && (addr.id == RSP_ID || addr.id == RBP_ID))
                        stack_store = true;
                    if (addr.kind == VarnodeKind::Stack)
                        stack_store = true;
                }
                if (stack_store) { op.op = PcodeOp::NOP; continue; }
            }

            // kill loads from stack that restore callee-saved regs
            if (op.op == PcodeOp::LOAD && op.output.valid() && op.output.is_reg()) {
                if (is_callee_saved(op.output.id)) {
                    op.op = PcodeOp::NOP;
                    continue;
                }
            }

            // kill flag computations not used by branches
            if (op.output.valid() && is_flag_reg(op.output.id)) {
                if (!is_used(op.output, func, -1, -1)) {
                    op.op = PcodeOp::NOP;
                    continue;
                }
            }
        }
    }

    // Pass 2: iterative dead code elimination
    for (int pass = 0; pass < 6; ++pass) {
        bool changed = false;
        for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
            auto& blk = func.blocks[bi];
            for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
                auto& op = blk.ops[oi];
                if (op.op == PcodeOp::NOP || op.op == PcodeOp::CALL ||
                    op.op == PcodeOp::RETURN || op.op == PcodeOp::CBRANCH ||
                    op.op == PcodeOp::BRANCH || op.op == PcodeOp::STORE) continue;

                if (!op.output.valid()) continue;

                // keep RAX (return value)
                if (op.output.is_reg() && op.output.id == 0) continue;

                if (!is_used(op.output, func, bi, oi)) {
                    op.op = PcodeOp::NOP;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }

    // Remove NOP ops
    for (auto& blk : func.blocks)
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
}

}

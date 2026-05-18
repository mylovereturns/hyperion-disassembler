#include "lifter_arm64.h"
#include <capstone/arm64.h>
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <charconv>

namespace hype {

static constexpr int REG_ARM64_SP = ARM64_REG_SP;
static constexpr int REG_ARM64_XZR = ARM64_REG_XZR;
static constexpr int REG_ARM64_WZR = ARM64_REG_WZR;
static constexpr int REG_ARM64_NZCV = ARM64_REG_NZCV;

Varnode LifterARM64::reg_vn(int reg_id) {
    if (reg_id == ARM64_REG_INVALID) return vn_const(0);
    if (reg_id == REG_ARM64_XZR || reg_id == REG_ARM64_WZR) return vn_const(0, (reg_id == REG_ARM64_WZR) ? 4 : 8);

    int sz = 8;
    const char* name = "unk";

    if (reg_id >= ARM64_REG_X0 && reg_id <= ARM64_REG_X28) {
        static thread_local char buf[8];
        std::snprintf(buf, sizeof(buf), "x%d", reg_id - ARM64_REG_X0);
        name = buf; sz = 8;
    } else if (reg_id >= ARM64_REG_W0 && reg_id <= ARM64_REG_W30) {
        static thread_local char buf[8];
        std::snprintf(buf, sizeof(buf), "w%d", reg_id - ARM64_REG_W0);
        name = buf; sz = 4;
    } else if (reg_id == ARM64_REG_X29) { name = "x29"; sz = 8; }
    else if (reg_id == ARM64_REG_X30) { name = "x30"; sz = 8; }
    else if (reg_id == ARM64_REG_SP)  { name = "sp";  sz = 8; }
    else if (reg_id == ARM64_REG_WSP) { name = "wsp"; sz = 4; }
    else if (reg_id == ARM64_REG_NZCV) { name = "nzcv"; sz = 4; }
    
    return vn_reg(reg_id, name, sz);
}

Varnode LifterARM64::operand_read(const Insn& insn, int idx, PcodeBlock& out) {
    if (idx >= insn.op_count) return vn_const(0);
    auto& op = insn.ops[idx];
    switch (op.type) {
    case OpType::Reg:
        return reg_vn(op.reg);
    case OpType::Imm:
        return vn_const(op.val);
    case OpType::Mem: {
        Varnode addr = vn_const(0);
        bool has = false;
        if (op.mem.base) {
            addr = reg_vn(op.mem.base);
            has = true;
        }
        if (op.mem.index) {
            Varnode idx_vn = reg_vn(op.mem.index);
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, idx_vn});
                addr = t;
            } else { addr = idx_vn; }
            has = true;
        }
        if (op.mem.disp != 0) {
            Varnode d = vn_const(static_cast<u64>(op.mem.disp));
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, d});
                addr = t;
            } else { addr = d; }
        }
        Varnode res = alloc_temp(8); // Default to 8 byte load
        emit(out, PcodeOp::LOAD, res, {addr});
        return res;
    }
    default: return vn_const(0);
    }
}

void LifterARM64::operand_write(const Insn& insn, int idx, Varnode val, PcodeBlock& out) {
    if (idx >= insn.op_count) return;
    auto& op = insn.ops[idx];
    if (op.type == OpType::Reg) {
        emit(out, PcodeOp::COPY, reg_vn(op.reg), {val});
    } else if (op.type == OpType::Mem) {
        Varnode addr = vn_const(0);
        bool has = false;
        if (op.mem.base) {
            addr = reg_vn(op.mem.base);
            has = true;
        }
        if (op.mem.index) {
            Varnode idx_vn = reg_vn(op.mem.index);
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, idx_vn});
                addr = t;
            } else { addr = idx_vn; }
            has = true;
        }
        if (op.mem.disp != 0) {
            Varnode d = vn_const(static_cast<u64>(op.mem.disp));
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, d});
                addr = t;
            } else { addr = d; }
        }
        emit(out, PcodeOp::STORE, {}, {addr, val});
    }
}

Varnode LifterARM64::alloc_temp(int sz) { return vn_temp(next_temp_++, sz); }

void LifterARM64::emit(PcodeBlock& b, PcodeOp op, Varnode out, std::vector<Varnode> in, va_t a) {
    PcodeInsn p;
    p.op = op;
    p.output = out;
    p.inputs = std::move(in);
    p.addr = a ? a : cur_addr_;
    p.seq = cur_seq_++;
    b.ops.push_back(std::move(p));
}

void LifterARM64::lift_insn(const Insn& insn, PcodeBlock& blk, const AnalysisDB& db) {
    cur_addr_ = insn.addr;
    cur_seq_ = 0;

    std::string_view mn(insn.mnemonic);

    if (mn == "mov" || mn == "movz" || mn == "movk" || mn == "movn") {
        Varnode src = operand_read(insn, 1, blk);
        operand_write(insn, 0, src, blk);
    } else if (mn == "add" || mn == "adds") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (insn.op_count == 2) {
            lhs = operand_read(insn, 0, blk);
            rhs = operand_read(insn, 1, blk);
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::ADD, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "sub" || mn == "subs") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (insn.op_count == 2) {
            lhs = operand_read(insn, 0, blk);
            rhs = operand_read(insn, 1, blk);
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::SUB, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "mul" || mn == "madd") {
        Varnode op1 = operand_read(insn, 1, blk);
        Varnode op2 = operand_read(insn, 2, blk);
        Varnode res = alloc_temp(op1.size);
        emit(blk, PcodeOp::INT_MULT, res, {op1, op2});
        if (mn == "madd" && insn.op_count == 4) {
            Varnode op3 = operand_read(insn, 3, blk);
            Varnode res2 = alloc_temp(op1.size);
            emit(blk, PcodeOp::ADD, res2, {op3, res});
            res = res2;
        }
        operand_write(insn, 0, res, blk);
    } else if (mn == "and" || mn == "ands" || mn == "bic" || mn == "bics") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (mn == "bic" || mn == "bics") {
            Varnode not_rhs = alloc_temp(rhs.size);
            emit(blk, PcodeOp::INT_NEGATE, not_rhs, {rhs});
            rhs = not_rhs;
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::AND, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "orr" || mn == "orn") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (mn == "orn") {
            Varnode not_rhs = alloc_temp(rhs.size);
            emit(blk, PcodeOp::INT_NEGATE, not_rhs, {rhs});
            rhs = not_rhs;
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::OR, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "eor" || mn == "eon") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (mn == "eon") {
            Varnode not_rhs = alloc_temp(rhs.size);
            emit(blk, PcodeOp::INT_NEGATE, not_rhs, {rhs});
            rhs = not_rhs;
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::XOR, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "lsl" || mn == "lsr" || mn == "asr" || mn == "ror") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        Varnode res = alloc_temp(lhs.size);
        PcodeOp op = PcodeOp::SHIFT_LEFT;
        if (mn == "lsr") op = PcodeOp::SHIFT_RIGHT;
        else if (mn == "asr") op = PcodeOp::SHIFT_RIGHT; // Should be signed shift
        emit(blk, op, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "ldr" || mn == "ldrb" || mn == "ldrh" || mn == "ldrsw" || mn == "ldrsh" || mn == "ldrsb") {
        Varnode res = operand_read(insn, 1, blk);
        if (mn == "ldrsw" || mn == "ldrsh" || mn == "ldrsb") {
            Varnode ext = alloc_temp(insn.ops[0].size);
            emit(blk, PcodeOp::INT_SEXT, ext, {res});
            res = ext;
        }
        operand_write(insn, 0, res, blk);
    } else if (mn == "str" || mn == "strb" || mn == "strh") {
        Varnode val = operand_read(insn, 0, blk);
        operand_write(insn, 1, val, blk);
    } else if (mn == "ldp") {
        Varnode addr = vn_const(0);
        if (insn.ops[2].type == OpType::Mem) {
            addr = reg_vn(insn.ops[2].mem.base);
            if (insn.ops[2].mem.disp) {
                Varnode t = alloc_temp();
                emit(blk, PcodeOp::ADD, t, {addr, vn_const(static_cast<u64>(insn.ops[2].mem.disp))});
                addr = t;
            }
        }
        int sz = insn.ops[0].size / 8; if (sz < 4) sz = 8;
        Varnode l1 = alloc_temp(sz);
        emit(blk, PcodeOp::LOAD, l1, {addr});
        operand_write(insn, 0, l1, blk);
        
        Varnode addr2 = alloc_temp();
        emit(blk, PcodeOp::ADD, addr2, {addr, vn_const(static_cast<u64>(sz))});
        Varnode l2 = alloc_temp(sz);
        emit(blk, PcodeOp::LOAD, l2, {addr2});
        operand_write(insn, 1, l2, blk);
    } else if (mn == "stp") {
        Varnode addr = vn_const(0);
        if (insn.ops[2].type == OpType::Mem) {
            addr = reg_vn(insn.ops[2].mem.base);
            if (insn.ops[2].mem.disp) {
                Varnode t = alloc_temp();
                emit(blk, PcodeOp::ADD, t, {addr, vn_const(static_cast<u64>(insn.ops[2].mem.disp))});
                addr = t;
            }
        }
        int sz = insn.ops[0].size / 8; if (sz < 4) sz = 8;
        Varnode s1 = operand_read(insn, 0, blk);
        emit(blk, PcodeOp::STORE, {}, {addr, s1});
        
        Varnode addr2 = alloc_temp();
        emit(blk, PcodeOp::ADD, addr2, {addr, vn_const(static_cast<u64>(sz))});
        Varnode s2 = operand_read(insn, 1, blk);
        emit(blk, PcodeOp::STORE, {}, {addr2, s2});
    } else if (mn == "cmp" || mn == "cmn" || mn == "tst") {
        // Just dummy for now to avoid crashes
    } else if (mn == "cbz" || mn == "cbnz") {
        va_t target = insn.branch_target();
        Varnode cond = alloc_temp(1);
        Varnode reg = operand_read(insn, 0, blk);
        emit(blk, mn == "cbz" ? PcodeOp::INT_EQUAL : PcodeOp::INT_NEQUAL, cond, {reg, vn_const(0, reg.size)});
        emit(blk, PcodeOp::CBRANCH, {}, {vn_const(target), cond});
    } else if (mn == "b") {
        emit(blk, PcodeOp::BRANCH, {}, {vn_const(insn.branch_target())});
    } else if (mn.starts_with("b.")) {
        std::string_view cond_str = mn.substr(2);
        Varnode cond = vn_const(1, 1);
        if (cond_str == "eq") cond = vn_reg(100, "ZF", 1);
        else if (cond_str == "ne") { cond = alloc_temp(1); emit(blk, PcodeOp::BOOL_NOT, cond, {vn_reg(100, "ZF", 1)}); }
        emit(blk, PcodeOp::CBRANCH, {}, {vn_const(insn.branch_target()), cond});
    } else if (mn == "bl" || mn == "blr") {
        va_t target = insn.branch_target();
        Varnode fn_addr = vn_const(target);
        if (target) {
            auto it = db.names.find(target);
            if (it != db.names.end()) fn_addr.name = it->second;
        }
        emit(blk, PcodeOp::CALL, reg_vn(ARM64_REG_X0), {fn_addr});
    } else if (mn == "ret") {
        blk.has_return = true;
        emit(blk, PcodeOp::RETURN, {}, {reg_vn(ARM64_REG_X0)});
    } else if (mn == "adr" || mn == "adrp") {
        operand_write(insn, 0, vn_const(insn.ops[1].val), blk);
    } else if (mn == "nop") {
    } else {
        emit(blk, PcodeOp::NOP, alloc_temp(), {});
    }
}

void LifterARM64::lift_block(const BasicBlock& bb, const AnalysisDB& db, PcodeBlock& out) {
    out.addr = bb.start;
    for (auto& insn : bb.insns)
        lift_insn(insn, out, db);
}

PcodeFunc LifterARM64::lift(const Function& func, const AnalysisDB& db) {
    next_temp_ = 256;

    PcodeFunc pf;
    pf.entry = func.entry;
    if (!func.name.empty())
        pf.name = func.name;
    else if (db.image_base && func.entry >= db.image_base)
        pf.name = fmt::format("sub_{:X}", func.entry - db.image_base);
    else
        pf.name = fmt::format("sub_{:X}", func.entry);

    std::vector<va_t> order;
    for (auto& [addr, _] : func.blocks)
        order.push_back(addr);
    std::sort(order.begin(), order.end());

    for (int i = 0; i < (int)order.size(); ++i)
        addr_to_block_[order[i]] = i;

    for (int i = 0; i < (int)order.size(); ++i) {
        auto it = func.blocks.find(order[i]);
        if (it == func.blocks.end()) continue;
        PcodeBlock blk;
        blk.id = i;
        lift_block(it->second, db, blk);

        for (va_t s : it->second.succs) {
            auto sit = addr_to_block_.find(s);
            if (sit != addr_to_block_.end())
                blk.succs.push_back(sit->second);
        }
        pf.blocks.push_back(std::move(blk));
    }

    for (int i = 0; i < (int)pf.blocks.size(); ++i) {
        for (int s : pf.blocks[i].succs)
            if (s >= 0 && s < (int)pf.blocks.size())
                pf.blocks[s].preds.push_back(i);
    }

    pf.next_temp = next_temp_;
    pf.params = {
        reg_vn(ARM64_REG_X0), reg_vn(ARM64_REG_X1),
        reg_vn(ARM64_REG_X2), reg_vn(ARM64_REG_X3),
        reg_vn(ARM64_REG_X4), reg_vn(ARM64_REG_X5),
        reg_vn(ARM64_REG_X6), reg_vn(ARM64_REG_X7)
    };

    addr_to_block_.clear();
    return pf;
}

}

#include "lifter_arm.h"
#include <capstone/arm.h>
#include <fmt/format.h>
#include <algorithm>
#include <cstring>

namespace hype {

Varnode LifterARM::reg_vn(int reg_id) {
    if (reg_id == ARM_REG_INVALID) return vn_const(0);

    int sz = 4;
    const char* name = "unk";

    if (reg_id >= ARM_REG_R0 && reg_id <= ARM_REG_R12) {
        static thread_local char buf[8];
        std::snprintf(buf, sizeof(buf), "r%d", reg_id - ARM_REG_R0);
        name = buf;
    } else if (reg_id == ARM_REG_SP) { name = "sp"; }
    else if (reg_id == ARM_REG_LR) { name = "lr"; }
    else if (reg_id == ARM_REG_PC) { name = "pc"; }
    
    return vn_reg(reg_id, name, sz);
}

Varnode LifterARM::operand_read(const Insn& insn, int idx, PcodeBlock& out) {
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
        Varnode res = alloc_temp(4);
        emit(out, PcodeOp::LOAD, res, {addr});
        return res;
    }
    default: return vn_const(0);
    }
}

void LifterARM::operand_write(const Insn& insn, int idx, Varnode val, PcodeBlock& out) {
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

Varnode LifterARM::alloc_temp(int sz) { return vn_temp(next_temp_++, sz); }

void LifterARM::emit(PcodeBlock& b, PcodeOp op, Varnode out, std::vector<Varnode> in, va_t a) {
    PcodeInsn p;
    p.op = op;
    p.output = out;
    p.inputs = std::move(in);
    p.addr = a ? a : cur_addr_;
    p.seq = cur_seq_++;
    b.ops.push_back(std::move(p));
}

void LifterARM::lift_insn(const Insn& insn, PcodeBlock& blk, const AnalysisDB& db) {
    cur_addr_ = insn.addr;
    cur_seq_ = 0;

    std::string_view mn(insn.mnemonic);

    if (mn == "mov" || mn == "movw" || mn == "movt") {
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
    } else if (mn == "ldr" || mn == "ldrb" || mn == "ldrh") {
        Varnode res = operand_read(insn, 1, blk);
        operand_write(insn, 0, res, blk);
    } else if (mn == "str" || mn == "strb" || mn == "strh") {
        Varnode val = operand_read(insn, 0, blk);
        operand_write(insn, 1, val, blk);
    } else if (mn == "b" || mn == "bl" || mn == "bx" || mn == "blx") {
        va_t target = insn.branch_target();
        if (mn == "bl" || mn == "blx") {
            Varnode fn_addr = vn_const(target);
            if (target) {
                auto it = db.names.find(target);
                if (it != db.names.end()) fn_addr.name = it->second;
            }
            emit(blk, PcodeOp::CALL, reg_vn(ARM_REG_R0), {fn_addr});
        } else if (mn == "bx" && insn.ops[0].type == OpType::Reg && insn.ops[0].reg == ARM_REG_LR) {
            blk.has_return = true;
            emit(blk, PcodeOp::RETURN, {}, {reg_vn(ARM_REG_R0)});
        } else {
            emit(blk, PcodeOp::BRANCH, {}, {vn_const(target)});
        }
    } else {
        emit(blk, PcodeOp::NOP, alloc_temp(), {});
    }
}

void LifterARM::lift_block(const BasicBlock& bb, const AnalysisDB& db, PcodeBlock& out) {
    out.addr = bb.start;
    for (auto& insn : bb.insns)
        lift_insn(insn, out, db);
}

PcodeFunc LifterARM::lift(const Function& func, const AnalysisDB& db) {
    next_temp_ = 256;
    PcodeFunc pf;
    pf.entry = func.entry;
    pf.name = func.name.empty() ? fmt::format("sub_{:X}", func.entry) : func.name;

    std::vector<va_t> order;
    for (auto& [addr, _] : func.blocks) order.push_back(addr);
    std::sort(order.begin(), order.end());

    for (int i = 0; i < (int)order.size(); ++i) addr_to_block_[order[i]] = i;

    for (int i = 0; i < (int)order.size(); ++i) {
        auto it = func.blocks.find(order[i]);
        if (it == func.blocks.end()) continue;
        PcodeBlock blk;
        blk.id = i;
        lift_block(it->second, db, blk);
        for (va_t s : it->second.succs) {
            auto sit = addr_to_block_.find(s);
            if (sit != addr_to_block_.end()) blk.succs.push_back(sit->second);
        }
        pf.blocks.push_back(std::move(blk));
    }

    for (int i = 0; i < (int)pf.blocks.size(); ++i) {
        for (int s : pf.blocks[i].succs)
            if (s >= 0 && s < (int)pf.blocks.size())
                pf.blocks[s].preds.push_back(i);
    }

    pf.next_temp = next_temp_;
    pf.params = { reg_vn(ARM_REG_R0), reg_vn(ARM_REG_R1), reg_vn(ARM_REG_R2), reg_vn(ARM_REG_R3) };
    addr_to_block_.clear();
    return pf;
}

}

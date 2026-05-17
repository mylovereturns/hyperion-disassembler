#include "lifter.h"
#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <algorithm>

namespace hype {

static constexpr int REG_RAX = 0, REG_RCX = 1, REG_RDX = 2, REG_RBX = 3;
static constexpr int REG_RSP = 4, REG_RBP = 5, REG_RSI = 6, REG_RDI = 7;
static constexpr int REG_R8 = 8, REG_R9 = 9, REG_R10 = 10, REG_R11 = 11;
static constexpr int REG_R12 = 12, REG_R13 = 13, REG_R14 = 14, REG_R15 = 15;
static constexpr int REG_ZF = 100, REG_CF = 101, REG_SF = 102, REG_OF = 103;

static const struct { u16 zreg; const char* name; int id; int size; } kRegTable[] = {
    {ZYDIS_REGISTER_RAX,"rax",0,8},{ZYDIS_REGISTER_EAX,"eax",0,4},{ZYDIS_REGISTER_AX,"ax",0,2},{ZYDIS_REGISTER_AL,"al",0,1},
    {ZYDIS_REGISTER_RCX,"rcx",1,8},{ZYDIS_REGISTER_ECX,"ecx",1,4},{ZYDIS_REGISTER_CX,"cx",1,2},{ZYDIS_REGISTER_CL,"cl",1,1},
    {ZYDIS_REGISTER_RDX,"rdx",2,8},{ZYDIS_REGISTER_EDX,"edx",2,4},{ZYDIS_REGISTER_DX,"dx",2,2},{ZYDIS_REGISTER_DL,"dl",2,1},
    {ZYDIS_REGISTER_RBX,"rbx",3,8},{ZYDIS_REGISTER_EBX,"ebx",3,4},{ZYDIS_REGISTER_BX,"bx",3,2},{ZYDIS_REGISTER_BL,"bl",3,1},
    {ZYDIS_REGISTER_RSP,"rsp",4,8},{ZYDIS_REGISTER_ESP,"esp",4,4},
    {ZYDIS_REGISTER_RBP,"rbp",5,8},{ZYDIS_REGISTER_EBP,"ebp",5,4},
    {ZYDIS_REGISTER_RSI,"rsi",6,8},{ZYDIS_REGISTER_ESI,"esi",6,4},{ZYDIS_REGISTER_SIL,"sil",6,1},
    {ZYDIS_REGISTER_RDI,"rdi",7,8},{ZYDIS_REGISTER_EDI,"edi",7,4},{ZYDIS_REGISTER_DIL,"dil",7,1},
    {ZYDIS_REGISTER_R8,"r8",8,8},{ZYDIS_REGISTER_R8D,"r8d",8,4},{ZYDIS_REGISTER_R8W,"r8w",8,2},{ZYDIS_REGISTER_R8B,"r8b",8,1},
    {ZYDIS_REGISTER_R9,"r9",9,8},{ZYDIS_REGISTER_R9D,"r9d",9,4},{ZYDIS_REGISTER_R9W,"r9w",9,2},{ZYDIS_REGISTER_R9B,"r9b",9,1},
    {ZYDIS_REGISTER_R10,"r10",10,8},{ZYDIS_REGISTER_R10D,"r10d",10,4},
    {ZYDIS_REGISTER_R11,"r11",11,8},{ZYDIS_REGISTER_R11D,"r11d",11,4},
    {ZYDIS_REGISTER_R12,"r12",12,8},{ZYDIS_REGISTER_R12D,"r12d",12,4},
    {ZYDIS_REGISTER_R13,"r13",13,8},{ZYDIS_REGISTER_R13D,"r13d",13,4},
    {ZYDIS_REGISTER_R14,"r14",14,8},{ZYDIS_REGISTER_R14D,"r14d",14,4},
    {ZYDIS_REGISTER_R15,"r15",15,8},{ZYDIS_REGISTER_R15D,"r15d",15,4},
};

Varnode Lifter::reg_vn(u16 zreg, u16 bits) {
    for (auto& r : kRegTable)
        if (r.zreg == zreg) return vn_reg(r.id, r.name, r.size);
    int id = 50 + (zreg % 50);
    return vn_reg(id, "unk", bits / 8);
}

Varnode Lifter::alloc_temp(int sz) {
    return vn_temp(next_temp_++, sz);
}

void Lifter::emit(PcodeBlock& b, PcodeOp op, Varnode out, std::vector<Varnode> in, va_t a) {
    PcodeInsn p;
    p.op = op;
    p.output = out;
    p.inputs = std::move(in);
    p.addr = a ? a : cur_addr_;
    p.seq = cur_seq_++;
    b.ops.push_back(std::move(p));
}


Varnode Lifter::operand_read(const Insn& insn, int idx, const AnalysisDB& /*db*/, PcodeBlock& out) {
    if (idx >= insn.op_count) return vn_const(0);
    auto& op = insn.ops[idx];
    switch (op.type) {
    case OpType::Reg:
        return reg_vn(op.reg, op.size);
    case OpType::Imm:
        return vn_const(op.val, op.size / 8 ? op.size / 8 : 8);
    case OpType::Mem: {
        if (op.val != 0 && op.mem_base != ZYDIS_REGISTER_NONE &&
            (op.mem_base == ZYDIS_REGISTER_RIP || op.mem_base == ZYDIS_REGISTER_EIP)) {
            Varnode addr = vn_const(op.val);
            int sz = op.size / 8;
            if (sz < 1) sz = 8;
            Varnode result = alloc_temp(sz);
            emit(out, PcodeOp::LOAD, result, {addr});
            return result;
        }

        Varnode addr = vn_const(0);
        bool has = false;

        if (op.mem_base && op.mem_base != ZYDIS_REGISTER_NONE) {
            addr = reg_vn(op.mem_base, 64);
            has = true;
        }

        if (op.mem_index && op.mem_index != ZYDIS_REGISTER_NONE) {
            Varnode idx_r = reg_vn(op.mem_index, 64);
            if (op.scale > 1) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::INT_MULT, t, {idx_r, vn_const(op.scale)});
                idx_r = t;
            }
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, idx_r});
                addr = t;
            } else {
                addr = idx_r;
            }
            has = true;
        }

        if (op.mem_disp != 0) {
            Varnode d = vn_const(static_cast<u64>(op.mem_disp));
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, d});
                addr = t;
            } else {
                addr = d;
            }
            has = true;
        }

        if (!has) addr = vn_const(0);

        int sz = op.size / 8;
        if (sz < 1) sz = 8;
        Varnode result = alloc_temp(sz);
        emit(out, PcodeOp::LOAD, result, {addr});
        return result;
    }
    default:
        return vn_const(0);
    }
}

void Lifter::operand_write(const Insn& insn, int idx, Varnode val, PcodeBlock& out) {
    if (idx >= insn.op_count) return;
    auto& op = insn.ops[idx];
    if (op.type == OpType::Reg) {
        Varnode dst = reg_vn(op.reg, op.size);
        emit(out, PcodeOp::COPY, dst, {val});
    } else if (op.type == OpType::Mem) {
        Varnode addr = vn_const(0);
        bool has = false;
        if (op.mem_base && op.mem_base != ZYDIS_REGISTER_NONE) {
            addr = reg_vn(op.mem_base, 64);
            has = true;
        }
        if (op.mem_index && op.mem_index != ZYDIS_REGISTER_NONE) {
            Varnode idx_r = reg_vn(op.mem_index, 64);
            if (op.scale > 1) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::INT_MULT, t, {idx_r, vn_const(op.scale)});
                idx_r = t;
            }
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, idx_r});
                addr = t;
            } else { addr = idx_r; }
            has = true;
        }
        if (op.mem_disp != 0) {
            Varnode d = vn_const(static_cast<u64>(op.mem_disp));
            if (has) {
                Varnode t = alloc_temp();
                emit(out, PcodeOp::ADD, t, {addr, d});
                addr = t;
            } else { addr = d; }
        }
        emit(out, PcodeOp::STORE, {}, {addr, val});
    }
}

void Lifter::emit_flags(const Insn& /*insn*/, Varnode lhs, Varnode rhs, PcodeBlock& out, bool is_test) {
    Varnode zf = vn_reg(REG_ZF, "ZF", 1);
    Varnode cf = vn_reg(REG_CF, "CF", 1);
    Varnode sf = vn_reg(REG_SF, "SF", 1);
    Varnode of_v = vn_reg(REG_OF, "OF", 1);

    if (is_test) {
        Varnode tmp = alloc_temp(lhs.size);
        emit(out, PcodeOp::AND, tmp, {lhs, rhs});
        emit(out, PcodeOp::INT_EQUAL, zf, {tmp, vn_const(0, lhs.size)});
        emit(out, PcodeOp::INT_SLESS, sf, {tmp, vn_const(0, lhs.size)});
        emit(out, PcodeOp::COPY, cf, {vn_const(0, 1)});
        emit(out, PcodeOp::COPY, of_v, {vn_const(0, 1)});
    } else {
        Varnode diff = alloc_temp(lhs.size);
        emit(out, PcodeOp::SUB, diff, {lhs, rhs});
        emit(out, PcodeOp::INT_EQUAL, zf, {diff, vn_const(0, lhs.size)});
        emit(out, PcodeOp::INT_SLESS, sf, {diff, vn_const(0, lhs.size)});
        emit(out, PcodeOp::INT_LESS, cf, {lhs, rhs});
        // simplified overflow
        emit(out, PcodeOp::COPY, of_v, {vn_const(0, 1)});
    }
}

static PcodeOp jcc_to_flag_op(u16 mnemonic_id, int& flag_reg, bool& negate) {
    negate = false;
    flag_reg = REG_ZF;
    switch (mnemonic_id) {
    case ZYDIS_MNEMONIC_JZ:   flag_reg = REG_ZF; negate = false; return PcodeOp::NOP;
    case ZYDIS_MNEMONIC_JNZ:  flag_reg = REG_ZF; negate = true;  return PcodeOp::NOP;
    case ZYDIS_MNEMONIC_JB:   flag_reg = REG_CF; negate = false; return PcodeOp::NOP;
    case ZYDIS_MNEMONIC_JNB:  flag_reg = REG_CF; negate = true;  return PcodeOp::NOP;
    case ZYDIS_MNEMONIC_JL:   flag_reg = REG_SF; negate = false; return PcodeOp::NOP;
    case ZYDIS_MNEMONIC_JNL:  flag_reg = REG_SF; negate = true;  return PcodeOp::NOP;
    case ZYDIS_MNEMONIC_JLE:  flag_reg = REG_ZF; negate = false; return PcodeOp::BOOL_OR;
    case ZYDIS_MNEMONIC_JNLE: flag_reg = REG_ZF; negate = true;  return PcodeOp::BOOL_OR;
    case ZYDIS_MNEMONIC_JBE:  flag_reg = REG_CF; negate = false; return PcodeOp::BOOL_OR;
    case ZYDIS_MNEMONIC_JNBE: flag_reg = REG_CF; negate = true;  return PcodeOp::BOOL_OR;
    default: flag_reg = REG_ZF; negate = true; return PcodeOp::NOP;
    }
}

void Lifter::lift_insn(const Insn& insn, const AnalysisDB& db, PcodeBlock& out) {
    cur_addr_ = insn.addr;
    cur_seq_ = 0;

    auto rsp = vn_reg(REG_RSP, "rsp", 8);

    switch (insn.type) {
    case InsnType::Mov: {
        Varnode src = operand_read(insn, 1, db, out);
        operand_write(insn, 0, src, out);
        break;
    }
    case InsnType::Lea: {
        auto& dst_op = insn.ops[0];
        auto& src_op = insn.ops[1];
        if (dst_op.type == OpType::Reg && src_op.type == OpType::Mem) {
            if (src_op.val != 0 && src_op.mem_base != ZYDIS_REGISTER_NONE &&
                (src_op.mem_base == ZYDIS_REGISTER_RIP || src_op.mem_base == ZYDIS_REGISTER_EIP)) {
                emit(out, PcodeOp::COPY, reg_vn(dst_op.reg, dst_op.size), {vn_const(src_op.val)});
                break;
            }
            Varnode addr = vn_const(0);
            bool has = false;
            if (src_op.mem_base && src_op.mem_base != ZYDIS_REGISTER_NONE) {
                addr = reg_vn(src_op.mem_base, 64);
                has = true;
            }
            if (src_op.mem_index && src_op.mem_index != ZYDIS_REGISTER_NONE) {
                Varnode idx_r = reg_vn(src_op.mem_index, 64);
                if (src_op.scale > 1) {
                    Varnode t = alloc_temp();
                    emit(out, PcodeOp::INT_MULT, t, {idx_r, vn_const(src_op.scale)});
                    idx_r = t;
                }
                if (has) {
                    Varnode t = alloc_temp();
                    emit(out, PcodeOp::ADD, t, {addr, idx_r});
                    addr = t;
                } else { addr = idx_r; }
                has = true;
            }
            if (src_op.mem_disp != 0) {
                Varnode d = vn_const(static_cast<u64>(src_op.mem_disp));
                if (has) {
                    Varnode t = alloc_temp();
                    emit(out, PcodeOp::ADD, t, {addr, d});
                    addr = t;
                } else { addr = d; }
            }
            emit(out, PcodeOp::COPY, reg_vn(dst_op.reg, dst_op.size), {addr});
        }
        break;
    }
    case InsnType::Add: case InsnType::Sub:
    case InsnType::And: case InsnType::Or: case InsnType::Xor:
    case InsnType::Shl: case InsnType::Shr: {
        auto& dst_op = insn.ops[0];
        Varnode lhs = operand_read(insn, 0, db, out);
        Varnode rhs = operand_read(insn, 1, db, out);

        if (insn.type == InsnType::Xor && insn.op_count >= 2 &&
            insn.ops[0].type == OpType::Reg && insn.ops[1].type == OpType::Reg &&
            insn.ops[0].reg == insn.ops[1].reg) {
            operand_write(insn, 0, vn_const(0, dst_op.size / 8), out);
            break;
        }

        PcodeOp pop = PcodeOp::ADD;
        switch (insn.type) {
        case InsnType::Add: pop = PcodeOp::ADD; break;
        case InsnType::Sub: pop = PcodeOp::SUB; break;
        case InsnType::And: pop = PcodeOp::AND; break;
        case InsnType::Or:  pop = PcodeOp::OR;  break;
        case InsnType::Xor: pop = PcodeOp::XOR; break;
        case InsnType::Shl: pop = PcodeOp::SHIFT_LEFT; break;
        case InsnType::Shr: pop = PcodeOp::SHIFT_RIGHT; break;
        default: break;
        }
        Varnode result = alloc_temp(lhs.size);
        emit(out, pop, result, {lhs, rhs});
        operand_write(insn, 0, result, out);
        break;
    }
    case InsnType::Mul: {
        if (insn.op_count <= 1) {
            auto rax_v = vn_reg(REG_RAX, "rax", 8);
            Varnode src = operand_read(insn, 0, db, out);
            Varnode result = alloc_temp();
            emit(out, PcodeOp::INT_MULT, result, {rax_v, src});
            emit(out, PcodeOp::COPY, rax_v, {result});
        } else if (insn.op_count == 2) {
            Varnode dst = operand_read(insn, 0, db, out);
            Varnode src = operand_read(insn, 1, db, out);
            Varnode result = alloc_temp(dst.size);
            emit(out, PcodeOp::INT_MULT, result, {dst, src});
            operand_write(insn, 0, result, out);
        } else {
            Varnode src = operand_read(insn, 1, db, out);
            Varnode imm = operand_read(insn, 2, db, out);
            Varnode result = alloc_temp(src.size);
            emit(out, PcodeOp::INT_MULT, result, {src, imm});
            operand_write(insn, 0, result, out);
        }
        break;
    }
    case InsnType::Div: {
        auto rax_v = vn_reg(REG_RAX, "rax", 8);
        Varnode src = operand_read(insn, insn.op_count > 1 ? 1 : 0, db, out);
        Varnode result = alloc_temp();
        emit(out, PcodeOp::INT_DIV, result, {rax_v, src});
        emit(out, PcodeOp::COPY, rax_v, {result});
        break;
    }
    case InsnType::Not: {
        Varnode src = operand_read(insn, 0, db, out);
        Varnode result = alloc_temp(src.size);
        emit(out, PcodeOp::INT_NEGATE, result, {src});
        operand_write(insn, 0, result, out);
        break;
    }
    case InsnType::Push: {
        Varnode src = operand_read(insn, 0, db, out);
        Varnode new_sp = alloc_temp();
        emit(out, PcodeOp::SUB, new_sp, {rsp, vn_const(8)});
        emit(out, PcodeOp::COPY, rsp, {new_sp});
        emit(out, PcodeOp::STORE, {}, {rsp, src});
        break;
    }
    case InsnType::Pop: {
        Varnode loaded = alloc_temp();
        emit(out, PcodeOp::LOAD, loaded, {rsp});
        operand_write(insn, 0, loaded, out);
        Varnode new_sp = alloc_temp();
        emit(out, PcodeOp::ADD, new_sp, {rsp, vn_const(8)});
        emit(out, PcodeOp::COPY, rsp, {new_sp});
        break;
    }
    case InsnType::Cmp: {
        Varnode lhs = operand_read(insn, 0, db, out);
        Varnode rhs = operand_read(insn, 1, db, out);
        emit_flags(insn, lhs, rhs, out, false);
        break;
    }
    case InsnType::Test: {
        Varnode lhs = operand_read(insn, 0, db, out);
        Varnode rhs = operand_read(insn, 1, db, out);
        emit_flags(insn, lhs, rhs, out, true);
        break;
    }
    case InsnType::Jcc: {
        int flag_reg; bool negate;
        PcodeOp compound = jcc_to_flag_op(insn.mnemonic_id, flag_reg, negate);
        Varnode flag = vn_reg(flag_reg, flag_reg == REG_ZF ? "ZF" :
                              flag_reg == REG_CF ? "CF" :
                              flag_reg == REG_SF ? "SF" : "OF", 1);
        Varnode cond_val = flag;
        if (compound == PcodeOp::BOOL_OR) {
            int sec_flag = (flag_reg == REG_ZF) ? REG_SF : REG_ZF;
            Varnode sec = vn_reg(sec_flag, sec_flag == REG_ZF ? "ZF" : "SF", 1);
            cond_val = alloc_temp(1);
            emit(out, PcodeOp::BOOL_OR, cond_val, {flag, sec});
        }
        if (negate) {
            Varnode neg = alloc_temp(1);
            emit(out, PcodeOp::BOOL_NOT, neg, {cond_val});
            cond_val = neg;
        }
        va_t target = insn.branch_target();
        emit(out, PcodeOp::CBRANCH, {}, {vn_const(target), cond_val});
        break;
    }
    case InsnType::Jmp:
        emit(out, PcodeOp::BRANCH, {}, {vn_const(insn.branch_target())});
        break;
    case InsnType::Call: {
        va_t target = insn.branch_target();
        std::string name;
        if (target) {
            auto nit = db.names.find(target);
            if (nit != db.names.end())
                name = nit->second;
            else if (db.image_base && target >= db.image_base)
                name = fmt::format("sub_{:X}", target - db.image_base);
            else
                name = fmt::format("sub_{:X}", target);
        } else {
            name = fmt::format("indirect_{:X}", insn.addr);
        }
        Varnode rax_v = vn_reg(REG_RAX, "rax", 8);
        Varnode fn_addr = vn_const(target);
        fn_addr.name = std::move(name);
        emit(out, PcodeOp::CALL, rax_v, {fn_addr,
            vn_reg(REG_RCX, "rcx"), vn_reg(REG_RDX, "rdx"),
            vn_reg(REG_R8, "r8"), vn_reg(REG_R9, "r9")});
        break;
    }
    case InsnType::Ret: {
        out.has_return = true;
        emit(out, PcodeOp::RETURN, {}, {vn_reg(REG_RAX, "rax")});
        break;
    }
    case InsnType::Nop:
        break;
    default:
        emit(out, PcodeOp::NOP, alloc_temp(), {});
        break;
    }
}

void Lifter::lift_block(const BasicBlock& bb, const AnalysisDB& db, PcodeBlock& out) {
    out.addr = bb.start;
    db.for_each_insn_in_block(bb, [&](const Insn& insn) {
        lift_insn(insn, db, out);
    });
}

PcodeFunc Lifter::lift(const Function& func, const AnalysisDB& db) {
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

    // build preds
    for (int i = 0; i < (int)pf.blocks.size(); ++i) {
        for (int s : pf.blocks[i].succs)
            if (s >= 0 && s < (int)pf.blocks.size())
                pf.blocks[s].preds.push_back(i);
    }

    pf.next_temp = next_temp_;
    pf.params = {
        vn_reg(REG_RCX, "rcx"), vn_reg(REG_RDX, "rdx"),
        vn_reg(REG_R8, "r8"), vn_reg(REG_R9, "r9")
    };

    addr_to_block_.clear();
    return pf;
}

}

#include "lifter_arm64.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <charconv>

namespace hype {

static constexpr int REG_SP = 31;
static constexpr int REG_ZF = 100, REG_NF = 102, REG_CF = 101, REG_VF = 103;

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

static std::string_view trim(std::string_view s) {
    while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
    while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
    return s;
}

static bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

static int parse_reg_id(std::string_view name) {
    if (name == "sp") return REG_SP;
    if (name == "xzr" || name == "wzr") return -1;
    if (name == "lr") return 30;
    if ((name[0] == 'x' || name[0] == 'w') && name.size() >= 2) {
        int v = 0;
        auto r = std::from_chars(name.data() + 1, name.data() + name.size(), v);
        if (r.ec == std::errc{} && v >= 0 && v <= 30) return v;
    }
    return -2;
}

static int reg_size_from_name(std::string_view name) {
    if (name.empty()) return 8;
    if (name[0] == 'w') return 4;
    return 8;
}

Varnode LifterARM64::parse_reg(std::string_view tok) {
    tok = trim(tok);
    int id = parse_reg_id(tok);
    if (id == -1) return vn_const(0, reg_size_from_name(tok));
    if (id == -2) return vn_const(0);
    int sz = reg_size_from_name(tok);
    const char* n = (id == REG_SP) ? "sp" : nullptr;
    if (!n) {
        static thread_local char buf[8];
        buf[0] = (sz == 4) ? 'w' : 'x';
        auto [p, _] = std::to_chars(buf + 1, buf + 7, id);
        *p = '\0';
        return vn_reg(id, buf, sz);
    }
    return vn_reg(id, n, sz);
}

Varnode LifterARM64::reg_var(int capstone_reg) {
    (void)capstone_reg;
    return vn_const(0);
}

static i64 parse_imm(std::string_view tok) {
    tok = trim(tok);
    if (starts_with(tok, "#")) tok.remove_prefix(1);
    if (starts_with(tok, "0x") || starts_with(tok, "0X")) {
        u64 v = 0;
        std::from_chars(tok.data() + 2, tok.data() + tok.size(), v, 16);
        return static_cast<i64>(v);
    }
    if (starts_with(tok, "-0x") || starts_with(tok, "-0X")) {
        u64 v = 0;
        std::from_chars(tok.data() + 3, tok.data() + tok.size(), v, 16);
        return -static_cast<i64>(v);
    }
    i64 v = 0;
    std::from_chars(tok.data(), tok.data() + tok.size(), v);
    return v;
}

static bool is_reg_name(std::string_view tok) {
    if (tok.empty()) return false;
    if (tok == "sp" || tok == "lr" || tok == "xzr" || tok == "wzr") return true;
    return (tok[0] == 'x' || tok[0] == 'w') && tok.size() >= 2 && tok[1] >= '0' && tok[1] <= '9';
}

LifterARM64::ParsedOps LifterARM64::parse_operands(std::string_view op_str) {
    ParsedOps r{};
    r.count = 0;
    r.has_mem = false;
    r.mem = {};

    if (op_str.empty()) return r;

    auto bracket = op_str.find('[');
    if (bracket != std::string_view::npos) {
        r.has_mem = true;
        auto before = trim(op_str.substr(0, bracket));
        if (!before.empty() && before.back() == ',')
            before.remove_suffix(1);
        before = trim(before);
        if (!before.empty() && is_reg_name(before)) {
            r.ops[0] = parse_reg(before);
            r.count = 1;
        }

        auto close = op_str.find(']', bracket);
        if (close == std::string_view::npos) close = op_str.size();
        auto inside = trim(op_str.substr(bracket + 1, close - bracket - 1));

        auto comma = inside.find(',');
        if (comma != std::string_view::npos) {
            auto base_tok = trim(inside.substr(0, comma));
            auto off_tok = trim(inside.substr(comma + 1));
            r.mem.base = parse_reg(base_tok);
            r.mem.offset = parse_imm(off_tok);
        } else {
            r.mem.base = parse_reg(inside);
            r.mem.offset = 0;
        }
        r.mem.valid = true;
        r.mem.pre_index = (close + 1 < op_str.size() && op_str[close + 1] == '!');
        return r;
    }

    std::string_view rest = op_str;
    while (!rest.empty() && r.count < 4) {
        auto c = rest.find(',');
        auto tok = (c != std::string_view::npos) ? trim(rest.substr(0, c)) : trim(rest);
        if (tok.empty()) { rest = (c != std::string_view::npos) ? rest.substr(c + 1) : std::string_view{}; continue; }

        if (is_reg_name(tok)) {
            r.ops[r.count++] = parse_reg(tok);
        } else if (starts_with(tok, "#") || (tok[0] >= '0' && tok[0] <= '9') || tok[0] == '-') {
            i64 imm = parse_imm(tok);
            r.ops[r.count++] = vn_const(static_cast<u64>(imm));
        } else {
            r.ops[r.count++] = vn_const(0);
        }
        rest = (c != std::string_view::npos) ? rest.substr(c + 1) : std::string_view{};
    }
    return r;
}

void LifterARM64::lift_insn(const Insn& insn, PcodeBlock& blk, const AnalysisDB& db) {
    cur_addr_ = insn.addr;
    cur_seq_ = 0;

    std::string_view mn(insn.mnemonic);
    std::string_view ops_str(insn.op_str);
    auto po = parse_operands(ops_str);

    auto sp_vn = vn_reg(REG_SP, "sp", 8);

    if (mn == "mov" || mn == "movz" || mn == "movk" || mn == "movn") {
        if (po.count >= 2) {
            emit(blk, PcodeOp::COPY, po.ops[0], {po.ops[1]});
        } else if (po.count == 1) {
            emit(blk, PcodeOp::COPY, po.ops[0], {vn_const(0)});
        }
    } else if (mn == "add") {
        if (po.count >= 3)
            emit(blk, PcodeOp::ADD, po.ops[0], {po.ops[1], po.ops[2]});
        else if (po.count == 2)
            emit(blk, PcodeOp::ADD, po.ops[0], {po.ops[0], po.ops[1]});
    } else if (mn == "sub") {
        if (po.count >= 3)
            emit(blk, PcodeOp::SUB, po.ops[0], {po.ops[1], po.ops[2]});
        else if (po.count == 2)
            emit(blk, PcodeOp::SUB, po.ops[0], {po.ops[0], po.ops[1]});
    } else if (mn == "mul" || mn == "madd") {
        if (po.count >= 3) {
            Varnode t = alloc_temp(po.ops[0].size);
            emit(blk, PcodeOp::INT_MULT, t, {po.ops[1], po.ops[2]});
            emit(blk, PcodeOp::COPY, po.ops[0], {t});
        }
    } else if (mn == "and" || mn == "ands") {
        if (po.count >= 3)
            emit(blk, PcodeOp::AND, po.ops[0], {po.ops[1], po.ops[2]});
        if (mn == "ands") {
            Varnode zf = vn_reg(REG_ZF, "ZF", 1);
            emit(blk, PcodeOp::INT_EQUAL, zf, {po.ops[0], vn_const(0, po.ops[0].size)});
        }
    } else if (mn == "orr") {
        if (po.count >= 3)
            emit(blk, PcodeOp::OR, po.ops[0], {po.ops[1], po.ops[2]});
    } else if (mn == "eor") {
        if (po.count >= 3)
            emit(blk, PcodeOp::XOR, po.ops[0], {po.ops[1], po.ops[2]});
    } else if (mn == "lsl") {
        if (po.count >= 3)
            emit(blk, PcodeOp::SHIFT_LEFT, po.ops[0], {po.ops[1], po.ops[2]});
    } else if (mn == "lsr") {
        if (po.count >= 3)
            emit(blk, PcodeOp::SHIFT_RIGHT, po.ops[0], {po.ops[1], po.ops[2]});
    } else if (mn == "asr") {
        if (po.count >= 3)
            emit(blk, PcodeOp::SHIFT_RIGHT, po.ops[0], {po.ops[1], po.ops[2]});
    } else if (mn == "ldr" || mn == "ldrb" || mn == "ldrh" || mn == "ldrsw" || mn == "ldrsh" || mn == "ldrsb") {
        if (po.has_mem && po.count >= 1) {
            int load_sz = po.ops[0].size;
            if (mn == "ldrb" || mn == "ldrsb") load_sz = 1;
            else if (mn == "ldrh" || mn == "ldrsh") load_sz = 2;
            else if (mn == "ldrsw") load_sz = 4;

            Varnode addr = po.mem.base;
            if (po.mem.offset != 0) {
                Varnode t = alloc_temp();
                emit(blk, PcodeOp::ADD, t, {po.mem.base, vn_const(static_cast<u64>(po.mem.offset))});
                addr = t;
            }
            Varnode loaded = alloc_temp(load_sz);
            emit(blk, PcodeOp::LOAD, loaded, {addr});
            if (mn == "ldrsw" || mn == "ldrsh" || mn == "ldrsb") {
                Varnode ext = alloc_temp(po.ops[0].size);
                emit(blk, PcodeOp::INT_SEXT, ext, {loaded});
                emit(blk, PcodeOp::COPY, po.ops[0], {ext});
            } else {
                emit(blk, PcodeOp::COPY, po.ops[0], {loaded});
            }
        }
    } else if (mn == "str" || mn == "strb" || mn == "strh") {
        if (po.has_mem && po.count >= 1) {
            Varnode addr = po.mem.base;
            if (po.mem.offset != 0) {
                Varnode t = alloc_temp();
                emit(blk, PcodeOp::ADD, t, {po.mem.base, vn_const(static_cast<u64>(po.mem.offset))});
                addr = t;
            }
            emit(blk, PcodeOp::STORE, {}, {addr, po.ops[0]});
        }
    } else if (mn == "ldp") {
        if (po.has_mem && po.count >= 2) {
            int sz = po.ops[0].size;
            Varnode addr = po.mem.base;
            if (po.mem.offset != 0) {
                Varnode t = alloc_temp();
                emit(blk, PcodeOp::ADD, t, {po.mem.base, vn_const(static_cast<u64>(po.mem.offset))});
                addr = t;
            }
            Varnode l1 = alloc_temp(sz);
            emit(blk, PcodeOp::LOAD, l1, {addr});
            emit(blk, PcodeOp::COPY, po.ops[0], {l1});

            Varnode addr2 = alloc_temp();
            emit(blk, PcodeOp::ADD, addr2, {addr, vn_const(static_cast<u64>(sz))});
            Varnode l2 = alloc_temp(sz);
            emit(blk, PcodeOp::LOAD, l2, {addr2});
            emit(blk, PcodeOp::COPY, po.ops[1], {l2});
        }
    } else if (mn == "stp") {
        if (po.has_mem && po.count >= 2) {
            int sz = po.ops[0].size;
            Varnode addr = po.mem.base;
            if (po.mem.offset != 0) {
                Varnode t = alloc_temp();
                emit(blk, PcodeOp::ADD, t, {po.mem.base, vn_const(static_cast<u64>(po.mem.offset))});
                addr = t;
            }
            emit(blk, PcodeOp::STORE, {}, {addr, po.ops[0]});
            Varnode addr2 = alloc_temp();
            emit(blk, PcodeOp::ADD, addr2, {addr, vn_const(static_cast<u64>(sz))});
            emit(blk, PcodeOp::STORE, {}, {addr2, po.ops[1]});
        }
    } else if (mn == "cmp" || mn == "cmn") {
        Varnode lhs = (po.count >= 1) ? po.ops[0] : vn_const(0);
        Varnode rhs = (po.count >= 2) ? po.ops[1] : vn_const(0);
        Varnode zf = vn_reg(REG_ZF, "ZF", 1);
        Varnode nf = vn_reg(REG_NF, "NF", 1);
        Varnode cf = vn_reg(REG_CF, "CF", 1);
        Varnode diff = alloc_temp(lhs.size);
        if (mn == "cmp")
            emit(blk, PcodeOp::SUB, diff, {lhs, rhs});
        else
            emit(blk, PcodeOp::ADD, diff, {lhs, rhs});
        emit(blk, PcodeOp::INT_EQUAL, zf, {diff, vn_const(0, lhs.size)});
        emit(blk, PcodeOp::INT_SLESS, nf, {diff, vn_const(0, lhs.size)});
        emit(blk, PcodeOp::INT_LESS, cf, {lhs, rhs});
    } else if (mn == "cbz" || mn == "cbnz") {
        va_t target = insn.branch_target();
        Varnode cond = alloc_temp(1);
        if (po.count >= 1) {
            if (mn == "cbz")
                emit(blk, PcodeOp::INT_EQUAL, cond, {po.ops[0], vn_const(0, po.ops[0].size)});
            else
                emit(blk, PcodeOp::INT_NEQUAL, cond, {po.ops[0], vn_const(0, po.ops[0].size)});
        }
        emit(blk, PcodeOp::CBRANCH, {}, {vn_const(target), cond});
    } else if (mn == "tbz" || mn == "tbnz") {
        va_t target = insn.branch_target();
        Varnode cond = alloc_temp(1);
        if (po.count >= 1) {
            if (mn == "tbz")
                emit(blk, PcodeOp::INT_EQUAL, cond, {po.ops[0], vn_const(0, po.ops[0].size)});
            else
                emit(blk, PcodeOp::INT_NEQUAL, cond, {po.ops[0], vn_const(0, po.ops[0].size)});
        }
        emit(blk, PcodeOp::CBRANCH, {}, {vn_const(target), cond});
    } else if (starts_with(mn, "b.")) {
        va_t target = insn.branch_target();
        std::string_view cond_str = mn.substr(2);
        Varnode flag = vn_reg(REG_ZF, "ZF", 1);
        bool negate = false;

        if (cond_str == "eq") { flag = vn_reg(REG_ZF, "ZF", 1); negate = false; }
        else if (cond_str == "ne") { flag = vn_reg(REG_ZF, "ZF", 1); negate = true; }
        else if (cond_str == "lt") { flag = vn_reg(REG_NF, "NF", 1); negate = false; }
        else if (cond_str == "ge") { flag = vn_reg(REG_NF, "NF", 1); negate = true; }
        else if (cond_str == "lo" || cond_str == "cc") { flag = vn_reg(REG_CF, "CF", 1); negate = false; }
        else if (cond_str == "hs" || cond_str == "cs") { flag = vn_reg(REG_CF, "CF", 1); negate = true; }
        else if (cond_str == "le") { flag = vn_reg(REG_ZF, "ZF", 1); negate = false; }
        else if (cond_str == "gt") { flag = vn_reg(REG_ZF, "ZF", 1); negate = true; }
        else if (cond_str == "mi") { flag = vn_reg(REG_NF, "NF", 1); negate = false; }
        else if (cond_str == "pl") { flag = vn_reg(REG_NF, "NF", 1); negate = true; }

        Varnode cond_val = flag;
        if (negate) {
            cond_val = alloc_temp(1);
            emit(blk, PcodeOp::BOOL_NOT, cond_val, {flag});
        }
        emit(blk, PcodeOp::CBRANCH, {}, {vn_const(target), cond_val});
    } else if (mn == "b") {
        va_t target = insn.branch_target();
        emit(blk, PcodeOp::BRANCH, {}, {vn_const(target)});
    } else if (mn == "bl" || mn == "blr") {
        va_t target = insn.branch_target();
        std::string name;
        if (target) {
            auto nit = db.names.find(target);
            if (nit != db.names.end()) name = nit->second;
            else if (db.image_base && target >= db.image_base)
                name = fmt::format("sub_{:X}", target - db.image_base);
            else name = fmt::format("sub_{:X}", target);
        } else {
            if (mn == "blr" && po.count >= 1)
                name = fmt::format("indirect_{:X}", insn.addr);
            else
                name = fmt::format("sub_{:X}", insn.addr);
        }
        Varnode x0 = vn_reg(0, "x0", 8);
        Varnode fn_addr = vn_const(target);
        fn_addr.name = std::move(name);
        emit(blk, PcodeOp::CALL, x0, {fn_addr,
            vn_reg(0, "x0", 8), vn_reg(1, "x1", 8),
            vn_reg(2, "x2", 8), vn_reg(3, "x3", 8),
            vn_reg(4, "x4", 8), vn_reg(5, "x5", 8),
            vn_reg(6, "x6", 8), vn_reg(7, "x7", 8)});
    } else if (mn == "ret") {
        blk.has_return = true;
        emit(blk, PcodeOp::RETURN, {}, {vn_reg(0, "x0", 8)});
    } else if (mn == "adrp" || mn == "adr") {
        if (po.count >= 2) {
            emit(blk, PcodeOp::COPY, po.ops[0], {po.ops[1]});
        }
    } else if (mn == "sxtw") {
        if (po.count >= 2) {
            Varnode ext = alloc_temp(po.ops[0].size);
            emit(blk, PcodeOp::INT_SEXT, ext, {po.ops[1]});
            emit(blk, PcodeOp::COPY, po.ops[0], {ext});
        }
    } else if (mn == "uxtb" || mn == "uxth" || mn == "uxtw") {
        if (po.count >= 2) {
            Varnode ext = alloc_temp(po.ops[0].size);
            emit(blk, PcodeOp::INT_ZEXT, ext, {po.ops[1]});
            emit(blk, PcodeOp::COPY, po.ops[0], {ext});
        }
    } else if (mn == "subs") {
        if (po.count >= 3) {
            emit(blk, PcodeOp::SUB, po.ops[0], {po.ops[1], po.ops[2]});
            Varnode zf = vn_reg(REG_ZF, "ZF", 1);
            Varnode nf = vn_reg(REG_NF, "NF", 1);
            emit(blk, PcodeOp::INT_EQUAL, zf, {po.ops[0], vn_const(0, po.ops[0].size)});
            emit(blk, PcodeOp::INT_SLESS, nf, {po.ops[0], vn_const(0, po.ops[0].size)});
        }
    } else if (mn == "adds") {
        if (po.count >= 3) {
            emit(blk, PcodeOp::ADD, po.ops[0], {po.ops[1], po.ops[2]});
            Varnode zf = vn_reg(REG_ZF, "ZF", 1);
            emit(blk, PcodeOp::INT_EQUAL, zf, {po.ops[0], vn_const(0, po.ops[0].size)});
        }
    } else if (mn == "nop") {
        // no-op
    } else {
        emit(blk, PcodeOp::NOP, alloc_temp(), {});
    }
}

void LifterARM64::lift_block(const BasicBlock& bb, const AnalysisDB& db, PcodeBlock& out) {
    out.addr = bb.start;
    db.for_each_insn_in_block(bb, [&](const Insn& insn) {
        lift_insn(insn, out, db);
    });
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
        vn_reg(0, "x0", 8), vn_reg(1, "x1", 8),
        vn_reg(2, "x2", 8), vn_reg(3, "x3", 8),
        vn_reg(4, "x4", 8), vn_reg(5, "x5", 8),
        vn_reg(6, "x6", 8), vn_reg(7, "x7", 8)
    };

    addr_to_block_.clear();
    return pf;
}

}

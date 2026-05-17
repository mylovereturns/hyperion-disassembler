#include "pseudo_gen.h"
#include <fmt/format.h>
#include <unordered_set>

namespace hype {

std::vector<PseudoLine> PseudoGen::generate(const Function& func, const AnalysisDB& db) {
    std::vector<PseudoLine> out;

    auto sig = fmt::format("void {}()", func.name);
    out.push_back({0, sig + " {", func.entry});

    std::vector<va_t> order;
    for (auto& [addr, _] : func.blocks)
        order.push_back(addr);
    std::sort(order.begin(), order.end());

    for (va_t baddr : order) {
        auto bit = func.blocks.find(baddr);
        if (bit == func.blocks.end()) continue;
        out.push_back({0, fmt::format("loc_{:X}:", baddr), baddr});
        emit_block(bit->second, db, out, 1);
    }

    out.push_back({0, "}", 0});
    return out;
}

void PseudoGen::emit_block(const BasicBlock& bb, const AnalysisDB& db,
                           std::vector<PseudoLine>& out, int indent) {
    db.for_each_insn_in_block(bb, [&](const Insn& insn) {
        std::string line;
        switch (insn.type) {
        case InsnType::Mov:
        case InsnType::Lea:
            if (insn.op_count >= 2)
                line = fmt::format("{} = {};", operand_to_c(insn, 0, db), operand_to_c(insn, 1, db));
            break;
        case InsnType::Call: {
            va_t target = insn.branch_target();
            std::string name;
            if (target) {
                auto nit = db.names.find(target);
                if (nit != db.names.end()) name = nit->second;
                else name = fmt::format("sub_{:X}", target);
            } else {
                name = operand_to_c(insn, 0, db);
            }
            line = fmt::format("{}();", name);
            break;
        }
        case InsnType::Ret:
            line = "return;";
            break;
        case InsnType::Push:
            line = fmt::format("push({});", operand_to_c(insn, 0, db));
            break;
        case InsnType::Pop:
            line = fmt::format("{} = pop();", operand_to_c(insn, 0, db));
            break;
        case InsnType::Cmp:
        case InsnType::Test:
            if (insn.op_count >= 2)
                line = fmt::format("if ({} == {}) ...", operand_to_c(insn, 0, db), operand_to_c(insn, 1, db));
            break;
        case InsnType::Jcc:
            line = fmt::format("if (cond) goto loc_{:X};", insn.branch_target());
            break;
        case InsnType::Jmp:
            line = fmt::format("goto loc_{:X};", insn.branch_target());
            break;
        case InsnType::Add:
            if (insn.op_count >= 2)
                line = fmt::format("{} += {};", operand_to_c(insn, 0, db), operand_to_c(insn, 1, db));
            break;
        case InsnType::Sub:
            if (insn.op_count >= 2)
                line = fmt::format("{} -= {};", operand_to_c(insn, 0, db), operand_to_c(insn, 1, db));
            break;
        case InsnType::Xor:
            if (insn.op_count >= 2) {
                auto a = operand_to_c(insn, 0, db);
                auto b = operand_to_c(insn, 1, db);
                if (a == b) line = fmt::format("{} = 0;", a);
                else line = fmt::format("{} ^= {};", a, b);
            }
            break;
        case InsnType::And:
            if (insn.op_count >= 2)
                line = fmt::format("{} &= {};", operand_to_c(insn, 0, db), operand_to_c(insn, 1, db));
            break;
        case InsnType::Or:
            if (insn.op_count >= 2)
                line = fmt::format("{} |= {};", operand_to_c(insn, 0, db), operand_to_c(insn, 1, db));
            break;
        case InsnType::Nop:
            break;
        default:
            line = fmt::format("__asm {{ {} {} }}", insn.mnemonic, insn.op_str);
            break;
        }
        if (!line.empty())
            out.push_back({indent, line, insn.addr});
    });
}

std::string PseudoGen::operand_to_c(const Insn& insn, int op_idx, const AnalysisDB& db) {
    if (op_idx >= insn.op_count) return "?";
    auto& op = insn.ops[op_idx];
    switch (op.type) {
    case OpType::Reg:
        return insn.op_str;
    case OpType::Imm: {
        va_t val = op.val;
        // check if this immediate is a string address
        for (auto& [saddr, sval] : db.strings) {
            if (saddr == val) {
                std::string truncated = sval.substr(0, 40);
                if (sval.size() > 40) truncated += "...";
                return fmt::format("\"{}\"", truncated);
            }
        }
        // check if it's a named address
        auto nit = db.names.find(val);
        if (nit != db.names.end())
            return nit->second;
        return fmt::format("0x{:X}", val);
    }
    case OpType::Mem: {
        va_t val = op.val;
        if (val) {
            // check if memory target points to a string
            for (auto& [saddr, sval] : db.strings) {
                if (saddr == val) {
                    std::string truncated = sval.substr(0, 40);
                    if (sval.size() > 40) truncated += "...";
                    return fmt::format("\"{}\"", truncated);
                }
            }
            auto nit = db.names.find(val);
            if (nit != db.names.end())
                return fmt::format("&{}", nit->second);
            return fmt::format("*(0x{:X})", val);
        }
        return "[mem]";
    }
    default:
        return "?";
    }
}

}

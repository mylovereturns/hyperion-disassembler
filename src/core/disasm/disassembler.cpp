#include "disassembler.h"
#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <cstring>

namespace hype {

struct Disassembler::Impl {
    ZydisDecoder    decoder;
    ZydisFormatter  formatter;
};

Disassembler::Disassembler() : impl_(std::make_unique<Impl>()) {
    ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&impl_->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

Disassembler::~Disassembler() = default;

void Disassembler::set_arch(Arch arch) {
    if (arch == Arch::X86)
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    else
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

static InsnType classify(ZydisMnemonic m) {
    switch (m) {
    case ZYDIS_MNEMONIC_NOP:  return InsnType::Nop;
    case ZYDIS_MNEMONIC_MOV:
    case ZYDIS_MNEMONIC_MOVZX:
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD: return InsnType::Mov;
    case ZYDIS_MNEMONIC_PUSH:   return InsnType::Push;
    case ZYDIS_MNEMONIC_POP:    return InsnType::Pop;
    case ZYDIS_MNEMONIC_CALL:   return InsnType::Call;
    case ZYDIS_MNEMONIC_RET:    return InsnType::Ret;
    case ZYDIS_MNEMONIC_JMP:    return InsnType::Jmp;
    case ZYDIS_MNEMONIC_CMP:    return InsnType::Cmp;
    case ZYDIS_MNEMONIC_TEST:   return InsnType::Test;
    case ZYDIS_MNEMONIC_ADD:    return InsnType::Add;
    case ZYDIS_MNEMONIC_SUB:    return InsnType::Sub;
    case ZYDIS_MNEMONIC_IMUL:
    case ZYDIS_MNEMONIC_MUL:    return InsnType::Mul;
    case ZYDIS_MNEMONIC_DIV:
    case ZYDIS_MNEMONIC_IDIV:   return InsnType::Div;
    case ZYDIS_MNEMONIC_AND:    return InsnType::And;
    case ZYDIS_MNEMONIC_OR:     return InsnType::Or;
    case ZYDIS_MNEMONIC_XOR:    return InsnType::Xor;
    case ZYDIS_MNEMONIC_NOT:    return InsnType::Not;
    case ZYDIS_MNEMONIC_SHL:    return InsnType::Shl;
    case ZYDIS_MNEMONIC_SHR:
    case ZYDIS_MNEMONIC_SAR:    return InsnType::Shr;
    case ZYDIS_MNEMONIC_LEA:    return InsnType::Lea;
    case ZYDIS_MNEMONIC_INT:
    case ZYDIS_MNEMONIC_INT3:   return InsnType::Int;
    case ZYDIS_MNEMONIC_SYSCALL: return InsnType::Syscall;
    default:
        if (m >= ZYDIS_MNEMONIC_JB && m <= ZYDIS_MNEMONIC_JS)
            return InsnType::Jcc;
        return InsnType::Other;
    }
}

bool Disassembler::decode(va_t addr, const u8* data, size_t len, Insn& out) {
    ZydisDecodedInstruction zi;
    ZydisDecodedOperand     zo[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&impl_->decoder, data, len, &zi, zo)))
        return false;

    out.addr = addr;
    out.len = zi.length;
    out.mnemonic_id = zi.mnemonic;
    out.type = classify(zi.mnemonic);
    std::memcpy(out.bytes, data, std::min<size_t>(zi.length, sizeof(out.bytes)));

    char buf[256];
    ZydisFormatterFormatInstruction(&impl_->formatter, &zi, zo,
        zi.operand_count_visible, buf, sizeof(buf), addr, nullptr);

    std::string full(buf);
    auto sp = full.find(' ');
    if (sp != std::string::npos) {
        out.set_mnemonic(full.substr(0, sp).c_str());
        out.set_op_str(full.substr(sp + 1).c_str());
    } else {
        out.set_mnemonic(full.c_str());
        out.op_str[0] = '\0';
    }

    out.op_count = 0;
    for (u8 i = 0; i < zi.operand_count_visible && i < 3; ++i) {
        auto& zop = zo[i];
        auto& op = out.ops[i];
        op.size = zop.size;

        switch (zop.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            op.type = OpType::Reg;
            op.reg = zop.reg.value;
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            op.type = OpType::Imm;
            if (zop.imm.is_relative)
                ZydisCalcAbsoluteAddress(&zi, &zop, addr, &op.val);
            else
                op.val = zop.imm.value.u;
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            op.type = OpType::Mem;
            op.mem_base = zop.mem.base;
            op.mem_index = zop.mem.index;
            op.scale = zop.mem.scale;
            op.mem_disp = static_cast<i32>(zop.mem.disp.value);
            if (zop.mem.base == ZYDIS_REGISTER_RIP || zop.mem.base == ZYDIS_REGISTER_EIP)
                ZydisCalcAbsoluteAddress(&zi, &zop, addr, &op.val);
            break;
        default:
            op.type = OpType::None;
            break;
        }
        ++out.op_count;
    }
    out.update_branch_target();
    return true;
}

std::vector<Insn> Disassembler::decode_range(va_t start, const u8* data, size_t len) {
    std::vector<Insn> result;
    result.reserve(len / 4);
    size_t off = 0;
    while (off < len) {
        Insn insn{};
        if (decode(start + off, data + off, len - off, insn)) {
            if (insn.len == 0) insn.len = 1;
            off += insn.len;
            result.push_back(std::move(insn));
        } else {
            Insn bad{};
            bad.addr = start + off;
            bad.len = 1;
            bad.type = InsnType::Unknown;
            bad.bytes[0] = data[off];
            bad.set_mnemonic("db");
            char tmp[16];
            std::snprintf(tmp, sizeof(tmp), "0x%02X", data[off]);
            bad.set_op_str(tmp);
            result.push_back(std::move(bad));
            ++off;
        }
    }
    return result;
}

}

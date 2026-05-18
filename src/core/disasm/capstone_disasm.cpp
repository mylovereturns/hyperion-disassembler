#include "capstone_disasm.h"
#include <capstone/capstone.h>
#include <cstring>
#include <cstdio>

namespace hype {

struct CapstoneDisasm::Impl {
    csh handle = 0;
    bool open = false;
    Arch arch = Arch::ARM64;
};

CapstoneDisasm::CapstoneDisasm() : impl_(std::make_unique<Impl>()) {}

CapstoneDisasm::~CapstoneDisasm() {
    if (impl_->open)
        cs_close(&impl_->handle);
}

void CapstoneDisasm::set_arch(Arch arch) {
    if (impl_->open)
        cs_close(&impl_->handle);

    impl_->arch = arch;
    cs_arch cs_a = CS_ARCH_ARM64;
    cs_mode cs_m = CS_MODE_ARM;

    switch (arch) {
    case Arch::ARM64:
        cs_a = CS_ARCH_ARM64;
        cs_m = CS_MODE_ARM;
        break;
    case Arch::ARM:
        cs_a = CS_ARCH_ARM;
        cs_m = CS_MODE_ARM;
        break;
    case Arch::MIPS:
        cs_a = CS_ARCH_MIPS;
        cs_m = static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN);
        break;
    case Arch::PPC:
        cs_a = CS_ARCH_PPC;
        cs_m = CS_MODE_64;
        break;
    case Arch::X64:
        cs_a = CS_ARCH_X86;
        cs_m = CS_MODE_64;
        break;
    case Arch::X86:
        cs_a = CS_ARCH_X86;
        cs_m = CS_MODE_32;
        break;
    }

    impl_->open = (cs_open(cs_a, cs_m, &impl_->handle) == CS_ERR_OK);
    if (impl_->open)
        cs_option(impl_->handle, CS_OPT_DETAIL, CS_OPT_ON);
}

static InsnType classify_groups(cs_insn* insn) {
    if (!insn->detail) return InsnType::Other;
    cs_detail* d = insn->detail;

    for (u8 i = 0; i < d->groups_count; ++i) {
        switch (d->groups[i]) {
        case CS_GRP_CALL:      return InsnType::Call;
        case CS_GRP_RET:
        case CS_GRP_IRET:      return InsnType::Ret;
        case CS_GRP_JUMP:      return InsnType::Jmp;
        case CS_GRP_INT:       return InsnType::Int;
        default: break;
        }
    }

    const char* mn = insn->mnemonic;
    if (mn[0] == 'n' && mn[1] == 'o' && mn[2] == 'p') return InsnType::Nop;
    if (mn[0] == 'b' && mn[1] == '.' )                 return InsnType::Jcc;
    if (mn[0] == 'c' && mn[1] == 'b')                  return InsnType::Jcc;
    if (mn[0] == 't' && mn[1] == 'b')                  return InsnType::Jcc;

    return InsnType::Other;
}

static va_t extract_branch_target(cs_insn* insn, Arch arch) {
    if (!insn->detail) return 0;
    cs_detail* d = insn->detail;

    switch (arch) {
    case Arch::ARM64: {
        auto& arm64 = d->arm64;
        for (u8 i = 0; i < arm64.op_count; ++i) {
            if (arm64.operands[i].type == ARM64_OP_IMM)
                return static_cast<va_t>(arm64.operands[i].imm);
        }
        break;
    }
    case Arch::ARM: {
        auto& arm = d->arm;
        for (u8 i = 0; i < arm.op_count; ++i) {
            if (arm.operands[i].type == ARM_OP_IMM)
                return static_cast<va_t>(arm.operands[i].imm);
        }
        break;
    }
    case Arch::MIPS: {
        auto& mips = d->mips;
        for (u8 i = 0; i < mips.op_count; ++i) {
            if (mips.operands[i].type == MIPS_OP_IMM)
                return static_cast<va_t>(mips.operands[i].imm);
        }
        break;
    }
    case Arch::PPC: {
        auto& ppc = d->ppc;
        for (u8 i = 0; i < ppc.op_count; ++i) {
            if (ppc.operands[i].type == PPC_OP_IMM)
                return static_cast<va_t>(ppc.operands[i].imm);
        }
        break;
    }
    default: break;
    }
    return 0;
}

bool CapstoneDisasm::decode(va_t addr, const u8* data, size_t len, Insn& out) {
    if (!impl_->open) return false;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(impl_->handle, data, len, addr, 1, &insn);
    if (count == 0) return false;

    out.addr = addr;
    out.len = static_cast<u8>(insn->size);
    std::memcpy(out.bytes, insn->bytes, (insn->size < 15) ? insn->size : 15);
    out.set_mnemonic(insn->mnemonic);
    out.set_op_str(insn->op_str);
    out.mnemonic_id = static_cast<u16>(insn->id);

    InsnType t = classify_groups(insn);
    if (t == InsnType::Jmp) {
        bool conditional = false;
        if (insn->detail) {
            for (u8 i = 0; i < insn->detail->groups_count; ++i) {
                if (insn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
                    const char* mn = insn->mnemonic;
                    if (mn[0] == 'b' && mn[1] == '.') conditional = true;
                    if (mn[0] == 'c' && mn[1] == 'b') conditional = true;
                    if (mn[0] == 't' && mn[1] == 'b') conditional = true;
                    if (mn[0] == 'b' && mn[1] != '\0' && mn[1] != 'l' && mn[1] != 'r')
                        conditional = true;
                    break;
                }
            }
        }
        if (conditional) t = InsnType::Jcc;
    }
    out.type = t;

    out.op_count = 0;
    if (insn->detail) {
        cs_detail* d = insn->detail;
        if (impl_->arch == Arch::ARM64) {
            auto& arm64 = d->arm64;
            out.op_count = arm64.op_count;
            for (u8 i = 0; i < arm64.op_count && i < 4; ++i) {
                auto& cop = arm64.operands[i];
                auto& oop = out.ops[i];
                switch (cop.type) {
                case ARM64_OP_REG:
                    oop.type = OpType::Reg;
                    oop.reg = static_cast<u16>(cop.reg);
                    break;
                case ARM64_OP_IMM:
                    oop.type = OpType::Imm;
                    oop.val = static_cast<u64>(cop.imm);
                    break;
                case ARM64_OP_MEM:
                    oop.type = OpType::Mem;
                    oop.mem.base = static_cast<u16>(cop.mem.base);
                    oop.mem.index = static_cast<u16>(cop.mem.index);
                    oop.mem.disp = cop.mem.disp;
                    break;
                default:
                    oop.type = OpType::None;
                    break;
                }
            }
        } else if (impl_->arch == Arch::ARM) {
            auto& arm = d->arm;
            out.op_count = arm.op_count;
            for (u8 i = 0; i < arm.op_count && i < 4; ++i) {
                auto& cop = arm.operands[i];
                auto& oop = out.ops[i];
                switch (cop.type) {
                case ARM_OP_REG:
                    oop.type = OpType::Reg;
                    oop.reg = static_cast<u16>(cop.reg);
                    break;
                case ARM_OP_IMM:
                    oop.type = OpType::Imm;
                    oop.val = static_cast<u64>(cop.imm);
                    break;
                case ARM_OP_MEM:
                    oop.type = OpType::Mem;
                    oop.mem.base = static_cast<u16>(cop.mem.base);
                    oop.mem.index = static_cast<u16>(cop.mem.index);
                    oop.mem.disp = cop.mem.disp;
                    break;
                default:
                    oop.type = OpType::None;
                    break;
                }
            }
        }
        // Add more architectures here as needed
    }

    if (out.op_count == 0) {
        va_t target = extract_branch_target(insn, impl_->arch);
        if (target && (t == InsnType::Call || t == InsnType::Jmp || t == InsnType::Jcc)) {
            out.ops[0].type = OpType::Imm;
            out.ops[0].val = target;
            out.op_count = 1;
        }
    }

    cs_free(insn, count);
    return true;
}

std::vector<Insn> CapstoneDisasm::decode_range(va_t start, const u8* data, size_t len) {
    std::vector<Insn> result;
    result.reserve(len / 4);
    size_t off = 0;
    while (off < len) {
        Insn insn{};
        if (decode(start + off, data + off, len - off, insn)) {
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

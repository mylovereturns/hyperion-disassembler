#include "dotnet_loader.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <cstring>

namespace hype {

const u8* DotNetLoader::rva_to_ptr(const PEImage& img, u32 rva, size_t* avail) {
    for (auto& seg : img.segments) {
        u32 seg_rva = static_cast<u32>(seg.va - img.base);
        if (rva >= seg_rva && rva < seg_rva + seg.data.size()) {
            size_t off = rva - seg_rva;
            if (avail) *avail = seg.data.size() - off;
            return seg.data.data() + off;
        }
    }
    return nullptr;
}

bool DotNetLoader::detect(const PEImage& img) {
    // CLI header is at data directory index 14 in PE
    // We check if the image has .NET metadata by looking for "BSJB" signature
    for (auto& seg : img.segments) {
        for (size_t i = 0; i + 4 <= seg.data.size(); i++) {
            if (seg.data[i] == 'B' && seg.data[i+1] == 'S' && seg.data[i+2] == 'J' && seg.data[i+3] == 'B')
                return true;
        }
    }
    return false;
}

bool DotNetLoader::load(const PEImage& img) {
    dn_ = {};
    if (!parse_cli_header(img)) return false;
    if (!parse_metadata(img)) return false;
    if (!parse_tables()) return false;
    parse_method_bodies(img);
    dn_.valid = true;
    spdlog::info(".NET: {} types, {} methods", dn_.types.size(), dn_.methods.size());
    return true;
}

bool DotNetLoader::parse_cli_header(const PEImage& img) {
    // find CLI header by scanning for the metadata signature
    for (auto& seg : img.segments) {
        for (size_t i = 0; i + 16 <= seg.data.size(); i++) {
            if (seg.data[i] == 'B' && seg.data[i+1] == 'S' && seg.data[i+2] == 'J' && seg.data[i+3] == 'B') {
                u32 seg_rva = static_cast<u32>(seg.va - img.base);
                meta_rva_ = seg_rva + static_cast<u32>(i);
                meta_size_ = static_cast<u32>(seg.data.size() - i);
                return true;
            }
        }
    }
    return false;
}

bool DotNetLoader::parse_metadata(const PEImage& img) {
    size_t avail = 0;
    const u8* meta = rva_to_ptr(img, meta_rva_, &avail);
    if (!meta || avail < 20) return false;
    return parse_streams(meta, std::min((size_t)meta_size_, avail));
}

bool DotNetLoader::parse_streams(const u8* root, size_t sz) {
    if (sz < 16) return false;
    // BSJB header: signature(4), major(2), minor(2), reserved(4), version_len(4), version(N), flags(2), streams(2)
    u32 ver_len;
    std::memcpy(&ver_len, root + 12, 4);
    size_t pos = 16 + ((ver_len + 3) & ~3u);
    if (pos + 4 > sz) return false;

    u16 num_streams;
    std::memcpy(&num_streams, root + pos + 2, 2);
    pos += 4;

    for (int i = 0; i < num_streams && pos + 8 < sz; i++) {
        u32 off, size;
        std::memcpy(&off, root + pos, 4);
        std::memcpy(&size, root + pos + 4, 4);
        pos += 8;
        const char* name = reinterpret_cast<const char*>(root + pos);
        size_t name_len = strnlen(name, sz - pos);
        pos += (name_len + 4) & ~3u;

        if (off + size > sz) continue;
        const u8* data = root + off;

        if (std::strcmp(name, "#~") == 0 || std::strcmp(name, "#-") == 0) {
            streams_.tables = data; streams_.tables_sz = size;
        } else if (std::strcmp(name, "#Strings") == 0) {
            streams_.strings = data; streams_.strings_sz = size;
        } else if (std::strcmp(name, "#US") == 0) {
            streams_.us = data; streams_.us_sz = size;
        } else if (std::strcmp(name, "#Blob") == 0) {
            streams_.blob = data; streams_.blob_sz = size;
        } else if (std::strcmp(name, "#GUID") == 0) {
            streams_.guid = data; streams_.guid_sz = size;
        }
    }
    return streams_.tables != nullptr;
}

std::string DotNetLoader::read_meta_string(u32 offset) {
    if (!streams_.strings || offset >= streams_.strings_sz) return "";
    const char* s = reinterpret_cast<const char*>(streams_.strings + offset);
    size_t max_len = streams_.strings_sz - offset;
    size_t len = strnlen(s, max_len);
    return std::string(s, len);
}

std::string DotNetLoader::read_us_string(u32 offset) {
    if (!streams_.us || offset >= streams_.us_sz) return "";
    size_t remaining = streams_.us_sz - offset;
    const u8* p = streams_.us + offset;
    if (remaining < 1) return "";
    u32 len = *p++; --remaining;
    if (len & 0x80) {
        if (remaining < 1) return "";
        len = ((len & 0x7F) << 8) | *p++; --remaining;
    }
    std::string s;
    for (u32 i = 0; i + 1 < len && i + 1 < remaining; i += 2) {
        char16_t ch = p[i] | (p[i+1] << 8);
        if (ch < 128) s += static_cast<char>(ch);
        else s += '?';
    }
    return s;
}

bool DotNetLoader::parse_tables() {
    if (!streams_.tables || streams_.tables_sz < 24) return false;
    const u8* t = streams_.tables;

    u8 heap_sizes = t[6];
    str_idx_size_ = (heap_sizes & 1) ? 4 : 2;
    guid_idx_size_ = (heap_sizes & 2) ? 4 : 2;
    blob_idx_size_ = (heap_sizes & 4) ? 4 : 2;

    u64 valid_mask;
    std::memcpy(&valid_mask, t + 8, 8);

    const u8* row_counts = t + 24;
    int table_count = 0;
    for (int i = 0; i < 64; i++) {
        if (valid_mask & (1ULL << i)) {
            if (24 + (table_count + 1) * 4 > streams_.tables_sz) return false;
            u32 rows;
            std::memcpy(&rows, row_counts + table_count * 4, 4);
            tables_[i].rows = rows;
            table_count++;
        }
    }

    // TypeDef = table 2, MethodDef = table 6
    // simplified: just extract names from strings heap
    // parse TypeDef rows
    u32 num_types = tables_[2].rows;
    u32 num_methods = tables_[6].rows;

    // We can't easily compute row sizes without knowing all coded index sizes
    // Simplified: scan the strings heap for type/method names
    // and match them heuristically

    // Extract all non-empty strings from #Strings
    if (streams_.strings && streams_.strings_sz > 1) {
        size_t pos = 1; // first byte is always 0
        while (pos < streams_.strings_sz) {
            const char* s = reinterpret_cast<const char*>(streams_.strings + pos);
            size_t len = strnlen(s, streams_.strings_sz - pos);
            if (len >= 2 && len < 256) {
                // heuristic: names starting with uppercase or containing '.' are likely type names
                // names starting with lowercase or get_/set_ are methods
                std::string name(s, len);
                if (name.find('<') == std::string::npos && name.find('>') == std::string::npos) {
                    if (name[0] >= 'A' && name[0] <= 'Z' && name.find('.') == std::string::npos) {
                        DotNetType dt;
                        dt.token = static_cast<u32>(dn_.types.size());
                        dt.name = name;
                        dn_.types.push_back(std::move(dt));
                    }
                }
            }
            pos += len + 1;
        }
    }

    spdlog::info(".NET metadata: {} types detected from strings", dn_.types.size());
    return true;
}

void DotNetLoader::parse_method_bodies(const PEImage& img) {
    // Scan executable sections for method headers
    // Tiny header: (byte & 0x3) == 0x2, code_size = byte >> 2
    // Fat header: (byte & 0x3) == 0x3
    for (auto& seg : img.segments) {
        if (!seg.executable()) continue;
        for (size_t i = 0; i < seg.data.size();) {
            u8 b = seg.data[i];
            if ((b & 0x3) == 0x2) {
                // tiny method
                u32 code_sz = b >> 2;
                if (code_sz > 0 && code_sz < 1024 && i + 1 + code_sz <= seg.data.size()) {
                    DotNetMethod m;
                    m.rva = seg.va + i;
                    m.code_size = code_sz;
                    m.max_stack = 8;
                    m.name = fmt::format("method_{:X}", seg.va - img.base + i);
                    m.il = decode_il(seg.data.data() + i + 1, code_sz);
                    if (!m.il.empty() && m.il.back().mnemonic == "ret")
                        dn_.methods.push_back(std::move(m));
                    i += 1 + code_sz;
                    continue;
                }
            } else if ((b & 0x3) == 0x3 && i + 12 <= seg.data.size()) {
                // fat header
                u16 flags_size;
                std::memcpy(&flags_size, seg.data.data() + i, 2);
                u16 max_stack;
                std::memcpy(&max_stack, seg.data.data() + i + 2, 2);
                u32 code_sz;
                std::memcpy(&code_sz, seg.data.data() + i + 4, 4);
                u32 hdr_sz = (flags_size >> 12) * 4;
                if (hdr_sz < 12) hdr_sz = 12;

                if (code_sz > 0 && code_sz < 0x100000 && i + hdr_sz + code_sz <= seg.data.size()) {
                    DotNetMethod m;
                    m.rva = seg.va + i;
                    m.code_size = code_sz;
                    m.max_stack = max_stack;
                    m.name = fmt::format("method_{:X}", seg.va - img.base + i);
                    m.il = decode_il(seg.data.data() + i + hdr_sz, code_sz);
                    if (!m.il.empty() && m.il.back().mnemonic == "ret")
                        dn_.methods.push_back(std::move(m));
                    i += hdr_sz + code_sz;
                    continue;
                }
            }
            i++;
        }
    }
}

struct ILOpInfo { u16 code; const char* name; u8 operand_size; };
static const ILOpInfo il_opcodes[] = {
    {0x00, "nop", 0}, {0x01, "break", 0}, {0x02, "ldarg.0", 0}, {0x03, "ldarg.1", 0},
    {0x04, "ldarg.2", 0}, {0x05, "ldarg.3", 0}, {0x06, "ldloc.0", 0}, {0x07, "ldloc.1", 0},
    {0x08, "ldloc.2", 0}, {0x09, "ldloc.3", 0}, {0x0A, "stloc.0", 0}, {0x0B, "stloc.1", 0},
    {0x0C, "stloc.2", 0}, {0x0D, "stloc.3", 0}, {0x0E, "ldarg.s", 1}, {0x0F, "ldarga.s", 1},
    {0x10, "starg.s", 1}, {0x11, "ldloc.s", 1}, {0x12, "ldloca.s", 1}, {0x13, "stloc.s", 1},
    {0x14, "ldnull", 0}, {0x15, "ldc.i4.m1", 0}, {0x16, "ldc.i4.0", 0}, {0x17, "ldc.i4.1", 0},
    {0x18, "ldc.i4.2", 0}, {0x19, "ldc.i4.3", 0}, {0x1A, "ldc.i4.4", 0}, {0x1B, "ldc.i4.5", 0},
    {0x1C, "ldc.i4.6", 0}, {0x1D, "ldc.i4.7", 0}, {0x1E, "ldc.i4.8", 0}, {0x1F, "ldc.i4.s", 1},
    {0x20, "ldc.i4", 4}, {0x21, "ldc.i8", 8}, {0x22, "ldc.r4", 4}, {0x23, "ldc.r8", 8},
    {0x25, "dup", 0}, {0x26, "pop", 0}, {0x27, "jmp", 4}, {0x28, "call", 4},
    {0x29, "calli", 4}, {0x2A, "ret", 0}, {0x2B, "br.s", 1}, {0x2C, "brfalse.s", 1},
    {0x2D, "brtrue.s", 1}, {0x2E, "beq.s", 1}, {0x2F, "bge.s", 1}, {0x30, "bgt.s", 1},
    {0x31, "ble.s", 1}, {0x32, "blt.s", 1}, {0x38, "br", 4}, {0x39, "brfalse", 4},
    {0x3A, "brtrue", 4}, {0x46, "ldind.i1", 0}, {0x4A, "ldind.i4", 0},
    {0x58, "add", 0}, {0x59, "sub", 0}, {0x5A, "mul", 0}, {0x5B, "div", 0},
    {0x5F, "and", 0}, {0x60, "or", 0}, {0x61, "xor", 0}, {0x62, "shl", 0},
    {0x63, "shr", 0}, {0x67, "conv.i1", 0}, {0x68, "conv.i2", 0}, {0x69, "conv.i4", 0},
    {0x6A, "conv.i8", 0}, {0x6F, "callvirt", 4}, {0x70, "cpobj", 4}, {0x71, "ldobj", 4},
    {0x72, "ldstr", 4}, {0x73, "newobj", 4}, {0x74, "castclass", 4}, {0x75, "isinst", 4},
    {0x7B, "ldfld", 4}, {0x7C, "ldflda", 4}, {0x7D, "stfld", 4}, {0x7E, "ldsfld", 4},
    {0x80, "stsfld", 4}, {0x81, "stobj", 4}, {0x8C, "box", 4}, {0x8D, "newarr", 4},
    {0x8E, "ldlen", 0}, {0xA2, "stelem.ref", 0}, {0xD0, "ldtoken", 4}, {0xD1, "conv.u2", 0},
    {0xD2, "conv.u1", 0}, {0xD3, "conv.i", 0},
};

std::vector<ILInsn> DotNetLoader::decode_il(const u8* code, u32 size) {
    std::vector<ILInsn> result;
    u32 pos = 0;
    while (pos < size) {
        ILInsn insn;
        insn.offset = pos;
        u16 opcode = code[pos++];

        if (opcode == 0xFE && pos < size) {
            opcode = 0xFE00 | code[pos++];
        }

        const ILOpInfo* info = nullptr;
        for (auto& op : il_opcodes) {
            if (op.code == opcode) { info = &op; break; }
        }

        if (info) {
            insn.opcode = opcode;
            insn.mnemonic = info->name;
            u32 operand = 0;
            if (info->operand_size == 1 && pos < size) {
                operand = code[pos]; pos += 1;
            } else if (info->operand_size == 4 && pos + 4 <= size) {
                std::memcpy(&operand, code + pos, 4); pos += 4;
            } else if (info->operand_size == 8 && pos + 8 <= size) {
                pos += 8;
            }

            if (opcode == 0x72) { // ldstr
                insn.operand_str = "\"" + read_us_string(operand & 0x00FFFFFF) + "\"";
            } else if (opcode == 0x28 || opcode == 0x6F || opcode == 0x73) { // call/callvirt/newobj
                insn.operand_str = resolve_token(operand);
            } else if (info->operand_size > 0) {
                insn.operand_str = fmt::format("0x{:X}", operand);
            }
            insn.len = static_cast<u8>(pos - insn.offset);
        } else {
            insn.opcode = opcode;
            insn.mnemonic = fmt::format("IL_{:02X}", opcode);
            insn.len = 1;
        }
        result.push_back(std::move(insn));
    }
    return result;
}

std::string DotNetLoader::resolve_token(u32 token) {
    u8 table = (token >> 24) & 0xFF;
    u32 row = token & 0x00FFFFFF;
    // simplified: just return token description
    switch (table) {
        case 0x06: return fmt::format("MethodDef[{:X}]", row);
        case 0x0A: return fmt::format("MemberRef[{:X}]", row);
        case 0x01: return fmt::format("TypeRef[{:X}]", row);
        case 0x02: return fmt::format("TypeDef[{:X}]", row);
        default: return fmt::format("token_{:08X}", token);
    }
}

void DotNetLoader::populate_db(AnalysisDB& db, const PEImage& img) {
    for (auto& m : dn_.methods) {
        Function f;
        f.entry = m.rva;
        f.name = m.name;
        db.funcs[f.entry] = std::move(f);
        db.names[m.rva] = m.name;

        // add IL as "instructions"
        for (auto& il : m.il) {
            Insn insn{};
            insn.addr = m.rva + il.offset;
            insn.len = il.len;
            strncpy(insn.mnemonic, il.mnemonic.c_str(), sizeof(insn.mnemonic) - 1);
            strncpy(insn.op_str, il.operand_str.c_str(), sizeof(insn.op_str) - 1);
            insn.type = InsnType::Other;
            if (il.mnemonic == "ret") insn.type = InsnType::Ret;
            else if (il.mnemonic == "call" || il.mnemonic == "callvirt" || il.mnemonic == "newobj")
                insn.type = InsnType::Call;
            else if (il.mnemonic.find("br") == 0) insn.type = InsnType::Jmp;
            db.insns[insn.addr] = insn;
        }
    }
}

}

#include "sigmaker.h"
#include "ui/theme.h"
#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <algorithm>
#include <cstring>

namespace hype {

static const u8* va_to_ptr(const PEImage* img, va_t addr) {
    for (auto& seg : img->segments) {
        if (seg.contains(addr))
            return seg.data.data() + (addr - seg.va);
    }
    return nullptr;
}

static size_t va_available(const PEImage* img, va_t addr) {
    for (auto& seg : img->segments) {
        if (seg.contains(addr))
            return static_cast<size_t>((seg.va + seg.size) - addr);
    }
    return 0;
}

std::vector<SigMaker::PatternByte> SigMaker::build_pattern(va_t start, size_t len) {
    std::vector<PatternByte> pat;
    const u8* base = va_to_ptr(img_, start);
    if (!base) return pat;

    size_t avail = va_available(img_, start);
    if (len > avail) len = avail;

    ZydisDecoder decoder;
    if (img_->arch == Arch::X86)
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    else
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    size_t off = 0;
    while (off < len) {
        ZydisDecodedInstruction zi;
        ZydisDecodedOperand zo[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, base + off, len - off, &zi, zo))) {
            pat.push_back({base[off], false});
            ++off;
            continue;
        }

        std::vector<bool> wc(zi.length, false);

        for (u8 i = 0; i < zi.operand_count; ++i) {
            auto& op = zo[i];

            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                if (op.imm.is_relative) {
                    u8 imm_off = static_cast<u8>(zi.length - (op.size / 8));
                    for (u8 b = imm_off; b < zi.length; ++b)
                        wc[b] = true;
                } else if (op.imm.value.u > 0x1000 || op.imm.value.s < -0x1000) {
                    u8 imm_sz = static_cast<u8>(op.size / 8);
                    u8 imm_off = static_cast<u8>(zi.length - imm_sz);
                    for (u8 b = imm_off; b < zi.length; ++b)
                        wc[b] = true;
                }
            }

            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP) {
                    u8 disp_off = zi.length - 4;
                    for (u8 b = disp_off; b < zi.length; ++b)
                        wc[b] = true;
                } else if (op.mem.disp.has_displacement &&
                           (op.mem.disp.value > 0x1000 || op.mem.disp.value < -0x1000)) {
                    u8 disp_sz = (zi.raw.disp.size) / 8;
                    u8 disp_off = zi.raw.disp.offset;
                    for (u8 b = disp_off; b < disp_off + disp_sz && b < zi.length; ++b)
                        wc[b] = true;
                }
            }
        }

        for (u8 b = 0; b < zi.length; ++b)
            pat.push_back({base[off + b], wc[b]});

        off += zi.length;
    }

    return pat;
}

size_t SigMaker::scan_count(const std::vector<PatternByte>& pat) {
    if (pat.empty()) return 0;

    size_t count = 0;
    for (auto& seg : img_->segments) {
        if (!seg.executable()) continue;
        const u8* data = seg.data.data();
        size_t sz = seg.data.size();
        if (sz < pat.size()) continue;

        size_t end = sz - pat.size();
        for (size_t i = 0; i <= end; ++i) {
            bool match = true;
            for (size_t j = 0; j < pat.size(); ++j) {
                if (!pat[j].wildcard && data[i + j] != pat[j].value) {
                    match = false;
                    break;
                }
            }
            if (match) {
                ++count;
                if (count > 1) return count;
            }
        }
    }
    return count;
}

void SigMaker::trim_pattern() {
    while (pattern_.size() > 4) {
        auto trimmed = pattern_;
        while (!trimmed.empty() && trimmed.back().wildcard)
            trimmed.pop_back();
        if (trimmed.empty()) break;
        trimmed.pop_back();
        if (trimmed.empty()) break;

        if (scan_count(trimmed) == 1) {
            pattern_ = trimmed;
            format_outputs();
            match_count_ = 1;
        } else {
            break;
        }
    }
}

void SigMaker::format_outputs() {
    out_ida_ = fmt_ida();
    out_x64dbg_ = fmt_x64dbg();
    out_cpp_ = fmt_cpp();
    out_rust_ = fmt_rust();
}

std::string SigMaker::fmt_ida() const {
    std::string s;
    for (size_t i = 0; i < pattern_.size(); ++i) {
        if (i > 0) s += ' ';
        if (pattern_[i].wildcard) s += '?';
        else s += fmt::format("{:02X}", pattern_[i].value);
    }
    return s;
}

std::string SigMaker::fmt_x64dbg() const {
    std::string s;
    for (size_t i = 0; i < pattern_.size(); ++i) {
        if (i > 0) s += ' ';
        if (pattern_[i].wildcard) s += "??";
        else s += fmt::format("{:02X}", pattern_[i].value);
    }
    return s;
}

std::string SigMaker::fmt_cpp() const {
    std::string sig = "\"";
    std::string mask = "\"";
    for (auto& b : pattern_) {
        if (b.wildcard) { sig += "\\x00"; mask += '?'; }
        else { sig += fmt::format("\\x{:02X}", b.value); mask += 'x'; }
    }
    sig += "\"";
    mask += "\"";
    return sig + ", " + mask;
}

std::string SigMaker::fmt_rust() const {
    std::string s = "&[";
    for (size_t i = 0; i < pattern_.size(); ++i) {
        if (i > 0) s += ", ";
        if (pattern_[i].wildcard) s += "None";
        else s += fmt::format("Some(0x{:02X})", pattern_[i].value);
    }
    s += "]";
    return s;
}

void SigMaker::generate_for_function(va_t func_addr) {
    if (!db_ || !img_) return;

    target_addr_ = func_addr;
    auto it = db_->funcs.find(func_addr);
    if (it == db_->funcs.end()) return;

    target_name_ = it->second.name.empty()
        ? fmt::format("sub_{:X}", func_addr) : it->second.name;

    size_t func_len = 0;
    if (!it->second.blocks.empty()) {
        va_t lo = UINT64_MAX, hi = 0;
        for (auto& [_, bb] : it->second.blocks) {
            if (bb.start < lo) lo = bb.start;
            if (bb.end > hi) hi = bb.end;
        }
        func_len = static_cast<size_t>(hi - lo);
    }
    if (func_len == 0) func_len = 64;
    if (func_len > 256) func_len = 256;

    pattern_ = build_pattern(func_addr, func_len);
    match_count_ = scan_count(pattern_);

    if (match_count_ == 1) trim_pattern();
    format_outputs();
}

void SigMaker::generate_for_range(va_t start, size_t len) {
    if (!img_) return;

    target_addr_ = start;
    target_name_ = fmt::format("0x{:X} + 0x{:X}", start, len);

    pattern_ = build_pattern(start, len);
    match_count_ = scan_count(pattern_);

    if (match_count_ == 1) trim_pattern();
    format_outputs();
}

void SigMaker::render() {
    if (!visible_) return;

    ImGui::Begin("SigMaker", &visible_);
    if (!db_ || !img_) {
        ImGui::TextDisabled("No analysis data");
        ImGui::End();
        return;
    }

    ImGui::TextUnformatted("Target:");
    ImGui::SameLine();
    if (!target_name_.empty())
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.f, 1.f), "%s", target_name_.c_str());
    else
        ImGui::TextDisabled("(none)");

    ImGui::Separator();
    ImGui::Text("Generate from range:");
    ImGui::SetNextItemWidth(120);
    ImGui::InputTextWithHint("##rs", "address", range_start_, sizeof(range_start_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60);
    ImGui::InputTextWithHint("##rl", "len", range_len_, sizeof(range_len_));
    ImGui::SameLine();
    if (ImGui::Button("Generate")) {
        va_t addr = std::strtoull(range_start_, nullptr, 16);
        size_t len = std::strtoull(range_len_, nullptr, 0);
        if (addr && len) generate_for_range(addr, len);
    }

    ImGui::Separator();

    if (!pattern_.empty()) {
        if (match_count_ == 1)
            ImGui::TextColored(ImVec4(0.2f, 1.f, 0.2f, 1.f), "Matches: 1 (unique)");
        else if (match_count_ == 0)
            ImGui::TextColored(ImVec4(1.f, 0.2f, 0.2f, 1.f), "Matches: 0");
        else
            ImGui::TextColored(ImVec4(1.f, 0.4f, 0.2f, 1.f), "Matches: %zu (not unique)", match_count_);

        ImGui::Text("Length: %zu bytes", pattern_.size());

        ImGui::Spacing();
        auto copy_row = [](const char* label, const std::string& text) {
            ImGui::PushID(label);
            if (ImGui::Button("Copy")) ImGui::SetClipboardText(text.c_str());
            ImGui::SameLine();
            ImGui::TextUnformatted(label);
            ImGui::SameLine();
            ImGui::TextWrapped("%s", text.c_str());
            ImGui::PopID();
        };

        copy_row("IDA",    out_ida_);
        copy_row("x64dbg", out_x64dbg_);
        copy_row("C++",    out_cpp_);
        copy_row("Rust",   out_rust_);

        ImGui::Spacing();
        if (ImGui::Button("Trim Shorter")) trim_pattern();
        ImGui::SameLine();
        if (ImGui::Button("Test")) {
            match_count_ = scan_count(pattern_);
        }
    }

    ImGui::End();
}

}

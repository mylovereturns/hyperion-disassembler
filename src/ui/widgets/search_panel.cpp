#include "search_panel.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>

namespace hype {

namespace {
std::vector<u8> parse_hex_pattern(const char* s, std::vector<bool>& mask) {
    std::vector<u8> bytes;
    mask.clear();
    while (*s) {
        while (*s == ' ') ++s;
        if (!*s) break;
        if (s[0] == '?' && s[1] == '?') {
            bytes.push_back(0);
            mask.push_back(false);
            s += 2;
        } else {
            if (!s[1]) break;
            char tmp[3] = {s[0], s[1], 0};
            bytes.push_back(static_cast<u8>(strtoul(tmp, nullptr, 16)));
            mask.push_back(true);
            s += 2;
        }
    }
    return bytes;
}
}

void SearchPanel::render() {
    if (!show_) return;
    ImGui::Begin("Search", &show_);
    if (!db_ || !img_) { ImGui::TextDisabled("No data"); ImGui::End(); return; }

    const char* modes[] = {"Text", "Binary Pattern", "Immediate Value"};
    int m = static_cast<int>(mode_);
    if (ImGui::Combo("Mode", &m, modes, 3)) mode_ = static_cast<Mode>(m);

    ImGui::Separator();

    if (mode_ == Mode::Text) {
        if (ImGui::InputText("Query", query_, sizeof(query_), ImGuiInputTextFlags_EnterReturnsTrue))
            search_text();
        ImGui::SameLine();
        if (ImGui::Button("Search##t")) search_text();
    } else if (mode_ == Mode::Binary) {
        ImGui::TextDisabled("Hex bytes, ?? for wildcard");
        if (ImGui::InputText("Pattern", hex_pat_, sizeof(hex_pat_), ImGuiInputTextFlags_EnterReturnsTrue))
            search_binary();
        ImGui::SameLine();
        if (ImGui::Button("Search##b")) search_binary();
    } else {
        if (ImGui::InputText("Value (hex)", imm_buf_, sizeof(imm_buf_),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal))
            search_immediate();
        ImGui::SameLine();
        if (ImGui::Button("Search##i")) search_immediate();
    }

    ImGui::Separator();
    ImGui::Text("%zu results", results_.size());

    ImGui::BeginChild("##res");
    ImGuiListClipper clip;
    clip.Begin(static_cast<int>(results_.size()));
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            auto& r = results_[i];
            auto lbl = fmt::format("{:016X}  {}##{}", r.addr, r.desc, i);
            if (ImGui::Selectable(lbl.c_str()))
                if (nav_) nav_(r.addr);
        }
    }
    ImGui::EndChild();
    ImGui::End();
}

void SearchPanel::search_text() {
    results_.clear();
    std::string q(query_);
    if (q.empty()) return;

    for (auto& [addr, name] : db_->names) {
        if (name.find(q) != std::string::npos)
            results_.push_back({addr, "name: " + name});
    }
    for (auto& [addr, str] : db_->strings) {
        if (str.find(q) != std::string::npos)
            results_.push_back({addr, "str: " + str});
    }
    for (auto& [addr, cmt] : db_->comments) {
        if (cmt.find(q) != std::string::npos)
            results_.push_back({addr, "cmt: " + cmt});
    }
    std::sort(results_.begin(), results_.end(), [](auto& a, auto& b) { return a.addr < b.addr; });
}

void SearchPanel::search_binary() {
    results_.clear();
    std::vector<bool> mask;
    auto pat = parse_hex_pattern(hex_pat_, mask);
    if (pat.empty()) return;

    for (auto& seg : img_->segments) {
        if (seg.data.size() < pat.size()) continue;
        size_t end = seg.data.size() - pat.size();
        for (size_t i = 0; i <= end; ++i) {
            bool match = true;
            for (size_t j = 0; j < pat.size() && match; ++j) {
                if (mask[j] && seg.data[i + j] != pat[j]) match = false;
            }
            if (match) {
                results_.push_back({seg.va + i, fmt::format("match @ offset 0x{:X}", i)});
                if (results_.size() >= 10000) goto done;
            }
        }
    }
done:;
}

void SearchPanel::search_immediate() {
    results_.clear();
    char* end = nullptr;
    u64 val = strtoull(imm_buf_, &end, 16);
    if (end == imm_buf_ || !imm_buf_[0]) return;

    for (auto& insn : db_->insns) {
        for (int k = 0; k < insn.op_count; ++k) {
            if (insn.ops[k].type == OpType::Imm && insn.ops[k].val == val) {
                results_.push_back({insn.addr, fmt::format("{} {}", insn.mnemonic, insn.op_str)});
                break;
            }
        }
    }
    std::sort(results_.begin(), results_.end(), [](auto& a, auto& b) { return a.addr < b.addr; });
}

}

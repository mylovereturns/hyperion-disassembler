#include "xrefs_panel.h"
#include "ui/theme.h"
#include <fmt/format.h>

namespace hype {

static const char* xtype_str(XrefType t) {
    switch (t) {
    case XrefType::CodeCall:   return "call";
    case XrefType::CodeJump:   return "jmp";
    case XrefType::DataRead:   return "read";
    case XrefType::DataWrite:  return "write";
    case XrefType::DataOffset: return "off";
    }
    return "?";
}

std::string XrefsPanel::func_for(va_t addr) const {
    if (!db_) return {};
    for (auto& [entry, func] : db_->funcs) {
        if (addr == entry) return func.name;
        for (auto& [ba, bb] : func.blocks) {
            if (addr >= bb.start && addr < bb.end)
                return func.name;
        }
    }
    return {};
}

std::string XrefsPanel::insn_text(va_t addr) const {
    if (!db_) return {};
    auto it = db_->insns.find(addr);
    if (it == db_->insns.end()) return {};
    auto& insn = it->second;
    if (!insn.op_str[0]) return std::string(insn.mnemonic);
    return fmt::format("{} {}", insn.mnemonic, insn.op_str);
}

void XrefsPanel::render_popup() {
    if (open_popup_) {
        ImGui::OpenPopup("##xref_popup");
        open_popup_ = false;
    }

    if (ImGui::BeginPopup("##xref_popup")) {
        if (!db_ || !popup_target_) { ImGui::EndPopup(); return; }

        ImGui::Text("Xrefs to 0x%llX", (unsigned long long)popup_target_);
        auto nit = db_->names.find(popup_target_);
        if (nit != db_->names.end())
            ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "%s", nit->second.c_str());
        ImGui::Separator();

        auto it = db_->xrefs_to.find(popup_target_);
        if (it != db_->xrefs_to.end() && !it->second.empty()) {
            if (ImGui::BeginTable("##xp_tbl", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 40);
                ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 140);
                ImGui::TableHeadersRow();

                for (int xi = 0; xi < (int)it->second.size(); ++xi) {
                    auto& x = it->second[xi];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    auto addr_s = fmt::format("{:016X}##xp{}", x.from, xi);
                    if (ImGui::Selectable(addr_s.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                        if (nav_) nav_(x.from);
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(xtype_str(x.type));
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(insn_text(x.from).c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", func_for(x.from).c_str());
                }
                ImGui::EndTable();
            }
        } else {
            ImGui::TextDisabled("No xrefs found");
        }
        ImGui::EndPopup();
    }
}

void XrefsPanel::render() {
    render_popup();

    ImGui::Begin("Xrefs");
    if (!db_ || !target_) { ImGui::TextDisabled("Press X on address"); ImGui::End(); return; }

    auto nit = db_->names.find(target_);
    if (nit != db_->names.end())
        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "%s", nit->second.c_str());
    ImGui::Text("0x%016llX", (unsigned long long)target_);
    ImGui::Separator();

    if (ImGui::BeginTabBar("##xref_tabs")) {
        if (ImGui::BeginTabItem("Xrefs To")) {
            auto it = db_->xrefs_to.find(target_);
            if (it != db_->xrefs_to.end() && !it->second.empty()) {
                if (ImGui::BeginTable("##xto", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140);
                    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 45);
                    ImGui::TableSetupColumn("Instruction");
                    ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 160);
                    ImGui::TableHeadersRow();

                    for (auto& x : it->second) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        auto lbl = fmt::format("{:016X}##to{:X}", x.from, x.from);
                        if (ImGui::Selectable(lbl.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                            if (nav_) nav_(x.from);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(xtype_str(x.type));
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(insn_text(x.from).c_str());
                        ImGui::TableNextColumn();
                        ImGui::TextDisabled("%s", func_for(x.from).c_str());
                    }
                    ImGui::EndTable();
                }
            } else {
                ImGui::TextDisabled("No xrefs to this address");
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Xrefs From")) {
            auto it = db_->xrefs_from.find(target_);
            if (it != db_->xrefs_from.end() && !it->second.empty()) {
                if (ImGui::BeginTable("##xfrom", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140);
                    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 45);
                    ImGui::TableSetupColumn("Instruction");
                    ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 160);
                    ImGui::TableHeadersRow();

                    for (auto& x : it->second) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        auto lbl = fmt::format("{:016X}##fr{:X}", x.to, x.to);
                        if (ImGui::Selectable(lbl.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                            if (nav_) nav_(x.to);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(xtype_str(x.type));
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(insn_text(target_).c_str());
                        ImGui::TableNextColumn();
                        auto nit2 = db_->names.find(x.to);
                        ImGui::TextDisabled("%s", nit2 != db_->names.end() ? nit2->second.c_str() : "");
                    }
                    ImGui::EndTable();
                }
            } else {
                ImGui::TextDisabled("No xrefs from this address");
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

}

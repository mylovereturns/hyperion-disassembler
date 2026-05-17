#include "imports_panel.h"
#include "ui/theme.h"
#include <fmt/format.h>

namespace hype {

va_t ImportsPanel::find_caller(va_t iat_addr) {
    if (!db_) return 0;

    auto xit = db_->xrefs_to.find(iat_addr);
    if (xit != db_->xrefs_to.end()) {
        for (auto& xr : xit->second) {
            auto iit = db_->insns.find(xr.from);
            if (iit != db_->insns.end() && iit->is_call())
                return xr.from;
        }
        for (auto& xr : xit->second) {
            if (db_->insns.count(xr.from))
                return xr.from;
        }
    }

    for (auto& insn : db_->insns) {
        if (!insn.is_call()) continue;
        for (int k = 0; k < insn.op_count; ++k) {
            if (insn.ops[k].type == OpType::Mem && insn.ops[k].val == iat_addr)
                return insn.addr;
            if (insn.ops[k].type == OpType::Imm && insn.ops[k].val == iat_addr)
                return insn.addr;
        }
    }
    return 0;
}

void ImportsPanel::rebuild_cache() {
    import_cache_.clear();
    export_cache_.clear();
    if (!img_) return;

    std::string filt(filter_);
    last_filter_ = filt;
    dirty_ = false;

    import_cache_.reserve(img_->imports.size());
    for (int i = 0; i < (int)img_->imports.size(); ++i) {
        auto& imp = img_->imports[i];
        if (!filt.empty() && imp.name.find(filt) == std::string::npos && imp.dll.find(filt) == std::string::npos)
            continue;
        ImportRow row;
        row.src_index = i;
        row.iat_addr = imp.iat_addr;
        row.label = fmt::format("{:016X}##i{}", imp.iat_addr, i);
        row.dll = imp.dll;
        row.name = imp.name;
        import_cache_.push_back(std::move(row));
    }

    export_cache_.reserve(img_->exports.size());
    for (int i = 0; i < (int)img_->exports.size(); ++i) {
        auto& exp = img_->exports[i];
        if (!filt.empty() && exp.name.find(filt) == std::string::npos)
            continue;
        ExportRow row;
        row.src_index = i;
        row.addr = exp.addr;
        row.label = fmt::format("{:016X}##e{}", exp.addr, i);
        row.ordinal = exp.ordinal;
        row.name = exp.name;
        export_cache_.push_back(std::move(row));
    }
}

void ImportsPanel::render() {
    ImGui::Begin("Imports / Exports");
    if (!img_) { ImGui::End(); return; }

    if (ImGui::InputTextWithHint("##if", "Filter...", filter_, sizeof(filter_)))
        dirty_ = true;

    if (dirty_ || std::string(filter_) != last_filter_)
        rebuild_cache();

    if (ImGui::BeginTabBar("##ietab")) {
        if (ImGui::BeginTabItem("Imports")) {
            if (ImGui::BeginTable("##it", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn("IAT", ImGuiTableColumnFlags_WidthFixed, 140);
                ImGui::TableSetupColumn("DLL", ImGuiTableColumnFlags_WidthFixed, 120);
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                ImGuiListClipper clip;
                clip.Begin(static_cast<int>(import_cache_.size()));
                while (clip.Step()) {
                    for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        auto& row = import_cache_[i];
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        if (ImGui::Selectable(row.label.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                            if (nav_) {
                                va_t caller = find_caller(row.iat_addr);
                                if (caller)
                                    nav_(caller);
                            }
                        }
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", row.dll.c_str());
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", row.name.c_str());
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Exports")) {
            if (ImGui::BeginTable("##et", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140);
                ImGui::TableSetupColumn("Ord", ImGuiTableColumnFlags_WidthFixed, 50);
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                ImGuiListClipper clip;
                clip.Begin(static_cast<int>(export_cache_.size()));
                while (clip.Step()) {
                    for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        auto& row = export_cache_[i];
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        if (ImGui::Selectable(row.label.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                            if (nav_) nav_(row.addr);
                        ImGui::TableNextColumn();
                        ImGui::Text("%d", row.ordinal);
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", row.name.c_str());
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

}

#include "strings_panel.h"
#include "ui/theme.h"
#include <fmt/format.h>

namespace hype {

void StringsPanel::rebuild_cache() {
    cache_.clear();
    if (!db_) return;

    std::string filt(filter_);
    last_filter_ = filt;
    dirty_ = false;

    cache_.reserve(db_->strings.size());
    for (int i = 0; i < (int)db_->strings.size(); ++i) {
        auto& [addr, str] = db_->strings[i];
        if (!filt.empty() && str.find(filt) == std::string::npos) continue;

        CachedRow row;
        row.src_index = i;
        row.addr = addr;
        row.value = str;

        auto xit = db_->xrefs_to.find(addr);
        row.xref_count = xit != db_->xrefs_to.end() ? static_cast<int>(xit->second.size()) : 0;
        row.nav_target = (row.xref_count > 0) ? xit->second[0].from : 0;
        row.label = fmt::format("{:016X}##s{}", addr, i);

        cache_.push_back(std::move(row));
    }
}

void StringsPanel::render() {
    ImGui::Begin("Strings");
    if (!db_) { ImGui::End(); return; }

    if (ImGui::InputTextWithHint("##sf", "Filter...", filter_, sizeof(filter_)))
        dirty_ = true;

    ImGui::SameLine();
    if (ImGui::SmallButton("Copy")) {
        std::string out;
        for (auto& [addr, str] : db_->strings)
            out += fmt::format("{:016X}\t{}\n", addr, str);
        ImGui::SetClipboardText(out.c_str());
    }
    ImGui::Separator();

    if (dirty_ || std::string(filter_) != last_filter_)
        rebuild_cache();

    if (ImGui::BeginTable("##st", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Xrefs", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("String");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiListClipper clip;
        clip.Begin(static_cast<int>(cache_.size()));
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                auto& row = cache_[i];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();

                if (ImGui::Selectable(row.label.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (nav_) {
                        if (row.nav_target)
                            nav_(row.nav_target);
                        else
                            nav_(row.addr);
                    }
                }
                ImGui::TableNextColumn();
                if (row.xref_count > 0)
                    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::xref()), "%d", row.xref_count);
                else
                    ImGui::TextDisabled("-");
                ImGui::TableNextColumn();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::str()), "\"%s\"", row.value.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

}

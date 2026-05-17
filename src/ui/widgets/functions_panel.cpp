#include "functions_panel.h"
#include "ui/theme.h"
#include <fmt/format.h>
#include <algorithm>

namespace hype {

void FunctionsPanel::rebuild_cache() {
    cache_.clear();
    if (!db_) return;

    std::string filt(filter_);
    last_filter_ = filt;
    dirty_ = false;

    std::vector<const Function*> sorted;
    sorted.reserve(db_->funcs.size());
    for (auto& [_, f] : db_->funcs)
        if (filt.empty() || f.name.find(filt) != std::string::npos ||
            fmt::format("{:X}", f.entry).find(filt) != std::string::npos)
            sorted.push_back(&f);
    std::sort(sorted.begin(), sorted.end(), [](auto* a, auto* b) { return a->entry < b->entry; });

    cache_.reserve(sorted.size());
    for (int i = 0; i < (int)sorted.size(); ++i) {
        auto* f = sorted[i];
        CachedRow row;
        row.entry = f->entry;
        row.label = fmt::format("{:016X}##f{}", f->entry, i);
        row.name = f->name;
        row.block_count = static_cast<int>(f->blocks.size());
        cache_.push_back(std::move(row));
    }
}

void FunctionsPanel::render() {
    ImGui::Begin("Functions");
    if (!db_) { ImGui::TextDisabled("No analysis data"); ImGui::End(); return; }

    if (ImGui::InputTextWithHint("##ff", "Filter (name or address)...", filter_, sizeof(filter_)))
        dirty_ = true;

    ImGui::SameLine();
    ImGui::TextDisabled("(%d)", (int)db_->funcs.size());
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy")) {
        std::string out;
        for (auto& [_, f] : db_->funcs)
            out += fmt::format("{:016X}\t{}\n", f.entry, f.name);
        ImGui::SetClipboardText(out.c_str());
    }
    ImGui::Separator();

    if (dirty_ || std::string(filter_) != last_filter_)
        rebuild_cache();

    if (ImGui::BeginTable("##ft", 3,
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingStretchProp)) {

        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 145);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Blocks", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        ImGuiListClipper clip;
        clip.Begin(static_cast<int>(cache_.size()));
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                auto& row = cache_[i];
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                if (ImGui::Selectable(row.label.c_str(), false,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (nav_) nav_(row.entry);
                }

                ImGui::TableNextColumn();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::func()), "%s", row.name.c_str());

                ImGui::TableNextColumn();
                ImGui::Text("%d", row.block_count);
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

}

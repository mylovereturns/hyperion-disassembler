#include "diff_view.h"
#include <fmt/format.h>
#include <algorithm>

namespace hype {

void DiffView::render() {
    if (!ImGui::Begin("Diff View")) { ImGui::End(); return; }
    if (results_.empty()) { ImGui::TextDisabled("No diff results. File > Compare With..."); ImGui::End(); return; }

    int cnt_id = 0, cnt_mod = 0, cnt_add = 0, cnt_rem = 0;
    for (auto& r : results_) {
        switch (r.status) {
        case DiffResult::Identical: ++cnt_id; break;
        case DiffResult::Modified:  ++cnt_mod; break;
        case DiffResult::Added:     ++cnt_add; break;
        case DiffResult::Removed:   ++cnt_rem; break;
        }
    }
    ImGui::Text("%d identical, %d modified, %d added, %d removed", cnt_id, cnt_mod, cnt_add, cnt_rem);
    ImGui::Separator();

    ImGui::Checkbox("Identical", &show_identical_); ImGui::SameLine();
    ImGui::Checkbox("Modified", &show_modified_); ImGui::SameLine();
    ImGui::Checkbox("Added", &show_added_); ImGui::SameLine();
    ImGui::Checkbox("Removed", &show_removed_);

    ImGui::InputTextWithHint("##diffilt", "Filter name...", filter_, sizeof(filter_));
    ImGui::Separator();

    if (ImGui::BeginTable("##difftbl", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Addr A", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("Addr B", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("Similarity", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();

        std::string filt(filter_);
        std::transform(filt.begin(), filt.end(), filt.begin(),
            [](unsigned char c) { return std::tolower(c); });

        for (auto& r : results_) {
            if (r.status == DiffResult::Identical && !show_identical_) continue;
            if (r.status == DiffResult::Modified && !show_modified_) continue;
            if (r.status == DiffResult::Added && !show_added_) continue;
            if (r.status == DiffResult::Removed && !show_removed_) continue;

            if (!filt.empty()) {
                std::string ln = r.name;
                std::transform(ln.begin(), ln.end(), ln.begin(),
                    [](unsigned char c) { return std::tolower(c); });
                if (ln.find(filt) == std::string::npos) continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImVec4 col{};
            const char* label = "";
            switch (r.status) {
            case DiffResult::Identical: col = {0.3f,0.9f,0.3f,1}; label = "IDENT"; break;
            case DiffResult::Modified:  col = {1.f,0.85f,0.2f,1}; label = "MOD"; break;
            case DiffResult::Added:     col = {0.4f,0.7f,1.f,1};  label = "ADD"; break;
            case DiffResult::Removed:   col = {1.f,0.3f,0.3f,1};  label = "REM"; break;
            }
            ImGui::TextColored(col, "%s", label);

            ImGui::TableNextColumn();
            auto sel_id = fmt::format("{}##{:X}{:X}", r.name, r.addr_a, r.addr_b);
            if (ImGui::Selectable(sel_id.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                va_t target = r.addr_a ? r.addr_a : r.addr_b;
                if (nav_ && target) nav_(target);
            }
            ImGui::TableNextColumn();
            if (r.addr_a) ImGui::Text("%016llX", (unsigned long long)r.addr_a);
            else ImGui::TextDisabled("---");
            ImGui::TableNextColumn();
            if (r.addr_b) ImGui::Text("%016llX", (unsigned long long)r.addr_b);
            else ImGui::TextDisabled("---");
            ImGui::TableNextColumn();
            ImGui::Text("%.1f%%", r.similarity * 100.f);
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

}

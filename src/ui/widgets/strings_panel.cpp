#include "strings_panel.h"
#include "ui/theme.h"
#include <fmt/format.h>

namespace hype {

void StringsPanel::render() {
    ImGui::Begin("Strings");
    if (!db_) { ImGui::End(); return; }

    ImGui::InputTextWithHint("##sf", "Filter...", filter_, sizeof(filter_));
    ImGui::Separator();
    std::string filt(filter_);

    if (ImGui::BeginTable("##st", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Xrefs", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("String");
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)db_->strings.size(); ++i) {
            auto& [addr, str] = db_->strings[i];
            if (!filt.empty() && str.find(filt) == std::string::npos) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            auto lbl = fmt::format("{:016X}##s{}", addr, i);
            if (ImGui::Selectable(lbl.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                if (nav_) nav_(addr);
            ImGui::TableNextColumn();
            auto xit = db_->xrefs_to.find(addr);
            int cnt = xit != db_->xrefs_to.end() ? static_cast<int>(xit->second.size()) : 0;
            if (cnt > 0)
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::xref()), "%d", cnt);
            else
                ImGui::TextDisabled("-");
            ImGui::TableNextColumn();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::str()), "\"%s\"", str.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

}

#include "pseudo_view.h"
#include "ui/theme.h"
#include <fmt/format.h>

namespace hype {

void PseudoView::show_function(va_t entry) {
    if (func_ == entry && !lines_.empty()) return;
    func_ = entry;
    lines_.clear();
    if (!db_ || !func_) return;
    auto it = db_->funcs.find(entry);
    if (it == db_->funcs.end()) return;
    if (it->second.blocks.empty()) return;
    if (it->second.blocks.size() > 500) {
        lines_.push_back({0, fmt::format("// {} - {} blocks (too complex)", it->second.name, it->second.blocks.size()), entry});
        return;
    }
    lines_ = dec_.decompile(it->second, *db_);
}

void PseudoView::render() {
    ImGui::Begin("Pseudo Code");
    if (!db_ || !func_) { ImGui::TextDisabled("No function selected"); ImGui::End(); return; }

    if (lines_.empty()) {
        auto it = db_->funcs.find(func_);
        if (it != db_->funcs.end() && !it->second.blocks.empty())
            lines_ = dec_.decompile(it->second, *db_);
    }

    if (lines_.empty()) {
        ImGui::TextDisabled("No pseudo-code available for this function");
        ImGui::End();
        return;
    }

    auto fit = db_->funcs.find(func_);
    if (fit != db_->funcs.end()) {
        ImGui::TextColored(ImVec4(0.85f, 0.7f, 0.4f, 1), "%s", fit->second.name.c_str());
        ImGui::Separator();
    }

    ImGui::BeginChild("##pseudo_scroll");
    for (int i = 0; i < (int)lines_.size(); ++i) {
        auto& line = lines_[i];
        bool h = (line.addr && line.addr == hl_);

        if (h) {
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            ImGui::GetWindowDrawList()->AddRectFilled(p,
                ImVec2(p.x + w, p.y + ImGui::GetTextLineHeightWithSpacing()),
                IM_COL32(60, 60, 30, 200));
        }

        std::string pad(line.indent * 4, ' ');
        auto display = pad + line.text;
        auto id = fmt::format("{}##{}", display, i);

        if (h) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 0.8f, 1));
        if (ImGui::Selectable(id.c_str(), h))
            if (line.addr && nav_) nav_(line.addr);
        if (h) ImGui::PopStyleColor();
    }
    ImGui::EndChild();
    ImGui::End();
}

}

#include "script_console.h"
#include <cstring>

namespace hype {

void ScriptConsole::render() {
    if (!ImGui::Begin("Script Console")) {
        ImGui::End();
        return;
    }

    float footer_h = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing() + 4;
    ImGui::BeginChild("##script_output", ImVec2(0, -footer_h), true,
                      ImGuiWindowFlags_HorizontalScrollbar);
    for (auto& line : output_)
        ImGui::TextUnformatted(line.c_str());
    if (scroll_bottom_) {
        ImGui::SetScrollHereY(1.0f);
        scroll_bottom_ = false;
    }
    ImGui::EndChild();

    ImGui::Separator();
    ImGuiInputTextFlags flags = ImGuiInputTextFlags_EnterReturnsTrue |
                                ImGuiInputTextFlags_CallbackHistory;

    auto history_cb = [](ImGuiInputTextCallbackData* data) -> int {
        auto* self = static_cast<ScriptConsole*>(data->UserData);
        if (self->history_.empty()) return 0;
        if (data->EventKey == ImGuiKey_UpArrow) {
            if (self->hist_idx_ < (int)self->history_.size() - 1)
                self->hist_idx_++;
        } else if (data->EventKey == ImGuiKey_DownArrow) {
            if (self->hist_idx_ > 0) self->hist_idx_--;
            else { self->hist_idx_ = -1; data->DeleteChars(0, data->BufTextLen); return 0; }
        }
        if (self->hist_idx_ >= 0 && self->hist_idx_ < (int)self->history_.size()) {
            auto& h = self->history_[self->hist_idx_];
            data->DeleteChars(0, data->BufTextLen);
            data->InsertChars(0, h.c_str());
        }
        return 0;
    };

    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 60);
    bool exec = ImGui::InputText("##lua_input", input_, sizeof(input_), flags, history_cb, this);
    ImGui::SameLine();
    if (ImGui::Button("Run") || exec) {
        if (input_[0] && engine_) {
            std::string code(input_);
            output_.push_back("> " + code);
            history_.push_front(code);
            if (history_.size() > 100) history_.pop_back();
            hist_idx_ = -1;

            std::string result = engine_->execute(code);
            if (!result.empty()) output_.push_back(result);
            if (output_.size() > 1000) output_.pop_front();
            scroll_bottom_ = true;
            input_[0] = 0;
        }
    }

    // Ctrl+Enter handled by InputText EnterReturnsTrue above

    ImGui::End();
}

}

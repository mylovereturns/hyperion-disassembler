#include "output_panel.h"

namespace hype {

void OutputPanel::log(const std::string& msg) {
    std::lock_guard lk(mtx_);
    lines_.push_back(msg);
    if (lines_.size() > 10000) lines_.pop_front();
    scroll_ = true;
}

void OutputPanel::render() {
    ImGui::Begin("Output");
    if (ImGui::Button("Clear")) clear();
    ImGui::Separator();

    ImGui::BeginChild("##log");
    std::deque<std::string> snapshot;
    bool do_scroll;
    {
        std::lock_guard lk(mtx_);
        snapshot = lines_;
        do_scroll = scroll_;
        scroll_ = false;
    }
    ImGuiListClipper clip;
    clip.Begin(static_cast<int>(snapshot.size()));
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i)
            ImGui::TextUnformatted(snapshot[i].c_str());
    if (do_scroll) ImGui::SetScrollHereY(1.f);
    ImGui::EndChild();
    ImGui::End();
}

}

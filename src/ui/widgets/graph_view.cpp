#include "graph_view.h"
#include "ui/theme.h"
#include <fmt/format.h>
#include <algorithm>
#include <queue>
#include <cmath>

namespace hype {

void GraphView::show_function(va_t entry) {
    if (func_ == entry) return;
    func_ = entry;
    dirty_ = true;
}

void GraphView::layout() {
    nodes_.clear();
    if (!db_ || !func_) return;

    auto it = db_->funcs.find(func_);
    if (it == db_->funcs.end()) return;
    auto& func = it->second;
    if (func.blocks.empty()) return;

    std::unordered_map<va_t, int> layers;
    std::queue<va_t> q;
    q.push(func.entry);
    layers[func.entry] = 0;

    while (!q.empty()) {
        va_t cur = q.front(); q.pop();
        auto bit = func.blocks.find(cur);
        if (bit == func.blocks.end()) continue;
        int nl = layers[cur] + 1;
        for (va_t s : bit->second.succs)
            if (!layers.count(s) && func.blocks.count(s)) {
                layers[s] = nl;
                q.push(s);
            }
    }

    std::unordered_map<int, std::vector<va_t>> by_layer;
    for (auto& [a, l] : layers) by_layer[l].push_back(a);

    float y = 20, nw = 280, gap = 50;
    for (int l = 0; by_layer.count(l); ++l) {
        auto& addrs = by_layer[l];
        std::sort(addrs.begin(), addrs.end());
        float tw = addrs.size() * (nw + gap) - gap;
        float xs = -tw / 2;
        float mh = 0;
        for (size_t i = 0; i < addrs.size(); ++i) {
            auto bit = func.blocks.find(addrs[i]);
            float h = 50;
            if (bit != func.blocks.end()) {
                auto ri = db_->insns.range_begin(bit->second.start);
                auto re = db_->insns.range_end(bit->second.end);
                auto cnt = static_cast<size_t>(std::distance(ri, re));
                h = std::max(50.f, static_cast<float>(cnt) * 15.f + 30.f);
            }
            h = std::min(h, 300.f);
            mh = std::max(mh, h);
            nodes_.push_back({addrs[i], xs + i * (nw + gap), y, nw, h, l});
        }
        y += mh + 60;
    }
    dirty_ = false;
}

void GraphView::render() {
    ImGui::Begin("Graph");
    if (!db_ || !func_) { ImGui::TextDisabled("Select a function (click in Functions panel or press Tab)"); ImGui::End(); return; }
    if (dirty_) layout();

    auto it = db_->funcs.find(func_);
    if (it == db_->funcs.end() || nodes_.empty()) {
        ImGui::TextDisabled("No CFG data");
        ImGui::End();
        return;
    }
    auto& func = it->second;

    // header
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::func()), "%s", func.name.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("(%d blocks)", (int)func.blocks.size());
    ImGui::SameLine(ImGui::GetWindowWidth() - 120);
    if (ImGui::SmallButton("Fit")) { scroll_ = {0, 0}; zoom_ = 1.0f; }
    ImGui::SameLine();
    ImGui::Text("%.0f%%", zoom_ * 100);
    ImGui::Separator();

    ImVec2 cp = ImGui::GetCursorScreenPos();
    ImVec2 cs = ImGui::GetContentRegionAvail();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    // clip region
    dl->PushClipRect(cp, ImVec2(cp.x + cs.x, cp.y + cs.y), true);

    // interaction: pan + zoom
    ImGui::InvisibleButton("##grapharea", cs, ImGuiButtonFlags_MouseButtonMiddle);
    bool area_hovered = ImGui::IsItemHovered();
    if (area_hovered) {
        float w = ImGui::GetIO().MouseWheel;
        if (w) zoom_ = std::clamp(zoom_ + w * 0.1f, 0.2f, 4.0f);
    }
    if (area_hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Middle)) {
        scroll_.x += ImGui::GetIO().MouseDelta.x;
        scroll_.y += ImGui::GetIO().MouseDelta.y;
    }
    // right-drag also pans
    if (area_hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Right)) {
        scroll_.x += ImGui::GetIO().MouseDelta.x;
        scroll_.y += ImGui::GetIO().MouseDelta.y;
    }

    ImVec2 org(cp.x + cs.x / 2 + scroll_.x, cp.y + 20 + scroll_.y);

    std::unordered_map<va_t, size_t> ni;
    for (size_t i = 0; i < nodes_.size(); ++i) ni[nodes_[i].addr] = i;

    // edges
    for (auto& n : nodes_) {
        auto bit = func.blocks.find(n.addr);
        if (bit == func.blocks.end()) continue;
        ImVec2 fb(org.x + (n.x + n.w / 2) * zoom_, org.y + (n.y + n.h) * zoom_);

        for (size_t si = 0; si < bit->second.succs.size(); ++si) {
            va_t s = bit->second.succs[si];
            if (!ni.count(s)) continue;
            auto& t = nodes_[ni[s]];
            ImVec2 tt(org.x + (t.x + t.w / 2) * zoom_, org.y + t.y * zoom_);

            bool back_edge = t.layer <= n.layer;
            bool is_true_branch = (bit->second.succs.size() == 2 && si == 0);
            bool is_false_branch = (bit->second.succs.size() == 2 && si == 1);

            ImU32 ec;
            if (back_edge) ec = IM_COL32(200, 80, 80, 220);
            else if (is_true_branch) ec = IM_COL32(80, 200, 80, 220);
            else if (is_false_branch) ec = IM_COL32(200, 80, 80, 200);
            else ec = IM_COL32(150, 150, 180, 200);

            // curved edge
            ImVec2 mid1(fb.x, fb.y + 20 * zoom_);
            ImVec2 mid2(tt.x, tt.y - 20 * zoom_);
            dl->AddBezierCubic(fb, mid1, mid2, tt, ec, 2.0f * zoom_);

            // arrowhead
            ImVec2 dir(tt.x - mid2.x, tt.y - mid2.y);
            float len = sqrtf(dir.x * dir.x + dir.y * dir.y);
            if (len > 0) {
                dir.x /= len; dir.y /= len;
                float sz = 6.0f * zoom_;
                ImVec2 perp(-dir.y * sz, dir.x * sz);
                ImVec2 a1(tt.x - dir.x * sz * 1.5f + perp.x, tt.y - dir.y * sz * 1.5f + perp.y);
                ImVec2 a2(tt.x - dir.x * sz * 1.5f - perp.x, tt.y - dir.y * sz * 1.5f - perp.y);
                dl->AddTriangleFilled(tt, a1, a2, ec);
            }
        }
    }

    // nodes
    for (auto& n : nodes_) {
        ImVec2 tl(org.x + n.x * zoom_, org.y + n.y * zoom_);
        ImVec2 br(tl.x + n.w * zoom_, tl.y + n.h * zoom_);

        if (br.x < cp.x || tl.x > cp.x + cs.x || br.y < cp.y || tl.y > cp.y + cs.y)
            continue;

        ImVec2 mouse = ImGui::GetIO().MousePos;
        bool hovered = mouse.x >= tl.x && mouse.x <= br.x && mouse.y >= tl.y && mouse.y <= br.y;

        ImU32 bg = hovered ? IM_COL32(35, 40, 55, 250) : IM_COL32(24, 26, 35, 245);
        ImU32 border_col = hovered ? IM_COL32(100, 140, 200, 255) : IM_COL32(60, 65, 85, 255);

        dl->AddRectFilled(tl, br, bg, 5.f);
        dl->AddRect(tl, br, border_col, 5.f, 0, hovered ? 2.f : 1.f);

        // clip text to node bounds
        dl->PushClipRect(ImVec2(tl.x + 2, tl.y + 2), ImVec2(br.x - 2, br.y - 2), true);

        float tx = tl.x + 6 * zoom_;
        float ty = tl.y + 4 * zoom_;
        auto hdr = fmt::format("{:X}", n.addr);
        float font_sz = std::max(9.f, 12.f * zoom_);
        dl->AddText(nullptr, font_sz, ImVec2(tx, ty), col::addr(), hdr.c_str());
        ty += font_sz + 2 * zoom_;

        dl->AddLine(ImVec2(tl.x + 2, ty), ImVec2(br.x - 2, ty), IM_COL32(50, 55, 70, 200));
        ty += 3 * zoom_;

        auto bit = func.blocks.find(n.addr);
        va_t clicked_target = 0;
        if (bit != func.blocks.end()) {
            int max_lines = static_cast<int>((br.y - ty) / (font_sz + 1));
            int shown = 0;
            auto ri = db_->insns.range_begin(bit->second.start);
            auto re = db_->insns.range_end(bit->second.end);
            for (; ri != re; ++ri) {
                auto& insn = *ri;
                if (shown >= max_lines - 1) {
                    dl->AddText(nullptr, font_sz, ImVec2(tx, ty), col::comment(), "...");
                    break;
                }
                ImU32 mc = col::mnem();
                if (insn.is_call()) mc = IM_COL32(255, 200, 80, 255);
                else if (insn.is_branch()) mc = IM_COL32(100, 200, 140, 255);
                else if (insn.is_ret()) mc = IM_COL32(220, 100, 100, 255);

                float line_top = ty;
                float line_bot = ty + font_sz + 1;

                // highlight hovered instruction line
                bool line_hovered = hovered && mouse.y >= line_top && mouse.y < line_bot;
                if (line_hovered)
                    dl->AddRectFilled(ImVec2(tl.x + 2, line_top), ImVec2(br.x - 2, line_bot),
                        IM_COL32(50, 60, 90, 150));

                auto ln = fmt::format("{} {}", insn.mnemonic, insn.op_str);
                dl->AddText(nullptr, font_sz, ImVec2(tx, ty), mc, ln.c_str());

                // detect click on call/branch to follow
                if (line_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    va_t t = insn.branch_target();
                    if (t) clicked_target = t;
                }

                ty += font_sz + 1;
                ++shown;
            }
        }

        dl->PopClipRect();

        // double-click on call/branch line follows target
        if (clicked_target && nav_) {
            nav_(clicked_target);
        }
        // single click on node navigates to block start
        else if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            if (nav_) nav_(n.addr);
        }
    }

    dl->PopClipRect();
    ImGui::End();
}

}

#include "entropy_view.h"
#include <fmt/format.h>
#include <cmath>
#include <algorithm>
#include <GLFW/glfw3.h>

namespace hype {

EntropyView::~EntropyView() {
    destroy_texture();
}

void EntropyView::destroy_texture() {
    if (tex_id_) {
        GLuint id = static_cast<GLuint>(tex_id_);
        glDeleteTextures(1, &id);
        tex_id_ = 0;
    }
}

static ImU32 entropy_color(float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    u8 r = static_cast<u8>(t * 255);
    u8 b = static_cast<u8>((1.0f - t) * 255);
    u8 g = static_cast<u8>((t < 0.5f ? t * 2 : (1.0f - t) * 2) * 120);
    return IM_COL32(r, g, b, 255);
}

void EntropyView::rebuild() {
    blocks_.clear();
    if (!img_) return;

    for (auto& seg : img_->segments) {
        size_t n = seg.data.size() / BLOCK_SZ;
        for (size_t i = 0; i < n; ++i) {
            const u8* p = seg.data.data() + i * BLOCK_SZ;
            int freq[256] = {};
            for (size_t j = 0; j < BLOCK_SZ; ++j) freq[p[j]]++;
            float ent = 0.0f;
            for (int f : freq) {
                if (!f) continue;
                float prob = static_cast<float>(f) / BLOCK_SZ;
                ent -= prob * std::log2f(prob);
            }
            blocks_.push_back({seg.va + i * BLOCK_SZ, ent});
        }
    }
    dirty_ = false;
    last_avail_w_ = 0;
    last_avail_h_ = 0;
}

void EntropyView::rebuild_texture(int width, int height) {
    if (width <= 0 || height <= 0 || blocks_.empty()) return;

    tex_w_ = width;
    tex_h_ = height;

    std::vector<u8> pixels(static_cast<std::size_t>(width) *
                           static_cast<std::size_t>(height) * 4u);

    float blocks_per_col = static_cast<float>(blocks_.size()) / width;

    for (int x = 0; x < width; ++x) {
        int b_start = static_cast<int>(x * blocks_per_col);
        int b_end   = static_cast<int>((x + 1) * blocks_per_col);
        b_end = std::max(b_end, b_start + 1);
        b_end = std::min(b_end, static_cast<int>(blocks_.size()));

        float max_ent = 0.0f;
        for (int b = b_start; b < b_end; ++b)
            max_ent = std::max(max_ent, blocks_[b].entropy);

        float t = std::clamp(max_ent / 8.0f, 0.0f, 1.0f);
        float bar_h = t * height;
        int bar_px = static_cast<int>(bar_h + 0.5f);

        ImU32 col = entropy_color(t);
        u8 cr = (col >> 0) & 0xFF;
        u8 cg = (col >> 8) & 0xFF;
        u8 cb = (col >> 16) & 0xFF;

        for (int y = 0; y < height; ++y) {
            int row_from_bottom = height - 1 - y;
            int off = (y * width + x) * 4;
            if (row_from_bottom < bar_px) {
                pixels[off + 0] = cr;
                pixels[off + 1] = cg;
                pixels[off + 2] = cb;
                pixels[off + 3] = 255;
            } else {
                pixels[off + 0] = 0;
                pixels[off + 1] = 0;
                pixels[off + 2] = 0;
                pixels[off + 3] = 0;
            }
        }
    }

    if (!tex_id_) {
        GLuint id;
        glGenTextures(1, &id);
        tex_id_ = id;
    }

    glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(tex_id_));
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0,
                 GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
    glBindTexture(GL_TEXTURE_2D, 0);

    last_avail_w_ = width;
    last_avail_h_ = height;
}

void EntropyView::render() {
    ImGui::Begin("Entropy");
    if (!img_) { ImGui::TextDisabled("No data"); ImGui::End(); return; }
    if (dirty_) rebuild();
    if (blocks_.empty()) { ImGui::End(); return; }

    ImVec2 avail = ImGui::GetContentRegionAvail();
    int w = static_cast<int>(avail.x);
    int h = static_cast<int>(avail.y - 20);
    if (h < 40) h = 40;
    if (w < 1) w = 1;

    if (w != last_avail_w_ || h != last_avail_h_)
        rebuild_texture(w, h);

    if (tex_id_) {
        ImVec2 origin = ImGui::GetCursorScreenPos();
        ImGui::Image(static_cast<ImTextureID>(tex_id_),
                     ImVec2(static_cast<float>(tex_w_), static_cast<float>(tex_h_)));

        if (ImGui::IsItemHovered()) {
            float mx = ImGui::GetIO().MousePos.x - origin.x;
            float blocks_per_col = static_cast<float>(blocks_.size()) / tex_w_;
            int col = static_cast<int>(mx);
            col = std::clamp(col, 0, tex_w_ - 1);

            int b_start = static_cast<int>(col * blocks_per_col);
            int b_end   = static_cast<int>((col + 1) * blocks_per_col);
            b_end = std::max(b_end, b_start + 1);
            b_end = std::min(b_end, static_cast<int>(blocks_.size()));

            int mid = (b_start + b_end) / 2;
            mid = std::clamp(mid, 0, static_cast<int>(blocks_.size()) - 1);

            float max_ent = 0.0f;
            for (int b = b_start; b < b_end; ++b)
                max_ent = std::max(max_ent, blocks_[b].entropy);

            ImGui::SetTooltip("0x%llX  entropy: %.2f",
                              (unsigned long long)blocks_[mid].addr, max_ent);

            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                if (nav_) nav_(blocks_[mid].addr);
        }
    }

    ImGui::End();
}

}

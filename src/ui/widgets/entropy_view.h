#pragma once
#include "core/loader/pe_loader.h"
#include <imgui.h>
#include <functional>
#include <vector>

namespace hype {

class EntropyView {
public:
    using NavCB = std::function<void(va_t)>;
    void set_data(const PEImage* img) { img_ = img; dirty_ = true; }
    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void render();
    ~EntropyView();

private:
    void rebuild();
    void rebuild_texture(int width, int height);
    void destroy_texture();

    const PEImage* img_ = nullptr;
    NavCB          nav_;
    bool           dirty_ = true;

    struct Block { va_t addr; float entropy; };
    std::vector<Block> blocks_;
    static constexpr size_t BLOCK_SZ = 256;

    u32  tex_id_ = 0;
    int  tex_w_  = 0;
    int  tex_h_  = 0;
    int  last_avail_w_ = 0;
    int  last_avail_h_ = 0;
};

}

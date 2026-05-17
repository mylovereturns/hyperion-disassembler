#pragma once
#include "core/analysis/analysis_db.h"
#include <imgui.h>
#include <functional>
#include <string>
#include <vector>

namespace hype {

class StringsPanel {
public:
    using NavCB = std::function<void(va_t)>;
    void set_data(const AnalysisDB* db) { db_ = db; invalidate(); }
    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void render();
    void invalidate() { dirty_ = true; }

private:
    void rebuild_cache();

    struct CachedRow {
        int    src_index;
        va_t   addr;
        va_t   nav_target;
        int    xref_count;
        std::string label;       // "ADDR##sN"
        std::string value;       // the string content
    };

    const AnalysisDB* db_ = nullptr;
    NavCB             nav_;
    char              filter_[256] = {};
    std::string       last_filter_;
    bool              dirty_ = true;
    std::vector<CachedRow> cache_;
};

}

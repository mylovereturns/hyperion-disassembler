#pragma once
#include "core/analysis/analysis_db.h"
#include <imgui.h>
#include <functional>
#include <string>
#include <vector>

namespace hype {

class FunctionsPanel {
public:
    using NavCB = std::function<void(va_t)>;

    void set_data(const AnalysisDB* db) { db_ = db; invalidate(); }
    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void render();
    void invalidate() { dirty_ = true; }

private:
    void rebuild_cache();

    struct CachedRow {
        va_t        entry;
        std::string label;       // "ADDR##fN"
        std::string name;
        int         block_count;
    };

    const AnalysisDB* db_ = nullptr;
    NavCB             nav_;
    char              filter_[256] = {};
    std::string       last_filter_;
    bool              dirty_ = true;
    std::vector<CachedRow> cache_;
};

}

#pragma once
#include "core/loader/pe_loader.h"
#include "core/analysis/analysis_db.h"
#include <imgui.h>
#include <functional>
#include <string>
#include <vector>

namespace hype {

class ImportsPanel {
public:
    using NavCB = std::function<void(va_t)>;
    void set_data(const PEImage* img) { img_ = img; invalidate(); }
    void set_db(const AnalysisDB* db) { db_ = db; invalidate(); }
    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void render();
    void invalidate() { dirty_ = true; }

private:
    va_t find_caller(va_t iat_addr);
    void rebuild_cache();

    struct ImportRow {
        int         src_index;
        va_t        iat_addr;
        std::string label;   // "ADDR##iN"
        std::string dll;
        std::string name;
    };
    struct ExportRow {
        int         src_index;
        va_t        addr;
        std::string label;   // "ADDR##eN"
        int         ordinal;
        std::string name;
    };

    const PEImage*    img_ = nullptr;
    const AnalysisDB* db_ = nullptr;
    NavCB             nav_;
    char              filter_[256] = {};
    std::string       last_filter_;
    bool              dirty_ = true;
    std::vector<ImportRow> import_cache_;
    std::vector<ExportRow> export_cache_;
};

}

#pragma once
#include "core/analysis/analysis_db.h"
#include "core/loader/pe_loader.h"
#include <imgui.h>
#include <functional>
#include <string>
#include <vector>

namespace hype {

class SigMaker {
public:
    using NavCB = std::function<void(va_t)>;

    void set_data(AnalysisDB* db, PEImage* img) { db_ = db; img_ = img; }
    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void generate_for_function(va_t func_addr);
    void generate_for_range(va_t start, size_t len);
    void render();
    bool& visible() { return visible_; }

private:
    struct PatternByte { u8 value; bool wildcard; };

    std::vector<PatternByte> build_pattern(va_t start, size_t len);
    size_t scan_count(const std::vector<PatternByte>& pat);
    void trim_pattern();
    void format_outputs();

    std::string fmt_ida() const;
    std::string fmt_x64dbg() const;
    std::string fmt_cpp() const;
    std::string fmt_rust() const;

    AnalysisDB*  db_  = nullptr;
    PEImage*     img_ = nullptr;
    NavCB        nav_;
    bool         visible_ = false;

    va_t         target_addr_ = 0;
    std::string  target_name_;
    std::vector<PatternByte> pattern_;
    size_t       match_count_ = 0;

    std::string  out_ida_;
    std::string  out_x64dbg_;
    std::string  out_cpp_;
    std::string  out_rust_;

    char         range_start_[32] = {};
    char         range_len_[16]   = "64";
};

}

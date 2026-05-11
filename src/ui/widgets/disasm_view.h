#pragma once
#include "core/analysis/analysis_db.h"
#include "core/loader/pe_loader.h"
#include "core/disasm/disassembler.h"
#include "core/undo.h"
#include <imgui.h>
#include <functional>
#include <vector>
#include <unordered_set>
#include <unordered_map>

namespace hype {

class StackFrameView;

class DisasmView {
public:
    using NavCB = std::function<void(va_t)>;
    using SigCB = std::function<void(va_t)>;

    void set_data(AnalysisDB* db, PEImage* img) { db_ = db; img_ = img; dirty_ = true; }
    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void set_sig_cb(SigCB cb) { sig_cb_ = std::move(cb); }
    void set_undo(UndoManager* u) { undo_ = u; }
    void set_stack_frame_view(StackFrameView* sfv) { sfv_ = sfv; }
    void goto_addr(va_t addr);
    void render();
    va_t cursor() const { return cursor_; }
    bool& beautify() { return beautify_; }

    void cmd_define_data();
    void cmd_define_string();
    void cmd_undefine();
    void cmd_force_code();
    void cmd_toggle_hex();
    void cmd_nop();

private:
    void rebuild();
    void render_line(int idx, const Insn& insn, float lh);
    void render_data_line(const DataItem& item, float lh);
    void update_reg_highlight();

    AnalysisDB*       db_ = nullptr;
    PEImage*          img_ = nullptr;
    StackFrameView*   sfv_ = nullptr;
    UndoManager*      undo_ = nullptr;
    NavCB             nav_;
    SigCB             sig_cb_;
    va_t              cursor_ = 0;
    va_t              scroll_to_ = 0;
    bool              scroll_pending_ = false;
    std::vector<va_t> addrs_;
    bool              dirty_ = true;
    bool              beautify_ = false;
    u16               highlighted_reg_ = 0;
    std::unordered_set<va_t> reg_highlight_addrs_;
    std::unordered_map<va_t, const std::string*> str_map_;
};

}

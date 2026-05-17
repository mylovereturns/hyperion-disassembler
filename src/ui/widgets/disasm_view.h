#pragma once
#include "core/analysis/analysis_db.h"
#include "core/loader/pe_loader.h"
#include "core/disasm/disassembler.h"
#include "core/undo.h"
#include <imgui.h>
#include <functional>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>

namespace hype {

class StackFrameView;
class DebugEngine;

struct CachedDataLine {
    std::string label;
    ImU32       color;
    std::string name_comment;
};

struct CachedInsnLine {
    char        hex[22];
    std::string label;
    std::string annotation;
};

class DisasmView {
public:
    using NavCB = std::function<void(va_t)>;
    using SigCB = std::function<void(va_t)>;

    void set_data(AnalysisDB* db, PEImage* img) { db_ = db; img_ = img; dirty_ = true; }
    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void set_sig_cb(SigCB cb) { sig_cb_ = std::move(cb); }
    void set_undo(UndoManager* u) { undo_ = u; }
    void set_stack_frame_view(StackFrameView* sfv) { sfv_ = sfv; }
    void set_debug_state(va_t rip, const std::vector<va_t>* bps) { debug_rip_ = rip; debug_bps_ = bps; }
    void set_debug_engine(DebugEngine* eng) { dbg_eng_ = eng; }
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
    void rebuild_data_cache();
    void rebuild_insn_cache();
    void render_line(int idx, const Insn& insn, float lh);
    void render_live_line(int idx, const Insn& insn, float lh);
    void render_data_line(const DataItem& item, float lh);
    void render_live(float lh);
    void update_reg_highlight();

    AnalysisDB*       db_ = nullptr;
    PEImage*          img_ = nullptr;
    StackFrameView*   sfv_ = nullptr;
    UndoManager*      undo_ = nullptr;
    DebugEngine*      dbg_eng_ = nullptr;
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
    va_t              debug_rip_ = 0;
    const std::vector<va_t>* debug_bps_ = nullptr;

    bool              live_mode_ = false;
    std::vector<Insn> live_insns_;
    va_t              live_base_ = 0;

    std::unordered_map<va_t, CachedDataLine> data_cache_;
    std::unordered_map<va_t, CachedInsnLine> insn_cache_;
    std::unordered_map<va_t, std::string>    seg_hdr_cache_;
};

}

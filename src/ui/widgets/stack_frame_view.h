#pragma once
#include "core/analysis/analysis_db.h"
#include <imgui.h>
#include <map>

namespace hype {

struct StackVar {
    i64         offset;
    std::string name;
    u16         size;
    u32         type_id = 0;
};

struct StackFrame {
    va_t                    func_entry = 0;
    std::map<i64, StackVar> vars;
    i64                     frame_size = 0;

    void analyze(const Function& func);
    void rename(i64 offset, std::string new_name);
    const StackVar* find(i64 offset) const;
};

class StackFrameView {
public:
    void set_data(AnalysisDB* db) { db_ = db; }
    void set_function(va_t entry);
    void render();

    const StackFrame* current_frame() const;

private:
    AnalysisDB*                              db_ = nullptr;
    va_t                                     func_ = 0;
    std::unordered_map<va_t, StackFrame>     frames_;
    bool                                     renaming_ = false;
    i64                                      rename_offset_ = 0;
    char                                     rename_buf_[128] = {};
};

std::string format_operand_with_vars(const Insn& insn, const StackFrame* frame);

}

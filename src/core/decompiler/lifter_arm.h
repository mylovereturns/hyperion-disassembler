#pragma once
#include "core/decompiler/ir.h"
#include "core/analysis/analysis_db.h"
#include <unordered_map>
#include <string_view>

namespace hype {

class LifterARM {
public:
    PcodeFunc lift(const Function& func, const AnalysisDB& db);

private:
    void lift_block(const BasicBlock& bb, const AnalysisDB& db, PcodeBlock& out);
    void lift_insn(const Insn& insn, PcodeBlock& blk, const AnalysisDB& db);

    Varnode reg_vn(int reg_id);
    Varnode operand_read(const Insn& insn, int idx, PcodeBlock& out);
    void operand_write(const Insn& insn, int idx, Varnode val, PcodeBlock& out);
    
    Varnode alloc_temp(int sz = 4);
    void emit(PcodeBlock& b, PcodeOp op, Varnode out, std::vector<Varnode> in, va_t a = 0);

    int next_temp_ = 256;
    va_t cur_addr_ = 0;
    int  cur_seq_  = 0;
    std::unordered_map<va_t, int> addr_to_block_;
};

}

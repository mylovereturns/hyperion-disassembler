#pragma once
#include "core/loader/pe_loader.h"
#include "core/disasm/disassembler.h"
#include "core/disasm/capstone_disasm.h"
#include "analysis_db.h"
#include "signatures.h"
#include "rtti.h"
#include "threading/worker_pool.h"
#include "threading/task_scheduler.h"
#include <atomic>

namespace hype {

class Analyzer {
public:
    Analyzer(PEImage& img, WorkerPool& pool);

    void run();
    void apply_signatures();
    float progress() const { return progress_.load(); }
    AnalysisDB& db() { return db_; }
    const AnalysisDB& db() const { return db_; }
    SignatureMatcher& sig_matcher() { return sigmatch_; }
    const SignatureMatcher& sig_matcher() const { return sigmatch_; }
    RTTIParser& rtti_parser() { return rtti_; }
    const RTTIParser& rtti_parser() const { return rtti_; }

private:
    void linear_sweep();
    void merge_tentative();
    void recursive_descent();
    void detect_functions();
    void detect_thunks();
    void build_cfgs();
    void remove_junk_code();
    void detect_switches();
    void build_xrefs();
    void find_strings();
    void find_string_refs();
    void detect_vtables();
    void detect_globals();
    void apply_names();
    void detect_noreturn();
    void detect_tail_calls();
    void detect_calling_conventions();
    void detect_main();
    void propagate_dataflow();
    void detect_loops();
    void recover_structs();
    void populate_data_sections();
    void propagate_interproc_types();

    void descend(va_t addr, std::unordered_set<va_t>& visited);
    const u8* va_to_ptr(va_t addr, size_t* max_len = nullptr);
    bool is_iat_addr(va_t addr) const;
    bool is_code_addr(va_t addr) const;
    bool in_section(va_t addr, const char* name) const;
    const Segment* section_for(va_t addr) const;

    bool use_capstone() const {
        return img_.arch != Arch::X86 && img_.arch != Arch::X64;
    }
    bool decode_insn(va_t addr, const u8* data, size_t len, Insn& out);
    std::vector<Insn> decode_insn_range(va_t start, const u8* data, size_t len);

    PEImage&           img_;
    Disassembler       disasm_;
    CapstoneDisasm     cap_disasm_;
    AnalysisDB         db_;
    WorkerPool&        pool_;
    TaskScheduler      sched_;
    SignatureMatcher   sigmatch_;
    RTTIParser         rtti_;
    std::atomic<float> progress_{0.f};
    InsnStore          tentative_;
};

}

#include "analyzer.h"
#include "core/disasm/disassembler.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <algorithm>
#include <queue>
#include <unordered_set>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#else
#include <cxxabi.h>
#endif

namespace hype {

namespace {
std::string demangle(const std::string& name) {
    if (name.empty()) return name;
#ifdef _WIN32
    if (name[0] == '?' || name[0] == '@') {
        char buf[1024];
        DWORD result = UnDecorateSymbolName(name.c_str(), buf, sizeof(buf),
            UNDNAME_COMPLETE | UNDNAME_NO_ACCESS_SPECIFIERS | UNDNAME_NO_ALLOCATION_MODEL);
        if (result > 0)
            return buf;
    }
#else
    if (name.size() > 2 && name[0] == '_' && name[1] == 'Z') {
        int status = 0;
        char* demangled = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
        if (status == 0 && demangled) {
            std::string result(demangled);
            std::free(demangled);
            return result;
        }
    }
#endif
    if (name.size() > 1 && name[0] == '_' && name[1] != '_')
        return name.substr(1);
    return name;
}
}

Analyzer::Analyzer(PEImage& img, WorkerPool& pool)
    : img_(img), pool_(pool), sched_(pool) {
    disasm_.set_arch(img.arch);
    cap_disasm_.set_arch(img.arch);
    db_.image_base = img.base;
}

const u8* Analyzer::va_to_ptr(va_t addr, size_t* max_len) {
    for (auto& seg : img_.segments) {
        if (seg.contains(addr)) {
            size_t off = static_cast<size_t>(addr - seg.va);
            if (max_len) *max_len = seg.data.size() - off;
            return seg.data.data() + off;
        }
    }
    return nullptr;
}

bool Analyzer::is_iat_addr(va_t addr) const {
    for (auto& imp : img_.imports)
        if (imp.iat_addr == addr) return true;
    return false;
}

bool Analyzer::is_code_addr(va_t addr) const {
    for (auto& seg : img_.segments)
        if (seg.executable() && seg.contains(addr)) return true;
    return false;
}

bool Analyzer::in_section(va_t addr, const char* name) const {
    for (auto& seg : img_.segments)
        if (seg.name == name && seg.contains(addr)) return true;
    return false;
}

const Segment* Analyzer::section_for(va_t addr) const {
    for (auto& seg : img_.segments)
        if (seg.contains(addr)) return &seg;
    return nullptr;
}

void Analyzer::run() {
    spdlog::info("analysis: starting");
    progress_ = 0.0f;

    linear_sweep();
    progress_ = 0.12f;

    recursive_descent();
    progress_ = 0.25f;

    merge_tentative();
    progress_ = 0.30f;

    detect_functions();
    progress_ = 0.38f;

    detect_thunks();
    progress_ = 0.42f;

    sigmatch_.match_functions(db_, img_);
    progress_ = 0.45f;

    build_cfgs();
    progress_ = 0.55f;

    remove_junk_code();
    progress_ = 0.57f;

    detect_switches();
    progress_ = 0.62f;

    build_xrefs();
    progress_ = 0.72f;

    find_strings();
    progress_ = 0.78f;

    find_string_refs();
    progress_ = 0.82f;

    detect_vtables();
    progress_ = 0.85f;

    detect_globals();
    progress_ = 0.88f;

    detect_noreturn();
    progress_ = 0.87f;

    detect_tail_calls();
    progress_ = 0.89f;

    detect_calling_conventions();
    progress_ = 0.91f;

    propagate_dataflow();
    progress_ = 0.93f;

    detect_loops();
    progress_ = 0.95f;

    recover_structs();
    progress_ = 0.97f;

    propagate_interproc_types();
    progress_ = 0.98f;

    populate_data_sections();
    progress_ = 0.99f;

    apply_names();
    progress_ = 0.99f;

    detect_main();
    progress_ = 1.0f;

    rtti_.parse(img_, db_);

    spdlog::info("analysis: done - {} insns, {} funcs, {} xrefs, {} strings, {} vtables, {} globals, {} resolved_indirect",
                 db_.insns.size(), db_.funcs.size(), db_.xrefs.size(),
                 db_.strings.size(), db_.vtables.size(), db_.globals.size(),
                 db_.resolved_indirect.size());
}

void Analyzer::linear_sweep() {
    constexpr size_t kMaxLinearSweepSection = 50ULL * 1024 * 1024;
    std::vector<std::future<std::vector<Insn>>> futures;
    for (auto& seg : img_.segments) {
        if (!seg.executable() || seg.data.empty()) continue;
        if (seg.data.size() > kMaxLinearSweepSection) {
            spdlog::info("skipping linear sweep of section {} ({}MB > 50MB limit)",
                         seg.name, seg.data.size() / (1024*1024));
            continue;
        }
        futures.push_back(pool_.submit([this, &seg]() {
            return decode_insn_range(seg.va, seg.data.data(), seg.data.size());
        }));
    }
    for (auto& f : futures) {
        for (auto& insn : f.get())
            tentative_[insn.addr] = std::move(insn);
    }
}

void Analyzer::merge_tentative() {
    if (tentative_.empty()) return;

    std::vector<std::pair<va_t, va_t>> confirmed;
    confirmed.reserve(db_.insns.size());
    for (auto& [addr, insn] : db_.insns)
        confirmed.emplace_back(addr, addr + insn.len);
    std::sort(confirmed.begin(), confirmed.end());

    for (auto& [addr, insn] : tentative_) {
        if (db_.insns.count(addr)) continue;
        if (!is_code_addr(addr)) continue;

        va_t end = addr + insn.len;

        auto it = std::lower_bound(confirmed.begin(), confirmed.end(),
            std::make_pair(addr, va_t(0)));

        bool overlaps = false;
        if (it != confirmed.begin()) {
            auto prev = std::prev(it);
            if (prev->second > addr) overlaps = true;
        }
        if (!overlaps && it != confirmed.end() && it->first < end)
            overlaps = true;

        if (!overlaps)
            db_.insns[addr] = std::move(insn);
    }
    tentative_.clear();
    spdlog::info("merge: {} confirmed insns", db_.insns.size());
}

void Analyzer::recursive_descent() {
    std::unordered_set<va_t> visited;
    descend(img_.entry, visited);
    for (auto& exp : img_.exports)
        descend(exp.addr, visited);
}

void Analyzer::descend(va_t addr, std::unordered_set<va_t>& visited) {
    std::queue<va_t> wl;
    wl.push(addr);

    while (!wl.empty()) {
        va_t cur = wl.front(); wl.pop();
        if (visited.count(cur)) continue;
        if (!is_code_addr(cur)) continue;
        visited.insert(cur);

        size_t max_len = 0;
        const u8* ptr = va_to_ptr(cur, &max_len);
        if (!ptr || !max_len) continue;

        size_t off = 0;
        while (off < max_len) {
            Insn insn{};
            if (!decode_insn(cur + off, ptr + off, max_len - off, insn))
                break;
            db_.insns[insn.addr] = insn;
            off += insn.len;

            if (insn.is_ret()) break;
            if (insn.is_call()) {
                va_t t = insn.branch_target();
                if (t && !visited.count(t)) wl.push(t);
            }
            if (insn.is_branch()) {
                va_t t = insn.branch_target();
                if (t && !visited.count(t)) wl.push(t);
                if (insn.type == InsnType::Jmp) break;
            }
        }
    }
}

void Analyzer::detect_functions() {
    std::unordered_set<va_t> entries;
    entries.insert(img_.entry);
    for (auto& exp : img_.exports)
        entries.insert(exp.addr);

    // .pdata runtime functions — most reliable source for x64
    for (auto& rf : img_.runtime_funcs) {
        entries.insert(rf.start);
    }

    // call targets
    for (auto& [addr, insn] : db_.insns) {
        if (insn.is_call()) {
            va_t t = insn.branch_target();
            if (t && db_.insns.count(t)) entries.insert(t);
        }
    }

    for (va_t e : entries) {
        Function func;
        func.entry = e;
        func.name = fmt::format("sub_{:X}", e - img_.base);
        db_.add_func(std::move(func));
    }

    // apply known end addresses from .pdata
    for (auto& rf : img_.runtime_funcs) {
        auto it = db_.funcs.find(rf.start);
        if (it != db_.funcs.end()) {
            // store end as a hint in block_addrs[0] sentinel — we use it during CFG
        }
    }

    spdlog::info("detected {} functions", db_.funcs.size());
}

void Analyzer::detect_thunks() {
    // Look for jmp [rip+disp32] (FF 25 xx xx xx xx) at function entries
    // that target IAT addresses — label them with the import name
    std::unordered_map<va_t, std::string> iat_names;
    for (auto& imp : img_.imports)
        iat_names[imp.iat_addr] = imp.name;

    u32 found = 0;
    for (auto& seg : img_.segments) {
        if (!seg.executable() || seg.data.empty()) continue;
        const u8* data = seg.data.data();
        size_t sz = seg.data.size();

        for (size_t i = 0; i + 6 <= sz; ++i) {
            if (data[i] != 0xFF || data[i + 1] != 0x25) continue;

            va_t insn_addr = seg.va + i;
            i32 disp = 0;
            std::memcpy(&disp, data + i + 2, 4);
            va_t target = insn_addr + 6 + disp;

            auto it = iat_names.find(target);
            if (it == iat_names.end()) continue;

            if (!db_.funcs.count(insn_addr)) {
                Function func;
                func.entry = insn_addr;
                func.name = it->second;
                db_.add_func(std::move(func));
            } else {
                db_.funcs[insn_addr].name = it->second;
            }
            db_.set_name(insn_addr, it->second);
            ++found;
        }
    }
    spdlog::info("detected {} import thunks", found);
}

void Analyzer::remove_junk_code() {
    // collect all addresses that belong to a function's CFG
    std::unordered_set<va_t> in_func;
    for (auto& [entry, func] : db_.funcs) {
        for (auto& [ba, bb] : func.blocks) {
            va_t cur = bb.start;
            while (cur < bb.end) {
                in_func.insert(cur);
                auto it = db_.insns.find(cur);
                if (it == db_.insns.end()) break;
                cur += it->second.len;
            }
        }
    }

    // remove instructions not in any function that are clearly junk:
    // - null bytes (00 00 = add [rax], al)
    // - int3 padding (CC)
    // - nop padding (90)
    // - sequences of identical 2-byte instructions (padding patterns)
    std::vector<va_t> to_remove;
    for (auto& [addr, insn] : db_.insns) {
        if (in_func.count(addr)) continue;

        bool junk = false;
        if (insn.len <= 2 && insn.bytes[0] == 0x00 && (insn.len == 1 || insn.bytes[1] == 0x00))
            junk = true;
        if (insn.len == 1 && insn.bytes[0] == 0xCC)
            junk = true;
        if (insn.len == 1 && insn.bytes[0] == 0x90)
            junk = true;

        if (junk) to_remove.push_back(addr);
    }

    for (va_t a : to_remove)
        db_.insns.erase(a);

    spdlog::info("removed {} junk instructions", to_remove.size());
}

void Analyzer::build_cfgs() {
    for (auto& [entry, func] : db_.funcs) {
        std::unordered_set<va_t> visited;
        std::queue<va_t> wl;
        wl.push(entry);

        while (!wl.empty()) {
            va_t bb_start = wl.front(); wl.pop();
            if (visited.count(bb_start)) continue;
            visited.insert(bb_start);

            BasicBlock bb;
            bb.start = bb_start;
            va_t cur = bb_start;

            while (db_.insns.count(cur)) {
                auto& insn = db_.insns[cur];
                bb.insns.push_back(insn);
                cur += insn.len;

                if (insn.is_ret()) break;
                if (insn.type == InsnType::Jmp) {
                    va_t t = insn.branch_target();
                    if (t) { bb.succs.push_back(t); wl.push(t); }
                    break;
                }
                if (insn.is_cond_jmp()) {
                    va_t t = insn.branch_target();
                    if (t) { bb.succs.push_back(t); wl.push(t); }
                    bb.succs.push_back(cur); wl.push(cur);
                    break;
                }
                if (cur != entry && db_.funcs.count(cur)) break;
            }

            bb.end = cur;
            func.block_addrs.push_back(bb.start);
            func.blocks[bb.start] = std::move(bb);
        }

        for (auto& [ba, block] : func.blocks)
            for (va_t s : block.succs)
                if (func.blocks.count(s))
                    func.blocks[s].preds.push_back(ba);

        func.analyzed = true;
    }
}

void Analyzer::detect_switches() {
    u32 tables_found = 0;

    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed) continue;

        for (auto& [ba, block] : func.blocks) {
            if (block.insns.size() < 2) continue;
            auto& last = block.insns.back();
            if (last.type != InsnType::Jmp) continue;

            // Pattern 1: jmp reg (indirect through register, table was loaded)
            // Pattern 2: jmp [reg*scale + table_addr]
            if (last.op_count < 1) continue;
            auto& op = last.ops[0];

            // Direct memory operand: jmp [reg*8 + table_addr]
            if (op.type == OpType::Mem && op.mem.base == 0 && op.mem.index != 0 &&
                op.val != 0) {
                va_t table_addr = op.val;
                size_t max_len = 0;
                const u8* tbl = va_to_ptr(table_addr, &max_len);
                if (!tbl) continue;

                u32 max_entries = static_cast<u32>(max_len / 8);
                if (max_entries > 256) max_entries = 256;

                for (u32 i = 0; i < max_entries; ++i) {
                    va_t target = 0;
                    std::memcpy(&target, tbl + i * 8, 8);
                    if (!is_code_addr(target)) break;
                    block.succs.push_back(target);
                    if (!func.blocks.count(target)) {
                        // add to CFG worklist — simplified: just record the edge
                    }
                }
                ++tables_found;
                continue;
            }

            // RIP-relative LEA pattern: look back for lea+movsxd pattern
            // scan backwards for a LEA with rip-relative addressing
            va_t table_base = 0;
            for (int j = static_cast<int>(block.insns.size()) - 2; j >= 0; --j) {
                auto& prev = block.insns[j];
                if (prev.type == InsnType::Lea && prev.op_count >= 2 &&
                    prev.ops[1].type == OpType::Mem && prev.ops[1].val != 0) {
                    table_base = prev.ops[1].val;
                    break;
                }
            }
            if (!table_base) continue;

            // Look for bound: scan block preds for cmp+ja pattern
            u32 max_cases = 64;
            for (va_t pred_addr : block.preds) {
                auto pit = func.blocks.find(pred_addr);
                if (pit == func.blocks.end()) continue;
                auto& pblk = pit->second;
                for (auto& pi : pblk.insns) {
                    if (pi.type == InsnType::Cmp && pi.op_count >= 2 &&
                        pi.ops[1].type == OpType::Imm) {
                        max_cases = static_cast<u32>(pi.ops[1].val) + 1;
                        if (max_cases > 512) max_cases = 512;
                    }
                }
            }

            size_t max_len = 0;
            const u8* tbl = va_to_ptr(table_base, &max_len);
            if (!tbl) continue;

            u32 avail = static_cast<u32>(max_len / 4);
            if (max_cases > avail) max_cases = avail;

            for (u32 i = 0; i < max_cases; ++i) {
                i32 offset = 0;
                std::memcpy(&offset, tbl + i * 4, 4);
                va_t target = table_base + offset;
                if (!is_code_addr(target)) break;
                block.succs.push_back(target);
            }
            ++tables_found;
        }
    }
    spdlog::info("detected {} switch tables", tables_found);
}

void Analyzer::build_xrefs() {
    for (auto& [addr, insn] : db_.insns) {
        if (insn.is_call()) {
            va_t t = insn.branch_target();
            if (t) db_.add_xref({addr, t, XrefType::CodeCall});
        } else if (insn.is_branch()) {
            va_t t = insn.branch_target();
            if (t) db_.add_xref({addr, t, XrefType::CodeJump});
        }
        for (u8 i = 0; i < insn.op_count; ++i) {
            auto& op = insn.ops[i];
            if (op.type == OpType::Mem && op.val)
                db_.add_xref({addr, op.val, XrefType::DataRead});
            else if (op.type == OpType::Imm && op.val > img_.base &&
                     op.val < img_.base + 0x10000000)
                db_.add_xref({addr, op.val, XrefType::DataOffset});
        }
    }
}

void Analyzer::find_strings() {
    constexpr size_t kMaxStringLen = 256;
    for (auto& seg : img_.segments) {
        if (seg.data.empty()) continue;
        size_t i = 0;
        while (i < seg.data.size()) {
            if (seg.data[i] >= 0x20 && seg.data[i] < 0x7F) {
                size_t start = i;
                while (i < seg.data.size() && seg.data[i] >= 0x20 && seg.data[i] < 0x7F)
                    ++i;
                if (i - start >= 4 && i < seg.data.size() && seg.data[i] == 0) {
                    size_t len = (std::min)(i - start, kMaxStringLen);
                    std::string s(seg.data.begin() + start, seg.data.begin() + start + len);
                    db_.strings.emplace_back(seg.va + start, std::move(s));
                }
            } else {
                ++i;
            }
        }
    }
    spdlog::info("found {} strings", db_.strings.size());
}

void Analyzer::find_string_refs() {
    // Build lookup of string addresses for fast checking
    std::unordered_set<va_t> str_addrs;
    for (auto& [addr, s] : db_.strings)
        str_addrs.insert(addr);

    u32 refs_added = 0;
    for (auto& [addr, insn] : db_.insns) {
        if (insn.type != InsnType::Lea) continue;
        // LEA reg, [rip+X] — operand 1 is mem with computed VA
        for (u8 i = 0; i < insn.op_count; ++i) {
            auto& op = insn.ops[i];
            if (op.type == OpType::Mem && op.val && str_addrs.count(op.val)) {
                db_.add_xref({addr, op.val, XrefType::DataOffset});
                ++refs_added;
            }
        }
    }
    spdlog::info("found {} string refs via LEA", refs_added);
}

void Analyzer::detect_vtables() {
    u32 found = 0;
    for (auto& seg : img_.segments) {
        if (seg.executable() || seg.data.empty()) continue;
        if (seg.name != ".rdata" && seg.name != ".data") continue;

        const u8* data = seg.data.data();
        size_t sz = seg.data.size();
        size_t ptr_sz = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? 8 : 4;

        for (size_t i = 0; i + ptr_sz * 2 <= sz; i += ptr_sz) {
            // need at least 2 consecutive code pointers to consider it a vtable
            va_t first = 0;
            if (ptr_sz == 8)
                std::memcpy(&first, data + i, 8);
            else {
                u32 v = 0; std::memcpy(&v, data + i, 4); first = v;
            }

            if (!is_code_addr(first)) continue;

            Vtable vt;
            vt.addr = seg.va + i;

            size_t j = i;
            while (j + ptr_sz <= sz) {
                va_t val = 0;
                if (ptr_sz == 8)
                    std::memcpy(&val, data + j, 8);
                else {
                    u32 v = 0; std::memcpy(&v, data + j, 4); val = v;
                }
                if (!is_code_addr(val)) break;
                vt.entries.push_back(val);
                j += ptr_sz;
            }

            if (vt.entries.size() >= 2) {
                db_.set_name(vt.addr, fmt::format("vtable_{:X}", vt.addr));
                for (size_t s = 0; s < vt.entries.size(); ++s)
                    db_.set_name(vt.addr + s * ptr_sz,
                                 fmt::format("vtable_{:X}_slot{}", vt.addr, s));
                db_.vtables.push_back(std::move(vt));
                ++found;
                i = j - ptr_sz; // advance past this vtable
            }
        }
    }
    spdlog::info("detected {} vtables", found);
}

void Analyzer::detect_globals() {
    u32 found = 0;
    for (auto& [addr, insn] : db_.insns) {
        for (u8 i = 0; i < insn.op_count; ++i) {
            auto& op = insn.ops[i];
            if (op.type != OpType::Mem || op.val == 0) continue;

            va_t target = op.val;
            auto* sec = section_for(target);
            if (!sec) continue;
            if (sec->executable()) continue;
            if (sec->name != ".data" && sec->name != ".bss") continue;
            if (db_.globals.count(target)) {
                // update size if wider access
                u32 sz = op.size ? op.size : 4;
                if (sz > db_.globals[target].size)
                    db_.globals[target].size = sz;
                continue;
            }

            Global g;
            g.addr = target;
            g.size = op.size ? op.size : 4;
            g.name = fmt::format("g_var_{:X}", target);
            db_.globals[target] = std::move(g);
            db_.set_name(target, fmt::format("g_var_{:X}", target));
            ++found;
        }
    }
    spdlog::info("detected {} global variables", found);
}

void Analyzer::apply_names() {
    db_.set_name(img_.entry, "entry_point");
    for (auto& imp : img_.imports) {
        std::string demangled = demangle(imp.name);
        db_.set_name(imp.iat_addr, imp.dll + "!" + demangled);
    }
    for (auto& exp : img_.exports) {
        std::string demangled = demangle(exp.name);
        db_.set_name(exp.addr, demangled);
        auto fit = db_.funcs.find(exp.addr);
        if (fit != db_.funcs.end())
            fit->second.name = demangled;
    }

    DataSize ptr_size = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? DataSize::Qword : DataSize::Dword;
    for (auto& imp : img_.imports) {
        db_.insns.erase(imp.iat_addr);
        db_.data_items[imp.iat_addr] = {imp.iat_addr, ptr_size, DataStyle::Import, false};
    }
    spdlog::info("defined {} IAT data items", img_.imports.size());
}

void Analyzer::apply_signatures() {
    sigmatch_.match_functions(db_, img_);
}

void Analyzer::detect_noreturn() {
    static const std::unordered_set<std::string> known_noreturn = {
        "exit", "_exit", "abort", "__fastfail", "ExitProcess",
        "TerminateProcess", "RtlFailFast", "__report_rangecheckfailure",
        "_Exit", "quick_exit", "_abort", "FatalExit"
    };

    u32 count = 0;
    for (auto& [entry, func] : db_.funcs) {
        for (auto& nr_name : known_noreturn) {
            if (func.name.find(nr_name) != std::string::npos) {
                func.noreturn = true;
                ++count;
                goto next_func;
            }
        }

        if (func.analyzed && !func.blocks.empty()) {
            bool has_ret = false;
            for (auto& [ba, bb] : func.blocks) {
                for (auto& insn : bb.insns) {
                    if (insn.is_ret()) { has_ret = true; break; }
                }
                if (has_ret) break;
            }
            if (!has_ret) {
                bool has_exit_path = false;
                for (auto& [ba, bb] : func.blocks) {
                    if (bb.succs.empty() && !bb.insns.empty() && !bb.insns.back().is_ret()) {
                        auto& last = bb.insns.back();
                        if (last.is_call()) {
                            va_t t = last.branch_target();
                            if (t && db_.funcs.count(t) && db_.funcs[t].noreturn)
                                continue;
                        }
                    }
                    if (!bb.succs.empty()) has_exit_path = true;
                }
                if (!has_exit_path && func.blocks.size() > 0) {
                    func.noreturn = true;
                    ++count;
                }
            }
        }
        next_func:;
    }
    spdlog::info("detected {} noreturn functions", count);
}

void Analyzer::detect_tail_calls() {
    u32 count = 0;
    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed) continue;
        va_t func_end = 0;
        for (auto& [ba, bb] : func.blocks)
            if (bb.end > func_end) func_end = bb.end;

        for (auto& [ba, bb] : func.blocks) {
            if (bb.insns.empty()) continue;
            auto& last = bb.insns.back();
            if (last.type != InsnType::Jmp) continue;

            va_t target = last.branch_target();
            if (!target) continue;

            bool is_tail = false;
            if (db_.funcs.count(target) && target != entry)
                is_tail = true;
            else if (target < entry || target >= func_end)
                if (!func.blocks.count(target))
                    is_tail = true;

            if (is_tail) {
                db_.add_xref({last.addr, target, XrefType::CodeCall});
                auto it = std::find_if(db_.xrefs.begin(), db_.xrefs.end(), [&](const Xref& x) {
                    return x.from == last.addr && x.to == target && x.type == XrefType::CodeJump;
                });
                if (it != db_.xrefs.end()) {
                    it->type = XrefType::CodeCall;
                    for (auto& xr : db_.xrefs_to[target])
                        if (xr.from == last.addr && xr.type == XrefType::CodeJump)
                            xr.type = XrefType::CodeCall;
                    for (auto& xr : db_.xrefs_from[last.addr])
                        if (xr.to == target && xr.type == XrefType::CodeJump)
                            xr.type = XrefType::CodeCall;
                }
                ++count;
            }
        }
    }
    spdlog::info("detected {} tail calls", count);
}

void Analyzer::detect_calling_conventions() {
    bool is_x64 = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC);

    for (auto& [entry, func] : db_.funcs) {
        if (is_x64) {
            func.callconv = CallConv::X64;
            continue;
        }

        if (!func.analyzed) continue;

        bool has_ret_n = false;
        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (insn.is_ret() && insn.op_count > 0 && insn.ops[0].type == OpType::Imm &&
                    insn.ops[0].val > 0) {
                    has_ret_n = true;
                    break;
                }
            }
            if (has_ret_n) break;
        }

        if (has_ret_n)
            func.callconv = CallConv::Stdcall;
        else
            func.callconv = CallConv::Cdecl;
    }
    spdlog::info("calling conventions assigned (x64={})", is_x64 ? "yes" : "no");
}

void Analyzer::propagate_dataflow() {
    u32 resolved = 0;

    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed || func.blocks.empty()) continue;

        std::unordered_map<u16, va_t> reg_vals;

        for (auto& ba : func.block_addrs) {
            auto bit = func.blocks.find(ba);
            if (bit == func.blocks.end()) continue;
            auto& bb = bit->second;

            for (auto& insn : bb.insns) {
                if (insn.type == InsnType::Mov && insn.op_count >= 2 &&
                    insn.ops[0].type == OpType::Reg && insn.ops[1].type == OpType::Imm) {
                    reg_vals[insn.ops[0].reg] = insn.ops[1].val;
                }
                else if (insn.type == InsnType::Lea && insn.op_count >= 2 &&
                         insn.ops[0].type == OpType::Reg && insn.ops[1].type == OpType::Mem &&
                         insn.ops[1].val != 0) {
                    reg_vals[insn.ops[0].reg] = insn.ops[1].val;
                }
                else if (insn.op_count > 0 && insn.ops[0].type == OpType::Reg &&
                         insn.type != InsnType::Cmp && insn.type != InsnType::Test) {
                    reg_vals.erase(insn.ops[0].reg);
                }

                if ((insn.is_call() || insn.type == InsnType::Jmp) &&
                    insn.op_count > 0 && insn.ops[0].type == OpType::Reg) {
                    auto it = reg_vals.find(insn.ops[0].reg);
                    if (it != reg_vals.end() && it->second != 0 && is_code_addr(it->second)) {
                        db_.resolved_indirect[insn.addr] = it->second;
                        db_.add_xref({insn.addr, it->second, XrefType::CodeCall});
                        ++resolved;
                    }
                }
                else if ((insn.is_call() || insn.type == InsnType::Jmp) &&
                         insn.op_count > 0 && insn.ops[0].type == OpType::Mem &&
                         insn.ops[0].mem.base != 0 && insn.ops[0].val == 0) {
                    auto it = reg_vals.find(insn.ops[0].mem.base);
                    if (it != reg_vals.end() && it->second != 0) {
                        va_t effective = it->second + insn.ops[0].mem.disp;
                        size_t max_len = 0;
                        const u8* ptr = va_to_ptr(effective, &max_len);
                        if (ptr && max_len >= 8) {
                            va_t target = 0;
                            std::memcpy(&target, ptr, (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? 8 : 4);
                            if (is_code_addr(target)) {
                                db_.resolved_indirect[insn.addr] = target;
                                db_.add_xref({insn.addr, target, XrefType::CodeCall});
                                ++resolved;
                            }
                        }
                    }
                }

                if (insn.is_call()) reg_vals.clear();
            }
        }
    }
    spdlog::info("dataflow: resolved {} indirect call/jump targets", resolved);
}

void Analyzer::detect_loops() {
    u32 count = 0;
    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed) continue;

        for (auto& [ba, bb] : func.blocks) {
            for (va_t succ : bb.succs) {
                if (succ > ba) continue;
                if (!func.blocks.count(succ)) continue;

                LoopInfo loop;
                loop.header = succ;
                loop.back_edge_src = ba;

                std::unordered_set<va_t> loop_blocks;
                std::queue<va_t> wl;
                loop_blocks.insert(succ);
                loop_blocks.insert(ba);
                wl.push(ba);
                while (!wl.empty()) {
                    va_t cur = wl.front(); wl.pop();
                    auto bit2 = func.blocks.find(cur);
                    if (bit2 == func.blocks.end()) continue;
                    for (va_t pred : bit2->second.preds) {
                        if (loop_blocks.insert(pred).second)
                            wl.push(pred);
                    }
                }

                for (va_t lb : loop_blocks) {
                    auto lbit = func.blocks.find(lb);
                    if (lbit == func.blocks.end()) continue;
                    for (auto& insn : lbit->second.insns) {
                        if (std::strcmp(insn.mnemonic, "inc") == 0 && insn.op_count > 0 &&
                            insn.ops[0].type == OpType::Reg) {
                            loop.induction_reg = insn.ops[0].reg;
                            goto found_ind;
                        }
                        if (insn.type == InsnType::Add && insn.op_count >= 2 &&
                            insn.ops[0].type == OpType::Reg &&
                            insn.ops[1].type == OpType::Imm && insn.ops[1].val == 1) {
                            loop.induction_reg = insn.ops[0].reg;
                            goto found_ind;
                        }
                    }
                }
                found_ind:
                func.loops.push_back(loop);
                ++count;
            }
        }
    }
    spdlog::info("detected {} loops", count);
}

void Analyzer::recover_structs() {
    u32 count = 0;

    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed) continue;

        struct Access { u16 base_reg; i64 offset; u32 size; };
        std::unordered_map<u16, std::vector<Access>> accesses;

        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                for (u8 i = 0; i < insn.op_count; ++i) {
                    auto& op = insn.ops[i];
                    if (op.type != OpType::Mem) continue;
                    if (op.mem.base == 0) continue;
                    // skip RSP/RBP-based (stack frame)
                    if (op.mem.base == 4 || op.mem.base == 5) continue; // RSP=4, RBP=5
                    if (op.mem.base == 20 || op.mem.base == 21) continue; // x64 RSP/RBP
                    if (op.mem.disp < 0) continue;
                    if (op.mem.disp > 4096) continue;

                    Access a;
                    a.base_reg = op.mem.base;
                    a.offset = op.mem.disp;
                    a.size = op.size ? op.size : 8;
                    accesses[a.base_reg].push_back(a);
                }
            }
        }

        for (auto& [reg, accs] : accesses) {
            if (accs.size() < 3) continue;

            std::set<std::pair<i64, u32>> fields_set;
            for (auto& a : accs)
                fields_set.insert({a.offset, a.size});
            if (fields_set.size() < 3) continue;

            std::string name = fmt::format("struct_{:X}_{}", entry, reg);
            auto* existing = db_.types.find_by_name(name);
            if (existing) continue;

            u32 total_size = 0;
            for (auto& [off, sz] : fields_set)
                if (static_cast<u32>(off) + sz > total_size)
                    total_size = static_cast<u32>(off) + sz;

            u32 sid = db_.types.add_struct(name, total_size);
            u32 field_idx = 0;
            for (auto& [off, sz] : fields_set) {
                std::string fname = fmt::format("field_{:X}", off);
                u32 type_id = 0;
                auto* t8  = db_.types.find_by_name("u8");
                auto* t16 = db_.types.find_by_name("u16");
                auto* t32 = db_.types.find_by_name("u32");
                auto* t64 = db_.types.find_by_name("u64");
                if (sz == 1 && t8) type_id = t8->id;
                else if (sz == 2 && t16) type_id = t16->id;
                else if (sz == 4 && t32) type_id = t32->id;
                else if (sz == 8 && t64) type_id = t64->id;
                else if (t32) type_id = t32->id;
                db_.types.add_field(sid, fname, type_id, static_cast<u32>(off));
                ++field_idx;
            }
            ++count;
        }
    }
    spdlog::info("recovered {} struct types", count);
}

void Analyzer::populate_data_sections() {
    constexpr size_t kLargeSectionThreshold = 5ULL * 1024 * 1024;
    constexpr u32    kZeroRunThreshold = 4;

    std::unordered_set<va_t> str_addrs;
    for (auto& [addr, _] : db_.strings)
        str_addrs.insert(addr);

    std::unordered_set<va_t> iat_addrs;
    for (auto& imp : img_.imports)
        iat_addrs.insert(imp.iat_addr);

    size_t ptr_sz = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? 8 : 4;
    DataSize ds = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? DataSize::Qword : DataSize::Dword;
    u32 defined = 0;

    for (auto& seg : img_.segments) {
        if (seg.executable() || seg.data.empty()) continue;

        bool large = seg.data.size() > kLargeSectionThreshold;
        const u8* data = seg.data.data();
        size_t sz = seg.data.size();

        for (size_t i = 0; i + ptr_sz <= sz; i += ptr_sz) {
            va_t addr = seg.va + i;

            if (db_.data_items.count(addr)) continue;
            if (str_addrs.count(addr)) continue;
            if (iat_addrs.count(addr)) continue;

            va_t val = 0;
            if (ptr_sz == 8)
                std::memcpy(&val, data + i, 8);
            else {
                u32 v = 0; std::memcpy(&v, data + i, 4); val = v;
            }

            if (val == 0) {
                u32 run = 0;
                size_t j = i;
                while (j + ptr_sz <= sz) {
                    va_t zv = 0;
                    if (ptr_sz == 8)
                        std::memcpy(&zv, data + j, 8);
                    else {
                        u32 v2 = 0; std::memcpy(&v2, data + j, 4); zv = v2;
                    }
                    if (zv != 0) break;
                    ++run;
                    j += ptr_sz;
                }
                if (run >= kZeroRunThreshold) {
                    db_.data_items[addr] = {addr, ds, DataStyle::Align, false};
                    i = j - ptr_sz;
                    ++defined;
                    continue;
                }
            }

            if (large && !db_.xrefs_to.count(addr) && !is_code_addr(val))
                continue;

            if (is_code_addr(val)) {
                db_.data_items[addr] = {addr, ds, DataStyle::Pointer, false};
            } else {
                db_.data_items[addr] = {addr, ds, DataStyle::Raw, false};
            }
            ++defined;
        }
    }

    for (auto& imp : img_.imports) {
        auto it = db_.data_items.find(imp.iat_addr);
        if (it != db_.data_items.end())
            it->second.style = DataStyle::Import;
    }

    spdlog::info("populate_data_sections: defined {} data items", defined);
}

void Analyzer::detect_main() {
    static const std::unordered_set<std::string> crt_starters = {
        "__scrt_common_main_seh", "mainCRTStartup", "__tmainCRTStartup",
        "WinMainCRTStartup", "__wWinMainCRTStartup"
    };

    for (auto& [entry, func] : db_.funcs) {
        if (!crt_starters.count(func.name)) continue;
        if (!func.analyzed) continue;

        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (!insn.is_call()) continue;
                va_t target = insn.branch_target();
                if (!target) continue;
                if (!db_.funcs.count(target)) continue;
                if (crt_starters.count(db_.funcs[target].name)) continue;

                auto& callee = db_.funcs[target];
                bool is_winmain = func.name.find("WinMain") != std::string::npos;

                if (is_winmain) {
                    callee.name = "WinMain";
                    db_.set_name(target, "WinMain");
                } else {
                    callee.name = "main";
                    db_.set_name(target, "main");
                }
                spdlog::info("detected {} at {:X}", callee.name, target);
                return;
            }
        }
    }

    // Fallback: entry calls a CRT stub which calls main
    auto eit = db_.funcs.find(img_.entry);
    if (eit == db_.funcs.end() || !eit->second.analyzed) return;

    for (auto& [ba, bb] : eit->second.blocks) {
        for (auto& insn : bb.insns) {
            if (!insn.is_call()) continue;
            va_t stub = insn.branch_target();
            if (!stub || !db_.funcs.count(stub)) continue;
            auto& stub_func = db_.funcs[stub];
            if (!stub_func.analyzed) continue;

            for (auto& [ba2, bb2] : stub_func.blocks) {
                for (auto& ins2 : bb2.insns) {
                    if (!ins2.is_call()) continue;
                    va_t target = ins2.branch_target();
                    if (!target || !db_.funcs.count(target)) continue;
                    auto& callee = db_.funcs[target];
                    if (callee.name.rfind("sub_", 0) != 0) continue;

                    callee.name = "main";
                    db_.set_name(target, "main");
                    spdlog::info("detected main at {:X} (via entry stub)", target);
                    return;
                }
            }
        }
    }
}

void Analyzer::propagate_interproc_types() {
    static const std::unordered_map<std::string, FuncSignature> known_sigs = {
        {"strlen",   {{"str"}, {"const char*"}, "size_t", 1}},
        {"strcmp",   {{"s1","s2"}, {"const char*","const char*"}, "int32_t", 2}},
        {"strcpy",   {{"dst","src"}, {"char*","const char*"}, "char*", 2}},
        {"memcpy",   {{"dst","src","n"}, {"void*","const void*","size_t"}, "void*", 3}},
        {"memset",   {{"dst","val","n"}, {"void*","int32_t","size_t"}, "void*", 3}},
        {"malloc",   {{"size"}, {"size_t"}, "void*", 1}},
        {"free",     {{"ptr"}, {"void*"}, "void", 1}},
        {"printf",   {{"fmt"}, {"const char*"}, "int32_t", 1}},
        {"CreateFileA", {{"lpFileName","dwDesiredAccess","dwShareMode","lpSecurity","dwCreation","dwFlags","hTemplate"},
                         {"const char*","uint32_t","uint32_t","void*","uint32_t","uint32_t","void*"}, "void*", 7}},
    };

    u32 propagated = 0;

    for (auto& [entry, func] : db_.funcs) {
        auto kit = known_sigs.find(func.name);
        if (kit != known_sigs.end()) {
            db_.signatures[entry] = kit->second;
            ++propagated;
        }
    }

    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed) continue;

        int param_reg_count = 0;
        bool uses_rcx = false, uses_rdx = false, uses_r8 = false, uses_r9 = false;

        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                for (u8 i = 0; i < insn.op_count; ++i) {
                    if (insn.ops[i].type == OpType::Reg) {
                        if (insn.ops[i].reg == 1) uses_rcx = true;
                        if (insn.ops[i].reg == 2) uses_rdx = true;
                        if (insn.ops[i].reg == 8) uses_r8 = true;
                        if (insn.ops[i].reg == 9) uses_r9 = true;
                    }
                }
            }
        }

        if (uses_r9) param_reg_count = 4;
        else if (uses_r8) param_reg_count = 3;
        else if (uses_rdx) param_reg_count = 2;
        else if (uses_rcx) param_reg_count = 1;

        if (!db_.signatures.count(entry)) {
            FuncSignature sig;
            sig.param_count = param_reg_count;
            sig.return_type = "int64_t";
            for (int p = 0; p < param_reg_count; ++p) {
                sig.param_names.push_back(fmt::format("a{}", p + 1));
                sig.param_types.push_back("int64_t");
            }
            db_.signatures[entry] = std::move(sig);
        }
    }

    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed) continue;
        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (!insn.is_call()) continue;
                va_t target = insn.branch_target();
                if (!target) continue;
                auto sit = db_.signatures.find(target);
                if (sit == db_.signatures.end()) continue;
                auto& callee_sig = sit->second;

                if (callee_sig.return_type != "int64_t") {
                    auto& caller_sig = db_.signatures[entry];
                    (void)caller_sig;
                }
            }
        }
    }

    spdlog::info("interproc: propagated {} function signatures", propagated + (u32)db_.signatures.size());
}

bool Analyzer::decode_insn(va_t addr, const u8* data, size_t len, Insn& out) {
    if (use_capstone())
        return cap_disasm_.decode(addr, data, len, out);
    return disasm_.decode(addr, data, len, out);
}

std::vector<Insn> Analyzer::decode_insn_range(va_t start, const u8* data, size_t len) {
    if (use_capstone())
        return cap_disasm_.decode_range(start, data, len);
    return disasm_.decode_range(start, data, len);
}

}

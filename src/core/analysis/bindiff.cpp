#include "bindiff.h"
#include <fmt/format.h>
#include <algorithm>
#include <unordered_set>
#include <numeric>

namespace hype {

std::vector<DiffResult> BinDiff::compare(const AnalysisDB& a, const AnalysisDB& b) {
    std::vector<DiffResult> results;
    std::unordered_set<va_t> matched_b;

    for (auto& [ea, fa] : a.funcs) {
        bool found = false;
        for (auto& [eb, fb] : b.funcs) {
            if (matched_b.count(eb)) continue;
            if (!fa.name.empty() && fa.name == fb.name) {
                float sim = compute_similarity(fa, fb, a, b);
                auto st = sim >= 0.999f ? DiffResult::Identical : DiffResult::Modified;
                results.push_back({ea, eb, fa.name, sim, st});
                matched_b.insert(eb);
                found = true;
                break;
            }
        }
        if (found) continue;

        float best_sim = 0.f;
        va_t best_eb = 0;
        for (auto& [eb, fb] : b.funcs) {
            if (matched_b.count(eb)) continue;
            float sim = compute_similarity(fa, fb, a, b);
            if (sim > best_sim) { best_sim = sim; best_eb = eb; }
        }
        if (best_sim >= 0.5f && best_eb) {
            auto st = best_sim >= 0.999f ? DiffResult::Identical : DiffResult::Modified;
            std::string nm = fa.name.empty() ? fmt::format("sub_{:X}", ea) : fa.name;
            results.push_back({ea, best_eb, nm, best_sim, st});
            matched_b.insert(best_eb);
        } else {
            std::string nm = fa.name.empty() ? fmt::format("sub_{:X}", ea) : fa.name;
            results.push_back({ea, 0, nm, 0.f, DiffResult::Removed});
        }
    }

    for (auto& [eb, fb] : b.funcs) {
        if (matched_b.count(eb)) continue;
        std::string nm = fb.name.empty() ? fmt::format("sub_{:X}", eb) : fb.name;
        results.push_back({0, eb, nm, 0.f, DiffResult::Added});
    }

    std::sort(results.begin(), results.end(), [](auto& x, auto& y) {
        return x.status < y.status;
    });
    return results;
}

float BinDiff::compute_similarity(const Function& fa, const Function& fb,
                                  const AnalysisDB& da, const AnalysisDB& db) {
    auto ba = func_bytes(fa, da);
    auto bb = func_bytes(fb, db);
    if (ba.empty() && bb.empty()) return 1.f;
    if (ba.empty() || bb.empty()) return 0.f;

    size_t match = 0;
    size_t total = std::max(ba.size(), bb.size());
    size_t cmp_len = std::min(ba.size(), bb.size());
    for (size_t i = 0; i < cmp_len; ++i)
        if (ba[i] == bb[i]) ++match;

    return static_cast<float>(match) / static_cast<float>(total);
}

std::vector<u8> BinDiff::func_bytes(const Function& f, const AnalysisDB& db) {
    std::vector<u8> out;
    for (auto& [_, bb] : f.blocks) {
        db.for_each_insn_in_block(bb, [&](const Insn& insn) {
            out.insert(out.end(), insn.bytes, insn.bytes + insn.len);
        });
    }
    return out;
}

}

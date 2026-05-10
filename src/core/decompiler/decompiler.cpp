#include "decompiler.h"
#include <fmt/format.h>
#include <unordered_set>

namespace hype {

std::vector<PseudoLine> Decompiler::decompile(const Function& func, const AnalysisDB& db) {
    if (func.blocks.empty())
        return {{0, "// empty function", func.entry}};

    // bail on very complex functions to avoid hanging
    if (func.blocks.size() > 200) {
        std::vector<PseudoLine> out;
        out.push_back({0, fmt::format("// function too complex ({} blocks) - showing summary", func.blocks.size()), func.entry});
        out.push_back({0, fmt::format("void {}() {{", func.name), func.entry});

        // just list calls made by this function
        std::unordered_set<std::string> calls_seen;
        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (!insn.is_call()) continue;
                va_t t = insn.branch_target();
                if (!t) continue;
                auto nit = db.names.find(t);
                std::string name = nit != db.names.end() ? nit->second : fmt::format("sub_{:X}", t);
                if (calls_seen.insert(name).second)
                    out.push_back({1, fmt::format("{}();", name), insn.addr});
            }
        }
        out.push_back({1, "// ...", 0});
        out.push_back({0, "}", 0});
        return out;
    }

    IRFunc ir = lifter_.lift(func, db);
    sym_.run(ir);
    ti_.run(ir);
    prop_.run(ir);
    CFunc cf = cf_.structure(ir);
    return emitter_.emit(cf, &ti_);
}

}

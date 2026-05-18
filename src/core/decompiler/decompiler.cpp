#include "decompiler.h"
#include <fmt/format.h>
#include <unordered_set>

namespace hype {

std::vector<PseudoLine> Decompiler::decompile(const Function& func, const AnalysisDB& db,
                                               const RTTIParser* rtti) {
    if (func.blocks.empty())
        return {{0, "// empty function", func.entry}};

    if (func.blocks.size() > 200) {
        std::vector<PseudoLine> out;
        out.push_back({0, fmt::format("// function too complex ({} blocks)", func.blocks.size()), func.entry});
        out.push_back({0, fmt::format("void {}() {{", func.name), func.entry});

        std::unordered_set<std::string> calls_seen;
        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (!insn.is_call()) continue;
                va_t t = insn.branch_target();
                if (!t) continue;
                auto nit = db.names.find(t);
                std::string name;
                if (nit != db.names.end())
                    name = nit->second;
                else if (db.image_base && t >= db.image_base)
                    name = fmt::format("sub_{:X}", t - db.image_base);
                else
                    name = fmt::format("sub_{:X}", t);
                if (calls_seen.insert(name).second)
                    out.push_back({1, fmt::format("{}();", name), insn.addr});
            }
        }
        out.push_back({1, "// ...", 0});
        out.push_back({0, "}", 0});
        return out;
    }

    PcodeFunc pf;
    if (db.arch == Arch::ARM64)
        pf = arm64_lifter_.lift(func, db);
    else if (db.arch == Arch::ARM)
        pf = arm_lifter_.lift(func, db);
    else if (db.arch == Arch::X64 || db.arch == Arch::X86)
        pf = lifter_.lift(func, db);
    else {
        // Fallback for other architectures or unsupported ones
        return {{0, fmt::format("// architecture not supported in decompiler yet"), func.entry}};
    }
    ssa_.build(pf);
    dce_.run(pf);
    prop_.run(pf);
    ti_.run(pf);
    CFunc cf = cf_.structure(pf);
    return emitter_.emit(cf, &ti_, &db, rtti);
}

}

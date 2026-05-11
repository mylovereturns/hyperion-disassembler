#include "pdb_loader.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#endif

namespace hype {

std::filesystem::path PDBLoader::pdb_for(const std::filesystem::path& binary) {
    auto p = binary;
    p.replace_extension(".pdb");
    if (std::filesystem::exists(p)) return p;
    return {};
}

bool PDBLoader::load(const std::filesystem::path& pdb_path, va_t base, AnalysisDB& db) {
#ifdef _WIN32
    if (!std::filesystem::exists(pdb_path)) {
        status_ = "No PDB found. For better analysis, place the .pdb next to the binary.";
        found_ = false;
        return false;
    }

    found_ = true;
    status_ = fmt::format("PDB found: {} \xe2\x80\x94 loading symbols", pdb_path.filename().string());
    spdlog::info("pdb: loading {}", pdb_path.string());

    HANDLE hProc = GetCurrentProcess();
    if (!SymInitialize(hProc, nullptr, FALSE)) {
        status_ = "PDB: SymInitialize failed";
        spdlog::warn("pdb: SymInitialize failed: {}", GetLastError());
        return false;
    }

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

    DWORD64 mod_base = SymLoadModuleExW(hProc, nullptr, pdb_path.c_str(), nullptr,
                                         base, 0x7FFFFFFF, nullptr, 0);
    if (!mod_base) {
        spdlog::warn("pdb: SymLoadModuleEx failed: {}", GetLastError());
        SymCleanup(hProc);
        status_ = "PDB: SymLoadModuleEx failed";
        return false;
    }

    struct EnumCtx { AnalysisDB* db; u32 count; };
    EnumCtx ctx{&db, 0};

    SymEnumSymbols(hProc, mod_base, "*", [](PSYMBOL_INFO si, ULONG, PVOID user) -> BOOL {
        auto* c = static_cast<EnumCtx*>(user);
        if (!si->Name || !si->Name[0]) return TRUE;
        va_t addr = static_cast<va_t>(si->Address);
        std::string name(si->Name);

        c->db->set_name(addr, name);

        if (si->Tag == 5 /* SymTagFunction */) {
            auto fit = c->db->funcs.find(addr);
            if (fit != c->db->funcs.end())
                fit->second.name = name;
        }
        c->count++;
        return TRUE;
    }, &ctx);

    SymUnloadModule64(hProc, mod_base);
    SymCleanup(hProc);

    status_ = fmt::format("PDB: loaded {} symbols from {}", ctx.count, pdb_path.filename().string());
    spdlog::info("pdb: loaded {} symbols", ctx.count);
    return true;
#else
    (void)pdb_path; (void)base; (void)db;
    status_ = "PDB loading not supported on this platform";
    found_ = false;
    return false;
#endif
}

}

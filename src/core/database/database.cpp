#include "database.h"
#include <fstream>
#include <spdlog/spdlog.h>

namespace hype {

namespace fs = std::filesystem;

bool Database::save(const fs::path& dir, const PEImage& img, const AnalysisDB& db) {
    fs::create_directories(dir);

    {
        std::ofstream f(dir / "meta.bin", std::ios::binary);
        if (!f) return false;
        u8 arch = static_cast<u8>(img.arch);
        f.write(reinterpret_cast<const char*>(&arch), 1);
        f.write(reinterpret_cast<const char*>(&img.base), 8);
        f.write(reinterpret_cast<const char*>(&img.entry), 8);
    }

    {
        std::ofstream f(dir / "funcs.bin", std::ios::binary);
        if (!f) return false;
        u32 n = static_cast<u32>(db.funcs.size());
        f.write(reinterpret_cast<const char*>(&n), 4);
        for (auto& [entry, func] : db.funcs) {
            f.write(reinterpret_cast<const char*>(&func.entry), 8);
            u16 nlen = static_cast<u16>(func.name.size());
            f.write(reinterpret_cast<const char*>(&nlen), 2);
            f.write(func.name.data(), nlen);
        }
    }

    {
        std::ofstream f(dir / "names.bin", std::ios::binary);
        if (!f) return false;
        u32 n = static_cast<u32>(db.names.size());
        f.write(reinterpret_cast<const char*>(&n), 4);
        for (auto& [addr, name] : db.names) {
            f.write(reinterpret_cast<const char*>(&addr), 8);
            u16 nlen = static_cast<u16>(name.size());
            f.write(reinterpret_cast<const char*>(&nlen), 2);
            f.write(name.data(), nlen);
        }
    }

    {
        std::ofstream f(dir / "comments.bin", std::ios::binary);
        if (!f) return false;
        u32 n = static_cast<u32>(db.comments.size());
        f.write(reinterpret_cast<const char*>(&n), 4);
        for (auto& [addr, cmt] : db.comments) {
            f.write(reinterpret_cast<const char*>(&addr), 8);
            u16 clen = static_cast<u16>(cmt.size());
            f.write(reinterpret_cast<const char*>(&clen), 2);
            f.write(cmt.data(), clen);
        }
    }

    {
        std::ofstream f(dir / "xrefs.bin", std::ios::binary);
        if (!f) return false;
        u32 n = static_cast<u32>(db.xrefs.size());
        f.write(reinterpret_cast<const char*>(&n), 4);
        for (auto& xr : db.xrefs) {
            f.write(reinterpret_cast<const char*>(&xr.from), 8);
            f.write(reinterpret_cast<const char*>(&xr.to), 8);
            u8 type = static_cast<u8>(xr.type);
            f.write(reinterpret_cast<const char*>(&type), 1);
        }
    }

    {
        std::ofstream f(dir / "types.bin", std::ios::binary);
        if (!f) return false;
        auto& all = db.types.all();
        u32 n = static_cast<u32>(all.size());
        f.write(reinterpret_cast<const char*>(&n), 4);
        for (auto& [id, td] : all) {
            f.write(reinterpret_cast<const char*>(&td.id), 4);
            u8 kind = static_cast<u8>(td.kind);
            f.write(reinterpret_cast<const char*>(&kind), 1);
            u16 nlen = static_cast<u16>(td.name.size());
            f.write(reinterpret_cast<const char*>(&nlen), 2);
            f.write(td.name.data(), nlen);
            f.write(reinterpret_cast<const char*>(&td.size), 4);
            u32 fc = static_cast<u32>(td.fields.size());
            f.write(reinterpret_cast<const char*>(&fc), 4);
            for (auto& fl : td.fields) {
                u16 fnl = static_cast<u16>(fl.name.size());
                f.write(reinterpret_cast<const char*>(&fnl), 2);
                f.write(fl.name.data(), fnl);
                f.write(reinterpret_cast<const char*>(&fl.type_id), 4);
                f.write(reinterpret_cast<const char*>(&fl.offset), 4);
                f.write(reinterpret_cast<const char*>(&fl.size), 4);
            }
            u32 mc = static_cast<u32>(td.members.size());
            f.write(reinterpret_cast<const char*>(&mc), 4);
            for (auto& m : td.members) {
                u16 mnl = static_cast<u16>(m.name.size());
                f.write(reinterpret_cast<const char*>(&mnl), 2);
                f.write(m.name.data(), mnl);
                f.write(reinterpret_cast<const char*>(&m.value), 8);
            }
        }

        u32 atc = static_cast<u32>(db.applied_types.size());
        f.write(reinterpret_cast<const char*>(&atc), 4);
        for (auto& [addr, tid] : db.applied_types) {
            f.write(reinterpret_cast<const char*>(&addr), 8);
            f.write(reinterpret_cast<const char*>(&tid), 4);
        }
    }

    spdlog::info("saved project: {}", dir.string());
    return true;
}

bool Database::load(const fs::path& dir, PEImage& img, AnalysisDB& db) {
    if (!fs::exists(dir / "meta.bin")) return false;

    {
        std::ifstream f(dir / "meta.bin", std::ios::binary);
        if (!f) return false;
        u8 arch; f.read(reinterpret_cast<char*>(&arch), 1);
        img.arch = static_cast<Arch>(arch);
        f.read(reinterpret_cast<char*>(&img.base), 8);
        f.read(reinterpret_cast<char*>(&img.entry), 8);
        db.image_base = img.base;
    }

    {
        std::ifstream f(dir / "names.bin", std::ios::binary);
        if (f) {
            u32 n; f.read(reinterpret_cast<char*>(&n), 4);
            if (!f) return false;
            for (u32 i = 0; i < n; ++i) {
                va_t addr; f.read(reinterpret_cast<char*>(&addr), 8);
                u16 nlen; f.read(reinterpret_cast<char*>(&nlen), 2);
                if (!f) break;
                std::string name(nlen, '\0');
                f.read(name.data(), nlen);
                if (!f) break;
                db.names[addr] = std::move(name);
            }
        }
    }

    {
        std::ifstream f(dir / "comments.bin", std::ios::binary);
        if (f) {
            u32 n; f.read(reinterpret_cast<char*>(&n), 4);
            if (!f) return false;
            for (u32 i = 0; i < n; ++i) {
                va_t addr; f.read(reinterpret_cast<char*>(&addr), 8);
                u16 clen; f.read(reinterpret_cast<char*>(&clen), 2);
                if (!f) break;
                std::string cmt(clen, '\0');
                f.read(cmt.data(), clen);
                if (!f) break;
                db.comments[addr] = std::move(cmt);
            }
        }
    }

    {
        std::ifstream f(dir / "types.bin", std::ios::binary);
        if (f) {
            u32 n; f.read(reinterpret_cast<char*>(&n), 4);
            for (u32 i = 0; i < n; ++i) {
                TypeDef td{};
                f.read(reinterpret_cast<char*>(&td.id), 4);
                u8 kind; f.read(reinterpret_cast<char*>(&kind), 1);
                td.kind = static_cast<TypeKind>(kind);
                u16 nlen; f.read(reinterpret_cast<char*>(&nlen), 2);
                td.name.resize(nlen);
                f.read(td.name.data(), nlen);
                f.read(reinterpret_cast<char*>(&td.size), 4);
                u32 fc; f.read(reinterpret_cast<char*>(&fc), 4);
                for (u32 j = 0; j < fc; ++j) {
                    TypeField fl{};
                    u16 fnl; f.read(reinterpret_cast<char*>(&fnl), 2);
                    fl.name.resize(fnl);
                    f.read(fl.name.data(), fnl);
                    f.read(reinterpret_cast<char*>(&fl.type_id), 4);
                    f.read(reinterpret_cast<char*>(&fl.offset), 4);
                    f.read(reinterpret_cast<char*>(&fl.size), 4);
                    td.fields.push_back(std::move(fl));
                }
                u32 mc; f.read(reinterpret_cast<char*>(&mc), 4);
                for (u32 j = 0; j < mc; ++j) {
                    EnumMember m{};
                    u16 mnl; f.read(reinterpret_cast<char*>(&mnl), 2);
                    m.name.resize(mnl);
                    f.read(m.name.data(), mnl);
                    f.read(reinterpret_cast<char*>(&m.value), 8);
                    td.members.push_back(std::move(m));
                }
            }
            u32 atc; f.read(reinterpret_cast<char*>(&atc), 4);
            for (u32 i = 0; i < atc; ++i) {
                va_t addr; f.read(reinterpret_cast<char*>(&addr), 8);
                u32 tid; f.read(reinterpret_cast<char*>(&tid), 4);
                db.applied_types[addr] = tid;
            }
        }
    }

    spdlog::info("loaded project: {}", dir.string());
    return true;
}

}

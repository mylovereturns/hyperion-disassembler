#include "pe_loader.h"
#include <fstream>
#include <cstring>
#include <spdlog/spdlog.h>
#include <fmt/format.h>

namespace hype {

namespace {

constexpr size_t kMaxFileSize   = 2ULL * 1024 * 1024 * 1024;
constexpr u16    kMaxSections   = 256;
constexpr u32    kMaxImports    = 1'000'000;
constexpr u32    kMaxExports    = 1'000'000;
constexpr u32    kMaxNameLen    = 1024;
constexpr u32    kMaxILTEntries = 500'000;

#pragma pack(push, 1)
struct DosHdr {
    u16 magic;
    u8  pad[58];
    u32 lfanew;
};

struct CoffHdr {
    u16 machine;
    u16 num_sections;
    u32 timestamp;
    u32 sym_table;
    u32 num_symbols;
    u16 opt_size;
    u16 characteristics;
};

struct DataDir {
    u32 rva;
    u32 size;
};

struct OptHdr64 {
    u16 magic;
    u8  link_maj, link_min;
    u32 code_sz, idata_sz, udata_sz;
    u32 entry_rva, code_base;
    u64 image_base;
    u32 sect_align, file_align;
    u16 os_maj, os_min, img_maj, img_min, sub_maj, sub_min;
    u32 win32ver;
    u32 image_sz, hdr_sz, checksum;
    u16 subsys, dll_chars;
    u64 stack_res, stack_com, heap_res, heap_com;
    u32 loader_flags, num_dd;
    DataDir dd[16];
};

struct OptHdr32 {
    u16 magic;
    u8  link_maj, link_min;
    u32 code_sz, idata_sz, udata_sz;
    u32 entry_rva, code_base, data_base;
    u32 image_base;
    u32 sect_align, file_align;
    u16 os_maj, os_min, img_maj, img_min, sub_maj, sub_min;
    u32 win32ver;
    u32 image_sz, hdr_sz, checksum;
    u16 subsys, dll_chars;
    u32 stack_res, stack_com, heap_res, heap_com;
    u32 loader_flags, num_dd;
    DataDir dd[16];
};

struct SectHdr {
    char name[8];
    u32  vsize;
    u32  vrva;
    u32  raw_sz;
    u32  raw_ptr;
    u32  reloc_ptr;
    u32  line_ptr;
    u16  num_relocs;
    u16  num_lines;
    u32  chars;
};

struct ImpDesc {
    u32 orig_thunk;
    u32 timestamp;
    u32 forwarder;
    u32 name_rva;
    u32 thunk;
};

struct ExpDir {
    u32 chars, timestamp;
    u16 maj, min;
    u32 name_rva, ord_base;
    u32 num_funcs, num_names;
    u32 funcs_rva, names_rva, ords_rva;
};
#pragma pack(pop)

template<typename T>
const T* ptr_at(const u8* base, size_t off, size_t total) {
    if (off > total || total - off < sizeof(T)) return nullptr;
    return reinterpret_cast<const T*>(base + off);
}

bool safe_add(size_t a, size_t b, size_t& result) {
    result = a + b;
    return result >= a;
}

bool safe_add32(u32 a, u32 b, u32& result) {
    result = a + b;
    return result >= a;
}

std::string safe_string(const u8* base, size_t off, size_t total, size_t max_len = kMaxNameLen) {
    if (off >= total) return {};
    size_t avail = total - off;
    size_t limit = std::min(avail, max_len);
    auto* start = reinterpret_cast<const char*>(base + off);
    size_t len = strnlen(start, limit);
    return std::string(start, len);
}

u32 rva_to_raw(const PEImage& img, u32 rva) {
    for (auto& seg : img.segments) {
        u32 seg_rva = static_cast<u32>(seg.va - img.base);
        if (rva >= seg_rva && rva < seg_rva + seg.file_sz)
            return static_cast<u32>(seg.file_off + (rva - seg_rva));
    }
    return 0;
}

bool entry_in_section(const PEImage& img, va_t entry) {
    for (auto& seg : img.segments) {
        if (entry >= seg.va && entry < seg.va + seg.size)
            return true;
    }
    return false;
}

bool sections_overlap(const std::vector<Segment>& segs) {
    for (size_t i = 0; i < segs.size(); ++i) {
        for (size_t j = i + 1; j < segs.size(); ++j) {
            va_t a_start = segs[i].va, a_end = segs[i].va + segs[i].size;
            va_t b_start = segs[j].va, b_end = segs[j].va + segs[j].size;
            if (a_start < b_end && b_start < a_end) return true;
        }
    }
    return false;
}

} // anon

std::optional<PEImage> PELoader::load(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        spdlog::error("cannot open: {}", path.string());
        return std::nullopt;
    }

    auto file_sz = static_cast<size_t>(f.tellg());
    if (file_sz > kMaxFileSize) {
        spdlog::error("file too large: {} bytes (max {})", file_sz, kMaxFileSize);
        return std::nullopt;
    }
    if (file_sz < sizeof(DosHdr)) {
        spdlog::error("file too small for DOS header");
        return std::nullopt;
    }

    PEImage img;
    img.raw.resize(file_sz);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(img.raw.data()), static_cast<std::streamsize>(file_sz));

    base_ = img.raw.data();
    size_ = img.raw.size();

    if (!parse_headers(img)) return std::nullopt;
    if (!parse_sections(img)) return std::nullopt;

    if (!entry_in_section(img, img.entry) && img.entry != img.base) {
        spdlog::warn("entry point 0x{:X} not within any section", img.entry);
    }

    if (sections_overlap(img.segments)) {
        spdlog::warn("overlapping section RVAs detected");
    }

    parse_imports(img);
    parse_exports(img);
    parse_exceptions(img);

    spdlog::info("PE: {} segs, {} imports, {} exports, {} runtime_funcs",
                 img.segments.size(), img.imports.size(), img.exports.size(),
                 img.runtime_funcs.size());
    return img;
}

bool PELoader::parse_headers(PEImage& img) {
    auto dos = ptr_at<DosHdr>(base_, 0, size_);
    if (!dos || dos->magic != 0x5A4D) return false;

    u32 pe_off = dos->lfanew;
    size_t pe_sig_end;
    if (!safe_add(pe_off, 4, pe_sig_end) || pe_sig_end > size_) return false;
    if (std::memcmp(base_ + pe_off, "PE\0\0", 4) != 0) return false;

    size_t coff_off;
    if (!safe_add(pe_off, 4, coff_off)) return false;
    auto coff = ptr_at<CoffHdr>(base_, coff_off, size_);
    if (!coff) return false;

    if (coff->num_sections > kMaxSections) {
        spdlog::error("too many sections: {}", coff->num_sections);
        return false;
    }

    size_t opt_off;
    if (!safe_add(coff_off, sizeof(CoffHdr), opt_off)) return false;
    if (opt_off + 2 > size_) return false;

    u16 magic = 0;
    std::memcpy(&magic, base_ + opt_off, 2);

    if (magic == 0x20B) {
        img.arch = Arch::X64;
        auto opt = ptr_at<OptHdr64>(base_, opt_off, size_);
        if (!opt) return false;
        img.base = opt->image_base;
        img.entry = img.base + opt->entry_rva;

        if (opt->image_base % opt->sect_align != 0 && opt->sect_align != 0) {
            spdlog::warn("image_base 0x{:X} not aligned to section_alignment 0x{:X}",
                         opt->image_base, opt->sect_align);
        }
    } else if (magic == 0x10B) {
        img.arch = Arch::X86;
        auto opt = ptr_at<OptHdr32>(base_, opt_off, size_);
        if (!opt) return false;
        img.base = opt->image_base;
        img.entry = img.base + opt->entry_rva;

        if (opt->image_base % opt->sect_align != 0 && opt->sect_align != 0) {
            spdlog::warn("image_base 0x{:X} not aligned to section_alignment 0x{:X}",
                         opt->image_base, opt->sect_align);
        }
    } else {
        spdlog::error("unknown PE optional magic: 0x{:X}", magic);
        return false;
    }
    return true;
}

bool PELoader::parse_sections(PEImage& img) {
    auto dos = ptr_at<DosHdr>(base_, 0, size_);
    if (!dos) return false;
    u32 pe_off = dos->lfanew;

    size_t coff_off;
    if (!safe_add(pe_off, 4, coff_off)) return false;
    auto coff = ptr_at<CoffHdr>(base_, coff_off, size_);
    if (!coff) return false;

    size_t sec_off;
    if (!safe_add(coff_off, sizeof(CoffHdr) + coff->opt_size, sec_off)) return false;

    for (u16 i = 0; i < coff->num_sections; ++i) {
        size_t entry_off;
        if (!safe_add(sec_off, static_cast<size_t>(i) * sizeof(SectHdr), entry_off)) break;
        auto sh = ptr_at<SectHdr>(base_, entry_off, size_);
        if (!sh) break;

        Segment seg;
        seg.name.assign(sh->name, strnlen(sh->name, 8));
        seg.va = img.base + sh->vrva;
        seg.size = sh->vsize;
        seg.file_off = sh->raw_ptr;
        seg.file_sz = sh->raw_sz;
        seg.flags = sh->chars;

        size_t raw_end;
        if (safe_add(sh->raw_ptr, sh->raw_sz, raw_end) && raw_end <= size_) {
            seg.data.assign(base_ + sh->raw_ptr, base_ + sh->raw_ptr + sh->raw_sz);
            if (sh->vsize > sh->raw_sz)
                seg.data.resize(sh->vsize, 0);
        }
        img.segments.push_back(std::move(seg));
    }
    return true;
}

bool PELoader::parse_imports(PEImage& img) {
    auto dos = ptr_at<DosHdr>(base_, 0, size_);
    if (!dos) return false;
    u32 pe_off = dos->lfanew;

    size_t opt_off;
    if (!safe_add(static_cast<size_t>(pe_off) + 4, sizeof(CoffHdr), opt_off)) return false;
    if (opt_off + 2 > size_) return false;

    u16 magic = 0;
    std::memcpy(&magic, base_ + opt_off, 2);

    DataDir idir{};
    if (magic == 0x20B) {
        auto opt = ptr_at<OptHdr64>(base_, opt_off, size_);
        if (!opt || opt->num_dd < 2) return false;
        idir = opt->dd[1];
    } else {
        auto opt = ptr_at<OptHdr32>(base_, opt_off, size_);
        if (!opt || opt->num_dd < 2) return false;
        idir = opt->dd[1];
    }
    if (idir.rva == 0) return true;

    u32 off = rva_to_raw(img, idir.rva);
    if (!off) return false;
    bool x64 = (img.arch == Arch::X64);

    u32 desc_count = 0;
    for (;;) {
        if (desc_count >= kMaxImports) {
            spdlog::warn("import descriptor limit reached");
            break;
        }
        auto desc = ptr_at<ImpDesc>(base_, off, size_);
        if (!desc || (!desc->orig_thunk && !desc->thunk)) break;

        u32 nm_off = rva_to_raw(img, desc->name_rva);
        std::string dll = safe_string(base_, nm_off, size_);

        u32 thunk_rva = desc->orig_thunk ? desc->orig_thunk : desc->thunk;
        u32 iat_rva = desc->thunk;
        u32 t_off = rva_to_raw(img, thunk_rva);

        u32 ilt_count = 0;
        while (t_off && t_off < size_) {
            if (ilt_count >= kMaxILTEntries) {
                spdlog::warn("ILT iteration limit for {}", dll);
                break;
            }
            u64 entry = 0;
            if (x64) {
                if (t_off + 8 > size_) break;
                std::memcpy(&entry, base_ + t_off, 8);
                t_off += 8;
            } else {
                u32 e32 = 0;
                if (t_off + 4 > size_) break;
                std::memcpy(&e32, base_ + t_off, 4);
                entry = e32;
                t_off += 4;
            }
            if (!entry) break;

            Import imp;
            imp.dll = dll;
            imp.iat_addr = img.base + iat_rva;
            iat_rva += x64 ? 8 : 4;

            u64 ord_flag = x64 ? (1ULL << 63) : (1ULL << 31);
            if (entry & ord_flag) {
                imp.ordinal = static_cast<u16>(entry & 0xFFFF);
                imp.name = fmt::format("ord_{}", imp.ordinal);
            } else {
                u32 h_off = rva_to_raw(img, static_cast<u32>(entry));
                if (h_off && h_off + 2 < size_) {
                    std::memcpy(&imp.ordinal, base_ + h_off, 2);
                    imp.name = safe_string(base_, static_cast<size_t>(h_off) + 2, size_);
                }
            }
            img.imports.push_back(std::move(imp));
            ++ilt_count;
        }
        off += sizeof(ImpDesc);
        ++desc_count;
    }
    return true;
}

bool PELoader::parse_exports(PEImage& img) {
    auto dos = ptr_at<DosHdr>(base_, 0, size_);
    if (!dos) return false;
    u32 pe_off = dos->lfanew;

    size_t opt_off;
    if (!safe_add(static_cast<size_t>(pe_off) + 4, sizeof(CoffHdr), opt_off)) return false;
    if (opt_off + 2 > size_) return false;

    u16 magic = 0;
    std::memcpy(&magic, base_ + opt_off, 2);

    DataDir edir{};
    if (magic == 0x20B) {
        auto opt = ptr_at<OptHdr64>(base_, opt_off, size_);
        if (!opt || opt->num_dd < 1) return false;
        edir = opt->dd[0];
    } else {
        auto opt = ptr_at<OptHdr32>(base_, opt_off, size_);
        if (!opt || opt->num_dd < 1) return false;
        edir = opt->dd[0];
    }
    if (edir.rva == 0) return true;

    u32 off = rva_to_raw(img, edir.rva);
    if (!off) return false;

    auto dir = ptr_at<ExpDir>(base_, off, size_);
    if (!dir) return false;

    if (dir->num_funcs > kMaxExports || dir->num_names > kMaxExports) {
        spdlog::error("export table too large: {} funcs, {} names", dir->num_funcs, dir->num_names);
        return false;
    }
    if (dir->ord_base > 0xFFFF) {
        spdlog::warn("suspicious ordinal_base: {}", dir->ord_base);
    }

    u32 funcs_off = rva_to_raw(img, dir->funcs_rva);
    u32 names_off = rva_to_raw(img, dir->names_rva);
    u32 ords_off  = rva_to_raw(img, dir->ords_rva);

    for (u32 i = 0; i < dir->num_names && names_off && ords_off; ++i) {
        size_t name_entry_off = static_cast<size_t>(names_off) + static_cast<size_t>(i) * 4;
        size_t ord_entry_off  = static_cast<size_t>(ords_off) + static_cast<size_t>(i) * 2;
        if (name_entry_off + 4 > size_ || ord_entry_off + 2 > size_) break;

        u32 name_rva = 0;
        u16 ord_idx = 0;
        std::memcpy(&name_rva, base_ + name_entry_off, 4);
        std::memcpy(&ord_idx, base_ + ord_entry_off, 2);

        u32 func_rva = 0;
        if (funcs_off && ord_idx < dir->num_funcs) {
            size_t func_entry_off = static_cast<size_t>(funcs_off) + static_cast<size_t>(ord_idx) * 4;
            if (func_entry_off + 4 <= size_)
                std::memcpy(&func_rva, base_ + func_entry_off, 4);
        }

        Export exp;
        u32 n_off = rva_to_raw(img, name_rva);
        exp.name = safe_string(base_, n_off, size_);
        exp.ordinal = static_cast<u16>(ord_idx + dir->ord_base);
        exp.addr = img.base + func_rva;
        img.exports.push_back(std::move(exp));
    }
    return true;
}

void PELoader::parse_exceptions(PEImage& img) {
    if (img.arch != Arch::X64) return;

    auto dos = ptr_at<DosHdr>(base_, 0, size_);
    if (!dos) return;
    u32 pe_off = dos->lfanew;

    size_t opt_off;
    if (!safe_add(static_cast<size_t>(pe_off) + 4, sizeof(CoffHdr), opt_off)) return;
    auto opt = ptr_at<OptHdr64>(base_, opt_off, size_);
    if (!opt || opt->num_dd < 4) return;

    DataDir pdata = opt->dd[3];
    if (pdata.rva == 0 || pdata.size == 0) return;

    u32 raw_off = rva_to_raw(img, pdata.rva);
    if (!raw_off) return;

    struct RtFunc { u32 begin_rva; u32 end_rva; u32 unwind_rva; };
    u32 count = pdata.size / sizeof(RtFunc);

    for (u32 i = 0; i < count; ++i) {
        size_t entry_off;
        if (!safe_add(raw_off, static_cast<size_t>(i) * sizeof(RtFunc), entry_off)) break;
        auto rf = ptr_at<RtFunc>(base_, entry_off, size_);
        if (!rf || rf->begin_rva == 0) break;
        img.runtime_funcs.push_back({img.base + rf->begin_rva, img.base + rf->end_rva});
    }
}

}

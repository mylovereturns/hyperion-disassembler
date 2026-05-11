#include "macho_loader.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <fstream>
#include <cstring>

namespace hype {

namespace {

constexpr u32 MH_MAGIC_32    = 0xFEEDFACE;
constexpr u32 MH_MAGIC_64    = 0xFEEDFACF;
constexpr u32 MH_CIGAM_32    = 0xCEFAEDFE;
constexpr u32 MH_CIGAM_64    = 0xCFFAEDFE;
constexpr u32 FAT_MAGIC      = 0xBEBAFECA;
constexpr u32 FAT_CIGAM      = 0xCAFEBABE;

constexpr u32 CPU_TYPE_X86     = 0x00000007;
constexpr u32 CPU_TYPE_X86_64  = 0x01000007;
constexpr u32 CPU_TYPE_ARM     = 0x0000000C;
constexpr u32 CPU_TYPE_ARM64   = 0x0100000C;

constexpr u32 LC_SEGMENT       = 0x01;
constexpr u32 LC_SYMTAB        = 0x02;
constexpr u32 LC_SEGMENT_64    = 0x19;
constexpr u32 LC_MAIN          = 0x80000028;
constexpr u32 LC_UNIXTHREAD    = 0x05;

constexpr u32 VM_PROT_READ    = 1;
constexpr u32 VM_PROT_WRITE   = 2;
constexpr u32 VM_PROT_EXECUTE = 4;

constexpr u8 N_EXT  = 0x01;
constexpr u8 N_TYPE = 0x0E;
constexpr u8 N_SECT = 0x0E;

#pragma pack(push, 1)
struct MachHeader32 {
    u32 magic;
    u32 cputype;
    u32 cpusubtype;
    u32 filetype;
    u32 ncmds;
    u32 sizeofcmds;
    u32 flags;
};

struct MachHeader64 {
    u32 magic;
    u32 cputype;
    u32 cpusubtype;
    u32 filetype;
    u32 ncmds;
    u32 sizeofcmds;
    u32 flags;
    u32 reserved;
};

struct LoadCmd {
    u32 cmd;
    u32 cmdsize;
};

struct SegmentCmd32 {
    u32  cmd;
    u32  cmdsize;
    char segname[16];
    u32  vmaddr;
    u32  vmsize;
    u32  fileoff;
    u32  filesize;
    u32  maxprot;
    u32  initprot;
    u32  nsects;
    u32  flags;
};

struct SegmentCmd64 {
    u32  cmd;
    u32  cmdsize;
    char segname[16];
    u64  vmaddr;
    u64  vmsize;
    u64  fileoff;
    u64  filesize;
    u32  maxprot;
    u32  initprot;
    u32  nsects;
    u32  flags;
};

struct Section32 {
    char sectname[16];
    char segname[16];
    u32  addr;
    u32  size;
    u32  offset;
    u32  align;
    u32  reloff;
    u32  nreloc;
    u32  flags;
    u32  reserved1;
    u32  reserved2;
};

struct Section64 {
    char sectname[16];
    char segname[16];
    u64  addr;
    u64  size;
    u32  offset;
    u32  align;
    u32  reloff;
    u32  nreloc;
    u32  flags;
    u32  reserved1;
    u32  reserved2;
    u32  reserved3;
};

struct SymtabCmd {
    u32 cmd;
    u32 cmdsize;
    u32 symoff;
    u32 nsyms;
    u32 stroff;
    u32 strsize;
};

struct Nlist32 {
    u32 n_strx;
    u8  n_type;
    u8  n_sect;
    i16 n_desc;
    u32 n_value;
};

struct Nlist64 {
    u32 n_strx;
    u8  n_type;
    u8  n_sect;
    u16 n_desc;
    u64 n_value;
};

struct EntryPointCmd {
    u32 cmd;
    u32 cmdsize;
    u64 entryoff;
    u64 stacksize;
};

struct FatHeader {
    u32 magic;
    u32 nfat_arch;
};

struct FatArch {
    u32 cputype;
    u32 cpusubtype;
    u32 offset;
    u32 size;
    u32 align;
};
#pragma pack(pop)

u32 macho_to_pe_flags(u32 prot) {
    u32 f = 0;
    if (prot & VM_PROT_READ)    f |= 0x40000000;
    if (prot & VM_PROT_WRITE)   f |= 0x80000000;
    if (prot & VM_PROT_EXECUTE) f |= 0x20000000;
    return f;
}

u32 bswap32(u32 v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
}

std::string seg_sect_name(const char* seg, const char* sect) {
    std::string s(seg, strnlen(seg, 16));
    std::string n(sect, strnlen(sect, 16));
    if (n.empty()) return s;
    return s + "." + n;
}

} // anon

std::optional<PEImage> MachOLoader::load(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return std::nullopt;

    size_t sz = static_cast<size_t>(f.tellg());
    if (sz < sizeof(MachHeader32)) return std::nullopt;
    f.seekg(0);

    PEImage img;
    img.raw.resize(sz);
    f.read(reinterpret_cast<char*>(img.raw.data()), static_cast<std::streamsize>(sz));

    base_ = img.raw.data();
    size_ = sz;

    u32 magic = 0;
    std::memcpy(&magic, base_, 4);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        bool cigam = (magic == FAT_CIGAM);
        if (size_ < sizeof(FatHeader)) return std::nullopt;
        auto* fh = reinterpret_cast<const FatHeader*>(base_);
        u32 narch = cigam ? bswap32(fh->nfat_arch) : fh->nfat_arch;

        size_t offset = sizeof(FatHeader);
        u32 chosen_off = 0, chosen_sz = 0;
        for (u32 i = 0; i < narch; ++i) {
            if (offset + sizeof(FatArch) > size_) break;
            auto* fa = reinterpret_cast<const FatArch*>(base_ + offset);
            u32 cpu = cigam ? bswap32(fa->cputype) : fa->cputype;
            u32 fo  = cigam ? bswap32(fa->offset) : fa->offset;
            u32 fs  = cigam ? bswap32(fa->size) : fa->size;

            if (cpu == CPU_TYPE_X86_64 || cpu == CPU_TYPE_ARM64) {
                chosen_off = fo;
                chosen_sz = fs;
                if (cpu == CPU_TYPE_ARM64) break;
            } else if ((cpu == CPU_TYPE_X86 || cpu == CPU_TYPE_ARM) && !chosen_sz) {
                chosen_off = fo;
                chosen_sz = fs;
            }
            offset += sizeof(FatArch);
        }

        if (!chosen_sz || chosen_off + chosen_sz > size_) {
            spdlog::error("macho: no suitable arch in fat binary");
            return std::nullopt;
        }

        base_ = img.raw.data() + chosen_off;
        size_ = chosen_sz;
    }

    if (!parse_header(img)) return std::nullopt;
    if (!parse_load_commands(img)) return std::nullopt;

    if (img.entry == 0 && !img.segments.empty())
        img.entry = img.segments[0].va;

    spdlog::info("macho: loaded {} - base=0x{:X} entry=0x{:X} segs={} imports={} exports={}",
                 path.filename().string(), img.base, img.entry,
                 img.segments.size(), img.imports.size(), img.exports.size());
    return img;
}

bool MachOLoader::parse_header(PEImage& img) {
    if (size_ < sizeof(MachHeader32)) return false;

    u32 magic = 0;
    std::memcpy(&magic, base_, 4);

    swap_ = (magic == MH_CIGAM_64 || magic == MH_CIGAM_32);

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64_ = true;
        header_size_ = sizeof(MachHeader64);
        if (size_ < header_size_) return false;
        auto* hdr = reinterpret_cast<const MachHeader64*>(base_);
        ncmds_ = hdr->ncmds;
        sizeofcmds_ = hdr->sizeofcmds;

        u32 cpu = hdr->cputype;
        if (cpu == CPU_TYPE_X86_64) {
            img.arch = Arch::X64;
        } else if (cpu == CPU_TYPE_X86) {
            img.arch = Arch::X86;
        } else if (cpu == CPU_TYPE_ARM64) {
            img.arch = Arch::ARM64;
        } else if (cpu == CPU_TYPE_ARM) {
            img.arch = Arch::ARM;
        } else {
            spdlog::error("macho: unsupported cputype 0x{:08X}", cpu);
            return false;
        }
    } else if (magic == MH_MAGIC_32 || magic == MH_CIGAM_32) {
        is64_ = false;
        header_size_ = sizeof(MachHeader32);
        if (size_ < header_size_) return false;
        auto* hdr = reinterpret_cast<const MachHeader32*>(base_);
        ncmds_ = hdr->ncmds;
        sizeofcmds_ = hdr->sizeofcmds;

        u32 cpu = hdr->cputype;
        if (cpu == CPU_TYPE_X86) {
            img.arch = Arch::X86;
        } else if (cpu == CPU_TYPE_X86_64) {
            img.arch = Arch::X64;
        } else if (cpu == CPU_TYPE_ARM64) {
            img.arch = Arch::ARM64;
        } else if (cpu == CPU_TYPE_ARM) {
            img.arch = Arch::ARM;
        } else {
            spdlog::error("macho: unsupported cputype 0x{:08X}", cpu);
            return false;
        }
    } else {
        spdlog::error("macho: bad magic 0x{:08X}", magic);
        return false;
    }
    return true;
}

bool MachOLoader::parse_load_commands(PEImage& img) {
    size_t off = header_size_;
    va_t entry = 0;
    base_addr_ = ~va_t(0);

    for (u32 i = 0; i < ncmds_; ++i) {
        if (off + sizeof(LoadCmd) > size_) break;
        auto* lc = reinterpret_cast<const LoadCmd*>(base_ + off);
        if (lc->cmdsize < sizeof(LoadCmd) || off + lc->cmdsize > size_) break;

        switch (lc->cmd) {
        case LC_SEGMENT_64:
        case LC_SEGMENT:
            parse_segment(img, base_ + off);
            break;
        case LC_SYMTAB:
            parse_symtab(img, base_ + off);
            break;
        case LC_MAIN: {
            if (lc->cmdsize >= sizeof(EntryPointCmd)) {
                auto* ep = reinterpret_cast<const EntryPointCmd*>(base_ + off);
                entry = ep->entryoff;
            }
            break;
        }
        case LC_UNIXTHREAD: {
            if (is64_ && lc->cmdsize >= 16 + 8 * 17) {
                u64 rip = 0;
                std::memcpy(&rip, base_ + off + 16 + 8 * 16, 8);
                entry = rip;
            } else if (!is64_ && lc->cmdsize >= 16 + 4 * 11) {
                u32 eip = 0;
                std::memcpy(&eip, base_ + off + 16 + 4 * 10, 4);
                entry = eip;
            }
            break;
        }
        default:
            break;
        }
        off += lc->cmdsize;
    }

    if (base_addr_ == ~va_t(0)) base_addr_ = 0;
    img.base = base_addr_;

    if (entry && entry < base_addr_) {
        for (auto& seg : img.segments) {
            if (seg.name.find("__TEXT") != std::string::npos) {
                img.entry = seg.va + entry;
                break;
            }
        }
        if (img.entry == 0) img.entry = base_addr_ + entry;
    } else if (entry) {
        img.entry = entry;
    }

    return !img.segments.empty();
}

bool MachOLoader::parse_segment(PEImage& img, const u8* cmd) {
    if (is64_) {
        auto* sc = reinterpret_cast<const SegmentCmd64*>(cmd);
        if (sc->vmsize == 0 && sc->filesize == 0) return true;

        if (sc->vmaddr < base_addr_) base_addr_ = sc->vmaddr;

        if (sc->nsects == 0) {
            Segment seg;
            seg.name = std::string(sc->segname, strnlen(sc->segname, 16));
            seg.va = sc->vmaddr;
            seg.size = sc->vmsize;
            seg.file_off = sc->fileoff;
            seg.file_sz = sc->filesize;
            seg.flags = macho_to_pe_flags(sc->initprot);
            if (sc->fileoff + sc->filesize <= size_) {
                seg.data.assign(base_ + sc->fileoff, base_ + sc->fileoff + sc->filesize);
                if (sc->vmsize > sc->filesize)
                    seg.data.resize(static_cast<size_t>(sc->vmsize), 0);
            }
            img.segments.push_back(std::move(seg));
        } else {
            const u8* sect_ptr = cmd + sizeof(SegmentCmd64);
            for (u32 s = 0; s < sc->nsects; ++s) {
                size_t sect_off = static_cast<size_t>(sect_ptr - base_) + s * sizeof(Section64);
                if (sect_off + sizeof(Section64) > size_) break;
                auto* sec = reinterpret_cast<const Section64*>(base_ + sect_off);

                Segment seg;
                seg.name = seg_sect_name(sec->segname, sec->sectname);
                seg.va = sec->addr;
                seg.size = sec->size;
                seg.file_off = sec->offset;
                seg.file_sz = sec->size;
                seg.flags = macho_to_pe_flags(sc->initprot);
                if (sec->offset + sec->size <= size_) {
                    seg.data.assign(base_ + sec->offset, base_ + sec->offset + sec->size);
                }
                img.segments.push_back(std::move(seg));
            }
        }
    } else {
        auto* sc = reinterpret_cast<const SegmentCmd32*>(cmd);
        if (sc->vmsize == 0 && sc->filesize == 0) return true;

        if (sc->vmaddr < base_addr_) base_addr_ = sc->vmaddr;

        if (sc->nsects == 0) {
            Segment seg;
            seg.name = std::string(sc->segname, strnlen(sc->segname, 16));
            seg.va = sc->vmaddr;
            seg.size = sc->vmsize;
            seg.file_off = sc->fileoff;
            seg.file_sz = sc->filesize;
            seg.flags = macho_to_pe_flags(sc->initprot);
            if (sc->fileoff + sc->filesize <= size_) {
                seg.data.assign(base_ + sc->fileoff, base_ + sc->fileoff + sc->filesize);
                if (sc->vmsize > sc->filesize)
                    seg.data.resize(static_cast<size_t>(sc->vmsize), 0);
            }
            img.segments.push_back(std::move(seg));
        } else {
            const u8* sect_ptr = cmd + sizeof(SegmentCmd32);
            for (u32 s = 0; s < sc->nsects; ++s) {
                size_t sect_off = static_cast<size_t>(sect_ptr - base_) + s * sizeof(Section32);
                if (sect_off + sizeof(Section32) > size_) break;
                auto* sec = reinterpret_cast<const Section32*>(base_ + sect_off);

                Segment seg;
                seg.name = seg_sect_name(sec->segname, sec->sectname);
                seg.va = sec->addr;
                seg.size = sec->size;
                seg.file_off = sec->offset;
                seg.file_sz = sec->size;
                seg.flags = macho_to_pe_flags(sc->initprot);
                if (sec->offset + sec->size <= size_) {
                    seg.data.assign(base_ + sec->offset, base_ + sec->offset + sec->size);
                }
                img.segments.push_back(std::move(seg));
            }
        }
    }
    return true;
}

bool MachOLoader::parse_symtab(PEImage& img, const u8* cmd) {
    auto* sc = reinterpret_cast<const SymtabCmd*>(cmd);
    if (sc->nsyms == 0 || sc->strsize == 0) return true;
    if (sc->symoff >= size_ || sc->stroff >= size_) return false;
    if (sc->stroff + sc->strsize > size_) return false;

    const char* strtab = reinterpret_cast<const char*>(base_ + sc->stroff);
    u32 strsz = sc->strsize;

    if (is64_) {
        size_t sym_end = static_cast<size_t>(sc->symoff) + static_cast<size_t>(sc->nsyms) * sizeof(Nlist64);
        if (sym_end > size_) return false;

        for (u32 i = 0; i < sc->nsyms; ++i) {
            auto* nl = reinterpret_cast<const Nlist64*>(base_ + sc->symoff + i * sizeof(Nlist64));
            if ((nl->n_type & N_TYPE) != N_SECT) continue;
            if (nl->n_value == 0) continue;
            if (nl->n_strx >= strsz) continue;

            const char* name = strtab + nl->n_strx;
            if (!name[0]) continue;

            if (nl->n_type & N_EXT) {
                Export exp;
                exp.name = (name[0] == '_') ? name + 1 : name;
                exp.ordinal = 0;
                exp.addr = nl->n_value;
                img.exports.push_back(std::move(exp));
            }
        }
    } else {
        size_t sym_end = static_cast<size_t>(sc->symoff) + static_cast<size_t>(sc->nsyms) * sizeof(Nlist32);
        if (sym_end > size_) return false;

        for (u32 i = 0; i < sc->nsyms; ++i) {
            auto* nl = reinterpret_cast<const Nlist32*>(base_ + sc->symoff + i * sizeof(Nlist32));
            if ((nl->n_type & N_TYPE) != N_SECT) continue;
            if (nl->n_value == 0) continue;
            if (nl->n_strx >= strsz) continue;

            const char* name = strtab + nl->n_strx;
            if (!name[0]) continue;

            if (nl->n_type & N_EXT) {
                Export exp;
                exp.name = (name[0] == '_') ? name + 1 : name;
                exp.ordinal = 0;
                exp.addr = nl->n_value;
                img.exports.push_back(std::move(exp));
            }
        }
    }
    return true;
}

bool MachOLoader::parse_dysymtab(PEImage& img, const u8* cmd) {
    (void)img;
    (void)cmd;
    return true;
}

va_t MachOLoader::find_entry() {
    return 0;
}

}

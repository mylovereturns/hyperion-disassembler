#pragma once
#include "core/types.h"
#include "pe_loader.h"
#include <filesystem>
#include <optional>

namespace hype {

class MachOLoader {
public:
    std::optional<PEImage> load(const std::filesystem::path& path);

private:
    bool parse_header(PEImage& img);
    bool parse_load_commands(PEImage& img);
    bool parse_segment(PEImage& img, const u8* cmd);
    bool parse_symtab(PEImage& img, const u8* cmd);
    bool parse_dysymtab(PEImage& img, const u8* cmd);
    va_t find_entry();

    const u8* base_ = nullptr;
    size_t size_ = 0;
    bool is64_ = true;
    bool swap_ = false;
    u32 ncmds_ = 0;
    u32 sizeofcmds_ = 0;
    u32 header_size_ = 0;
    va_t base_addr_ = 0;
};

}

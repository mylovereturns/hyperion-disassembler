#pragma once
#include "core/types.h"
#include "pe_loader.h"
#include <filesystem>
#include <optional>

namespace hype {

class ELFLoader {
public:
    std::optional<PEImage> load(const std::filesystem::path& path);

private:
    bool parse_header(PEImage& img);
    bool parse_segments(PEImage& img);
    bool parse_sections(PEImage& img);
    bool parse_symbols(PEImage& img);
    bool parse_dynamic(PEImage& img);

    const u8* base_ = nullptr;
    size_t size_ = 0;
    bool is64_ = false;
    bool le_ = true;
};

}

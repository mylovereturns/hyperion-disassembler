#pragma once
#include "core/types.h"
#include "core/loader/pe_loader.h"
#include "core/analysis/analysis_db.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace hype {

struct ILInsn {
    u32         offset;
    u16         opcode;
    std::string mnemonic;
    std::string operand_str;
    u8          len;
};

struct DotNetMethod {
    u32         token;
    std::string name;
    std::string full_name;
    va_t        rva;
    u16         max_stack;
    u32         code_size;
    std::vector<ILInsn> il;
};

struct DotNetType {
    u32         token;
    std::string ns;
    std::string name;
    std::vector<u32> method_tokens;
};

struct DotNetImage {
    std::vector<DotNetType>   types;
    std::vector<DotNetMethod> methods;
    std::unordered_map<u32, std::string> strings;
    std::unordered_map<u32, std::string> member_refs;
    bool valid = false;
};

class DotNetLoader {
public:
    bool detect(const PEImage& img);
    bool load(const PEImage& img);
    void populate_db(AnalysisDB& db, const PEImage& img);

    const DotNetImage& image() const { return dn_; }

private:
    struct MetaStreams {
        const u8* tables = nullptr;  size_t tables_sz = 0;
        const u8* strings = nullptr; size_t strings_sz = 0;
        const u8* us = nullptr;      size_t us_sz = 0;
        const u8* blob = nullptr;    size_t blob_sz = 0;
        const u8* guid = nullptr;    size_t guid_sz = 0;
    };

    bool parse_cli_header(const PEImage& img);
    bool parse_metadata(const PEImage& img);
    bool parse_streams(const u8* meta_root, size_t meta_sz);
    bool parse_tables();
    void parse_method_bodies(const PEImage& img);
    std::vector<ILInsn> decode_il(const u8* code, u32 size);
    std::string resolve_token(u32 token);
    std::string read_meta_string(u32 offset);
    std::string read_us_string(u32 offset);

    const u8* rva_to_ptr(const PEImage& img, u32 rva, size_t* avail = nullptr);

    DotNetImage dn_;
    MetaStreams streams_{};
    u32 cli_rva_ = 0;
    u32 cli_size_ = 0;
    u32 meta_rva_ = 0;
    u32 meta_size_ = 0;

    u8 str_idx_size_ = 2;
    u8 guid_idx_size_ = 2;
    u8 blob_idx_size_ = 2;

    struct TableInfo { u32 rows; const u8* data; };
    TableInfo tables_[64]{};
};

}

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <span>

namespace hype {

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using va_t = u64;
constexpr va_t INVALID_VA = ~va_t(0);

enum class Arch : u8 { X86, X64, ARM, ARM64, MIPS, PPC };

struct Segment {
    std::string name;
    va_t        va;
    u64         size;
    u64         file_off;
    u64         file_sz;
    u32         flags;
    std::vector<u8> data;

    bool executable() const { return flags & 0x20000000; }
    bool writable()   const { return flags & 0x80000000; }
    bool readable()   const { return flags & 0x40000000; }
    bool contains(va_t addr) const { return addr >= va && addr < va + size; }
};

struct Import {
    std::string dll;
    std::string name;
    u16         ordinal;
    va_t        iat_addr;
};

struct Export {
    std::string name;
    u16         ordinal;
    va_t        addr;
};

}

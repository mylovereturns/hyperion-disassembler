#pragma once
#include "core/types.h"
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <algorithm>

namespace hype {

enum class InsnType : u8 {
    Unknown, Nop, Mov, Push, Pop,
    Call, Ret, Jmp, Jcc,
    Cmp, Test,
    Add, Sub, Mul, Div,
    And, Or, Xor, Not, Shl, Shr,
    Lea, Int, Syscall, Other
};

enum class OpType : u8 { None, Reg, Imm, Mem };

#pragma pack(push, 1)
struct Operand {
    OpType type = OpType::None;
    u8     scale = 0;
    u16    reg  = 0;
    u16    size = 0;
    u16    mem_base = 0;
    u16    mem_index = 0;
    i32    mem_disp = 0;
    u64    val  = 0;
};
#pragma pack(pop)
static_assert(sizeof(Operand) == 22, "Operand should be 22 bytes packed");

struct Insn {
    va_t        addr;
    u64         branch_target_cache;
    Operand     ops[3];
    char        op_str[40];
    char        mnemonic[8];
    u8          bytes[4];
    u16         mnemonic_id;
    InsnType    type;
    u8          len;
    u8          op_count;
    u8          _pad[3]{};

    void set_mnemonic(const char* s) {
        std::strncpy(mnemonic, s, sizeof(mnemonic) - 1);
        mnemonic[sizeof(mnemonic) - 1] = '\0';
    }
    void set_mnemonic(const std::string& s) { set_mnemonic(s.c_str()); }

    void set_op_str(const char* s) {
        std::strncpy(op_str, s, sizeof(op_str) - 1);
        op_str[sizeof(op_str) - 1] = '\0';
    }
    void set_op_str(const std::string& s) { set_op_str(s.c_str()); }

    bool is_branch()   const { return type == InsnType::Jmp || type == InsnType::Jcc; }
    bool is_call()     const { return type == InsnType::Call; }
    bool is_ret()      const { return type == InsnType::Ret; }
    bool is_cond_jmp() const { return type == InsnType::Jcc; }

    va_t branch_target() const {
        return branch_target_cache;
    }

    void update_branch_target() {
        if (op_count > 0 && ops[0].type == OpType::Imm)
            branch_target_cache = ops[0].val;
        else
            branch_target_cache = 0;
    }
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    void set_arch(Arch arch);
    bool decode(va_t addr, const u8* data, size_t len, Insn& out);
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class InsnStore {
public:
    using iterator = std::vector<Insn>::iterator;
    using const_iterator = std::vector<Insn>::const_iterator;

    void reserve(size_t n) { data_.reserve(n); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    void insert(const Insn& insn) {
        data_.push_back(insn);
        if (data_.size() > 1 && data_[data_.size()-2].addr >= insn.addr)
            sorted_ = false;
    }
    void insert(Insn&& insn) {
        va_t a = insn.addr;
        data_.push_back(std::move(insn));
        if (data_.size() > 1 && data_[data_.size()-2].addr >= a)
            sorted_ = false;
    }

    void merge_sorted_range(std::vector<Insn>&& chunk) {
        if (chunk.empty()) return;
        if (data_.empty()) {
            data_ = std::move(chunk);
            sorted_ = true;
            return;
        }
        ensure_sorted();
        std::vector<Insn> merged;
        merged.reserve(data_.size() + chunk.size());
        std::merge(data_.begin(), data_.end(), chunk.begin(), chunk.end(), std::back_inserter(merged),
            [](const Insn& a, const Insn& b) { return a.addr < b.addr; });
        data_ = std::move(merged);
        sorted_ = true;
    }

    Insn& operator[](va_t addr) {
        ensure_sorted();
        auto it = lower(addr);
        if (it != data_.end() && it->addr == addr)
            return *it;
        sorted_ = false;
        data_.push_back(Insn{});
        data_.back().addr = addr;
        return data_.back();
    }

    void finalize() { ensure_sorted(); }

    iterator find(va_t addr) {
        ensure_sorted();
        auto it = lower(addr);
        if (it != data_.end() && it->addr == addr) return it;
        return data_.end();
    }
    const_iterator find(va_t addr) const {
        ensure_sorted();
        auto it = lower(addr);
        if (it != data_.end() && it->addr == addr) return it;
        return data_.end();
    }

    size_t count(va_t addr) const {
        ensure_sorted();
        auto it = lower(addr);
        return (it != data_.end() && it->addr == addr) ? 1 : 0;
    }

    void erase(va_t addr) {
        ensure_sorted();
        auto it = lower(addr);
        if (it != data_.end() && it->addr == addr)
            data_.erase(it);
    }

    void clear() { data_.clear(); sorted_ = true; }

    iterator begin() { ensure_sorted(); return data_.begin(); }
    iterator end() { return data_.end(); }
    const_iterator begin() const { ensure_sorted(); return data_.begin(); }
    const_iterator end() const { return data_.end(); }

    std::vector<Insn>& raw() { return data_; }
    const std::vector<Insn>& raw() const { return data_; }

    InsnStore& operator=(InsnStore&& o) noexcept {
        data_ = std::move(o.data_);
        sorted_ = o.sorted_;
        return *this;
    }
    InsnStore(InsnStore&& o) noexcept : data_(std::move(o.data_)), sorted_(o.sorted_) {}
    InsnStore() = default;
    InsnStore(const InsnStore&) = default;
    InsnStore& operator=(const InsnStore&) = default;

    const_iterator range_begin(va_t start) const {
        ensure_sorted();
        return lower(start);
    }
    const_iterator range_end(va_t end) const {
        ensure_sorted();
        return std::lower_bound(data_.begin(), data_.end(), end,
            [](const Insn& a, va_t v) { return a.addr < v; });
    }

private:
    void ensure_sorted() const {
        if (!sorted_) {
            auto& v = const_cast<std::vector<Insn>&>(data_);
            std::sort(v.begin(), v.end(),
                [](const Insn& a, const Insn& b) { return a.addr < b.addr; });
            auto last = std::unique(v.begin(), v.end(),
                [](const Insn& a, const Insn& b) { return a.addr == b.addr; });
            v.erase(last, v.end());
            const_cast<bool&>(sorted_) = true;
        }
    }
    iterator lower(va_t addr) {
        return std::lower_bound(data_.begin(), data_.end(), addr,
            [](const Insn& a, va_t v) { return a.addr < v; });
    }
    const_iterator lower(va_t addr) const {
        return std::lower_bound(data_.begin(), data_.end(), addr,
            [](const Insn& a, va_t v) { return a.addr < v; });
    }

    std::vector<Insn> data_;
    bool sorted_ = true;
};

}

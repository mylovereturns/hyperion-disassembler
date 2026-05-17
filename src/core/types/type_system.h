#pragma once
#include "core/types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <fmt/format.h>

namespace hype {

enum class TypeKind : u8 {
    Void, Int, UInt, Float, Pointer, Array, Struct, Enum, Typedef
};

struct TypeField {
    std::string name;
    u32         type_id;
    u32         offset;
    u32         size;
    std::string comment;
};

struct EnumMember {
    std::string name;
    i64         value;
};

struct TypeDef {
    u32                     id;
    TypeKind                kind;
    std::string             name;
    u32                     size;
    std::vector<TypeField>  fields;
    std::vector<EnumMember> members;
    u32                     pointee_id = 0;
    u32                     array_elem_id = 0;
    u32                     array_count = 0;
};

class TypeSystem {
public:
    TypeSystem() { init_builtins(); }

    u32 add_struct(const std::string& name, u32 size) {
        u32 id = next_id_++;
        TypeDef td{id, TypeKind::Struct, name, size, {}, {}, 0, 0, 0};
        types_[id] = std::move(td);
        return id;
    }

    u32 add_enum(const std::string& name) {
        u32 id = next_id_++;
        TypeDef td{id, TypeKind::Enum, name, 4, {}, {}, 0, 0, 0};
        types_[id] = std::move(td);
        return id;
    }

    u32 add_typedef(const std::string& name, u32 target_id) {
        u32 id = next_id_++;
        auto* target = get(target_id);
        u32 sz = target ? target->size : 0;
        TypeDef td{id, TypeKind::Typedef, name, sz, {}, {}, target_id, 0, 0};
        types_[id] = std::move(td);
        return id;
    }

    void add_field(u32 struct_id, const std::string& name, u32 type_id, u32 offset) {
        auto it = types_.find(struct_id);
        if (it == types_.end()) return;
        auto* ft = get(type_id);
        u32 sz = ft ? ft->size : 0;
        it->second.fields.push_back({name, type_id, offset, sz, {}});
    }

    void add_member(u32 enum_id, const std::string& name, i64 value) {
        auto it = types_.find(enum_id);
        if (it == types_.end()) return;
        it->second.members.push_back({name, value});
    }

    TypeDef* get(u32 id) {
        auto it = types_.find(id);
        return it != types_.end() ? &it->second : nullptr;
    }

    const TypeDef* get(u32 id) const {
        auto it = types_.find(id);
        return it != types_.end() ? &it->second : nullptr;
    }

    TypeDef* find_by_name(const std::string& name) {
        for (auto& [_, td] : types_)
            if (td.name == name) return &td;
        return nullptr;
    }

    const TypeDef* find_by_name(const std::string& name) const {
        for (auto& [_, td] : types_)
            if (td.name == name) return &td;
        return nullptr;
    }

    std::string format_at(va_t addr, u32 type_id, const u8* data, size_t len) const {
        auto* td = get(type_id);
        if (!td) return "<?>";
        if (td->kind == TypeKind::Struct) return format_struct(addr, *td, data, len);
        if (td->kind == TypeKind::Enum) return format_enum(*td, data, len);
        return format_primitive(*td, data, len);
    }

    const std::unordered_map<u32, TypeDef>& all() const { return types_; }
    u32 next_id() const { return next_id_; }

    void remove(u32 id) { types_.erase(id); }

private:
    void init_builtins() {
        auto add = [&](TypeKind k, const char* n, u32 sz) {
            u32 id = next_id_++;
            types_[id] = {id, k, n, sz, {}, {}, 0, 0, 0};
        };
        add(TypeKind::Void,  "void",    0);
        add(TypeKind::UInt,  "u8",      1);
        add(TypeKind::UInt,  "u16",     2);
        add(TypeKind::UInt,  "u32",     4);
        add(TypeKind::UInt,  "u64",     8);
        add(TypeKind::Int,   "i8",      1);
        add(TypeKind::Int,   "i16",     2);
        add(TypeKind::Int,   "i32",     4);
        add(TypeKind::Int,   "i64",     8);
        add(TypeKind::Float, "float",   4);
        add(TypeKind::Float, "double",  8);
        add(TypeKind::UInt,  "char",    1);
        add(TypeKind::UInt,  "wchar_t", 2);
        add(TypeKind::UInt,  "ptr32",   4);
        add(TypeKind::UInt,  "ptr64",   8);
    }

    std::string format_struct(va_t addr, const TypeDef& td, const u8* data, size_t len) const {
        std::string out = fmt::format("{} @ {:X} {{\n", td.name, addr);
        for (auto& f : td.fields) {
            if (f.offset >= len) break;
            out += fmt::format("  +{:04X} {} = ", f.offset, f.name);
            auto* ft = get(f.type_id);
            size_t remain = len - f.offset;
            if (ft && remain > 0)
                out += format_primitive(*ft, data + f.offset, remain);
            else
                out += "?";
            out += "\n";
        }
        out += "}";
        return out;
    }

    std::string format_enum(const TypeDef& td, const u8* data, size_t len) const {
        if (len < 4) return "?";
        i32 raw; std::memcpy(&raw, data, 4);
        i64 val = raw;
        for (auto& m : td.members)
            if (m.value == val) return fmt::format("{}::{} ({})", td.name, m.name, val);
        return fmt::format("{}({})", td.name, val);
    }

    std::string format_primitive(const TypeDef& td, const u8* data, size_t len) const {
        if (td.size == 0 || td.size > len) return "?";
        switch (td.kind) {
        case TypeKind::UInt:
            if (td.size == 1) return fmt::format("0x{:02X}", data[0]);
            if (td.size == 2) { u16 v; std::memcpy(&v, data, 2); return fmt::format("0x{:04X}", v); }
            if (td.size == 4) { u32 v; std::memcpy(&v, data, 4); return fmt::format("0x{:08X}", v); }
            if (td.size == 8) { u64 v; std::memcpy(&v, data, 8); return fmt::format("0x{:016X}", v); }
            break;
        case TypeKind::Int:
            if (td.size == 1) return fmt::format("{}", static_cast<i8>(data[0]));
            if (td.size == 2) { i16 v; std::memcpy(&v, data, 2); return fmt::format("{}", v); }
            if (td.size == 4) { i32 v; std::memcpy(&v, data, 4); return fmt::format("{}", v); }
            if (td.size == 8) { i64 v; std::memcpy(&v, data, 8); return fmt::format("{}", v); }
            break;
        case TypeKind::Float:
            if (td.size == 4) { float v; std::memcpy(&v, data, 4); return fmt::format("{:.6g}", v); }
            if (td.size == 8) { double v; std::memcpy(&v, data, 8); return fmt::format("{:.12g}", v); }
            break;
        default: break;
        }
        u64 v = 0;
        std::memcpy(&v, data, std::min<size_t>(td.size, sizeof(v)));
        return fmt::format("0x{:X}", v);
    }

    std::unordered_map<u32, TypeDef> types_;
    u32 next_id_ = 1;
};

}

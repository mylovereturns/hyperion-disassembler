#include "type_infer.h"
#include <fmt/format.h>

namespace hype {

int DecompType::bit_width() const {
    switch (kind) {
    case DTypeKind::Bool: case DTypeKind::Int8: case DTypeKind::UInt8: case DTypeKind::Char: return 8;
    case DTypeKind::Int16: case DTypeKind::UInt16: case DTypeKind::WChar: return 16;
    case DTypeKind::Int32: case DTypeKind::UInt32: case DTypeKind::Float: return 32;
    case DTypeKind::Int64: case DTypeKind::UInt64: case DTypeKind::Double:
    case DTypeKind::Pointer: case DTypeKind::FuncPtr: case DTypeKind::SizeT: return 64;
    default: return 64;
    }
}

std::string DecompType::to_string() const {
    switch (kind) {
    case DTypeKind::Void:   return "void";
    case DTypeKind::Bool:   return "bool";
    case DTypeKind::Char:   return "char";
    case DTypeKind::WChar:  return "wchar_t";
    case DTypeKind::Int8:   return "int8_t";
    case DTypeKind::Int16:  return "int16_t";
    case DTypeKind::Int32:  return "int32_t";
    case DTypeKind::Int64:  return "int64_t";
    case DTypeKind::UInt8:  return "uint8_t";
    case DTypeKind::UInt16: return "uint16_t";
    case DTypeKind::UInt32: return "uint32_t";
    case DTypeKind::UInt64: return "uint64_t";
    case DTypeKind::Float:  return "float";
    case DTypeKind::Double: return "double";
    case DTypeKind::SizeT:  return "size_t";
    case DTypeKind::FuncPtr:return "void(*)()";
    case DTypeKind::Pointer: {
        if (!inner) return "void*";
        std::string base = inner->to_string();
        if (is_const) return fmt::format("const {}*", base);
        return fmt::format("{}*", base);
    }
    case DTypeKind::Array: {
        if (!inner) return "void[]";
        return fmt::format("{}[{}]", inner->to_string(), array_count);
    }
    }
    return "int64_t";
}

void TypeInfer::init_known_funcs() {
    auto char_ptr = DecompType::make_ptr(DecompType::make_char());
    auto const_char_ptr = DecompType::make_ptr(DecompType::make_char(), true);
    auto void_ptr = DecompType::make_ptr(DecompType::make_void());
    auto sizet = DecompType::make_sizet();
    auto int32 = DecompType::make_int(32);
    auto int64 = DecompType::make_int(64);
    auto uint32 = DecompType::make_int(32, false);

    known_funcs_ = {
        {"strlen",    sizet,   {const_char_ptr}, {"str"}},
        {"wcslen",    sizet,   {DecompType::make_ptr(DecompType::make_char())}, {"str"}},
        {"strcmp",    int32,   {const_char_ptr, const_char_ptr}, {"s1", "s2"}},
        {"strncmp",   int32,   {const_char_ptr, const_char_ptr, sizet}, {"s1", "s2", "n"}},
        {"strcpy",    char_ptr,{char_ptr, const_char_ptr}, {"dst", "src"}},
        {"strcat",    char_ptr,{char_ptr, const_char_ptr}, {"dst", "src"}},
        {"memcpy",    void_ptr,{void_ptr, void_ptr, sizet}, {"dst", "src", "size"}},
        {"memset",    void_ptr,{void_ptr, int32, sizet}, {"dst", "val", "size"}},
        {"malloc",    void_ptr,{sizet}, {"size"}},
        {"calloc",    void_ptr,{sizet, sizet}, {"count", "size"}},
        {"realloc",   void_ptr,{void_ptr, sizet}, {"ptr", "size"}},
        {"free",      DecompType::make_void(), {void_ptr}, {"ptr"}},
        {"printf",    int32,   {const_char_ptr}, {"fmt"}},
        {"sprintf",   int32,   {char_ptr, const_char_ptr}, {"buf", "fmt"}},
        {"puts",      int32,   {const_char_ptr}, {"str"}},
        {"atoi",      int32,   {const_char_ptr}, {"str"}},
        {"atol",      int64,   {const_char_ptr}, {"str"}},
        {"CreateFileA",     void_ptr, {const_char_ptr, uint32, uint32, void_ptr, uint32, uint32, void_ptr},
                            {"lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes",
                             "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"}},
        {"CreateFileW",     void_ptr, {DecompType::make_ptr(DecompType{DTypeKind::WChar}), uint32, uint32, void_ptr, uint32, uint32, void_ptr},
                            {"lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes",
                             "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"}},
        {"CloseHandle",     int32, {void_ptr}, {"hObject"}},
        {"ReadFile",        int32, {void_ptr, void_ptr, uint32, DecompType::make_ptr(uint32), void_ptr},
                            {"hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped"}},
        {"WriteFile",       int32, {void_ptr, void_ptr, uint32, DecompType::make_ptr(uint32), void_ptr},
                            {"hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpNumberOfBytesWritten", "lpOverlapped"}},
        {"VirtualAlloc",    void_ptr, {void_ptr, sizet, uint32, uint32},
                            {"lpAddress", "dwSize", "flAllocationType", "flProtect"}},
        {"VirtualFree",     int32, {void_ptr, sizet, uint32}, {"lpAddress", "dwSize", "dwFreeType"}},
        {"GetLastError",    uint32, {}, {}},
        {"GetProcAddress",  void_ptr, {void_ptr, const_char_ptr}, {"hModule", "lpProcName"}},
        {"LoadLibraryA",    void_ptr, {const_char_ptr}, {"lpLibFileName"}},
        {"_initterm",       DecompType::make_void(), {void_ptr, void_ptr}, {"first", "last"}},
        {"_initterm_e",     int32, {void_ptr, void_ptr}, {"first", "last"}},
        {"__p___argv",      DecompType::make_ptr(DecompType::make_ptr(char_ptr)), {}, {}},
        {"__p___argc",      DecompType::make_ptr(int32), {}, {}},
        {"exit",            DecompType::make_void(), {int32}, {"status"}},
        {"_exit",           DecompType::make_void(), {int32}, {"status"}},
        {"__acrt_iob_func", void_ptr, {uint32}, {"index"}},
        {"_set_app_type",   DecompType::make_void(), {int32}, {"app_type"}},
        {"__setusermatherr",DecompType::make_void(), {void_ptr}, {"handler"}},
        {"_configure_narrow_argv", int32, {int32}, {"mode"}},
        {"_initialize_narrow_environment", int32, {}, {}},
        {"_get_initial_narrow_environment", DecompType::make_ptr(char_ptr), {}, {}},
        {"_cexit",          DecompType::make_void(), {}, {}},
        {"_c_exit",         DecompType::make_void(), {}, {}},
        {"_register_onexit_function", int32, {void_ptr, void_ptr}, {"table", "func"}},
    };
}

void TypeInfer::set_type(int var_id, DecompType t) {
    auto it = types_.find(var_id);
    if (it == types_.end()) {
        types_[var_id] = std::move(t);
    } else {
        if (it->second.kind == DTypeKind::Int64 && t.kind != DTypeKind::Int64)
            it->second = std::move(t);
        else if (t.is_pointer() && !it->second.is_pointer())
            it->second = std::move(t);
    }
}

void TypeInfer::infer_from_ops(const PcodeFunc& func) {
    for (auto& blk : func.blocks) {
        for (auto& op : blk.ops) {
            if (!op.output.valid()) continue;
            int vid = op.output.is_reg() ? op.output.id :
                      op.output.is_temp() ? 1000 + op.output.id :
                      2000 + op.output.id;
            if (op.output.size == 4) set_type(vid, DecompType::make_int(32));
            else if (op.output.size == 2) set_type(vid, DecompType::make_int(16));
            else if (op.output.size == 1) set_type(vid, DecompType::make_int(8));

            if (op.op == PcodeOp::LOAD && !op.inputs.empty()) {
                if (op.inputs[0].is_reg())
                    set_type(op.inputs[0].id, DecompType::make_ptr(get_type(vid)));
            }
        }
    }
}

void TypeInfer::infer_from_calls(const PcodeFunc& func) {
    for (auto& blk : func.blocks) {
        for (auto& op : blk.ops) {
            if (op.op != PcodeOp::CALL) continue;
            if (op.inputs.empty()) continue;
            auto& fn_vn = op.inputs[0];
            if (fn_vn.name.empty()) continue;

            auto* kf = find_known(fn_vn.name);
            if (!kf) continue;

            if (op.output.valid())
                set_type(op.output.id, kf->ret_type);

            for (size_t i = 0; i < kf->param_types.size() && (i + 1) < op.inputs.size(); ++i) {
                auto& arg = op.inputs[i + 1];
                if (arg.is_reg())
                    set_type(arg.id, kf->param_types[i]);
            }
        }
    }
}

void TypeInfer::infer_params(const PcodeFunc& func) {
    for (auto& p : func.params)
        set_type(p.id, DecompType{DTypeKind::Int64});

    for (auto& blk : func.blocks) {
        for (auto& op : blk.ops) {
            if (op.op == PcodeOp::RETURN && !op.inputs.empty()) {
                auto& rv = op.inputs[0];
                if (rv.is_reg()) ret_type_ = get_type(rv.id);
            }
        }
    }
}

void TypeInfer::name_variables(const PcodeFunc& func) {
    for (auto& blk : func.blocks) {
        for (auto& op : blk.ops) {
            if (op.op != PcodeOp::CALL) continue;
            if (op.inputs.empty()) continue;
            auto& fn_vn = op.inputs[0];
            if (!op.output.valid()) continue;

            if (fn_vn.name == "strlen" || fn_vn.name == "wcslen")
                names_[op.output.id] = "len";
            else if (fn_vn.name == "malloc" || fn_vn.name == "calloc" || fn_vn.name == "VirtualAlloc")
                names_[op.output.id] = "buf";
            else if (fn_vn.name == "GetProcAddress")
                names_[op.output.id] = "proc";
            else if (fn_vn.name == "LoadLibraryA" || fn_vn.name == "LoadLibraryW")
                names_[op.output.id] = "hModule";
            else if (fn_vn.name == "CreateFileA" || fn_vn.name == "CreateFileW")
                names_[op.output.id] = "hFile";
            else if (fn_vn.name == "GetLastError")
                names_[op.output.id] = "err";
            else if (fn_vn.name == "__p___argv")
                names_[op.output.id] = "argv";
            else if (fn_vn.name == "__p___argc")
                names_[op.output.id] = "argc";
        }
    }
}

const KnownFunc* TypeInfer::find_known(const std::string& name) const {
    for (auto& kf : known_funcs_)
        if (kf.name == name) return &kf;
    return nullptr;
}

DecompType TypeInfer::get_type(int var_id) const {
    auto it = types_.find(var_id);
    if (it != types_.end()) return it->second;
    return DecompType{DTypeKind::Int64};
}

std::string TypeInfer::get_var_name(int var_id) const {
    auto it = names_.find(var_id);
    if (it != names_.end()) return it->second;
    return {};
}

void TypeInfer::run(PcodeFunc& func) {
    types_.clear();
    names_.clear();
    ret_type_ = DecompType{DTypeKind::Int64};

    init_known_funcs();
    infer_params(func);
    infer_from_ops(func);
    infer_from_calls(func);
    name_variables(func);
}

TypeInfer::StlKind TypeInfer::detect_stl_container(int /*var_id*/, u32 struct_size,
    const std::vector<std::pair<i64,u32>>& accesses) const {
    // std::unique_ptr<T>: 8 bytes, single pointer field at +0
    if (struct_size == 8) {
        for (auto& [off, sz] : accesses)
            if (off == 0 && sz == 8) return StlKind::UniquePtr;
    }
    // std::shared_ptr<T>: 16 bytes, {ptr, ctrl} at +0, +8
    if (struct_size == 16) {
        bool has_0 = false, has_8 = false;
        for (auto& [off, sz] : accesses) {
            if (off == 0 && sz == 8) has_0 = true;
            if (off == 8 && sz == 8) has_8 = true;
        }
        if (has_0 && has_8) return StlKind::SharedPtr;
    }
    // std::vector<T>: 24 bytes, {begin, end, cap} at +0, +8, +16
    if (struct_size == 24 || (struct_size >= 20 && struct_size <= 24)) {
        bool has_0 = false, has_8 = false, has_16 = false;
        for (auto& [off, sz] : accesses) {
            if (off == 0 && sz == 8) has_0 = true;
            if (off == 8 && sz == 8) has_8 = true;
            if (off == 16 && sz == 8) has_16 = true;
        }
        if (has_0 && has_8 && has_16) return StlKind::Vector;
    }
    // std::string (MSVC): 32 bytes, {buf/ptr union, size, capacity} at +0, +16, +24
    if (struct_size == 32 || (struct_size >= 28 && struct_size <= 40)) {
        bool has_0 = false, has_16 = false, has_24 = false;
        for (auto& [off, sz] : accesses) {
            if (off == 0) has_0 = true;
            if (off == 16 && sz == 8) has_16 = true;
            if (off == 24 && sz == 8) has_24 = true;
        }
        if (has_0 && has_16 && has_24) return StlKind::String;
    }
    return StlKind::None;
}

}

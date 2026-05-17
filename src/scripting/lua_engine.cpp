#include "lua_engine.h"
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <imgui.h>
#include <cstring>
#include <algorithm>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

namespace hype {

namespace {

// -----------------------------------------------------------------------
// Registry helpers
// -----------------------------------------------------------------------

LuaEngine* get_engine(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "__hype_engine");
    auto* eng = static_cast<LuaEngine*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return eng;
}

AnalysisDB* get_db(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "__hype_db");
    auto* db = static_cast<AnalysisDB*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return db;
}

PEImage* get_img(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "__hype_img");
    auto* img = static_cast<PEImage*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return img;
}

// -----------------------------------------------------------------------
// Hotkey parsing helpers
// -----------------------------------------------------------------------

struct HotkeySpec {
    ImGuiKey key  = ImGuiKey_None;
    bool ctrl     = false;
    bool shift    = false;
    bool alt      = false;
};

// Parse strings like "Ctrl+Shift+R", "Alt+F7", "F5", "Ctrl+G"
HotkeySpec parse_hotkey(const std::string& s) {
    HotkeySpec spec;
    std::string token;
    std::string src = s;
    // Split on '+'
    std::vector<std::string> parts;
    size_t pos = 0;
    while ((pos = src.find('+')) != std::string::npos) {
        parts.push_back(src.substr(0, pos));
        src.erase(0, pos + 1);
    }
    parts.push_back(src); // last part

    for (auto& p : parts) {
        // to lower for comparison
        std::string lp = p;
        for (auto& c : lp) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lp == "ctrl")  { spec.ctrl  = true; continue; }
        if (lp == "shift") { spec.shift = true; continue; }
        if (lp == "alt")   { spec.alt   = true; continue; }

        // Match ImGuiKey
        if (p.size() == 1) {
            char c = static_cast<char>(std::toupper(static_cast<unsigned char>(p[0])));
            if (c >= 'A' && c <= 'Z')
                spec.key = static_cast<ImGuiKey>(ImGuiKey_A + (c - 'A'));
            else if (c >= '0' && c <= '9')
                spec.key = static_cast<ImGuiKey>(ImGuiKey_0 + (c - '0'));
        } else if (lp[0] == 'f' && lp.size() <= 3) {
            // F1–F12
            int n = 0;
            try { n = std::stoi(lp.substr(1)); } catch (...) {}
            if (n >= 1 && n <= 12)
                spec.key = static_cast<ImGuiKey>(ImGuiKey_F1 + (n - 1));
        } else if (lp == "space")  { spec.key = ImGuiKey_Space; }
          else if (lp == "tab")    { spec.key = ImGuiKey_Tab; }
          else if (lp == "enter")  { spec.key = ImGuiKey_Enter; }
          else if (lp == "escape") { spec.key = ImGuiKey_Escape; }
          else if (lp == "delete") { spec.key = ImGuiKey_Delete; }
          else if (lp == "home")   { spec.key = ImGuiKey_Home; }
          else if (lp == "end")    { spec.key = ImGuiKey_End; }
    }
    return spec;
}

bool check_hotkey(const HotkeySpec& spec) {
    if (spec.key == ImGuiKey_None) return false;
    auto& io = ImGui::GetIO();
    if (spec.ctrl  != io.KeyCtrl)  return false;
    if (spec.shift != io.KeyShift) return false;
    if (spec.alt   != io.KeyAlt)   return false;
    return ImGui::IsKeyPressed(spec.key);
}

// -----------------------------------------------------------------------
// Existing Lua API
// -----------------------------------------------------------------------

int l_get_name(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_pushnil(L); return 1; }
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    auto it = db->names.find(addr);
    if (it != db->names.end())
        lua_pushstring(L, it->second.c_str());
    else
        lua_pushnil(L);
    return 1;
}

int l_set_name(lua_State* L) {
    auto* db = get_db(L);
    if (!db) return 0;
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    const char* name = luaL_checkstring(L, 2);
    db->set_name(addr, name);
    return 0;
}

int l_get_func(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_pushnil(L); return 1; }
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    auto it = db->funcs.find(addr);
    if (it == db->funcs.end()) { lua_pushnil(L); return 1; }

    lua_newtable(L);
    lua_pushstring(L, it->second.name.c_str());
    lua_setfield(L, -2, "name");
    lua_pushinteger(L, static_cast<lua_Integer>(it->second.entry));
    lua_setfield(L, -2, "entry");
    lua_pushinteger(L, static_cast<lua_Integer>(it->second.blocks.size()));
    lua_setfield(L, -2, "block_count");
    lua_pushboolean(L, it->second.noreturn);
    lua_setfield(L, -2, "noreturn");
    return 1;
}

int l_get_insn(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_pushnil(L); return 1; }
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    auto it = db->insns.find(addr);
    if (it == db->insns.end()) { lua_pushnil(L); return 1; }

    lua_newtable(L);
    lua_pushstring(L, it->mnemonic);
    lua_setfield(L, -2, "mnemonic");
    lua_pushstring(L, it->op_str);
    lua_setfield(L, -2, "op_str");
    lua_pushinteger(L, it->len);
    lua_setfield(L, -2, "len");
    lua_pushinteger(L, static_cast<lua_Integer>(it->addr));
    lua_setfield(L, -2, "addr");
    return 1;
}

int l_get_bytes(lua_State* L) {
    auto* img = get_img(L);
    if (!img) { lua_pushnil(L); return 1; }
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    int len = static_cast<int>(luaL_checkinteger(L, 2));
    if (len <= 0 || len > 4096) { lua_pushnil(L); return 1; }

    for (auto& seg : img->segments) {
        if (!seg.contains(addr)) continue;
        size_t off   = static_cast<size_t>(addr - seg.va);
        size_t avail = seg.data.size() - off;
        size_t n     = static_cast<size_t>(len) < avail ? static_cast<size_t>(len) : avail;
        lua_pushlstring(L, reinterpret_cast<const char*>(seg.data.data() + off), n);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int l_set_comment(lua_State* L) {
    auto* db = get_db(L);
    if (!db) return 0;
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    const char* text = luaL_checkstring(L, 2);
    std::lock_guard lk(db->mtx);
    db->comments[addr] = text;
    return 0;
}

int l_get_xrefs_to(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_pushnil(L); return 1; }
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    auto it = db->xrefs_to.find(addr);
    if (it == db->xrefs_to.end()) { lua_newtable(L); return 1; }

    lua_newtable(L);
    int idx = 1;
    for (auto& xr : it->second) {
        lua_pushinteger(L, static_cast<lua_Integer>(xr.from));
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int l_get_functions(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_newtable(L); return 1; }
    lua_newtable(L);
    int idx = 1;
    for (auto& [entry, _] : db->funcs) {
        lua_pushinteger(L, static_cast<lua_Integer>(entry));
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int l_print(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "__hype_output");
    auto* out = static_cast<std::string*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (!out) return 0;

    int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        if (i > 1) *out += "\t";
        const char* s = luaL_tolstring(L, i, nullptr);
        if (s) *out += s;
        lua_pop(L, 1);
    }
    *out += "\n";
    return 0;
}

int l_goto(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    lua_getfield(L, LUA_REGISTRYINDEX, "__hype_nav");
    auto* cb = static_cast<std::function<void(va_t)>*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (cb && *cb) (*cb)(addr);
    return 0;
}

int l_get_comment(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_pushstring(L, ""); return 1; }
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    auto it = db->comments.find(addr);
    if (it != db->comments.end())
        lua_pushstring(L, it->second.c_str());
    else
        lua_pushstring(L, "");
    return 1;
}

int l_get_string(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_pushnil(L); return 1; }
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    for (auto& [sa, ss] : db->strings) {
        if (sa == addr) {
            lua_pushstring(L, ss.c_str());
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

int l_get_image_base(lua_State* L) {
    auto* db = get_db(L);
    if (!db) { lua_pushinteger(L, 0); return 1; }
    lua_pushinteger(L, static_cast<lua_Integer>(db->image_base));
    return 1;
}

int l_get_arch(lua_State* L) {
    auto* img = get_img(L);
    if (!img) { lua_pushstring(L, "unknown"); return 1; }
    switch (img->arch) {
    case Arch::X86:   lua_pushstring(L, "x86");   break;
    case Arch::X64:   lua_pushstring(L, "x64");   break;
    case Arch::ARM:   lua_pushstring(L, "arm");   break;
    case Arch::ARM64: lua_pushstring(L, "arm64"); break;
    case Arch::MIPS:  lua_pushstring(L, "mips");  break;
    case Arch::PPC:   lua_pushstring(L, "ppc");   break;
    default:          lua_pushstring(L, "unknown"); break;
    }
    return 1;
}

int l_get_segments(lua_State* L) {
    auto* img = get_img(L);
    if (!img) { lua_newtable(L); return 1; }
    lua_newtable(L);
    int idx = 1;
    for (auto& seg : img->segments) {
        lua_newtable(L);
        lua_pushstring(L, seg.name.c_str());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.va));
        lua_setfield(L, -2, "addr");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.data.size()));
        lua_setfield(L, -2, "size");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.flags));
        lua_setfield(L, -2, "flags");
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int l_get_cursor(lua_State* L) {
    // The cursor is held by DisasmView; we expose it via a registry pointer set by App
    lua_getfield(L, LUA_REGISTRYINDEX, "__hype_cursor");
    auto* cur = static_cast<va_t*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (!cur) { lua_pushinteger(L, 0); return 1; }
    lua_pushinteger(L, static_cast<lua_Integer>(*cur));
    return 1;
}

int l_create_function(lua_State* L) {
    auto* db = get_db(L);
    if (!db) return 0;
    va_t addr = static_cast<va_t>(luaL_checkinteger(L, 1));
    std::lock_guard lk(db->mtx);
    if (!db->funcs.count(addr)) {
        Function f;
        f.entry = addr;
        f.name = fmt::format("sub_{:X}", addr - db->image_base);
        db->funcs[addr] = std::move(f);
        db->names[addr] = db->funcs[addr].name;
    }
    return 0;
}

// -----------------------------------------------------------------------
// open_results(title, headers_table, rows_table)
//   headers_table  : {"Col1", "Col2", ...}
//   rows_table     : { {addr=0x..., cols={"v1","v2",...}}, ... }
// -----------------------------------------------------------------------
int l_open_results(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;

    const char* title = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    luaL_checktype(L, 3, LUA_TTABLE);

    ResultsWindow w;
    w.title = title;

    // Read headers
    int nhdr = static_cast<int>(lua_rawlen(L, 2));
    for (int i = 1; i <= nhdr; ++i) {
        lua_rawgeti(L, 2, i);
        const char* s = lua_tostring(L, -1);
        w.headers.push_back(s ? s : "");
        lua_pop(L, 1);
    }

    // Read rows
    int nrows = static_cast<int>(lua_rawlen(L, 3));
    for (int i = 1; i <= nrows; ++i) {
        lua_rawgeti(L, 3, i);            // push row table
        if (!lua_istable(L, -1)) { lua_pop(L, 1); continue; }

        ResultsRow row;

        lua_getfield(L, -1, "addr");
        row.addr = static_cast<va_t>(lua_tointeger(L, -1));
        lua_pop(L, 1);

        lua_getfield(L, -1, "cols");     // push cols table
        if (lua_istable(L, -1)) {
            int ncols = static_cast<int>(lua_rawlen(L, -1));
            for (int c = 1; c <= ncols; ++c) {
                lua_rawgeti(L, -1, c);
                const char* s = lua_tostring(L, -1);
                row.cols.push_back(s ? s : "");
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);                   // pop cols table
        lua_pop(L, 1);                   // pop row table

        w.rows.push_back(std::move(row));
    }

    eng->push_result_window(std::move(w));
    return 0;
}

// -----------------------------------------------------------------------
// Plugin registration Lua API
// -----------------------------------------------------------------------

int l_register_plugin(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;
    const char* name = luaL_optstring(L, 1, "Unnamed Plugin");
    const char* desc = luaL_optstring(L, 2, "");

    // Find the entry that was pre-created for the current file, or create one
    auto& plugins = const_cast<std::vector<PluginEntry>&>(eng->plugins());
    for (auto& p : plugins) {
        if (p.path == eng->current_plugin_name()) {
            p.name = name;
            p.desc = desc;
            return 0;
        }
    }
    // Fallback: shouldn't normally reach here
    PluginEntry e;
    e.name = name;
    e.desc = desc;
    e.path = eng->current_plugin_name();
    plugins.push_back(std::move(e));
    return 0;
}

int l_register_menu_item(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;

    const char* label = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    auto& plugins = const_cast<std::vector<PluginEntry>&>(eng->plugins());
    // Add to the most recently active plugin
    for (auto it = plugins.rbegin(); it != plugins.rend(); ++it) {
        if (it->path == eng->current_plugin_name()) {
            it->items.push_back({label, ref});
            return 0;
        }
    }
    // If no plugin registered yet, attach to a default entry
    if (!plugins.empty()) {
        plugins.back().items.push_back({label, ref});
    }
    return 0;
}

int l_register_hotkey(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;
    const char* key_str = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    eng->add_hotkey(key_str, ref);
    return 0;
}

int l_register_on_analysis_complete(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    eng->add_analysis_cb(ref);
    return 0;
}

} // anon namespace

// -----------------------------------------------------------------------
// LuaEngine implementation
// -----------------------------------------------------------------------

LuaEngine::LuaEngine() {
    L_ = luaL_newstate();
    luaL_openlibs(L_);
}

LuaEngine::~LuaEngine() {
    // Release all Lua registry refs before closing
    for (auto& p : plugins_)
        for (auto& item : p.items)
            if (item.cb_ref != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, item.cb_ref);
    for (auto& [_, ref] : hotkeys_)
        if (ref != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, ref);
    for (auto ref : on_analysis_cbs_)
        if (ref != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, ref);
    if (L_) lua_close(L_);
}

void LuaEngine::init(AnalysisDB* db, PEImage* img) {
    db_  = db;
    img_ = img;
    register_api();
}

void LuaEngine::register_api() {
    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__hype_engine");
    lua_pushlightuserdata(L_, db_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__hype_db");
    lua_pushlightuserdata(L_, img_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__hype_img");
    lua_pushlightuserdata(L_, &output_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__hype_output");
    lua_pushlightuserdata(L_, &nav_cb_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__hype_nav");

    // Core API
    lua_register(L_, "get_name",       l_get_name);
    lua_register(L_, "set_name",       l_set_name);
    lua_register(L_, "get_func",       l_get_func);
    lua_register(L_, "get_insn",       l_get_insn);
    lua_register(L_, "get_bytes",      l_get_bytes);
    lua_register(L_, "set_comment",    l_set_comment);
    lua_register(L_, "get_comment",    l_get_comment);
    lua_register(L_, "get_xrefs_to",   l_get_xrefs_to);
    lua_register(L_, "get_functions",  l_get_functions);
    lua_register(L_, "print",          l_print);
    lua_register(L_, "goto_addr",      l_goto);
    lua_register(L_, "get_string",     l_get_string);
    lua_register(L_, "get_image_base", l_get_image_base);
    lua_register(L_, "get_arch",       l_get_arch);
    lua_register(L_, "get_segments",   l_get_segments);
    lua_register(L_, "get_cursor",     l_get_cursor);
    lua_register(L_, "create_function",l_create_function);
    lua_register(L_, "open_results",   l_open_results);

    // Plugin registration API
    lua_register(L_, "register_plugin",               l_register_plugin);
    lua_register(L_, "register_menu_item",            l_register_menu_item);
    lua_register(L_, "register_hotkey",               l_register_hotkey);
    lua_register(L_, "register_on_analysis_complete", l_register_on_analysis_complete);
}

// Register engine pointer and api before analysis (plugins load pre-loop).
// We call register_api early so plugins can call register_* at load time
// even though db_ and img_ are still null — API functions guard for null.
void LuaEngine::load_plugins(const std::filesystem::path& dir) {
    // Register the engine pointer early so register_* functions work
    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__hype_engine");
    lua_pushlightuserdata(L_, &output_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__hype_output");

    // Register plugin API functions (safe even with null db_/img_)
    lua_register(L_, "get_name",       l_get_name);
    lua_register(L_, "set_name",       l_set_name);
    lua_register(L_, "get_func",       l_get_func);
    lua_register(L_, "get_insn",       l_get_insn);
    lua_register(L_, "get_bytes",      l_get_bytes);
    lua_register(L_, "set_comment",    l_set_comment);
    lua_register(L_, "get_comment",    l_get_comment);
    lua_register(L_, "get_xrefs_to",   l_get_xrefs_to);
    lua_register(L_, "get_functions",  l_get_functions);
    lua_register(L_, "print",          l_print);
    lua_register(L_, "goto_addr",      l_goto);
    lua_register(L_, "get_string",     l_get_string);
    lua_register(L_, "get_image_base", l_get_image_base);
    lua_register(L_, "get_arch",       l_get_arch);
    lua_register(L_, "get_segments",   l_get_segments);
    lua_register(L_, "get_cursor",     l_get_cursor);
    lua_register(L_, "create_function",l_create_function);
    lua_register(L_, "open_results",   l_open_results);
    lua_register(L_, "register_plugin",               l_register_plugin);
    lua_register(L_, "register_menu_item",            l_register_menu_item);
    lua_register(L_, "register_hotkey",               l_register_hotkey);
    lua_register(L_, "register_on_analysis_complete", l_register_on_analysis_complete);

    if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
        spdlog::info("lua_engine: plugins dir not found at {}", dir.string());
        return;
    }

    // Collect and sort .lua files alphabetically
    std::vector<std::filesystem::path> files;
    for (auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".lua")
            files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());

    for (auto& fp : files) {
        PluginEntry pe;
        pe.path = fp.string();
        pe.name = fp.stem().string(); // default name = filename stem
        pe.desc = "";

        current_plugin_ = pe.path;
        plugins_.push_back(std::move(pe));

        output_.clear();
        int err = luaL_dofile(L_, fp.string().c_str());
        if (err) {
            const char* msg = lua_tostring(L_, -1);
            plugins_.back().error     = true;
            plugins_.back().error_msg = msg ? msg : "unknown error";
            lua_pop(L_, 1);
            spdlog::warn("lua_engine: plugin error [{}]: {}", fp.filename().string(), plugins_.back().error_msg);
        } else {
            spdlog::info("lua_engine: loaded plugin [{}] -> \"{}\"",
                fp.filename().string(), plugins_.back().name);
        }
    }

    spdlog::info("lua_engine: {} plugin(s) loaded from {}", plugins_.size(), dir.string());
}

void LuaEngine::invoke_menu_item(int plugin_idx, int item_idx) {
    if (plugin_idx < 0 || plugin_idx >= static_cast<int>(plugins_.size())) return;
    auto& plugin = plugins_[static_cast<size_t>(plugin_idx)];
    if (item_idx < 0 || item_idx >= static_cast<int>(plugin.items.size())) return;
    int ref = plugin.items[static_cast<size_t>(item_idx)].cb_ref;
    if (ref == LUA_NOREF) return;

    output_.clear();
    lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
    int err = lua_pcall(L_, 0, 0, 0);
    if (err) {
        const char* msg = lua_tostring(L_, -1);
        output_ += std::string("[plugin error] ") + (msg ? msg : "unknown") + "\n";
        lua_pop(L_, 1);
    }
    // output_ holds everything l_print wrote during the call.
    // The caller (App::render_menubar) reads it via last_output().
}

void LuaEngine::run_analysis_complete_callbacks() {
    for (int ref : on_analysis_cbs_) {
        if (ref == LUA_NOREF) continue;
        output_.clear();
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
        int err = lua_pcall(L_, 0, 0, 0);
        if (err) {
            const char* msg = lua_tostring(L_, -1);
            spdlog::warn("lua_engine: on_analysis_complete callback error: {}",
                msg ? msg : "unknown");
            lua_pop(L_, 1);
        }
    }
}

void LuaEngine::check_hotkeys() {
    auto& io = ImGui::GetIO();
    if (io.WantTextInput) return;
    for (auto& [key_str, ref] : hotkeys_) {
        if (ref == LUA_NOREF) continue;
        auto spec = parse_hotkey(key_str);
        if (!check_hotkey(spec)) continue;

        output_.clear();
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
        int err = lua_pcall(L_, 0, 0, 0);
        if (err) {
            const char* msg = lua_tostring(L_, -1);
            spdlog::warn("lua_engine: hotkey callback error: {}", msg ? msg : "unknown");
            lua_pop(L_, 1);
        }
    }
}

std::string LuaEngine::execute(const std::string& code) {
    output_.clear();
    int err = luaL_dostring(L_, code.c_str());
    if (err) {
        const char* msg = lua_tostring(L_, -1);
        std::string result = msg ? msg : "unknown error";
        lua_pop(L_, 1);
        return "[error] " + result;
    }
    return output_;
}

} // namespace hype

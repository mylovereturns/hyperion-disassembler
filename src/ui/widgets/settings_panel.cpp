#define NOMINMAX
#include "settings_panel.h"
#include "ui/theme.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <fmt/format.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef __APPLE__
#define GL_SILENCE_DEPRECATION
#include <OpenGL/gl.h>
#elif defined(_WIN32)
#include <windows.h>
#include <GL/gl.h>
#else
#include <GL/gl.h>
#endif

#define STB_IMAGE_IMPLEMENTATION
#include "third_party/stb_image.h"

#ifdef _WIN32
#include <windows.h>
#include <commdlg.h>
#include <GL/gl.h>
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#endif

namespace hype {

namespace {

std::filesystem::path exe_directory() {
#ifdef _WIN32
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::filesystem::path(buf).parent_path();
#else
    return std::filesystem::current_path();
#endif
}

std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

#ifdef _WIN32
std::string file_dialog_hth(bool save) {
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "Hyperion Theme\0*.hth\0All Files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = "hth";
    if (save) {
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
        if (GetSaveFileNameA(&ofn)) return path;
    } else {
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
        if (GetOpenFileNameA(&ofn)) return path;
    }
    return {};
}

std::string file_dialog_image() {
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "Images\0*.png;*.jpg;*.jpeg;*.bmp\0All Files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&ofn)) return path;
    return {};
}
#endif

struct KeyNamePair { ImGuiKey key; const char* name; };
static const KeyNamePair g_key_table[] = {
    {ImGuiKey_A, "A"}, {ImGuiKey_B, "B"}, {ImGuiKey_C, "C"}, {ImGuiKey_D, "D"},
    {ImGuiKey_E, "E"}, {ImGuiKey_F, "F"}, {ImGuiKey_G, "G"}, {ImGuiKey_H, "H"},
    {ImGuiKey_I, "I"}, {ImGuiKey_J, "J"}, {ImGuiKey_K, "K"}, {ImGuiKey_L, "L"},
    {ImGuiKey_M, "M"}, {ImGuiKey_N, "N"}, {ImGuiKey_O, "O"}, {ImGuiKey_P, "P"},
    {ImGuiKey_Q, "Q"}, {ImGuiKey_R, "R"}, {ImGuiKey_S, "S"}, {ImGuiKey_T, "T"},
    {ImGuiKey_U, "U"}, {ImGuiKey_V, "V"}, {ImGuiKey_W, "W"}, {ImGuiKey_X, "X"},
    {ImGuiKey_Y, "Y"}, {ImGuiKey_Z, "Z"},
    {ImGuiKey_0, "0"}, {ImGuiKey_1, "1"}, {ImGuiKey_2, "2"}, {ImGuiKey_3, "3"},
    {ImGuiKey_4, "4"}, {ImGuiKey_5, "5"}, {ImGuiKey_6, "6"}, {ImGuiKey_7, "7"},
    {ImGuiKey_8, "8"}, {ImGuiKey_9, "9"},
    {ImGuiKey_F1, "F1"}, {ImGuiKey_F2, "F2"}, {ImGuiKey_F3, "F3"}, {ImGuiKey_F4, "F4"},
    {ImGuiKey_F5, "F5"}, {ImGuiKey_F6, "F6"}, {ImGuiKey_F7, "F7"}, {ImGuiKey_F8, "F8"},
    {ImGuiKey_F9, "F9"}, {ImGuiKey_F10, "F10"}, {ImGuiKey_F11, "F11"}, {ImGuiKey_F12, "F12"},
    {ImGuiKey_Space, "Space"}, {ImGuiKey_Enter, "Enter"}, {ImGuiKey_Escape, "Escape"},
    {ImGuiKey_Tab, "Tab"}, {ImGuiKey_Backspace, "Backspace"}, {ImGuiKey_Delete, "Delete"},
    {ImGuiKey_Insert, "Insert"}, {ImGuiKey_Home, "Home"}, {ImGuiKey_End, "End"},
    {ImGuiKey_PageUp, "PageUp"}, {ImGuiKey_PageDown, "PageDown"},
    {ImGuiKey_LeftArrow, "Left"}, {ImGuiKey_RightArrow, "Right"},
    {ImGuiKey_UpArrow, "Up"}, {ImGuiKey_DownArrow, "Down"},
    {ImGuiKey_Semicolon, "Semicolon"}, {ImGuiKey_Comma, "Comma"},
    {ImGuiKey_Period, "Period"}, {ImGuiKey_Slash, "Slash"},
    {ImGuiKey_Backslash, "Backslash"}, {ImGuiKey_Minus, "Minus"},
    {ImGuiKey_Equal, "Equal"}, {ImGuiKey_LeftBracket, "LBracket"},
    {ImGuiKey_RightBracket, "RBracket"}, {ImGuiKey_GraveAccent, "Grave"},
    {ImGuiKey_Apostrophe, "Apostrophe"},
};

} // anon

// --- KeybindManager ---

void KeybindManager::set_defaults() {
    binds.clear();
    set("goto", ImGuiKey_G);
    set("rename", ImGuiKey_N);
    set("comment", ImGuiKey_Semicolon);
    set("xrefs", ImGuiKey_X);
    set("data", ImGuiKey_D);
    set("string", ImGuiKey_A);
    set("undefine", ImGuiKey_U);
    set("code", ImGuiKey_C);
    set("hex", ImGuiKey_H);
    set("graph", ImGuiKey_Space);
    set("decompile", ImGuiKey_F5);
    set("create_func", ImGuiKey_P);
    set("strings_panel", ImGuiKey_F12, false, true);
    set("follow", ImGuiKey_Enter);
    set("back", ImGuiKey_Escape);
}

bool KeybindManager::check(const std::string& action) const {
    auto it = binds.find(action);
    if (it == binds.end()) return false;
    auto& e = it->second;
    auto& io = ImGui::GetIO();
    if (e.ctrl != io.KeyCtrl) return false;
    if (e.shift != io.KeyShift) return false;
    if (e.alt != io.KeyAlt) return false;
    return ImGui::IsKeyPressed(e.key);
}

void KeybindManager::set(const std::string& action, ImGuiKey key, bool ctrl, bool shift, bool alt) {
    binds[action] = {key, ctrl, shift, alt};
}

std::string KeybindManager::key_name(ImGuiKey key) {
    for (auto& kv : g_key_table)
        if (kv.key == key) return kv.name;
    return "Unknown";
}

ImGuiKey KeybindManager::key_from_name(const std::string& name) {
    for (auto& kv : g_key_table)
        if (name == kv.name) return kv.key;
    return ImGuiKey_None;
}

std::string KeybindManager::display_string(const std::string& action) const {
    auto it = binds.find(action);
    if (it == binds.end()) return "None";
    auto& e = it->second;
    std::string s;
    if (e.ctrl) s += "Ctrl+";
    if (e.shift) s += "Shift+";
    if (e.alt) s += "Alt+";
    s += key_name(e.key);
    return s;
}

void KeybindManager::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == '[') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto action = trim(line.substr(0, eq));
        auto val = trim(line.substr(eq + 1));

        bool ctrl = false, shift = false, alt = false;
        while (true) {
            if (val.starts_with("Ctrl+")) { ctrl = true; val = val.substr(5); }
            else if (val.starts_with("Shift+")) { shift = true; val = val.substr(6); }
            else if (val.starts_with("Alt+")) { alt = true; val = val.substr(4); }
            else break;
        }
        auto key = key_from_name(val);
        if (key != ImGuiKey_None)
            binds[action] = {key, ctrl, shift, alt};
    }
}

void KeybindManager::save(const std::string& path) const {
    std::ofstream out(path);
    if (!out) return;
    out << "[keybinds]\n";
    for (auto& [action, entry] : binds) {
        out << action << "=";
        if (entry.ctrl) out << "Ctrl+";
        if (entry.shift) out << "Shift+";
        if (entry.alt) out << "Alt+";
        out << key_name(entry.key) << "\n";
    }
}

// --- Settings ---

void Settings::load(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) return;
    std::string line, section;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line[0] == '[') {
            section = line.substr(1, line.find(']') - 1);
            continue;
        }
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto k = trim(line.substr(0, eq));
        auto v = trim(line.substr(eq + 1));

        if (section == "appearance") {
            try {
            if (k == "font_size") font_size = std::stof(v);
            else if (k == "theme") theme_index = std::stoi(v);
            else if (k == "accent_r") accent_color[0] = std::stof(v);
            else if (k == "accent_g") accent_color[1] = std::stof(v);
            else if (k == "accent_b") accent_color[2] = std::stof(v);
            else if (k == "bg_r") bg_color[0] = std::stof(v);
            else if (k == "bg_g") bg_color[1] = std::stof(v);
            else if (k == "bg_b") bg_color[2] = std::stof(v);
            else if (k == "text_r") text_color[0] = std::stof(v);
            else if (k == "text_g") text_color[1] = std::stof(v);
            else if (k == "text_b") text_color[2] = std::stof(v);
            else if (k == "bg_image_path") bg_image_path = v;
            else if (k == "bg_opacity") bg_opacity = std::stof(v);
            else if (k == "window_opacity") window_opacity = std::stof(v);
            else if (k == "cursor_line_r") cursor_line_color[0] = std::stof(v);
            else if (k == "cursor_line_g") cursor_line_color[1] = std::stof(v);
            else if (k == "cursor_line_b") cursor_line_color[2] = std::stof(v);
            else if (k == "cursor_line_a") cursor_line_color[3] = std::stof(v);
            else if (k == "func_header_r") func_header_color[0] = std::stof(v);
            else if (k == "func_header_g") func_header_color[1] = std::stof(v);
            else if (k == "func_header_b") func_header_color[2] = std::stof(v);
            else if (k == "func_header_a") func_header_color[3] = std::stof(v);
            else if (k == "border_radius") border_radius = std::stof(v);
            else if (k == "scrollbar_width") scrollbar_width = std::stof(v);
            else if (k == "font_index") font_index = std::stoi(v);
            } catch (...) {}
        } else if (section == "editor") {
            try {
            if (k == "show_bytes") show_bytes = (v == "true" || v == "1");
            else if (k == "max_bytes") max_bytes = std::stoi(v);
            else if (k == "address_width") address_width = std::stoi(v);
            else if (k == "tab_size") tab_size = std::stoi(v);
            else if (k == "auto_beautify") auto_beautify = (v == "true" || v == "1");
            else if (k == "mono_font_path") std::strncpy(mono_font_path, v.c_str(), sizeof(mono_font_path) - 1);
            } catch (...) {}
        } else if (section == "advanced") {
            try {
            if (k == "threads") max_threads = std::stoi(v);
            else if (k == "autosave_interval") autosave_interval = std::stoi(v);
            else if (k == "max_decompiler_blocks") max_decompiler_blocks = std::stoi(v);
            } catch (...) {}
        }
    }
}

void Settings::save(const std::filesystem::path& path) const {
    std::ofstream out(path);
    if (!out) return;
    out << "[appearance]\n";
    out << "font_size=" << font_size << "\n";
    out << "theme=" << theme_index << "\n";
    out << "accent_r=" << accent_color[0] << "\n";
    out << "accent_g=" << accent_color[1] << "\n";
    out << "accent_b=" << accent_color[2] << "\n";
    out << "bg_r=" << bg_color[0] << "\n";
    out << "bg_g=" << bg_color[1] << "\n";
    out << "bg_b=" << bg_color[2] << "\n";
    out << "text_r=" << text_color[0] << "\n";
    out << "text_g=" << text_color[1] << "\n";
    out << "text_b=" << text_color[2] << "\n";
    out << "bg_image_path=" << bg_image_path << "\n";
    out << "bg_opacity=" << bg_opacity << "\n";
    out << "window_opacity=" << window_opacity << "\n";
    out << "cursor_line_r=" << cursor_line_color[0] << "\n";
    out << "cursor_line_g=" << cursor_line_color[1] << "\n";
    out << "cursor_line_b=" << cursor_line_color[2] << "\n";
    out << "cursor_line_a=" << cursor_line_color[3] << "\n";
    out << "func_header_r=" << func_header_color[0] << "\n";
    out << "func_header_g=" << func_header_color[1] << "\n";
    out << "func_header_b=" << func_header_color[2] << "\n";
    out << "func_header_a=" << func_header_color[3] << "\n";
    out << "border_radius=" << border_radius << "\n";
    out << "scrollbar_width=" << scrollbar_width << "\n";
    out << "font_index=" << font_index << "\n";
    out << "\n[editor]\n";
    out << "show_bytes=" << (show_bytes ? "true" : "false") << "\n";
    out << "max_bytes=" << max_bytes << "\n";
    out << "address_width=" << address_width << "\n";
    out << "tab_size=" << tab_size << "\n";
    out << "auto_beautify=" << (auto_beautify ? "true" : "false") << "\n";
    out << "mono_font_path=" << mono_font_path << "\n";
    out << "\n[advanced]\n";
    out << "threads=" << max_threads << "\n";
    out << "autosave_interval=" << autosave_interval << "\n";
    out << "max_decompiler_blocks=" << max_decompiler_blocks << "\n";
}

// --- ThemeColors ---

void ThemeColors::export_hth(const std::filesystem::path& path) const {
    std::ofstream out(path);
    if (!out) return;
    auto write = [&](const char* name, const float* c) {
        out << name << "=" << c[0] << "," << c[1] << "," << c[2] << "," << c[3] << "\n";
    };
    write("bg", bg);
    write("text", text);
    write("accent", accent);
    write("surface", surface);
    write("border", border);
}

bool ThemeColors::import_hth(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto k = trim(line.substr(0, eq));
        auto v = trim(line.substr(eq + 1));

        float vals[4] = {0, 0, 0, 1};
        std::istringstream ss(v);
        char comma;
        ss >> vals[0] >> comma >> vals[1] >> comma >> vals[2];
        if (ss.peek() == ',') ss >> comma >> vals[3];

        float* target = nullptr;
        if (k == "bg") target = bg;
        else if (k == "text") target = text;
        else if (k == "accent") target = accent;
        else if (k == "surface") target = surface;
        else if (k == "border") target = border;

        if (target) std::memcpy(target, vals, sizeof(vals));
    }
    return true;
}

// --- SettingsPanel ---

SettingsPanel::SettingsPanel() {
    keybinds_.set_defaults();
    scan_themes_folder();
    scan_system_fonts();
}

void SettingsPanel::load_bg_image(const std::string& path) {
    if (path.empty()) return;
    int w, h, ch;
    unsigned char* data = stbi_load(path.c_str(), &w, &h, &ch, 4);
    if (!data) return;

    if (bg_texture_) glDeleteTextures(1, &bg_texture_);

    glGenTextures(1, &bg_texture_);
    glBindTexture(GL_TEXTURE_2D, bg_texture_);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
    glBindTexture(GL_TEXTURE_2D, 0);

    stbi_image_free(data);
    bg_width_ = w;
    bg_height_ = h;
    settings_.bg_image_path = path;
}

void SettingsPanel::clear_bg_image() {
    if (bg_texture_) {
        glDeleteTextures(1, &bg_texture_);
        bg_texture_ = 0;
    }
    bg_width_ = bg_height_ = 0;
    settings_.bg_image_path.clear();
}

void SettingsPanel::scan_system_fonts() {
    available_fonts_.clear();
    struct Candidate { const char* name; const char* file; };
    static constexpr Candidate candidates[] = {
        {"Segoe UI",        "C:\\Windows\\Fonts\\segoeui.ttf"},
        {"Consolas",        "C:\\Windows\\Fonts\\consola.ttf"},
        {"Cascadia Code",   "C:\\Windows\\Fonts\\CascadiaCode.ttf"},
        {"JetBrains Mono",  "C:\\Windows\\Fonts\\JetBrainsMono-Regular.ttf"},
        {"Fira Code",       "C:\\Windows\\Fonts\\FiraCode-Regular.ttf"},
    };
    for (auto& c : candidates) {
        if (std::filesystem::exists(c.file))
            available_fonts_.push_back({c.name, c.file});
    }
}

void SettingsPanel::scan_themes_folder() {
    community_themes_.clear();
    auto dir = exe_directory() / "themes";
    if (!std::filesystem::exists(dir))
        std::filesystem::create_directories(dir);
    for (auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".hth") {
            ThemeFile tf;
            tf.path = entry.path();
            tf.name = entry.path().stem().string();
            community_themes_.push_back(std::move(tf));
        }
    }
}

std::filesystem::path SettingsPanel::ini_path() const {
    return exe_directory() / "hyperion_settings.ini";
}

std::filesystem::path SettingsPanel::keybind_path() const {
    return exe_directory() / "hyperion_keybinds.ini";
}

void SettingsPanel::load_all() {
    settings_.load(ini_path());
    keybinds_.load(keybind_path().string());
    rebuild_keybind_display();

    switch (settings_.theme_index) {
    case 0: g_theme = Theme::BinaryNinja; break;
    case 1: g_theme = Theme::IDA; break;
    case 2: g_theme = Theme::Midnight; break;
    case 3: g_theme = Theme::Custom; break;
    }

    if (!settings_.bg_image_path.empty())
        load_bg_image(settings_.bg_image_path);
}

void SettingsPanel::save_all() {
    settings_.save(ini_path());
    keybinds_.save(keybind_path().string());
}

void SettingsPanel::rebuild_keybind_display() {
    keybind_display_.clear();
    static const char* actions[] = {
        "goto", "rename", "comment", "xrefs", "data", "string",
        "undefine", "code", "hex", "graph", "decompile", "create_func",
        "strings_panel", "follow", "back"
    };
    for (auto* a : actions)
        keybind_display_.emplace_back(a, keybinds_.display_string(a));
}

void SettingsPanel::render() {
    if (!visible_) return;

    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::Begin("Settings###settings_panel", &visible_,
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize)) {
        if (ImGui::BeginTabBar("##settings_tabs")) {
            if (ImGui::BeginTabItem("Appearance")) { render_appearance_tab(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Editor"))     { render_editor_tab();     ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Keybinds"))   { render_keybinds_tab();   ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Advanced"))   { render_advanced_tab();   ImGui::EndTabItem(); }
            ImGui::EndTabBar();
        }

        ImGui::Spacing(); ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        float btn_w = 120.0f;
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - btn_w) * 0.5f);
        if (ImGui::Button("Close", ImVec2(btn_w, 30)))
            visible_ = false;
    }
    ImGui::End();
}

void SettingsPanel::render_appearance_tab() {
    ImGui::SeparatorText("General");
    ImGui::BeginGroup();
    ImGui::SetNextItemWidth(200);
    float old_size = settings_.font_size;
    if (ImGui::SliderFloat("Font Size", &settings_.font_size, 12.0f, 24.0f, "%.0f pt")) {
        if (settings_.font_size != old_size) font_rebuild_ = true;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Controls the main UI font size");

    ImGui::SetNextItemWidth(200);
    const char* themes[] = {"Hyperion", "IDA", "Midnight", "Custom"};
    if (ImGui::Combo("Theme", &settings_.theme_index, themes, 4)) {
        switch (settings_.theme_index) {
        case 0: g_theme = Theme::BinaryNinja; break;
        case 1: g_theme = Theme::IDA; break;
        case 2: g_theme = Theme::Midnight; break;
        case 3: g_theme = Theme::Custom; break;
        }
        theme_changed_ = true;
        save_all();
    }
    ImGui::EndGroup();

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Colors");

    ImGui::BeginGroup();
    bool color_changed = false;
    color_changed |= ImGui::ColorEdit3("##accent_col", settings_.accent_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);
    ImGui::SameLine(); ImGui::Text("Accent");

    color_changed |= ImGui::ColorEdit3("##bg_col", settings_.bg_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);
    ImGui::SameLine(); ImGui::Text("Background");

    color_changed |= ImGui::ColorEdit3("##text_col", settings_.text_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);
    ImGui::SameLine(); ImGui::Text("Text");
    ImGui::EndGroup();

    if (color_changed) {
        custom_colors_.accent[0] = settings_.accent_color[0];
        custom_colors_.accent[1] = settings_.accent_color[1];
        custom_colors_.accent[2] = settings_.accent_color[2];
        custom_colors_.accent[3] = 1.0f;
        custom_colors_.bg[0] = settings_.bg_color[0];
        custom_colors_.bg[1] = settings_.bg_color[1];
        custom_colors_.bg[2] = settings_.bg_color[2];
        custom_colors_.bg[3] = 1.0f;
        custom_colors_.text[0] = settings_.text_color[0];
        custom_colors_.text[1] = settings_.text_color[1];
        custom_colors_.text[2] = settings_.text_color[2];
        custom_colors_.text[3] = 1.0f;
        if (settings_.theme_index == 3) theme_changed_ = true;
        save_all();
    }

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Background Image");
    ImGui::BeginGroup();
    {
        if (settings_.bg_image_path.empty())
            ImGui::TextDisabled("No image loaded");
        else {
            auto fname = std::filesystem::path(settings_.bg_image_path).filename().string();
            ImGui::Text("%s (%dx%d)", fname.c_str(), bg_width_, bg_height_);
        }
        if (ImGui::Button("Browse...")) {
#ifdef _WIN32
            auto p = file_dialog_image();
            if (!p.empty()) { load_bg_image(p); save_all(); }
#endif
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear") && bg_texture_) { clear_bg_image(); save_all(); }
        ImGui::SetNextItemWidth(200);
        {
            int pct = (int)(settings_.bg_opacity * 100);
            if (ImGui::SliderInt("Opacity##bg", &pct, 0, 100, "%d%%")) {
                settings_.bg_opacity = pct / 100.0f; save_all();
            }
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Background image opacity");
    }
    ImGui::EndGroup();

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Window");
    ImGui::SetNextItemWidth(200);
    {
        int pct = (int)(settings_.window_opacity * 100);
        ImGui::SetNextItemWidth(200);
        if (ImGui::SliderInt("Window Opacity", &pct, 30, 100, "%d%%")) {
            settings_.window_opacity = pct / 100.0f; save_all();
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Overall window transparency");

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Disassembly Colors");
    ImGui::BeginGroup();
    bool dc = false;
    dc |= ImGui::ColorEdit4("##cursorline_col", settings_.cursor_line_color,
        ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel | ImGuiColorEditFlags_AlphaBar);
    ImGui::SameLine(); ImGui::Text("Cursor Line");
    dc |= ImGui::ColorEdit4("##funchdr_col", settings_.func_header_color,
        ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel | ImGuiColorEditFlags_AlphaBar);
    ImGui::SameLine(); ImGui::Text("Func Header");
    ImGui::EndGroup();
    if (dc) save_all();

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Style");
    ImGui::BeginGroup();
    bool sc = false;
    ImGui::SetNextItemWidth(200);
    sc |= ImGui::SliderFloat("Border Radius", &settings_.border_radius, 0.0f, 12.0f, "%.0f px");
    ImGui::SetNextItemWidth(200);
    sc |= ImGui::SliderFloat("Scrollbar Width", &settings_.scrollbar_width, 6.0f, 16.0f, "%.0f px");
    ImGui::EndGroup();
    if (sc) { theme_changed_ = true; save_all(); }

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Font");
    if (!available_fonts_.empty()) {
        ImGui::SetNextItemWidth(200);
        auto getter = [](void* data, int idx) -> const char* {
            auto* fonts = reinterpret_cast<std::vector<FontEntry>*>(data);
            return (*fonts)[idx].name.c_str();
        };
        if (ImGui::Combo("System Font", &settings_.font_index, getter,
            &available_fonts_, (int)available_fonts_.size())) {
            font_rebuild_ = true;
            save_all();
        }
    } else {
        ImGui::TextDisabled("No system fonts detected");
    }

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Preview");
    {
        ImVec2 p = ImGui::GetCursorScreenPos();
        float w = ImGui::GetContentRegionAvail().x;
        float h = 50.0f;
        auto* dl = ImGui::GetWindowDrawList();
        ImU32 bg_col = ImGui::ColorConvertFloat4ToU32({settings_.bg_color[0], settings_.bg_color[1], settings_.bg_color[2], 1});
        ImU32 txt_col = ImGui::ColorConvertFloat4ToU32({settings_.text_color[0], settings_.text_color[1], settings_.text_color[2], 1});
        ImU32 acc_col = ImGui::ColorConvertFloat4ToU32({settings_.accent_color[0], settings_.accent_color[1], settings_.accent_color[2], 1});
        dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), bg_col);
        dl->AddText(ImVec2(p.x + 10, p.y + 6), txt_col, "Sample text in your chosen colors");
        dl->AddRectFilled(ImVec2(p.x + 10, p.y + 30), ImVec2(p.x + 130, p.y + 44), acc_col, 3.0f);
        dl->AddText(ImVec2(p.x + 20, p.y + 30), IM_COL32(255, 255, 255, 255), "Accent");
        ImGui::Dummy(ImVec2(w, h));
    }

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Theme Files");
    if (ImGui::Button("Export Theme (.hth)")) {
#ifdef _WIN32
        auto p = file_dialog_hth(true);
        if (!p.empty()) custom_colors_.export_hth(p);
#endif
    }
    ImGui::SameLine();
    if (ImGui::Button("Import Theme (.hth)")) {
#ifdef _WIN32
        auto p = file_dialog_hth(false);
        if (!p.empty() && custom_colors_.import_hth(p)) {
            settings_.accent_color[0] = custom_colors_.accent[0];
            settings_.accent_color[1] = custom_colors_.accent[1];
            settings_.accent_color[2] = custom_colors_.accent[2];
            settings_.bg_color[0] = custom_colors_.bg[0];
            settings_.bg_color[1] = custom_colors_.bg[1];
            settings_.bg_color[2] = custom_colors_.bg[2];
            settings_.text_color[0] = custom_colors_.text[0];
            settings_.text_color[1] = custom_colors_.text[1];
            settings_.text_color[2] = custom_colors_.text[2];
            settings_.theme_index = 3;
            g_theme = Theme::Custom;
            theme_changed_ = true;
            save_all();
        }
#endif
    }

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Community Themes");
    if (ImGui::Button("Refresh")) scan_themes_folder();
    ImGui::SameLine();
    ImGui::TextDisabled("(%d found)", (int)community_themes_.size());
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Place .hth files in the themes/ folder");

    if (!community_themes_.empty()) {
        for (int i = 0; i < (int)community_themes_.size(); i++) {
            auto& tf = community_themes_[i];
            auto lbl = fmt::format("{}##ct{}", tf.name, i);
            if (ImGui::Selectable(lbl.c_str())) {
                if (custom_colors_.import_hth(tf.path)) {
                    settings_.accent_color[0] = custom_colors_.accent[0];
                    settings_.accent_color[1] = custom_colors_.accent[1];
                    settings_.accent_color[2] = custom_colors_.accent[2];
                    settings_.bg_color[0] = custom_colors_.bg[0];
                    settings_.bg_color[1] = custom_colors_.bg[1];
                    settings_.bg_color[2] = custom_colors_.bg[2];
                    settings_.text_color[0] = custom_colors_.text[0];
                    settings_.text_color[1] = custom_colors_.text[1];
                    settings_.text_color[2] = custom_colors_.text[2];
                    settings_.theme_index = 3;
                    g_theme = Theme::Custom;
                    theme_changed_ = true;
                    save_all();
                }
            }
        }
    } else {
        ImGui::TextDisabled("Drop .hth files in the themes/ folder");
    }
}

void SettingsPanel::render_editor_tab() {
    bool changed = false;

    ImGui::SeparatorText("Disassembly View");
    ImGui::BeginGroup();
    changed |= ImGui::Checkbox("Show bytes in disassembly", &settings_.show_bytes);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Show raw hex bytes next to instructions");
    if (settings_.show_bytes) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(100);
        changed |= ImGui::SliderInt("Max bytes", &settings_.max_bytes, 1, 16, "%d");
    }
    ImGui::EndGroup();

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Formatting");
    ImGui::BeginGroup();
    ImGui::SetNextItemWidth(200);
    const char* widths[] = {"16 chars", "8 chars"};
    int idx = settings_.address_width == 8 ? 1 : 0;
    if (ImGui::Combo("Address width", &idx, widths, 2)) {
        settings_.address_width = idx == 1 ? 8 : 16;
        changed = true;
    }

    ImGui::SetNextItemWidth(200);
    const char* tabs[] = {"2", "4", "8"};
    int tab_idx = settings_.tab_size == 2 ? 0 : settings_.tab_size == 8 ? 2 : 1;
    if (ImGui::Combo("Tab size (pseudo-code)", &tab_idx, tabs, 3)) {
        settings_.tab_size = tab_idx == 0 ? 2 : tab_idx == 2 ? 8 : 4;
        changed = true;
    }
    ImGui::EndGroup();

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Behavior");
    changed |= ImGui::Checkbox("Auto-beautify on load", &settings_.auto_beautify);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Automatically format decompiled output on file load");

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Custom Font");
    ImGui::SetNextItemWidth(400);
    changed |= ImGui::InputText("Monospace font path", settings_.mono_font_path, sizeof(settings_.mono_font_path));
    if (ImGui::IsItemDeactivatedAfterEdit()) font_rebuild_ = true;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Full path to a .ttf file (leave empty for default)");

    if (changed) save_all();
}

void SettingsPanel::render_keybinds_tab() {
    if (ImGui::Button("Reset to Defaults")) {
        keybinds_.set_defaults();
        rebuild_keybind_display();
        save_all();
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Restore all keybinds to factory defaults");

    ImGui::Spacing(); ImGui::Spacing();
    if (ImGui::BeginTable("##keybinds_tbl", 3,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY
        | ImGuiTableFlags_PadOuterX,
        ImVec2(0, -1))) {
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Key", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("##change", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableHeadersRow();

        int row_idx = 0;
        for (auto& [action, display] : keybind_display_) {
            ImGui::TableNextRow();

            if (row_idx % 2 == 0) {
                ImU32 row_col = ImGui::ColorConvertFloat4ToU32(ImVec4(0.15f, 0.15f, 0.18f, 1.0f));
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, row_col);
            } else {
                ImU32 row_col = ImGui::ColorConvertFloat4ToU32(ImVec4(0.12f, 0.12f, 0.14f, 1.0f));
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, row_col);
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(action.c_str());
            ImGui::TableNextColumn();

            if (listening_action_ == action) {
                ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "Press a key...");

                for (auto& kv : g_key_table) {
                    if (ImGui::IsKeyPressed(kv.key)) {
                        auto& io = ImGui::GetIO();
                        keybinds_.set(action, kv.key, io.KeyCtrl, io.KeyShift, io.KeyAlt);
                        listening_action_.clear();
                        rebuild_keybind_display();
                        save_all();
                        break;
                    }
                }
            } else {
                ImGui::TextUnformatted(display.c_str());
            }

            ImGui::TableNextColumn();
            ImGui::PushID(action.c_str());
            if (listening_action_ == action) {
                if (ImGui::SmallButton("Cancel"))
                    listening_action_.clear();
            } else {
                if (ImGui::SmallButton("Change"))
                    listening_action_ = action;
            }
            ImGui::PopID();
            row_idx++;
        }
        ImGui::EndTable();
    }
}

void SettingsPanel::render_advanced_tab() {
    bool changed = false;

    ImGui::SeparatorText("Performance");
    ImGui::BeginGroup();
    ImGui::SetNextItemWidth(200);
    changed |= ImGui::SliderInt("Max analysis threads", &settings_.max_threads, 0, 32, "%d");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("0 = automatic (uses all cores)");

    ImGui::SetNextItemWidth(200);
    changed |= ImGui::SliderInt("Max decompiler blocks", &settings_.max_decompiler_blocks, 50, 2000, "%d");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Limit graph complexity for decompilation");
    ImGui::EndGroup();

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SeparatorText("Saving");
    ImGui::SetNextItemWidth(200);
    changed |= ImGui::SliderInt("Auto-save interval", &settings_.autosave_interval, 10, 600, "%d sec");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("How often the database is auto-saved");

    if (changed) save_all();
}

}

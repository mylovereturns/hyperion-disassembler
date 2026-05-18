#include "ui_utils.h"
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <commdlg.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <cstdio>
#else
#include <unistd.h>
#include <limits.h>
#include <cstdio>
#endif

namespace hype::ui {

std::filesystem::path get_exe_directory() {
#ifdef _WIN32
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::filesystem::path(buf).parent_path();
#elif defined(__APPLE__)
    char buf[1024];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0)
        return std::filesystem::path(buf).parent_path();
    return std::filesystem::current_path();
#else
    char buf[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", buf, PATH_MAX);
    if (count != -1)
        return std::filesystem::path(std::string(buf, count)).parent_path();
    return std::filesystem::current_path();
#endif
}

std::string open_file_dialog(const std::string& title, const std::string& filter) {
#ifdef _WIN32
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrTitle = title.c_str();
    // Simple filter conversion for Windows
    std::string win_filter = filter;
    if (win_filter.empty()) {
        win_filter = "All Files\0*.*\0";
    } else {
        // Assume format "Description|*.ext;*.ext2"
        size_t pipe = win_filter.find('|');
        if (pipe != std::string::npos) {
            std::string desc = win_filter.substr(0, pipe);
            std::string ext = win_filter.substr(pipe + 1);
            win_filter = desc + '\0' + ext + "\0All Files\0*.*\0";
        }
    }
    ofn.lpstrFilter = win_filter.c_str();
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&ofn)) return path;
#elif defined(__APPLE__)
    std::string cmd = "osascript -e 'POSIX path of (choose file with prompt \"" + title + "\")'";
    FILE* f = popen(cmd.c_str(), "r");
    if (f) {
        char buf[1024] = {};
        if (fgets(buf, sizeof(buf), f)) {
            pclose(f);
            std::string result(buf);
            while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
                result.pop_back();
            return result;
        }
        pclose(f);
    }
#else
    std::string cmd = "zenity --file-selection --title='" + title + "' 2>/dev/null || kdialog --getopenfilename . 2>/dev/null";
    FILE* f = popen(cmd.c_str(), "r");
    if (f) {
        char buf[1024] = {};
        if (fgets(buf, sizeof(buf), f)) {
            pclose(f);
            std::string result(buf);
            while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
                result.pop_back();
            return result;
        }
        pclose(f);
    }
#endif
    return {};
}

std::string save_file_dialog(const std::string& title, const std::string& filter, const std::string& default_ext) {
#ifdef _WIN32
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrTitle = title.c_str();
    std::string win_filter = filter;
    if (win_filter.empty()) {
        win_filter = "All Files\0*.*\0";
    } else {
        size_t pipe = win_filter.find('|');
        if (pipe != std::string::npos) {
            std::string desc = win_filter.substr(0, pipe);
            std::string ext = win_filter.substr(pipe + 1);
            win_filter = desc + '\0' + ext + "\0All Files\0*.*\0";
        }
    }
    ofn.lpstrFilter = win_filter.c_str();
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = default_ext.empty() ? nullptr : default_ext.c_str();
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    if (GetSaveFileNameA(&ofn)) return path;
#elif defined(__APPLE__)
    std::string cmd = "osascript -e 'POSIX path of (choose file name with prompt \"" + title + "\")'";
    FILE* f = popen(cmd.c_str(), "r");
    if (f) {
        char buf[1024] = {};
        if (fgets(buf, sizeof(buf), f)) {
            pclose(f);
            std::string result(buf);
            while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
                result.pop_back();
            return result;
        }
        pclose(f);
    }
#else
    std::string cmd = "zenity --file-selection --save --title='" + title + "' 2>/dev/null || kdialog --getsavefilename . 2>/dev/null";
    FILE* f = popen(cmd.c_str(), "r");
    if (f) {
        char buf[1024] = {};
        if (fgets(buf, sizeof(buf), f)) {
            pclose(f);
            std::string result(buf);
            while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
                result.pop_back();
            return result;
        }
        pclose(f);
    }
#endif
    return {};
}

std::vector<FontEntry> scan_system_fonts() {
    std::vector<FontEntry> result;
#ifdef _WIN32
    static constexpr const char* candidates[][2] = {
        {"Segoe UI",        "C:\\Windows\\Fonts\\segoeui.ttf"},
        {"Consolas",        "C:\\Windows\\Fonts\\consola.ttf"},
        {"Cascadia Code",   "C:\\Windows\\Fonts\\CascadiaCode.ttf"},
        {"JetBrains Mono",  "C:\\Windows\\Fonts\\JetBrainsMono-Regular.ttf"},
        {"Fira Code",       "C:\\Windows\\Fonts\\FiraCode-Regular.ttf"},
    };
    for (auto& c : candidates) {
        if (std::filesystem::exists(c[1]))
            result.push_back({c[0], c[1]});
    }
#elif defined(__APPLE__)
    static constexpr const char* candidates[][2] = {
        {"SFNS",            "/System/Library/Fonts/SFNS.ttf"},
        {"SF Mono",         "/System/Library/Fonts/SFNSMono.ttf"},
        {"Menlo",           "/System/Library/Fonts/Menlo.ttc"},
        {"Monaco",          "/System/Library/Fonts/Monaco.ttf"},
    };
    for (auto& c : candidates) {
        if (std::filesystem::exists(c[1]))
            result.push_back({c[0], c[1]});
    }
#else
    static constexpr const char* candidates[][2] = {
        {"DejaVu Sans",      "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"},
        {"DejaVu Sans Mono", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"},
        {"Ubuntu",           "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf"},
        {"Ubuntu Mono",      "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf"},
    };
    for (auto& c : candidates) {
        if (std::filesystem::exists(c[1]))
            result.push_back({c[0], c[1]});
    }
#endif
    return result;
}

}

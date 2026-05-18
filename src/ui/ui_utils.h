#pragma once
#include <string>
#include <filesystem>
#include <vector>

namespace hype::ui {

std::filesystem::path get_exe_directory();
std::string open_file_dialog(const std::string& title, const std::string& filter = "");
std::string save_file_dialog(const std::string& title, const std::string& filter = "", const std::string& default_ext = "");

struct FontEntry {
    std::string name;
    std::string path;
};
std::vector<FontEntry> scan_system_fonts();

}

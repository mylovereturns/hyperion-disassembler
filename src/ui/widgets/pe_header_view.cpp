#include "pe_header_view.h"
#include <fmt/format.h>
#include <cstring>
#include <ctime>

namespace hype {

namespace {

template<typename T>
T rd(const u8* p) { T v; std::memcpy(&v, p, sizeof(T)); return v; }

const char* machine_str(u16 machine) {
    switch (machine) {
    case 0x014C: return "i386";
    case 0x8664: return "AMD64";
    case 0xAA64: return "ARM64";
    case 0x01C4: return "ARM";
    default: return "Unknown";
    }
}

std::string timestamp_str(u32 ts) {
    if (ts == 0) return "0";
    time_t t = static_cast<time_t>(ts);
    char buf[64];
    struct tm tm_val{};
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_val);
    return buf;
}

std::string section_flags_str(u32 ch) {
    std::string s;
    if (ch & 0x00000020) s += "CODE ";
    if (ch & 0x00000040) s += "IDATA ";
    if (ch & 0x00000080) s += "UDATA ";
    if (ch & 0x02000000) s += "DISCARDABLE ";
    if (ch & 0x04000000) s += "NOT_CACHED ";
    if (ch & 0x08000000) s += "NOT_PAGED ";
    if (ch & 0x10000000) s += "SHARED ";
    if (ch & 0x20000000) s += "EXEC ";
    if (ch & 0x40000000) s += "READ ";
    if (ch & 0x80000000) s += "WRITE ";
    if (s.empty()) s = "NONE";
    return s;
}

const char* data_dir_names[] = {
    "Export", "Import", "Resource", "Exception",
    "Security", "BaseReloc", "Debug", "Architecture",
    "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
    "IAT", "DelayImport", "CLR", "Reserved"
};

}

void PEHeaderView::render() {
    if (!visible_) return;
    ImGui::Begin("PE Headers", &visible_);
    if (!img_ || img_->raw.empty()) {
        ImGui::TextDisabled("No binary loaded");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("##pe_tabs")) {
        if (ImGui::BeginTabItem("DOS Header")) { render_dos_header(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("NT Headers")) { render_nt_headers(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Optional Header")) { render_optional_header(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Data Directories")) { render_data_directories(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Sections")) { render_sections(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Packer Detection")) { render_packer_detection(); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

void PEHeaderView::render_dos_header() {
    if (img_->raw.size() < 64) return;
    const u8* d = img_->raw.data();

    u16 e_magic = rd<u16>(d);
    u32 e_lfanew = rd<u32>(d + 0x3C);

    if (ImGui::BeginTable("##dos", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Value");
        ImGui::TableHeadersRow();

        auto row = [](const char* f, const std::string& v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(f);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
        };

        row("e_magic", fmt::format("0x{:04X} ({})", e_magic, e_magic == 0x5A4D ? "MZ" : "?"));
        row("e_lfanew", fmt::format("0x{:X}", e_lfanew));
        ImGui::EndTable();
    }
}

void PEHeaderView::render_nt_headers() {
    if (img_->raw.size() < 64) return;
    const u8* d = img_->raw.data();
    u32 pe_off = rd<u32>(d + 0x3C);
    if (pe_off + 24 > img_->raw.size()) return;

    const u8* nt = d + pe_off;
    u32 sig = rd<u32>(nt);
    u16 machine = rd<u16>(nt + 4);
    u16 num_sections = rd<u16>(nt + 6);
    u32 timestamp = rd<u32>(nt + 8);
    u16 opt_hdr_sz = rd<u16>(nt + 20);
    u16 characteristics = rd<u16>(nt + 22);

    if (ImGui::BeginTable("##nth", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Value");
        ImGui::TableHeadersRow();

        auto row = [](const char* f, const std::string& v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(f);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
        };

        row("Signature", fmt::format("0x{:08X} ({})", sig, sig == 0x4550 ? "PE" : "?"));
        row("Machine", fmt::format("0x{:04X} ({})", machine, machine_str(machine)));
        row("NumberOfSections", fmt::format("{}", num_sections));
        row("TimeDateStamp", fmt::format("0x{:08X} ({})", timestamp, timestamp_str(timestamp)));
        row("SizeOfOptionalHeader", fmt::format("0x{:X}", opt_hdr_sz));
        row("Characteristics", fmt::format("0x{:04X}", characteristics));
        ImGui::EndTable();
    }
}

void PEHeaderView::render_optional_header() {
    if (img_->raw.size() < 64) return;
    const u8* d = img_->raw.data();
    u32 pe_off = rd<u32>(d + 0x3C);
    if (pe_off + 24 > img_->raw.size()) return;

    const u8* opt = d + pe_off + 24;
    size_t opt_avail = img_->raw.size() - (pe_off + 24);
    if (opt_avail < 72) return;
    u16 magic = rd<u16>(opt);
    bool pe32plus = (magic == 0x020B);
    size_t min_opt = pe32plus ? 112 : 96;
    if (opt_avail < min_opt) return;

    if (ImGui::BeginTable("##opth", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 220);
        ImGui::TableSetupColumn("Value");
        ImGui::TableHeadersRow();

        auto row = [](const char* f, const std::string& v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(f);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
        };

        row("Magic", fmt::format("0x{:04X} ({})", magic, pe32plus ? "PE32+" : "PE32"));
        row("AddressOfEntryPoint", fmt::format("0x{:X}", rd<u32>(opt + 16)));
        if (pe32plus) {
            row("ImageBase", fmt::format("0x{:X}", rd<u64>(opt + 24)));
        } else {
            row("ImageBase", fmt::format("0x{:X}", rd<u32>(opt + 28)));
        }
        row("SectionAlignment", fmt::format("0x{:X}", rd<u32>(opt + 32)));
        row("FileAlignment", fmt::format("0x{:X}", rd<u32>(opt + 36)));
        row("SizeOfImage", fmt::format("0x{:X}", rd<u32>(opt + 56)));
        row("SizeOfHeaders", fmt::format("0x{:X}", rd<u32>(opt + 60)));
        row("Subsystem", fmt::format("{}", rd<u16>(opt + 68)));
        row("NumberOfRvaAndSizes", fmt::format("{}",
            rd<u32>(opt + (pe32plus ? 108 : 92))));
        ImGui::EndTable();
    }
}

void PEHeaderView::render_data_directories() {
    if (img_->raw.size() < 64) return;
    const u8* d = img_->raw.data();
    u32 pe_off = rd<u32>(d + 0x3C);
    if (pe_off + 24 > img_->raw.size()) return;
    const u8* opt = d + pe_off + 24;
    size_t opt_avail = img_->raw.size() - (pe_off + 24);
    if (opt_avail < 96) return;
    u16 magic = rd<u16>(opt);
    bool pe32plus = (magic == 0x020B);
    u32 dd_offset = pe32plus ? 112 : 96;
    size_t min_needed = pe32plus ? 112 : 96;
    if (opt_avail < min_needed) return;
    u32 num_dd = rd<u32>(opt + (pe32plus ? 108 : 92));
    if (num_dd > 16) num_dd = 16;

    const u8* dd_base = opt + dd_offset;
    if (opt_avail < dd_offset + num_dd * 8) return;

    if (ImGui::BeginTable("##dd", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Directory", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("Size");
        ImGui::TableHeadersRow();

        for (u32 i = 0; i < num_dd; ++i) {
            u32 rva = rd<u32>(dd_base + i * 8);
            u32 size = rd<u32>(dd_base + i * 8 + 4);
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(data_dir_names[i]);
            ImGui::TableNextColumn(); ImGui::Text("0x%08X", rva);
            ImGui::TableNextColumn(); ImGui::Text("0x%X", size);
        }
        ImGui::EndTable();
    }
}

void PEHeaderView::render_sections() {
    if (ImGui::BeginTable("##secs", 6,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("VirtualAddr", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("VirtualSize", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("RawSize", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("RawOffset", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("Characteristics");
        ImGui::TableHeadersRow();

        for (auto& seg : img_->segments) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(seg.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)seg.va);
            ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)seg.size);
            ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)seg.file_sz);
            ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)seg.file_off);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(section_flags_str(seg.flags).c_str());
        }
        ImGui::EndTable();
    }
}

void PEHeaderView::render_packer_detection() {
    if (!packer_results_ || packer_results_->empty()) {
        ImGui::TextColored(ImVec4(0.4f, 1.f, 0.4f, 1.f), "No packer detected");
        return;
    }

    ImGui::TextColored(ImVec4(1.f, 0.6f, 0.2f, 1.f), "Packed binary detected!");
    ImGui::Spacing();

    if (ImGui::BeginTable("##packer", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Packer", ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("Details");
        ImGui::TableHeadersRow();

        for (auto& pi : *packer_results_) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(pi.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.0f%%", pi.confidence * 100);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(pi.details.c_str());
        }
        ImGui::EndTable();
    }
}

}

#define NOMINMAX
#include "app.h"
#include "ui/theme.h"
#include "ui/fonts.h"
#include "core/analysis/packer_detect.h"
#include "core/loader/dotnet_loader.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <thread>
#include <fstream>
#include <cstring>
#include <cmath>

#ifdef _WIN32
#include <windows.h>
#include <commdlg.h>
#endif

namespace hype {

namespace {
std::string open_dialog() {
#ifdef _WIN32
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "All Binaries\0*.exe;*.dll;*.sys;*.so;*.dylib;*.elf;*.bin;*.o\0All Files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&ofn)) return path;
#elif defined(__APPLE__)
    FILE* f = popen("osascript -e 'POSIX path of (choose file with prompt \"Open Binary\")'", "r");
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
    FILE* f = popen("zenity --file-selection --title='Open Binary' 2>/dev/null || kdialog --getopenfilename . 2>/dev/null", "r");
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

std::string save_dialog() {
#ifdef _WIN32
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "All Binaries\0*.exe;*.dll;*.sys;*.so;*.dylib;*.elf;*.bin;*.o\0All Files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    if (GetSaveFileNameA(&ofn)) return path;
#elif defined(__APPLE__)
    FILE* f = popen("osascript -e 'POSIX path of (choose file name with prompt \"Save As\")'", "r");
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
    FILE* f = popen("zenity --file-selection --save --title='Save As' 2>/dev/null || kdialog --getsavefilename . 2>/dev/null", "r");
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
}

App::App() : pool_(std::thread::hardware_concurrency()) {
    settings_panel_.load_all();
    auto nav = [this](va_t a) { navigate_to(a); };
    dv_.set_nav(nav);
    dv_.set_undo(&undo_);
    dv_.set_stack_frame_view(&sfv_);
    dv_.set_sig_cb([this](va_t a) {
        va_t func = find_func_for(a);
        if (func) sigmaker_.generate_for_function(func);
        else sigmaker_.generate_for_range(a, 64);
        sigmaker_.visible() = true;
    });
    fp_.set_nav([this](va_t a) { navigate_to(a); sync_panels(a); });
    xp_.set_nav(nav);
    sp_.set_nav(nav);
    ip_.set_nav(nav);
    gv_.set_nav(nav);
    pv_.set_nav([this](va_t a) { navigate_to(a); });
    srch_.set_nav(nav);
    ev_.set_nav(nav);
    cgv_.set_nav(nav);
    diffv_.set_nav(nav);
    clsv_.set_nav(nav);
    scriptc_.set_nav(nav);
    load_recent_files();
    last_autosave_ = std::chrono::steady_clock::now();
}

App::~App() = default;

int App::run() {
    if (!renderer_.init(1600, 900, "Hyperion v" HYPERION_VERSION))
        return 1;

    renderer_.set_drop_callback([this](const char* p) { open_file(p); });
    {
        auto& ct = settings_panel_.custom_theme();
        g_custom_theme.bg[0] = ct.bg[0]; g_custom_theme.bg[1] = ct.bg[1]; g_custom_theme.bg[2] = ct.bg[2]; g_custom_theme.bg[3] = ct.bg[3];
        g_custom_theme.text[0] = ct.text[0]; g_custom_theme.text[1] = ct.text[1]; g_custom_theme.text[2] = ct.text[2]; g_custom_theme.text[3] = ct.text[3];
        g_custom_theme.accent[0] = ct.accent[0]; g_custom_theme.accent[1] = ct.accent[1]; g_custom_theme.accent[2] = ct.accent[2]; g_custom_theme.accent[3] = ct.accent[3];
        g_custom_theme.surface[0] = ct.surface[0]; g_custom_theme.surface[1] = ct.surface[1]; g_custom_theme.surface[2] = ct.surface[2]; g_custom_theme.surface[3] = ct.surface[3];
        g_custom_theme.border[0] = ct.border[0]; g_custom_theme.border[1] = ct.border[1]; g_custom_theme.border[2] = ct.border[2]; g_custom_theme.border[3] = ct.border[3];
    }
    apply_theme();
    out_.log("Hyperion v" HYPERION_VERSION " ready");
    out_.log("Drop a PE file or use File > Open (Ctrl+O)");

    // Load plugins from plugins/ dir next to the executable (main thread, pre-loop)
    {
        auto plugin_dir = std::filesystem::path("plugins");
        lua_.load_plugins(plugin_dir);
        auto& loaded = lua_.plugins();
        if (!loaded.empty()) {
            int ok = 0, bad = 0;
            for (auto& p : loaded) (p.error ? bad : ok)++;
            out_.log(fmt::format("Plugins: {} loaded, {} error(s)", ok, bad));
        }
    }

    while (!renderer_.should_close()) {
        renderer_.begin_frame();

        // pick up analysis completion on main thread (thread-safe handoff)
        if (analysis_done_.exchange(false)) {
            busy_ = false;
            auto& db = analyzer_->db();
            dv_.set_data(&db, img_.get());
            hv_.set_data(img_.get());
            hv_.goto_addr(img_->entry);
            pv_.set_data(&db, &analyzer_->rtti_parser());
            fp_.set_data(&db);
            xp_.set_data(&db);
            xp_.set_img(img_.get());
            sp_.set_data(&db);
            ip_.set_data(img_.get());
            ip_.set_db(&db);
            gv_.set_data(&db);
            srch_.set_data(&db, img_.get());
            ev_.set_data(img_.get());
            cgv_.set_data(&db);
            tp_.set_data(&db);
            sfv_.set_data(&db);
            navigate_to(img_->entry);
            sync_panels(img_->entry);
            out_.log(fmt::format("Done: {} insns, {} funcs, {} xrefs, {} strings",
                db.insns.size(), db.funcs.size(), db.xrefs.size(), db.strings.size()));
            if (!analyzer_->rtti_parser().classes().empty())
                out_.log(fmt::format("RTTI: found {} classes", analyzer_->rtti_parser().classes().size()));
            clsv_.set_data(&analyzer_->rtti_parser(), &db);
            
            // PDB loading
            auto pdb_path = PDBLoader::pdb_for(std::filesystem::path(file_path_));
            if (!pdb_path.empty()) {
                pdb_.load(pdb_path, img_->base, analyzer_->db());
                out_.log(pdb_.status());
            } else {
                out_.log("No PDB found. For better analysis, place the .pdb next to the binary.");
            }

            // Lua scripting engine init
            lua_.init(&analyzer_->db(), img_.get());
            lua_.set_navigate_cb([this](va_t a) { navigate_to(a); sync_panels(a); });
            scriptc_.set_engine(&lua_);
            sigmaker_.set_data(&db, img_.get());
            sigmaker_.set_nav([this](va_t a) { navigate_to(a); sync_panels(a); });
            rebuild_nav_band();
            // Fire on_analysis_complete plugin callbacks
            lua_.run_analysis_complete_callbacks();
        }

        if (diff_done_.exchange(false)) {
            diffv_.set_results(diff_results_);
            out_.log(fmt::format("Diff complete: {} results", diff_results_.size()));
        }

        render_dockspace();
        handle_keys();
        render_menubar();

        dv_.render();
        hv_.render();
        pv_.render();
        fp_.render();
        xp_.render();
        sp_.render();
        ip_.render();
        gv_.render();
        out_.render();
        srch_.render();
        ev_.render();
        cgv_.render();
        tp_.render();
        diffv_.render();
        sfv_.render();
        pehv_.render();
        clsv_.render();
        scriptc_.render();
        sigmaker_.render();
        settings_panel_.render();

        if (show_plugin_manager_) render_plugin_manager();
        render_results_windows();

        if (settings_panel_.theme_changed()) {
            auto& ct = settings_panel_.custom_theme();
            g_custom_theme.bg[0] = ct.bg[0]; g_custom_theme.bg[1] = ct.bg[1]; g_custom_theme.bg[2] = ct.bg[2]; g_custom_theme.bg[3] = ct.bg[3];
            g_custom_theme.text[0] = ct.text[0]; g_custom_theme.text[1] = ct.text[1]; g_custom_theme.text[2] = ct.text[2]; g_custom_theme.text[3] = ct.text[3];
            g_custom_theme.accent[0] = ct.accent[0]; g_custom_theme.accent[1] = ct.accent[1]; g_custom_theme.accent[2] = ct.accent[2]; g_custom_theme.accent[3] = ct.accent[3];
            g_custom_theme.surface[0] = ct.surface[0]; g_custom_theme.surface[1] = ct.surface[1]; g_custom_theme.surface[2] = ct.surface[2]; g_custom_theme.surface[3] = ct.surface[3];
            g_custom_theme.border[0] = ct.border[0]; g_custom_theme.border[1] = ct.border[1]; g_custom_theme.border[2] = ct.border[2]; g_custom_theme.border[3] = ct.border[3];
            apply_theme();
            settings_panel_.clear_theme_changed();
        }

        {
            auto& s = ImGui::GetStyle();
            auto& st = settings_panel_.settings();
            s.WindowRounding = st.border_radius;
            s.ChildRounding = st.border_radius;
            s.FrameRounding = st.border_radius;
            s.PopupRounding = st.border_radius;
            s.TabRounding = st.border_radius * 0.5f;
            s.GrabRounding = st.border_radius;
            s.ScrollbarSize = st.scrollbar_width;
            s.Alpha = st.window_opacity;
        }

        autosave_tick();

        if (show_goto_)     show_goto_dlg();
        if (show_rename_)   show_rename_dlg();
        if (show_rebase_)   show_rebase_dlg();
        if (show_comment_)  show_comment_dlg();
        if (show_segments_) show_segments_dlg();
        if (show_bookmarks_) show_bookmarks_dlg();
        if (show_sigs_) show_sigs_dlg();
        if (show_apply_type_) show_apply_type_dlg();

        // status bar
        {
            std::string left_str;
            if (analyzer_) {
                auto cur = dv_.cursor();
                auto func_entry = find_func_for(cur);
                std::string fname;
                if (func_entry) {
                    auto nit = analyzer_->db().names.find(func_entry);
                    fname = nit != analyzer_->db().names.end() ? nit->second :
                        analyzer_->db().funcs.count(func_entry) ? analyzer_->db().funcs.at(func_entry).name : "";
                }
                left_str = fmt::format("0x{:X}", cur);
                if (!fname.empty()) left_str += "  " + fname;
            }

            auto center_str = file_path_.empty() ? "No file loaded" :
                std::filesystem::path(file_path_).filename().string();

            std::string right_str;
            if (analyzer_) {
                auto arch_str = [](Arch a) -> const char* {
                    switch (a) {
                    case Arch::X86:   return "x86";
                    case Arch::X64:   return "x64";
                    case Arch::ARM:   return "ARM";
                    case Arch::ARM64: return "ARM64";
                    case Arch::MIPS:  return "MIPS";
                    case Arch::PPC:   return "PPC";
                    }
                    return "?";
                };
                right_str = fmt::format("{}  |  {} insns",
                    arch_str(img_->arch), analyzer_->db().insns.size());
            }

            render_status_bar(left_str.c_str(), center_str.c_str(), right_str.c_str());
        }

        renderer_.end_frame();
    }

    renderer_.shutdown();
    return 0;
}

void App::open_file(const char* path) {
    if (busy_) return;

    out_.log(fmt::format("Loading: {}", path));
    file_path_ = path;

    dv_.set_data(nullptr, nullptr);
    hv_.set_data(nullptr);
    pv_.set_data(nullptr);
    fp_.set_data(nullptr);
    xp_.set_data(nullptr);
    sp_.set_data(nullptr);
    ip_.set_data(nullptr);
    ip_.set_db(nullptr);
    gv_.set_data(nullptr);
    srch_.set_data(nullptr, nullptr);
    ev_.set_data(nullptr);
    cgv_.set_data(nullptr);
    tp_.set_data(nullptr);
    sfv_.set_data(nullptr);
    pehv_.set_data(nullptr);
    sigmaker_.set_data(nullptr, nullptr);

    // detect file format by magic bytes
    std::ifstream probe(path, std::ios::binary);
    if (!probe) { out_.log("ERROR: cannot open file"); return; }
    u8 magic_bytes[4] = {};
    probe.read(reinterpret_cast<char*>(magic_bytes), 4);
    probe.close();

    u32 magic = 0;
    std::memcpy(&magic, magic_bytes, 4);

    std::optional<PEImage> result;
    if (magic_bytes[0] == 'M' && magic_bytes[1] == 'Z') {
        result = loader_.load(path);
        // check if .NET
        if (result) {
            DotNetLoader dnl;
            if (dnl.detect(*result)) {
                img_ = std::make_unique<PEImage>(std::move(*result));
                dnl.load(*img_);
                out_.log(fmt::format(".NET binary: {} types, {} methods",
                    dnl.image().types.size(), dnl.image().methods.size()));
                // populate DB with IL methods instead of running native analysis
                (void)0; // .NET path - no native analysis needed
                // create a minimal analyzer just for the DB
                busy_ = false;
                analysis_done_ = false;
                // use dotnet data directly
                static AnalysisDB* static_db = nullptr;
                if (static_db) delete static_db;
                static_db = new AnalysisDB();
                static_db->image_base = img_->base;
                dnl.populate_db(*static_db, *img_);
                analyzer_ = nullptr;
                dv_.set_data(static_db, img_.get());
                fp_.set_data(static_db);
                sp_.set_data(static_db);
                xp_.set_data(static_db);
                gv_.set_data(static_db);
                pv_.set_data(static_db);
                cgv_.set_data(static_db);
                srch_.set_data(static_db, img_.get());
                hv_.set_data(img_.get());
                ev_.set_data(img_.get());
                ip_.set_data(img_.get());
                ip_.set_db(static_db);
                out_.log(fmt::format("Done: {} IL methods loaded", static_db->funcs.size()));
                if (!static_db->funcs.empty())
                    navigate_to(static_db->funcs.begin()->second.entry);
                return;
            }
        }
    } else if (magic == 0x464C457F) {
        result = elf_loader_.load(path);
    } else {
        out_.log("ERROR: unsupported file format (expected PE or ELF)");
        return;
    }

    if (!result) { out_.log("ERROR: load failed"); return; }

    img_ = std::make_unique<PEImage>(std::move(*result));
    pehv_.set_data(img_.get());
    add_recent_file(file_path_);

    PackerDetector pdet;
    packer_results_ = pdet.detect(*img_);
    pehv_.set_packer_results(&packer_results_);
    for (auto& pi : packer_results_) {
        out_.log(fmt::format("[!] Packed binary detected: {} (confidence: {:.0f}%)", pi.name, pi.confidence * 100));
        out_.log("[!] Analysis may be incomplete - consider unpacking first");
    }

    auto arch_str = [](Arch a) -> const char* {
        switch (a) {
        case Arch::X86:   return "x86";
        case Arch::X64:   return "x64";
        case Arch::ARM:   return "ARM";
        case Arch::ARM64: return "ARM64";
        case Arch::MIPS:  return "MIPS";
        case Arch::PPC:   return "PPC";
        }
        return "?";
    };
    out_.log(fmt::format("Base: 0x{:X}  Entry: 0x{:X}  Arch: {}",
        img_->base, img_->entry, arch_str(img_->arch)));
    out_.log(fmt::format("Sections: {}  Imports: {}  Exports: {}",
        img_->segments.size(), img_->imports.size(), img_->exports.size()));

    busy_ = true;
    analysis_done_ = false;
    analyzer_ = std::make_unique<Analyzer>(*img_, pool_);

    std::thread([this]() {
        analyzer_->run();
        analysis_done_ = true;
    }).detach();
}

void App::build_default_layout(ImGuiID dock_id) {
    ImGui::DockBuilderRemoveNode(dock_id);
    ImGui::DockBuilderAddNode(dock_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dock_id, ImGui::GetMainViewport()->WorkSize);

    ImGuiID center = dock_id;
    ImGuiID left   = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.20f, nullptr, &center);
    ImGuiID right  = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.35f, nullptr, &center);
    ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.25f, nullptr, &center);

    ImGui::DockBuilderDockWindow("Functions", left);
    ImGui::DockBuilderDockWindow("Strings", left);
    ImGui::DockBuilderDockWindow("Imports / Exports", left);
    ImGui::DockBuilderDockWindow("Types", left);
    ImGui::DockBuilderDockWindow("Classes", left);

    ImGui::DockBuilderDockWindow("Disassembly", center);
    ImGui::DockBuilderDockWindow("Hex View", center);

    ImGui::DockBuilderDockWindow("Pseudo Code", right);
    ImGui::DockBuilderDockWindow("Graph", center);
    ImGui::DockBuilderDockWindow("Call Graph", right);

    ImGui::DockBuilderDockWindow("Output", bottom);
    ImGui::DockBuilderDockWindow("Xrefs", bottom);
    ImGui::DockBuilderDockWindow("Search", bottom);
    ImGui::DockBuilderDockWindow("Entropy", bottom);
    ImGui::DockBuilderDockWindow("Diff View", bottom);
    ImGui::DockBuilderDockWindow("Stack Frame", bottom);
    ImGui::DockBuilderDockWindow("Script Console", bottom);

    ImGui::DockBuilderFinish(dock_id);
}

void App::render_dockspace() {
    ImGuiViewport* vp = ImGui::GetMainViewport();

    render_bg_image();

    // make windows semi-transparent when bg image is set
    bool has_bg = settings_panel_.bg_texture() != 0;
    if (has_bg) {
        float win_alpha = settings_panel_.settings().window_opacity;
        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.067f, 0.071f, 0.090f, win_alpha));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    }

    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::SetNextWindowViewport(vp->ID);

    ImGuiWindowFlags fl = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_MenuBar;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##dock", nullptr, fl);
    ImGui::PopStyleVar(3);

    ImGuiID dock_id = ImGui::GetID("HyperionDock");
    if (!layout_built_) {
        build_default_layout(dock_id);
        layout_built_ = true;
    }

    render_nav_band();

    float status_h = 24.0f;
    ImGui::DockSpace(dock_id, ImVec2(0, -status_h), ImGuiDockNodeFlags_PassthruCentralNode);

    if (busy_) {
        ImVec2 sz = vp->WorkSize;
        ImVec2 popup_sz(300, 80);
        ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + sz.x / 2 - popup_sz.x / 2,
                                       vp->WorkPos.y + sz.y / 2 - popup_sz.y / 2));
        ImGui::SetNextWindowSize(popup_sz);
        ImGui::Begin("##analyzing", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse);
        ImGui::Text("Analyzing...");
        float prog = analyzer_ ? analyzer_->progress() : 0;
        ImGui::ProgressBar(prog, ImVec2(-1, 0), fmt::format("{:.0f}%", prog * 100).c_str());
        ImGui::TextDisabled("Please wait");
        ImGui::End();
    }
    ImGui::End();
    if (has_bg) ImGui::PopStyleColor(2);
}

void App::render_menubar() {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 10));
    if (ImGui::BeginMainMenuBar()) {
        ImGui::PopStyleVar();
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(14, 8));
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open", "Ctrl+O")) {
                auto p = open_dialog();
                if (!p.empty()) open_file(p.c_str());
            }
            if (ImGui::BeginMenu("Recent Files", !recent_files_.empty())) {
                for (auto& rf : recent_files_) {
                    auto fname = std::filesystem::path(rf).filename().string();
                    if (ImGui::MenuItem(fname.c_str())) open_file(rf.c_str());
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", rf.c_str());
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Save Project", "Ctrl+S", false, img_ != nullptr && analyzer_ != nullptr)) {
                auto pp = std::filesystem::path(file_path_).replace_extension(".hdb");
                database_.save(pp, *img_, analyzer_->db());
                out_.log("Saved: " + pp.string());
            }
            if (ImGui::MenuItem("Export IDA Script", nullptr, false, img_ != nullptr && analyzer_ != nullptr)) {
                auto pp = std::filesystem::path(file_path_).replace_extension(".py");
                ida_exp_.write(pp, *img_, analyzer_->db());
                out_.log("Exported: " + pp.string());
            }
            if (ImGui::MenuItem("Export Patched Binary", nullptr, false, img_ != nullptr && analyzer_ != nullptr))
                export_patched();
            if (ImGui::BeginMenu("Export", img_ != nullptr && analyzer_ != nullptr)) {
                if (ImGui::MenuItem("Assembly Listing (.asm)")) export_asm();
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Compare With...", nullptr, false, img_ != nullptr && analyzer_ != nullptr))
                compare_with();
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4"))
                glfwSetWindowShouldClose(renderer_.window(), GLFW_TRUE);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Undo", "Ctrl+Z", false, undo_.can_undo())) {
                auto d = undo_.undo();
                out_.log("Undo: " + d);
            }
            if (ImGui::MenuItem("Redo", "Ctrl+Y", false, undo_.can_redo())) {
                auto d = undo_.redo();
                out_.log("Redo: " + d);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Rename", "N", false, analyzer_ != nullptr)) show_rename_ = true;
            if (ImGui::MenuItem("Comment", ";", false, analyzer_ != nullptr)) show_comment_ = true;
            if (ImGui::MenuItem("Bookmark", "Ctrl+B", false, analyzer_ != nullptr)) {
                add_bookmark(dv_.cursor(), "");
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Define Data", "D", false, analyzer_ != nullptr)) dv_.cmd_define_data();
            if (ImGui::MenuItem("Define String", "A", false, analyzer_ != nullptr)) dv_.cmd_define_string();
            if (ImGui::MenuItem("Undefine", "U", false, analyzer_ != nullptr)) dv_.cmd_undefine();
            if (ImGui::MenuItem("Force Code", "C", false, analyzer_ != nullptr)) dv_.cmd_force_code();
            if (ImGui::MenuItem("Toggle Hex", "H", false, analyzer_ != nullptr)) dv_.cmd_toggle_hex();
            if (ImGui::MenuItem("NOP Out", nullptr, false, analyzer_ != nullptr)) dv_.cmd_nop();
            ImGui::Separator();
            if (ImGui::MenuItem("Rebase...", nullptr, false, img_ != nullptr)) show_rebase_ = true;
            if (ImGui::MenuItem("Apply Signatures", nullptr, false, analyzer_ != nullptr)) {
                analyzer_->apply_signatures();
                out_.log("Signatures re-applied");
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Auto-save", nullptr, autosave_enabled_))
                autosave_enabled_ = !autosave_enabled_;
            ImGui::Separator();
            if (ImGui::MenuItem("Settings", "Ctrl+,"))
                settings_panel_.show();
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Types", "T", false, analyzer_ != nullptr)) {}
            if (ImGui::MenuItem("Segments", nullptr, false, img_ != nullptr)) show_segments_ = true;
            if (ImGui::MenuItem("PE Headers", nullptr, false, img_ != nullptr)) pehv_.visible_ = true;
            if (ImGui::MenuItem("Bookmarks", "Ctrl+M")) show_bookmarks_ = true;
            if (ImGui::MenuItem("Signatures", nullptr, false, analyzer_ != nullptr)) show_sigs_ = true;
            if (ImGui::MenuItem("Script Console", nullptr, false, true)) {}
            if (ImGui::MenuItem("SigMaker", "Ctrl+Shift+S", false, analyzer_ != nullptr))
                sigmaker_.visible() = true;
            ImGui::Separator();
            if (ImGui::BeginMenu("Theme")) {
                if (ImGui::MenuItem("Binary Ninja", nullptr, g_theme == Theme::BinaryNinja)) {
                    g_theme = Theme::BinaryNinja; apply_theme();
                }
                if (ImGui::MenuItem("IDA", nullptr, g_theme == Theme::IDA)) {
                    g_theme = Theme::IDA; apply_theme();
                }
                if (ImGui::MenuItem("Midnight", nullptr, g_theme == Theme::Midnight)) {
                    g_theme = Theme::Midnight; apply_theme();
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Reset Layout")) layout_built_ = false;
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Search")) {
            if (ImGui::MenuItem("Text Search", "Ctrl+F")) srch_.open_text();
            if (ImGui::MenuItem("Binary Search", "Alt+B")) srch_.open_binary();
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Navigate")) {
            if (ImGui::MenuItem("Go to", "G")) show_goto_ = true;
            if (ImGui::MenuItem("Back", "Alt+Left")) nav_back();
            if (ImGui::MenuItem("Forward", "Alt+Right")) nav_fwd();
            ImGui::Separator();
            if (ImGui::MenuItem("Entry Point", nullptr, false, img_ != nullptr))
                navigate_to(img_->entry);
            ImGui::EndMenu();
        }

        // ---- Plugins menu ----
        if (ImGui::BeginMenu("Plugins")) {
            if (ImGui::MenuItem("Plugin Manager..."))
                show_plugin_manager_ = true;
            ImGui::Separator();
            auto& plgs = lua_.plugins();
            if (plgs.empty()) {
                ImGui::TextDisabled("No plugins loaded");
                ImGui::TextDisabled("Place .lua files in plugins/");
            }
            for (int pi = 0; pi < static_cast<int>(plgs.size()); ++pi) {
                auto& plg = plgs[static_cast<size_t>(pi)];
                if (plg.error) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.f, 0.4f, 0.4f, 1.f));
                    ImGui::TextDisabled("[!] %s", plg.name.c_str());
                    ImGui::PopStyleColor();
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s", plg.error_msg.c_str());
                    continue;
                }
                if (plg.items.size() == 1) {
                    // Single action — flat menu item labelled by the action
                    if (ImGui::MenuItem(plg.items[0].label.c_str())) {
                        lua_.invoke_menu_item(pi, 0);
                        if (!lua_.last_output().empty()) {
                            scriptc_.append_output(lua_.last_output());
                            ImGui::SetWindowFocus("Script Console");
                        }
                    }
                } else if (!plg.items.empty()) {
                    // Multiple actions — submenu labelled by the plugin name
                    if (ImGui::BeginMenu(plg.name.c_str())) {
                        for (int ii = 0; ii < static_cast<int>(plg.items.size()); ++ii) {
                            if (ImGui::MenuItem(plg.items[static_cast<size_t>(ii)].label.c_str())) {
                                lua_.invoke_menu_item(pi, ii);
                                if (!lua_.last_output().empty()) {
                                    scriptc_.append_output(lua_.last_output());
                                    ImGui::SetWindowFocus("Script Console");
                                }
                            }
                        }
                        ImGui::EndMenu();
                    }
                } else {
                    // Plugin registered but added no menu items
                    ImGui::TextDisabled("%s", plg.name.c_str());
                }
            }
            ImGui::EndMenu();
        }

        float w = ImGui::GetWindowWidth();
        if (busy_) {
            ImGui::SameLine(w - 120);
            ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "Analyzing...");
        } else if (analyzer_) {
            ImGui::SameLine(w - 200);
            ImGui::TextDisabled("%llu insns | %llu funcs",
                (unsigned long long)analyzer_->db().insns.size(),
                (unsigned long long)analyzer_->db().funcs.size());
        }
        ImGui::PopStyleVar();
        ImGui::EndMainMenuBar();
    } else {
        ImGui::PopStyleVar();
    }
}

void App::handle_keys() {
    auto& io = ImGui::GetIO();
    if (io.WantTextInput) return;

    if (show_goto_ || show_rename_ || show_comment_ || show_rebase_)
        return;

    auto& kb = settings_panel_.keybinds();

    if (kb.check("goto")) show_goto_ = true;
    if (kb.check("rename")) show_rename_ = true;
    if (kb.check("comment")) show_comment_ = true;
    if (kb.check("xrefs")) {
        va_t xaddr = dv_.cursor();
        if (analyzer_) {
            auto iit = analyzer_->db().insns.find(xaddr);
            if (iit != analyzer_->db().insns.end() && iit->second.is_call()) {
                va_t t = iit->second.branch_target();
                if (t) xaddr = t;
            }
        }
        xp_.show_for(xaddr);
        xp_.show_popup(xaddr);
    }

    if (kb.check("data") && analyzer_) dv_.cmd_define_data();
    if (kb.check("string") && analyzer_) dv_.cmd_define_string();
    if (kb.check("undefine") && analyzer_) dv_.cmd_undefine();
    if (kb.check("code") && analyzer_) dv_.cmd_force_code();
    if (kb.check("hex") && analyzer_) dv_.cmd_toggle_hex();

    if (ImGui::IsKeyPressed(ImGuiKey_T) && !io.KeyCtrl && analyzer_) show_apply_type_ = true;

    if (kb.check("follow") && analyzer_) {
        auto* insn_ptr = analyzer_->db().insns.count(dv_.cursor()) ?
            &analyzer_->db().insns.at(dv_.cursor()) : nullptr;
        if (insn_ptr) {
            va_t t = insn_ptr->branch_target();
            if (t && analyzer_->db().insns.count(t)) {
                navigate_to(t);
                sync_panels(t);
            }
        }
    }

    if (kb.check("back")) {
        if (show_goto_ || show_rename_ || show_rebase_ || show_comment_ ||
            show_segments_ || show_bookmarks_ || show_sigs_ || show_apply_type_) {
            show_goto_ = show_rename_ = show_rebase_ = show_comment_ = false;
            show_segments_ = show_bookmarks_ = show_sigs_ = show_apply_type_ = false;
            ImGui::CloseCurrentPopup();
        } else {
            nav_back();
        }
    }

    // Ctrl shortcuts
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O)) {
        auto p = open_dialog();
        if (!p.empty()) open_file(p.c_str());
    }
    if (io.KeyCtrl && !io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_S) && img_ && analyzer_) {
        auto pp = std::filesystem::path(file_path_).replace_extension(".hdb");
        database_.save(pp, *img_, analyzer_->db());
        out_.log("Saved: " + pp.string());
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_B)) add_bookmark(dv_.cursor(), "");
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_M)) show_bookmarks_ = true;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F)) srch_.open_text();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z)) {
        if (undo_.can_undo()) { auto d = undo_.undo(); out_.log("Undo: " + d); }
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Y)) {
        if (undo_.can_redo()) { auto d = undo_.redo(); out_.log("Redo: " + d); }
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Comma)) settings_panel_.show();
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_B)) srch_.open_binary();
    if (io.KeyCtrl && io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_S) && analyzer_) {
        va_t func = find_func_for(dv_.cursor());
        if (func) sigmaker_.generate_for_function(func);
        sigmaker_.visible() = true;
    }
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) nav_back();
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow)) nav_fwd();

    if (ImGui::IsKeyPressed(ImGuiKey_Tab) && !io.KeyCtrl)
        sync_panels(dv_.cursor());

    // Plugin hotkeys (checked last, after built-in keys)
    lua_.check_hotkeys();

    if (kb.check("decompile")) {
        va_t func = find_func_for(dv_.cursor());
        if (func) {
            pv_.show_function(func);
            pv_.highlight_addr(dv_.cursor());
            ImGui::SetWindowFocus("Pseudo Code");
        }
    }

    if (kb.check("strings_panel"))
        ImGui::SetWindowFocus("Strings");

    if (kb.check("graph")) {
        static bool in_graph = false;
        in_graph = !in_graph;
        if (in_graph) {
            sync_panels(dv_.cursor());
            ImGui::SetWindowFocus("Graph");
        } else {
            ImGui::SetWindowFocus("Disassembly");
        }
    }

    if (kb.check("create_func") && analyzer_) {
        va_t cur = dv_.cursor();
        if (!analyzer_->db().funcs.count(cur)) {
            Function f; f.entry = cur; f.name = fmt::format("sub_{:X}", cur - analyzer_->db().image_base);
            analyzer_->db().funcs[cur] = std::move(f);
            analyzer_->db().names[cur] = analyzer_->db().funcs[cur].name;
            out_.log(fmt::format("Created function at {:X}", cur));
        }
    }
}

void App::navigate_to(va_t addr) {
    if (hist_pos_ >= 0 && hist_pos_ < (int)hist_.size() && hist_[hist_pos_] == addr) return;

    va_t target = addr;

    if (analyzer_ && !analyzer_->db().insns.count(addr)) {
        auto xit = analyzer_->db().xrefs_to.find(addr);
        if (xit != analyzer_->db().xrefs_to.end() && !xit->second.empty())
            target = xit->second[0].from;
    }

    while ((int)hist_.size() > hist_pos_ + 1) hist_.pop_back();
    hist_.push_back(target);
    hist_pos_ = (int)hist_.size() - 1;
    if (hist_.size() > 2000) { hist_.pop_front(); --hist_pos_; }
    dv_.goto_addr(target);
    hv_.sync_to(addr);
}

void App::sync_panels(va_t addr) {
    va_t func = find_func_for(addr);
    if (func) {
        pv_.show_function(func);
        pv_.highlight_addr(addr);
        gv_.show_function(func);
        cgv_.show_function(func);
        sfv_.set_function(func);
    }
    xp_.show_for(addr);
    hv_.sync_to(addr);
}

va_t App::find_func_for(va_t addr) {
    if (!analyzer_) return 0;
    auto& db = analyzer_->db();

    if (db.funcs.count(addr)) return addr;
    for (auto& [entry, func] : db.funcs) {
        for (auto& [ba, bb] : func.blocks) {
            if (addr >= bb.start && addr < bb.end)
                return entry;
        }
    }
    return 0;
}

void App::export_patched() {
    if (!img_ || !analyzer_) return;
    auto p = save_dialog();
    if (p.empty()) return;

    std::ifstream in(file_path_, std::ios::binary);
    if (!in) { out_.log("ERROR: cannot read original file"); return; }
    std::vector<u8> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    auto& db = analyzer_->db();
    for (auto& [addr, patch] : db.patches) {
        for (auto& seg : img_->segments) {
            if (!seg.contains(addr)) continue;
            size_t file_off_base = seg.file_off + static_cast<size_t>(addr - seg.va);
            for (size_t i = 0; i < patch.size() && file_off_base + i < data.size(); ++i)
                data[file_off_base + i] = patch[i];
            break;
        }
    }

    std::ofstream out(p, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out_.log(fmt::format("Patched binary exported: {}", p));
}

void App::rebase(va_t new_base) {
    if (!img_ || !analyzer_) return;
    va_t old_base = img_->base;
    i64 delta = static_cast<i64>(new_base) - static_cast<i64>(old_base);
    if (delta == 0) return;

    out_.log(fmt::format("Rebasing: 0x{:X} -> 0x{:X} (delta {:+})", old_base, new_base, delta));

    img_->base = new_base;
    img_->entry = static_cast<va_t>(static_cast<i64>(img_->entry) + delta);
    for (auto& seg : img_->segments)
        seg.va = static_cast<va_t>(static_cast<i64>(seg.va) + delta);
    for (auto& imp : img_->imports)
        imp.iat_addr = static_cast<va_t>(static_cast<i64>(imp.iat_addr) + delta);
    for (auto& exp : img_->exports)
        exp.addr = static_cast<va_t>(static_cast<i64>(exp.addr) + delta);

    auto& db = analyzer_->db();
    std::unordered_map<va_t, Insn> new_insns;
    for (auto& [addr, insn] : db.insns) {
        insn.addr = static_cast<va_t>(static_cast<i64>(insn.addr) + delta);
        new_insns[insn.addr] = std::move(insn);
    }
    db.insns = std::move(new_insns);

    std::unordered_map<va_t, Function> new_funcs;
    for (auto& [entry, func] : db.funcs) {
        func.entry = static_cast<va_t>(static_cast<i64>(func.entry) + delta);
        std::unordered_map<va_t, BasicBlock> new_blocks;
        for (auto& [ba, bb] : func.blocks) {
            bb.start = static_cast<va_t>(static_cast<i64>(bb.start) + delta);
            bb.end = static_cast<va_t>(static_cast<i64>(bb.end) + delta);
            for (auto& s : bb.succs) s = static_cast<va_t>(static_cast<i64>(s) + delta);
            for (auto& p : bb.preds) p = static_cast<va_t>(static_cast<i64>(p) + delta);
            for (auto& i : bb.insns) i.addr = static_cast<va_t>(static_cast<i64>(i.addr) + delta);
            new_blocks[bb.start] = std::move(bb);
        }
        func.blocks = std::move(new_blocks);
        func.block_addrs.clear();
        for (auto& [ba, _] : func.blocks)
            func.block_addrs.push_back(ba);
        new_funcs[func.entry] = std::move(func);
    }
    db.funcs = std::move(new_funcs);

    std::unordered_map<va_t, std::string> new_names;
    for (auto& [addr, name] : db.names)
        new_names[static_cast<va_t>(static_cast<i64>(addr) + delta)] = std::move(name);
    db.names = std::move(new_names);

    std::unordered_map<va_t, std::string> new_comments;
    for (auto& [addr, cmt] : db.comments)
        new_comments[static_cast<va_t>(static_cast<i64>(addr) + delta)] = std::move(cmt);
    db.comments = std::move(new_comments);

    for (auto& xr : db.xrefs) {
        xr.from = static_cast<va_t>(static_cast<i64>(xr.from) + delta);
        xr.to = static_cast<va_t>(static_cast<i64>(xr.to) + delta);
    }
    db.xrefs_to.clear();
    db.xrefs_from.clear();
    for (auto& xr : db.xrefs) {
        db.xrefs_to[xr.to].push_back(xr);
        db.xrefs_from[xr.from].push_back(xr);
    }

    for (auto& [addr, str] : db.strings)
        addr = static_cast<va_t>(static_cast<i64>(addr) + delta);

    for (auto& bm : bookmarks_)
        bm.addr = static_cast<va_t>(static_cast<i64>(bm.addr) + delta);

    // rebuild xref indices
    db.xrefs_to.clear();
    db.xrefs_from.clear();
    for (auto& xr : db.xrefs) {
        db.xrefs_to[xr.to].push_back(xr);
        db.xrefs_from[xr.from].push_back(xr);
    }

    // rebase data items and patches
    std::unordered_map<va_t, DataItem> new_data;
    for (auto& [a, d] : db.data_items) {
        va_t na = static_cast<va_t>(static_cast<i64>(a) + delta);
        new_data[na] = d;
    }
    db.data_items = std::move(new_data);

    std::unordered_map<va_t, std::vector<u8>> new_patches;
    for (auto& [a, v] : db.patches)
        new_patches[static_cast<va_t>(static_cast<i64>(a) + delta)] = std::move(v);
    db.patches = std::move(new_patches);

    std::unordered_set<va_t> new_hex;
    for (auto a : db.hex_display)
        new_hex.insert(static_cast<va_t>(static_cast<i64>(a) + delta));
    db.hex_display = std::move(new_hex);

    dv_.set_data(&db, img_.get());
    gv_.set_data(&db);
    fp_.set_data(&db);
    sp_.set_data(&db);
    xp_.set_data(&db);
    xp_.set_img(img_.get());
    pv_.set_data(&db, analyzer_ ? &analyzer_->rtti_parser() : nullptr);
    ip_.set_data(img_.get());
    ip_.set_db(&db);
    hv_.set_data(img_.get());
    cgv_.set_data(&db);
    sfv_.set_data(&db);
    srch_.set_data(&db, img_.get());
    ev_.set_data(img_.get());

    navigate_to(img_->entry);
    sync_panels(img_->entry);
    out_.log(fmt::format("Rebased: 0x{:X} -> 0x{:X} (delta={:+})", old_base, new_base, delta));
}

void App::add_bookmark(va_t addr, const std::string& label) {
    std::string lbl = label.empty() ? fmt::format("bmark_{:X}", addr) : label;
    bookmarks_.push_back({addr, lbl});
    int idx = static_cast<int>(bookmarks_.size()) - 1;
    undo_.push({
        [this, idx]() { if (idx < (int)bookmarks_.size()) bookmarks_.erase(bookmarks_.begin() + idx); },
        [this, addr, lbl]() { bookmarks_.push_back({addr, lbl}); },
        "bookmark"
    });
    out_.log(fmt::format("Bookmark: {} @ 0x{:X}", lbl, addr));
}

void App::nav_back() {
    if (hist_pos_ > 0) {
        --hist_pos_;
        dv_.goto_addr(hist_[hist_pos_]);
        hv_.sync_to(hist_[hist_pos_]);
        sync_panels(hist_[hist_pos_]);
    }
}

void App::nav_fwd() {
    if (hist_pos_ < (int)hist_.size() - 1) {
        ++hist_pos_;
        dv_.goto_addr(hist_[hist_pos_]);
        hv_.sync_to(hist_[hist_pos_]);
        sync_panels(hist_[hist_pos_]);
    }
}

void App::show_goto_dlg() {
    ImGui::SetNextWindowSize(ImVec2(350, 0), ImGuiCond_Once);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Go to###goto", &show_goto_, ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize)) {
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        bool go = ImGui::InputText("Address (hex)", goto_buf_, sizeof(goto_buf_),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
        if (go || ImGui::Button("Go")) {
            if (goto_buf_[0]) {
                va_t a = std::strtoull(goto_buf_, nullptr, 16);
                navigate_to(a);
                sync_panels(a);
            }
            show_goto_ = false; goto_buf_[0] = 0;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) { show_goto_ = false; goto_buf_[0] = 0; }
    }
    ImGui::End();
}

void App::show_rename_dlg() {
    ImGui::SetNextWindowSize(ImVec2(400, 0), ImGuiCond_Once);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Rename###rename", &show_rename_, ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize)) {
        va_t cur = dv_.cursor();
        ImGui::Text("Address: 0x%016llX", (unsigned long long)cur);
        if (analyzer_) {
            auto nit = analyzer_->db().names.find(cur);
            if (nit != analyzer_->db().names.end())
                ImGui::TextDisabled("Current: %s", nit->second.c_str());
        }
        ImGui::Separator();
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        bool go = ImGui::InputText("New name", rename_buf_, sizeof(rename_buf_), ImGuiInputTextFlags_EnterReturnsTrue);
        if (go || ImGui::Button("OK")) {
            if (analyzer_ && rename_buf_[0]) {
                auto& db = analyzer_->db();
                std::string old_name;
                auto nit = db.names.find(cur);
                if (nit != db.names.end()) old_name = nit->second;
                std::string new_name(rename_buf_);
                db.set_name(cur, new_name);
                undo_.push({
                    [&db, cur, old_name]() { if (old_name.empty()) db.names.erase(cur); else db.set_name(cur, old_name); },
                    [&db, cur, new_name]() { db.set_name(cur, new_name); },
                    "rename"
                });
                out_.log(fmt::format("Renamed 0x{:X} -> {}", cur, rename_buf_));
            }
            show_rename_ = false; rename_buf_[0] = 0;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) { show_rename_ = false; rename_buf_[0] = 0; }
    }
    ImGui::End();
}

void App::show_rebase_dlg() {
    ImGui::OpenPopup("Rebase Program");
    if (ImGui::BeginPopupModal("Rebase Program", &show_rebase_, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (!img_) { ImGui::EndPopup(); return; }

        ImGui::Text("Current image base: 0x%016llX", (unsigned long long)img_->base);
        ImGui::Text("Entry point:        0x%016llX", (unsigned long long)img_->entry);
        ImGui::Separator();

        static int mode = 0;
        ImGui::RadioButton("New base address", &mode, 0);
        ImGui::RadioButton("Delta (shift by)", &mode, 1);
        ImGui::Spacing();

        if (mode == 0) {
            ImGui::SetNextItemWidth(200);
            ImGui::InputText("New base (hex)", rebase_buf_, sizeof(rebase_buf_),
                ImGuiInputTextFlags_CharsHexadecimal);
            va_t nb = std::strtoull(rebase_buf_, nullptr, 16);
            i64 delta = static_cast<i64>(nb) - static_cast<i64>(img_->base);
            ImGui::TextDisabled("Delta: %s0x%llX", delta >= 0 ? "+" : "-",
                (unsigned long long)(delta >= 0 ? delta : -delta));
        } else {
            static char delta_buf[64] = {};
            static bool negative = false;
            ImGui::Checkbox("Negative", &negative);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(160);
            ImGui::InputText("Delta (hex)", delta_buf, sizeof(delta_buf),
                ImGuiInputTextFlags_CharsHexadecimal);
            u64 d = std::strtoull(delta_buf, nullptr, 16);
            va_t preview = negative ? img_->base - d : img_->base + d;
            ImGui::TextDisabled("New base would be: 0x%016llX", (unsigned long long)preview);
            // store computed value in rebase_buf for the rebase call
            snprintf(rebase_buf_, sizeof(rebase_buf_), "%llX", (unsigned long long)preview);
        }

        ImGui::Spacing();
        ImGui::Separator();

        if (ImGui::Button("Rebase", ImVec2(100, 0))) {
            va_t nb = std::strtoull(rebase_buf_, nullptr, 16);
            if (nb != img_->base) rebase(nb);
            else if (nb == 0 && rebase_buf_[0] == '0') rebase(0);
            show_rebase_ = false; rebase_buf_[0] = 0;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(100, 0))) { show_rebase_ = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

void App::show_comment_dlg() {
    ImGui::SetNextWindowSize(ImVec2(400, 0), ImGuiCond_Once);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Comment###comment", &show_comment_, ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize)) {
        va_t cur = dv_.cursor();
        ImGui::Text("0x%016llX", (unsigned long long)cur);
        if (analyzer_) {
            auto cit = analyzer_->db().comments.find(cur);
            if (cit != analyzer_->db().comments.end()) {
                ImGui::TextDisabled("Current: %s", cit->second.c_str());
                if (comment_buf_[0] == 0)
                    strncpy(comment_buf_, cit->second.c_str(), sizeof(comment_buf_) - 1);
            }
        }
        ImGui::Separator();
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        bool go = ImGui::InputText("Comment", comment_buf_, sizeof(comment_buf_), ImGuiInputTextFlags_EnterReturnsTrue);
        if (go || ImGui::Button("OK")) {
            if (analyzer_) {
                auto& db = analyzer_->db();
                std::string old_cmt;
                auto cit = db.comments.find(cur);
                if (cit != db.comments.end()) old_cmt = cit->second;
                std::string new_cmt(comment_buf_);
                {
                    std::lock_guard lk(db.mtx);
                    if (new_cmt.empty()) db.comments.erase(cur);
                    else db.comments[cur] = new_cmt;
                }
                undo_.push({
                    [&db, cur, old_cmt]() { std::lock_guard lk(db.mtx); if (old_cmt.empty()) db.comments.erase(cur); else db.comments[cur] = old_cmt; },
                    [&db, cur, new_cmt]() { std::lock_guard lk(db.mtx); if (new_cmt.empty()) db.comments.erase(cur); else db.comments[cur] = new_cmt; },
                    "comment"
                });
            }
            show_comment_ = false; comment_buf_[0] = 0;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) { show_comment_ = false; comment_buf_[0] = 0; }
    }
    ImGui::End();
}

void App::show_segments_dlg() {
    ImGui::OpenPopup("Segments");
    if (ImGui::BeginPopupModal("Segments", &show_segments_, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (img_ && ImGui::BeginTable("##segs", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Start");
            ImGui::TableSetupColumn("Size");
            ImGui::TableSetupColumn("RWX");
            ImGui::TableSetupColumn("Raw Size");
            ImGui::TableHeadersRow();

            for (auto& seg : img_->segments) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%s", seg.name.c_str());
                ImGui::TableNextColumn(); ImGui::Text("0x%016llX", (unsigned long long)seg.va);
                ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)seg.size);
                ImGui::TableNextColumn();
                std::string perms;
                if (seg.readable()) perms += "R";
                if (seg.writable()) perms += "W";
                if (seg.executable()) perms += "X";
                ImGui::Text("%s", perms.c_str());
                ImGui::TableNextColumn(); ImGui::Text("0x%llX", (unsigned long long)seg.file_sz);
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Close")) { show_segments_ = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

void App::show_bookmarks_dlg() {
    ImGui::OpenPopup("Bookmarks");
    if (ImGui::BeginPopupModal("Bookmarks", &show_bookmarks_, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (ImGui::Button("Add current")) add_bookmark(dv_.cursor(), "");
        ImGui::Separator();

        if (ImGui::BeginTable("##bm", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
            ImGui::TableSetupColumn("Label");
            ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30);
            ImGui::TableHeadersRow();

            int to_delete = -1;
            for (int i = 0; i < (int)bookmarks_.size(); i++) {
                auto& bm = bookmarks_[i];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                auto lbl = fmt::format("{:016X}", bm.addr);
                if (ImGui::Selectable(lbl.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    navigate_to(bm.addr);
                    sync_panels(bm.addr);
                }
                ImGui::TableNextColumn(); ImGui::Text("%s", bm.label.c_str());
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                if (ImGui::SmallButton("X")) to_delete = i;
                ImGui::PopID();
            }
            if (to_delete >= 0) {
                auto deleted = bookmarks_[to_delete];
                int del_idx = to_delete;
                bookmarks_.erase(bookmarks_.begin() + to_delete);
                undo_.push({
                    [this, del_idx, deleted]() { bookmarks_.insert(bookmarks_.begin() + (std::min)(del_idx, (int)bookmarks_.size()), deleted); },
                    [this, del_idx]() { if (del_idx < (int)bookmarks_.size()) bookmarks_.erase(bookmarks_.begin() + del_idx); },
                    "remove bookmark"
                });
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Close")) { show_bookmarks_ = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

void App::show_sigs_dlg() {
    if (!ImGui::IsPopupOpen("Signature Libraries")) ImGui::OpenPopup("Signature Libraries");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, {0.5f, 0.5f});
    ImGui::SetNextWindowSize({600, 450}, ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Signature Libraries", &show_sigs_, ImGuiWindowFlags_NoScrollbar)) {
        if (!analyzer_) { ImGui::TextDisabled("No analysis data"); ImGui::EndPopup(); return; }
        auto& flirt = analyzer_->sig_matcher().flirt();
        auto& sigs = flirt.sigs();

        ImGui::Text("Loaded: %d .sig files, %d extracted names, %d byte patterns",
            (int)sigs.size(), flirt.total_names(), analyzer_->sig_matcher().sig_count());
        ImGui::Separator();

        if (ImGui::BeginTable("##sigtbl", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
            {0, -30})) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthFixed, 120);
            ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 50);
            ImGui::TableSetupColumn("Types", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Names", ImGuiTableColumnFlags_WidthFixed, 60);
            ImGui::TableHeadersRow();

            for (auto& s : sigs) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.filename.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.library_name.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(FlirtLoader::arch_str(s.arch).c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(FlirtLoader::file_types_str(s.file_types).c_str());
                ImGui::TableNextColumn(); ImGui::Text("%d", (int)s.extracted_names.size());
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Close")) { show_sigs_ = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

void App::show_apply_type_dlg() {
    if (!ImGui::IsPopupOpen("Apply Type")) ImGui::OpenPopup("Apply Type");
    if (ImGui::BeginPopupModal("Apply Type", &show_apply_type_, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (!analyzer_) { ImGui::EndPopup(); return; }
        va_t cur = dv_.cursor();
        ImGui::Text("Address: 0x%016llX", (unsigned long long)cur);
        ImGui::Separator();
        ImGui::InputTextWithHint("##tfilter", "Filter...", type_filter_, sizeof(type_filter_));

        auto& ts = analyzer_->db().types;
        std::string filt(type_filter_);
        std::transform(filt.begin(), filt.end(), filt.begin(), ::tolower);

        ImGui::BeginChild("##tlist", ImVec2(300, 250));
        for (auto& [id, td] : ts.all()) {
            if (td.kind != TypeKind::Struct && td.kind != TypeKind::Enum) continue;
            if (!filt.empty()) {
                std::string ln = td.name;
                std::transform(ln.begin(), ln.end(), ln.begin(), ::tolower);
                if (ln.find(filt) == std::string::npos) continue;
            }
            if (ImGui::Selectable(td.name.c_str())) {
                auto& db = analyzer_->db();
                va_t addr = dv_.cursor();
                u32 new_type_id = id;
                bool had_type = db.applied_types.count(addr) > 0;
                u32 old_type_id = had_type ? db.applied_types.at(addr) : 0;
                db.applied_types[addr] = new_type_id;
                undo_.push({
                    [this, addr, had_type, old_type_id]() {
                        if (had_type) analyzer_->db().applied_types[addr] = old_type_id;
                        else analyzer_->db().applied_types.erase(addr);
                    },
                    [this, addr, new_type_id]() { analyzer_->db().applied_types[addr] = new_type_id; },
                    "apply type"
                });
                show_apply_type_ = false;
                type_filter_[0] = 0;
                ImGui::CloseCurrentPopup();
                break;
            }
        }
        ImGui::EndChild();

        if (ImGui::Button("Remove Applied") && analyzer_->db().applied_types.count(cur)) {
            auto& db = analyzer_->db();
            u32 old_type_id = db.applied_types.at(cur);
            db.applied_types.erase(cur);
            undo_.push({
                [this, cur, old_type_id]() { analyzer_->db().applied_types[cur] = old_type_id; },
                [this, cur]() { analyzer_->db().applied_types.erase(cur); },
                "remove type"
            });
            show_apply_type_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) { show_apply_type_ = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

void App::compare_with() {
    if (!analyzer_) return;
    auto p = open_dialog();
    if (p.empty()) return;

    out_.log(fmt::format("Diff: loading {}", p));
    auto result = loader_.load(p.c_str());
    if (!result) { out_.log("ERROR: diff load failed"); return; }

    diff_img_ = std::make_unique<PEImage>(std::move(*result));
    diff_analyzer_ = std::make_unique<Analyzer>(*diff_img_, pool_);

    std::thread([this]() {
        diff_analyzer_->run();
        BinDiff differ;
        diff_results_ = differ.compare(analyzer_->db(), diff_analyzer_->db());
        diff_done_ = true;
    }).detach();
}

void App::load_recent_files() {
    auto exe_dir = std::filesystem::current_path();
    auto rf_path = exe_dir / "hyperion_recent.txt";
    std::ifstream in(rf_path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && recent_files_.size() < 10) {
            if (std::filesystem::exists(line))
                recent_files_.push_back(line);
        }
    }
}

void App::save_recent_files() {
    auto exe_dir = std::filesystem::current_path();
    auto rf_path = exe_dir / "hyperion_recent.txt";
    std::ofstream out(rf_path);
    for (auto& rf : recent_files_)
        out << rf << "\n";
}

void App::add_recent_file(const std::string& path) {
    auto it = std::find(recent_files_.begin(), recent_files_.end(), path);
    if (it != recent_files_.end()) recent_files_.erase(it);
    recent_files_.push_front(path);
    if (recent_files_.size() > 10) recent_files_.pop_back();
    save_recent_files();
}

void App::rebuild_nav_band() {
    nav_band_data_.clear();
    if (!img_ || img_->segments.empty() || !analyzer_) return;

    int w = nav_band_width_;
    if (w <= 0) return;
    nav_band_data_.resize(w, NB_Empty);

    va_t min_addr = img_->segments.front().va;
    va_t max_addr = min_addr;
    for (auto& seg : img_->segments)
        max_addr = (std::max)(max_addr, seg.va + seg.size);

    u64 range = max_addr - min_addr;
    if (range == 0) range = 1;

    auto addr_to_px = [&](va_t a) -> int {
        return (int)((double)(a - min_addr) / range * w);
    };

    // fill entire segments with base type first
    for (auto& seg : img_->segments) {
        int px_start = addr_to_px(seg.va);
        int px_end = addr_to_px(seg.va + seg.size);
        u8 base_type = seg.executable() ? NB_Code : NB_Data;
        for (int px = std::max(0, px_start); px < std::min(w, px_end); px++)
            nav_band_data_[px] = base_type;
    }

    // imports
    for (auto& imp : img_->imports) {
        int px = addr_to_px(imp.iat_addr);
        if (px >= 0 && px < w) nav_band_data_[px] = NB_Import;
    }

    // strings
    auto& db = analyzer_->db();
    for (auto& [sa, sv] : db.strings) {
        int px_start = addr_to_px(sa);
        int px_end = addr_to_px(sa + sv.size());
        for (int px = std::max(0, px_start); px <= std::min(w - 1, px_end); px++)
            nav_band_data_[px] = NB_String;
    }

    // functions (mark wider range)
    for (auto& [entry, func] : db.funcs) {
        int px = addr_to_px(entry);
        if (px >= 0 && px < w) nav_band_data_[px] = NB_Func;
        // try to mark a few pixels for visibility
        if (px + 1 < w) nav_band_data_[px + 1] = NB_Func;
    }

    // entropy heuristic: scan executable sections for high-entropy 256-byte blocks
    for (auto& seg : img_->segments) {
        if (!seg.executable() || seg.data.empty()) continue;
        constexpr int block = 256;
        for (size_t off = 0; off + block <= seg.data.size(); off += block) {
            int hist[256] = {};
            for (int i = 0; i < block; ++i) hist[seg.data[off + i]]++;
            double ent = 0;
            for (int i = 0; i < 256; ++i) {
                if (!hist[i]) continue;
                double p = hist[i] / (double)block;
                ent -= p * std::log2(p);
            }
            if (ent > 7.0) {
                int px = addr_to_px(seg.va + off);
                if (px >= 0 && px < w) nav_band_data_[px] = NB_Entropy;
            }
        }
    }
}

void App::render_nav_band() {
    ImVec2 pos = ImGui::GetCursorScreenPos();
    float width = ImGui::GetContentRegionAvail().x;
    constexpr float height = 18.0f;
    ImDrawList* dl = ImGui::GetWindowDrawList();

    if (!img_ || img_->segments.empty()) {
        dl->AddRectFilled(pos, ImVec2(pos.x + width, pos.y + height), IM_COL32(30, 30, 30, 255));
        ImGui::Dummy(ImVec2(width, height));
        return;
    }

    int w = (int)width;
    if (w != nav_band_width_) {
        nav_band_width_ = w;
        rebuild_nav_band();
    }

    static constexpr ImU32 type_colors[] = {
        IM_COL32(20, 20, 25, 255),    // Empty - very dark
        IM_COL32(50, 130, 230, 255),  // Code (bright blue)
        IM_COL32(80, 180, 255, 255),  // Func (light blue)
        IM_COL32(70, 75, 90, 255),    // Data (medium grey)
        IM_COL32(240, 190, 40, 255),  // String (bright yellow)
        IM_COL32(180, 70, 230, 255),  // Import (bright purple)
        IM_COL32(230, 60, 60, 255),   // Entropy (bright red)
    };

    for (int px = 0; px < w && px < (int)nav_band_data_.size(); ++px) {
        ImU32 col = type_colors[nav_band_data_[px]];
        dl->AddLine(ImVec2(pos.x + px, pos.y), ImVec2(pos.x + px, pos.y + height), col);
    }

    // cursor indicator
    va_t min_addr = img_->segments.front().va;
    va_t max_addr = min_addr;
    for (auto& seg : img_->segments)
        max_addr = (std::max)(max_addr, seg.va + seg.size);
    u64 range = max_addr - min_addr;
    if (range == 0) range = 1;

    va_t cur = dv_.cursor();
    if (cur >= min_addr && cur <= max_addr) {
        float cx = (float)((double)(cur - min_addr) / range * width);
        dl->AddTriangleFilled(
            ImVec2(pos.x + cx - 4, pos.y + height),
            ImVec2(pos.x + cx + 4, pos.y + height),
            ImVec2(pos.x + cx, pos.y + height - 6),
            IM_COL32(255, 255, 255, 255));
    }

    ImGui::InvisibleButton("##navband", ImVec2(width, height));
    if (ImGui::IsItemClicked()) {
        float mx = ImGui::GetIO().MousePos.x - pos.x;
        va_t target = min_addr + (u64)((double)mx / width * range);
        navigate_to(target);
        sync_panels(target);
    }
    if (ImGui::IsItemHovered()) {
        float mx = ImGui::GetIO().MousePos.x - pos.x;
        va_t hover_addr = min_addr + (u64)((double)mx / width * range);
        ImGui::SetTooltip("0x%llX", (unsigned long long)hover_addr);
    }
}

void App::autosave_tick() {
    if (!autosave_enabled_ || !analyzer_ || !img_ || busy_) return;
    if (file_path_.empty()) return;
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_autosave_).count();
    if (elapsed < 60) return;
    last_autosave_ = now;
    auto pp = std::filesystem::path(file_path_).replace_extension(".hdb");
    database_.save(pp, *img_, analyzer_->db());
    out_.log("Auto-saved");
}

void App::render_bg_image() {
    auto tex = settings_panel_.bg_texture();
    if (!tex) return;
    float opacity = settings_panel_.settings().bg_opacity;
    if (opacity <= 0.0f) return;

    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImVec2 p0 = vp->WorkPos;
    ImVec2 p1 = {p0.x + vp->WorkSize.x, p0.y + vp->WorkSize.y};
    ImU32 col = IM_COL32(255, 255, 255, (int)(opacity * 255));
    ImGui::GetBackgroundDrawList()->AddImage(
        (ImTextureID)(intptr_t)tex, p0, p1, {0, 0}, {1, 1}, col);
}

void App::export_asm() {
    if (!analyzer_ || !img_) return;
    auto p = std::filesystem::path(file_path_).replace_extension(".asm");
    std::ofstream out(p);
    if (!out) { out_.log("ERROR: cannot create .asm file"); return; }

    auto& db = analyzer_->db();
    out << "; Assembly listing generated by Hyperion\n";
    out << "; Source: " << file_path_ << "\n";
    out << fmt::format("; Image base: 0x{:X}\n\n", img_->base);

    for (auto& seg : img_->segments) {
        out << fmt::format("; === Section: {} (0x{:X} - 0x{:X}) ===\n",
            seg.name, seg.va, seg.va + seg.size);
    }
    out << "\n";

    std::vector<va_t> sorted_funcs;
    for (auto& [entry, _] : db.funcs) sorted_funcs.push_back(entry);
    std::sort(sorted_funcs.begin(), sorted_funcs.end());

    for (va_t entry : sorted_funcs) {
        auto& func = db.funcs.at(entry);
        out << "\n; " << std::string(60, '-') << "\n";
        auto nit = db.names.find(entry);
        std::string fname = nit != db.names.end() ? nit->second : func.name;
        out << fmt::format("; Function: {}\n", fname);
        out << "; " << std::string(60, '-') << "\n";

        auto xit = db.xrefs_to.find(entry);
        if (xit != db.xrefs_to.end() && !xit->second.empty()) {
            out << "; xrefs:";
            int xc = 0;
            for (auto& xr : xit->second) {
                if (xc++ >= 8) { out << " ..."; break; }
                out << fmt::format(" 0x{:X}", xr.from);
            }
            out << "\n";
        }

        out << fname << " proc\n";

        std::vector<va_t> block_order = func.block_addrs;
        std::sort(block_order.begin(), block_order.end());

        for (va_t ba : block_order) {
            auto bit = func.blocks.find(ba);
            if (bit == func.blocks.end()) continue;
            auto& bb = bit->second;

            if (ba != entry)
                out << fmt::format("loc_{:X}:\n", ba);

            for (auto& insn : bb.insns) {
                std::string line = fmt::format("  {:016X}  ", insn.addr);
                line += insn.mnemonic;
                if (insn.op_str[0]) {
                    size_t mlen = std::strlen(insn.mnemonic);
                    size_t pad = 8 - (mlen < 7 ? mlen : 7);
                    line += std::string(pad, ' ');
                    line += insn.op_str;
                }
                auto cit = db.comments.find(insn.addr);
                if (cit != db.comments.end())
                    line += "  ; " + cit->second;
                else {
                    for (u8 i = 0; i < insn.op_count; ++i) {
                        auto& op = insn.ops[i];
                        va_t ref = 0;
                        if (op.type == OpType::Mem && op.val) ref = op.val;
                        else if (op.type == OpType::Imm && op.val > 0x10000) ref = op.val;
                        if (!ref) continue;
                        for (auto& [sa, ss] : db.strings) {
                            if (sa == ref) {
                                auto s = ss.size() > 40 ? ss.substr(0, 40) + "..." : ss;
                                line += "  ; \"" + s + "\"";
                                goto str_done;
                            }
                        }
                        {
                            auto nit2 = db.names.find(ref);
                            if (nit2 != db.names.end())
                                line += "  ; " + nit2->second;
                        }
                        str_done:
                        break;
                    }
                }
                out << line << "\n";
            }
        }
        out << fname << " endp\n";
    }

    out_.log(fmt::format("Exported: {}", p.string()));
}

void App::render_plugin_manager() {
    ImGui::SetNextWindowSize(ImVec2(600, 400), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Plugin Manager", &show_plugin_manager_)) {
        ImGui::End();
        return;
    }

    auto& plgs = lua_.plugins();

    ImGui::TextDisabled("Plugins directory: plugins/  (%d loaded)", static_cast<int>(plgs.size()));
    ImGui::Separator();

    if (plgs.empty()) {
        ImGui::TextDisabled("No plugins found.");
        ImGui::TextDisabled("Place .lua files in the plugins/ directory next to the executable.");
    } else {
        ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
        if (ImGui::BeginTable("##plugins_tbl", 4, flags, ImVec2(0, -30))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Name",    ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 0.40f);
            ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 60.f);
            ImGui::TableSetupColumn("Status",  ImGuiTableColumnFlags_WidthFixed, 120.f);
            ImGui::TableHeadersRow();

            for (int pi = 0; pi < static_cast<int>(plgs.size()); ++pi) {
                auto& plg = plgs[static_cast<size_t>(pi)];
                ImGui::TableNextRow();

                // Name
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(plg.name.c_str());

                // Description
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(plg.desc.empty() ? "—" : plg.desc.c_str());

                // Action count
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%d", static_cast<int>(plg.items.size()));

                // Status
                ImGui::TableSetColumnIndex(3);
                if (plg.error) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.f, 0.4f, 0.4f, 1.f));
                    ImGui::TextUnformatted("Error");
                    ImGui::PopStyleColor();
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s", plg.error_msg.c_str());
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.f, 0.5f, 1.f));
                    ImGui::TextUnformatted("OK");
                    ImGui::PopStyleColor();
                }
            }
            ImGui::EndTable();
        }
    }

    ImGui::End();
}

void App::render_results_windows() {
    auto& windows = lua_.result_windows();
    for (auto& w : windows) {
        if (!w.open) continue;

        ImGui::SetNextWindowSize(ImVec2(820, 480), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSizeConstraints(ImVec2(400, 200), ImVec2(FLT_MAX, FLT_MAX));

        ImGuiWindowFlags wflags = ImGuiWindowFlags_None;
        if (!ImGui::Begin(w.title.c_str(), &w.open, wflags)) {
            ImGui::End();
            continue;
        }

        // Search / filter bar
        ImGui::SetNextItemWidth(-1.f);
        ImGui::InputTextWithHint("##rw_filter", "Filter results...", w.filter, sizeof(w.filter));
        ImGui::Separator();

        std::string filter_lower = w.filter;
        for (auto& c : filter_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        // Count visible rows for the footer
        int visible = 0;

        ImGuiTableFlags tflags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                 ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                 ImGuiTableFlags_SizingStretchProp;

        // +1 column for the address
        int ncols = static_cast<int>(w.headers.size()) + 1;
        if (ImGui::BeginTable("##rw_tbl", ncols, tflags, ImVec2(0, -ImGui::GetFrameHeightWithSpacing()))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 110.f);
            for (auto& h : w.headers)
                ImGui::TableSetupColumn(h.c_str(), ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (int ri = 0; ri < static_cast<int>(w.rows.size()); ++ri) {
                auto& row = w.rows[static_cast<size_t>(ri)];

                // Apply filter: check address hex + all col values
                if (filter_lower.size() > 0) {
                    char addr_buf[32];
                    std::snprintf(addr_buf, sizeof(addr_buf), "%llx",
                        static_cast<unsigned long long>(row.addr));
                    bool match = (std::string(addr_buf).find(filter_lower) != std::string::npos);
                    if (!match) {
                        for (auto& cv : row.cols) {
                            std::string cvl = cv;
                            for (auto& c : cvl) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                            if (cvl.find(filter_lower) != std::string::npos) { match = true; break; }
                        }
                    }
                    if (!match) continue;
                }
                visible++;

                ImGui::TableNextRow();

                // Address column — clickable
                ImGui::TableSetColumnIndex(0);
                char addr_label[48];
                std::snprintf(addr_label, sizeof(addr_label), "0x%llX##row%d",
                    static_cast<unsigned long long>(row.addr), ri);

                bool selected = (w.selected == ri);
                if (ImGui::Selectable(addr_label, selected,
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowOverlap,
                        ImVec2(0, 0))) {
                    w.selected = ri;
                    if (img_ && analyzer_) {
                        navigate_to(row.addr);
                        sync_panels(row.addr);
                    }
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Click to navigate to 0x%llX",
                        static_cast<unsigned long long>(row.addr));

                // Data columns
                for (int ci = 0; ci < static_cast<int>(row.cols.size()); ++ci) {
                    if (ImGui::TableSetColumnIndex(ci + 1))
                        ImGui::TextUnformatted(row.cols[static_cast<size_t>(ci)].c_str());
                }
            }
            ImGui::EndTable();
        }

        // Footer: count
        ImGui::TextDisabled("%d result(s)", visible);

        ImGui::End();
    }

    // Remove windows the user closed
    windows.erase(
        std::remove_if(windows.begin(), windows.end(),
            [](const ResultsWindow& w){ return !w.open; }),
        windows.end());
}

} // namespace hype
